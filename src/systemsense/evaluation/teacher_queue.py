"""Durable, local-only queue for quarantined next-probe teacher drafts.

The queue stores hashes and weak draft IDs, not requests, prompts, labels, or
evidence text. A trusted application-owned authorization provider must review
each exact prompt and confirm case consent before any local model call. This
module cannot admit training data or authenticate that provider by itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, cast
from uuid import uuid4

import psutil
from pydantic import Field

from systemsense.decision.contracts import DecisionRequest
from systemsense.domain.evidence import FrozenModel
from systemsense.evaluation.teacher_drafts import (
    PROMPT_VERSION,
    LocalOllamaTeacher,
    TeacherAttentionDraft,
    TeacherPrivacyReview,
    generate_teacher_draft,
    prepare_teacher_prompt,
    teacher_candidate_window_count,
)
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.storage.decision_snapshots import decision_request_sha256

_MAX_PAGE = 100
_QUEUE_SCHEMA_VERSION = 1
_SNAPSHOT_ID = re.compile(r"^decision_snapshot_[0-9a-f]{32}$")


class TeacherRunApproval(FrozenModel):
    """External approval, bound to one prompt and local teacher artifact."""

    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    snapshot_id: str = Field(pattern=r"^decision_snapshot_[0-9a-f]{32}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_id: str = Field(min_length=1, max_length=120)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_id: str = Field(min_length=1, max_length=160)
    purpose: Literal["local_teacher_draft"]
    expires_at: datetime
    privacy_review: TeacherPrivacyReview


class TeacherRunAuthorizer(Protocol):
    """Trusted application boundary; there is intentionally no allow-all default."""

    def authorize(
        self,
        *,
        prompt: str,
        prompt_sha256: str,
        case_id: str,
        snapshot_id: str,
        request_sha256: str,
        model_id: str,
        model_digest: str,
    ) -> TeacherRunApproval | None: ...


class TeacherQueueJob(FrozenModel):
    sequence: int = Field(ge=1)
    job_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: str
    case_id: str
    request_sha256: str
    prompt_sha256: str
    model_id: str
    model_digest: str
    window_index: int = Field(ge=0)
    synthetic: bool
    status: Literal["pending", "running", "blocked", "failed", "complete"]
    attempts: int = Field(ge=0)
    failure_code: str | None = None
    authorization_id: str | None = None
    authorization_purpose: Literal["local_teacher_draft"] | None = None
    authorization_expires_at: datetime | None = None
    authorization_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class TeacherQueuePage(FrozenModel):
    jobs: tuple[TeacherQueueJob, ...]
    next_sequence: int | None = None


class TeacherRunReport(FrozenModel):
    attempted: int = Field(ge=0)
    completed: int = Field(ge=0)
    blocked: int = Field(ge=0)
    failed: int = Field(ge=0)
    remaining_pending: int = Field(ge=0)


class TeacherDraftQueue:
    """Single-local-model queue with bounded pages and crash-safe per-job commits."""

    def __init__(self, path: Path) -> None:
        self._connection = sqlite3.connect(path, timeout=5)
        self._connection.row_factory = sqlite3.Row
        version_row = self._connection.execute("PRAGMA user_version").fetchone()
        version = int(version_row[0])
        if version not in {0, _QUEUE_SCHEMA_VERSION}:
            self._connection.close()
            raise ValueError("teacher queue storage schema is unsupported")
        if (
            version == 0
            and self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'teacher_draft_jobs'"
            ).fetchone()
        ):
            self._connection.close()
            raise ValueError("unversioned teacher queue storage schema is unsupported")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS teacher_draft_jobs (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL UNIQUE,
                snapshot_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                prompt_sha256 TEXT NOT NULL,
                prompt_version INTEGER NOT NULL,
                model_id TEXT NOT NULL,
                model_digest TEXT NOT NULL,
                window_index INTEGER NOT NULL,
                synthetic INTEGER NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                failure_code TEXT,
                draft_json TEXT,
                owner_pid INTEGER,
                owner_started_at REAL,
                claim_token TEXT,
                authorization_id TEXT,
                authorization_purpose TEXT,
                authorization_expires_at TEXT,
                authorization_sha256 TEXT,
                UNIQUE(snapshot_id, window_index, model_id, model_digest)
            )"""
        )
        self._connection.execute(f"PRAGMA user_version={_QUEUE_SCHEMA_VERSION}")
        self._connection.commit()

    def __enter__(self) -> TeacherDraftQueue:
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def enqueue(
        self,
        *,
        snapshot_id: str,
        request: DecisionRequest,
        model_id: str,
        model_digest: str,
        synthetic: bool,
    ) -> int:
        """Add each eligible candidate window once, retaining no source plaintext."""

        if _SNAPSHOT_ID.fullmatch(snapshot_id) is None:
            raise ValueError("snapshot ID is invalid")
        LocalInferenceConfig(reasoning_model=model_id, reasoning_digest=model_digest)
        if request.attention_only:
            raise ValueError("attention-only requests cannot become probe draft jobs")
        request_hash = decision_request_sha256(request)
        count = teacher_candidate_window_count(request)
        if count == 0:
            return 0
        planned: list[tuple[str, str, int]] = []
        for window_index in range(count):
            prompt = prepare_teacher_prompt(request, window_index=window_index)
            prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            job_id = hashlib.sha256(
                f"{snapshot_id}:{request_hash}:{PROMPT_VERSION}:{window_index}:"
                f"{model_id}:{model_digest}".encode()
            ).hexdigest()
            planned.append((job_id, prompt_hash, window_index))
        with self._connection:
            for job_id, prompt_hash, window_index in planned:
                existing = self._connection.execute(
                    """SELECT job_id, request_sha256, prompt_sha256, prompt_version, case_id,
                              synthetic FROM teacher_draft_jobs
                       WHERE snapshot_id = ? AND window_index = ? AND model_id = ?
                             AND model_digest = ?""",
                    (snapshot_id, window_index, model_id, model_digest),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["job_id"] != job_id
                        or existing["request_sha256"] != request_hash
                        or existing["prompt_sha256"] != prompt_hash
                        or existing["prompt_version"] != PROMPT_VERSION
                        or existing["case_id"] != str(request.case_id)
                        or bool(existing["synthetic"]) != synthetic
                    ):
                        raise ValueError("queued draft source changed for the same snapshot")
                    continue
                self._connection.execute(
                    """INSERT INTO teacher_draft_jobs (
                        job_id, snapshot_id, case_id, request_sha256, prompt_sha256,
                        prompt_version, model_id, model_digest, window_index,
                        synthetic, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
                    (
                        job_id,
                        snapshot_id,
                        str(request.case_id),
                        request_hash,
                        prompt_hash,
                        PROMPT_VERSION,
                        model_id,
                        model_digest,
                        window_index,
                        int(synthetic),
                    ),
                )
        return count

    def page(self, *, after_sequence: int = 0, limit: int = 50) -> TeacherQueuePage:
        if after_sequence < 0 or not 1 <= limit <= _MAX_PAGE:
            raise ValueError("queue page bounds are invalid")
        rows = self._connection.execute(
            """SELECT * FROM teacher_draft_jobs WHERE sequence > ?
               ORDER BY sequence LIMIT ?""",
            (after_sequence, limit + 1),
        ).fetchall()
        visible = rows[:limit]
        return TeacherQueuePage(
            jobs=tuple(_job_from_row(row) for row in visible),
            next_sequence=int(visible[-1]["sequence"]) if len(rows) > limit else None,
        )

    def run_page(
        self,
        *,
        load_request: Callable[[str], DecisionRequest],
        teacher: LocalOllamaTeacher,
        authorizer: TeacherRunAuthorizer | None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        limit: int = 10,
    ) -> TeacherRunReport:
        """Run a bounded page; external work occurs after an atomic short claim.

        A live owner is never reclaimed. A crashed owner's job is retried only
        after its OS process identity has disappeared. A crash after inference
        but before commit may rerun the weak draft; no gold label is duplicated.
        """

        if authorizer is None:
            raise PermissionError("external prompt privacy and case authorization is required")
        if type(teacher) is not LocalOllamaTeacher:
            raise TypeError("queue requires a pinned local Ollama teacher")
        if not 1 <= limit <= _MAX_PAGE:
            raise ValueError("run page bounds are invalid")
        self._recover_dead_owners()
        rows = self._connection.execute(
            """SELECT sequence FROM teacher_draft_jobs WHERE status = 'pending'
               AND model_id = ? AND model_digest = ?
               ORDER BY sequence LIMIT ?""",
            (teacher.model_id, teacher.model_digest, limit),
        ).fetchall()
        completed = blocked = failed = attempted = 0
        for selected in rows:
            claim = self._claim(int(selected["sequence"]))
            if claim is None:
                continue
            row, claim_token = claim
            attempted += 1
            try:
                status, failure_code, draft, approval = self._run_one(
                    row,
                    load_request=load_request,
                    teacher=teacher,
                    authorizer=authorizer,
                    now=now,
                )
            except BaseException:
                self._release_claim(int(row["sequence"]), claim_token)
                raise
            self._finish_claim(
                sequence=int(row["sequence"]),
                claim_token=claim_token,
                status=status,
                failure_code=failure_code,
                draft=draft,
                approval=approval,
            )
            completed += int(status == "complete")
            blocked += int(status == "blocked")
            failed += int(status == "failed")
        remaining = self._connection.execute(
            """SELECT COUNT(*) FROM teacher_draft_jobs WHERE status = 'pending'
               AND model_id = ? AND model_digest = ?""",
            (teacher.model_id, teacher.model_digest),
        ).fetchone()
        return TeacherRunReport(
            attempted=attempted,
            completed=completed,
            blocked=blocked,
            failed=failed,
            remaining_pending=int(remaining[0]),
        )

    def _claim(self, sequence: int) -> tuple[sqlite3.Row, str] | None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT * FROM teacher_draft_jobs WHERE sequence = ?", (sequence,)
            ).fetchone()
            if row is None or row["status"] != "pending":
                self._connection.rollback()
                return None
            token = uuid4().hex
            owner_pid = os.getpid()
            owner_started_at = psutil.Process(owner_pid).create_time()
            self._connection.execute(
                """UPDATE teacher_draft_jobs SET status = 'running', attempts = attempts + 1,
                   owner_pid = ?, owner_started_at = ?, claim_token = ? WHERE sequence = ?""",
                (owner_pid, owner_started_at, token, sequence),
            )
            self._connection.commit()
            return row, token
        except BaseException:
            self._connection.rollback()
            raise

    def _finish_claim(
        self,
        *,
        sequence: int,
        claim_token: str,
        status: Literal["blocked", "failed", "complete"],
        failure_code: str | None,
        draft: TeacherAttentionDraft | None,
        approval: TeacherRunApproval | None,
    ) -> None:
        approval_digest = (
            hashlib.sha256(
                json.dumps(
                    approval.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            if approval is not None
            else None
        )
        with self._connection:
            result = self._connection.execute(
                """UPDATE teacher_draft_jobs SET status = ?, failure_code = ?,
                   draft_json = ?, owner_pid = NULL, owner_started_at = NULL,
                   claim_token = NULL, authorization_id = ?, authorization_purpose = ?,
                   authorization_expires_at = ?, authorization_sha256 = ?
                   WHERE sequence = ? AND status = 'running' AND claim_token = ?""",
                (
                    status,
                    failure_code,
                    draft.model_dump_json() if draft is not None else None,
                    approval.authorization_id if approval is not None else None,
                    approval.purpose if approval is not None else None,
                    approval.expires_at.isoformat() if approval is not None else None,
                    approval_digest,
                    sequence,
                    claim_token,
                ),
            )
            if result.rowcount != 1:
                raise RuntimeError("teacher queue job claim was lost")

    def _release_claim(self, sequence: int, claim_token: str) -> None:
        with self._connection:
            self._connection.execute(
                """UPDATE teacher_draft_jobs SET status = 'pending', owner_pid = NULL,
                   owner_started_at = NULL, claim_token = NULL,
                   authorization_id = NULL, authorization_purpose = NULL,
                   authorization_expires_at = NULL, authorization_sha256 = NULL
                   WHERE sequence = ? AND status = 'running' AND claim_token = ?""",
                (sequence, claim_token),
            )

    def _recover_dead_owners(self) -> None:
        """Requeue only jobs whose exact owning process no longer exists."""

        rows = self._connection.execute(
            """SELECT sequence, owner_pid, owner_started_at
               FROM teacher_draft_jobs WHERE status = 'running'"""
        ).fetchall()
        for row in rows:
            pid = row["owner_pid"]
            started_at = row["owner_started_at"]
            if pid is None or started_at is None:
                continue
            if _owner_is_active(int(pid), float(started_at)):
                continue
            with self._connection:
                self._connection.execute(
                    """UPDATE teacher_draft_jobs SET status = 'pending', owner_pid = NULL,
                       owner_started_at = NULL, claim_token = NULL,
                       authorization_id = NULL, authorization_purpose = NULL,
                       authorization_expires_at = NULL, authorization_sha256 = NULL
                       WHERE sequence = ?
                       AND status = 'running' AND owner_pid = ? AND owner_started_at = ?""",
                    (row["sequence"], pid, started_at),
                )

    def _run_one(
        self,
        row: sqlite3.Row,
        *,
        load_request: Callable[[str], DecisionRequest],
        teacher: LocalOllamaTeacher,
        authorizer: TeacherRunAuthorizer,
        now: Callable[[], datetime],
    ) -> tuple[
        Literal["blocked", "failed", "complete"],
        str | None,
        TeacherAttentionDraft | None,
        TeacherRunApproval | None,
    ]:
        if row["model_id"] != teacher.model_id or row["model_digest"] != teacher.model_digest:
            return "blocked", "model_mismatch", None, None
        try:
            request = load_request(str(row["snapshot_id"]))
            if (
                str(request.case_id) != row["case_id"]
                or decision_request_sha256(request) != row["request_sha256"]
                or row["prompt_version"] != PROMPT_VERSION
            ):
                return "blocked", "source_changed", None, None
            prompt = prepare_teacher_prompt(request, window_index=int(row["window_index"]))
            prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            if prompt_hash != row["prompt_sha256"]:
                return "blocked", "prompt_changed", None, None
        except Exception:
            return "blocked", "source_unavailable", None, None
        try:
            approval = authorizer.authorize(
                prompt=prompt,
                prompt_sha256=prompt_hash,
                case_id=str(request.case_id),
                snapshot_id=str(row["snapshot_id"]),
                request_sha256=str(row["request_sha256"]),
                model_id=teacher.model_id,
                model_digest=teacher.model_digest,
            )
            generated_at = now()
            if approval is None or not _approval_matches(approval, row, generated_at):
                return "blocked", "authorization_missing", None, None
        except Exception:
            return "blocked", "authorization_unavailable", None, None
        try:
            draft = generate_teacher_draft(
                request=request,
                teacher=teacher,
                model_id=teacher.model_id,
                model_digest=teacher.model_digest,
                generated_at=generated_at,
                synthetic=bool(row["synthetic"]),
                privacy_review=approval.privacy_review,
                window_index=int(row["window_index"]),
            )
        except Exception:
            return "failed", "teacher_or_draft_invalid", None, approval
        return "complete", None, draft, approval

    def draft(self, job_id: str) -> TeacherAttentionDraft | None:
        row = self._connection.execute(
            "SELECT * FROM teacher_draft_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if row is None:
            return None
        job = _job_from_row(row)
        if job.status != "complete":
            return None
        return TeacherAttentionDraft.model_validate_json(str(row["draft_json"]))

    def retry(self, job_id: str) -> bool:
        """Explicitly requeue one blocked/failed job after the external issue is fixed."""

        with self._connection:
            result = self._connection.execute(
                """UPDATE teacher_draft_jobs SET status = 'pending', failure_code = NULL,
                   authorization_id = NULL, authorization_purpose = NULL,
                   authorization_expires_at = NULL, authorization_sha256 = NULL
                   WHERE job_id = ? AND status IN ('blocked', 'failed')""",
                (job_id,),
            )
        return result.rowcount == 1


def _job_from_row(row: sqlite3.Row) -> TeacherQueueJob:
    status = str(row["status"])
    if status not in {"pending", "running", "blocked", "failed", "complete"}:
        raise ValueError("stored teacher queue status is invalid")
    authorization_purpose = row["authorization_purpose"]
    if authorization_purpose not in {None, "local_teacher_draft"}:
        raise ValueError("stored teacher queue authorization purpose is invalid")
    if status == "complete" and (
        row["draft_json"] is None
        or row["authorization_id"] is None
        or authorization_purpose is None
        or row["authorization_expires_at"] is None
        or row["authorization_sha256"] is None
    ):
        raise ValueError("stored teacher queue authorization or draft is incomplete")
    return TeacherQueueJob(
        sequence=int(row["sequence"]),
        job_id=str(row["job_id"]),
        snapshot_id=str(row["snapshot_id"]),
        case_id=str(row["case_id"]),
        request_sha256=str(row["request_sha256"]),
        prompt_sha256=str(row["prompt_sha256"]),
        model_id=str(row["model_id"]),
        model_digest=str(row["model_digest"]),
        window_index=int(row["window_index"]),
        synthetic=bool(row["synthetic"]),
        status=cast(Literal["pending", "running", "blocked", "failed", "complete"], status),
        attempts=int(row["attempts"]),
        failure_code=str(row["failure_code"]) if row["failure_code"] is not None else None,
        authorization_id=(
            str(row["authorization_id"]) if row["authorization_id"] is not None else None
        ),
        authorization_purpose=(
            "local_teacher_draft" if authorization_purpose == "local_teacher_draft" else None
        ),
        authorization_expires_at=(
            datetime.fromisoformat(str(row["authorization_expires_at"]))
            if row["authorization_expires_at"] is not None
            else None
        ),
        authorization_sha256=(
            str(row["authorization_sha256"]) if row["authorization_sha256"] is not None else None
        ),
    )


def _owner_is_active(pid: int, started_at: float) -> bool:
    try:
        return abs(psutil.Process(pid).create_time() - started_at) < 0.01
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        return True


def _approval_matches(approval: TeacherRunApproval, row: sqlite3.Row, now: datetime) -> bool:
    try:
        TeacherRunApproval.model_validate(approval.model_dump(mode="json"))
    except Exception:
        return False
    if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(None):
        return False
    return bool(
        approval.case_id == row["case_id"]
        and approval.snapshot_id == row["snapshot_id"]
        and approval.request_sha256 == row["request_sha256"]
        and approval.prompt_sha256 == row["prompt_sha256"]
        and approval.model_id == row["model_id"]
        and approval.model_digest == row["model_digest"]
        and approval.expires_at.tzinfo is not None
        and approval.expires_at.utcoffset() == UTC.utcoffset(None)
        and approval.expires_at > now
        and approval.privacy_review.prompt_sha256 == row["prompt_sha256"]
        and approval.privacy_review.reviewed_at <= now
    )
