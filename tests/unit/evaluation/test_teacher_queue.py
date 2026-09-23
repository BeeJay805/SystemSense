from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import psutil
import pytest

from systemsense.decision.contracts import DecisionRequest, ProbeCapability
from systemsense.domain.ids import CaseId
from systemsense.evaluation.teacher_drafts import LocalOllamaTeacher, TeacherPrivacyReview
from systemsense.evaluation.teacher_queue import (
    TeacherDraftQueue,
    TeacherRunApproval,
)
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.orchestration.scheduler import ResourceClass

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
DIGEST = "a" * 64
MODEL = "qwen3.8:27b"


def _request(
    *, symptom: str = "private symptom", case_id: CaseId | None = None, candidates: int = 2
) -> DecisionRequest:
    return DecisionRequest(
        case_id=case_id or CaseId.new(),
        state_version=1,
        correlation_id="teacher_queue_test",
        deadline_at=NOW + timedelta(days=1),
        symptom=symptom,
        available_probes=tuple(
            ProbeCapability(
                probe_id=probe_id,
                description=f"Inspect {probe_id}",
                cost_ms=10,
                resource_class=ResourceClass.CPU,
            )
            for probe_id in (
                ("windows.proxy", "windows.dns")
                if candidates == 2
                else tuple(f"windows.probe_{index:02}" for index in range(candidates))
            )
        ),
        budget_ms=10 * candidates,
        max_probes=candidates,
    )


class _Transport:
    def __init__(self) -> None:
        self.calls = 0
        self.fail = False

    def tags(self, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        return json.dumps(
            {
                "models": [
                    {"name": MODEL, "digest": DIGEST, "size": 1024, "details": {"format": "gguf"}}
                ]
            }
        ).encode()

    def show(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        return b'{"details":{"format":"gguf"},"model_info":{"architecture":"qwen"}}'

    def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.calls += 1
        if self.fail:
            raise RuntimeError("secret failure text must not enter the queue")
        request = json.loads(body)
        prompt = json.loads(request["messages"][1]["content"])
        ids = [item["probe_id"] for item in prompt["candidates"]]
        return json.dumps(
            {
                "done": True,
                "message": {
                    "content": json.dumps(
                        {"ranked_probe_ids": ids, "cited_evidence_ids": [], "abstain": False}
                    )
                },
            }
        ).encode()


def _teacher(transport: _Transport) -> LocalOllamaTeacher:
    return LocalOllamaTeacher(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model=MODEL,
            reasoning_digest=DIGEST,
            timeout_seconds=10,
        ),
        model_id=MODEL,
        model_digest=DIGEST,
        transport=transport,
    )


class _ApprovalSource:
    def __init__(self) -> None:
        self.calls = 0
        self.deny = False

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
    ) -> TeacherRunApproval | None:
        self.calls += 1
        assert prompt_sha256 and "private symptom" in prompt
        if self.deny:
            return None
        return TeacherRunApproval(
            case_id=case_id,
            snapshot_id=snapshot_id,
            request_sha256=request_sha256,
            prompt_sha256=prompt_sha256,
            model_id=model_id,
            model_digest=model_digest,
            authorization_id=f"consent_{self.calls}",
            purpose="local_teacher_draft",
            expires_at=NOW + timedelta(days=2),
            privacy_review=TeacherPrivacyReview(
                prompt_sha256=prompt_sha256,
                reviewer_id="real_reviewer",
                reviewed_at=NOW,
            ),
        )


class _ForgedApprovalSource(_ApprovalSource):
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
    ) -> TeacherRunApproval | None:
        receipt = super().authorize(
            prompt=prompt,
            prompt_sha256=prompt_sha256,
            case_id=case_id,
            snapshot_id=snapshot_id,
            request_sha256=request_sha256,
            model_id=model_id,
            model_digest=model_digest,
        )
        assert receipt is not None
        return receipt.model_copy(update={"prompt_sha256": "f" * 64})


def test_queue_paginates_more_than_500_windows_without_storing_private_prompts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "teacher.db"
    with TeacherDraftQueue(path) as queue:
        for _ in range(501):
            queue.enqueue(
                snapshot_id=f"decision_snapshot_{uuid4().hex}",
                request=_request(),
                model_id=MODEL,
                model_digest=DIGEST,
                synthetic=True,
            )
        cursor = 0
        seen: set[str] = set()
        while True:
            page = queue.page(after_sequence=cursor, limit=73)
            seen.update(job.job_id for job in page.jobs)
            if page.next_sequence is None:
                break
            cursor = page.next_sequence
        assert len(seen) == 501
    with sqlite3.connect(path) as connection:
        stored = " ".join(str(row) for row in connection.iterdump())
    assert "private symptom" not in stored


def test_queue_requires_external_approval_before_any_model_call(tmp_path: Path) -> None:
    request = _request()
    transport = _Transport()
    with TeacherDraftQueue(tmp_path / "teacher.db") as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        with pytest.raises(PermissionError, match="authorization"):
            queue.run_page(
                load_request=lambda _: request,
                teacher=_teacher(transport),
                authorizer=None,
                now=lambda: NOW + timedelta(hours=1),
                limit=1,
            )
        assert transport.calls == 0
        assert queue.page(limit=1).jobs[0].status == "pending"


def test_queue_persists_only_weak_draft_and_resume_does_not_rerun(tmp_path: Path) -> None:
    request = _request()
    snapshot_id = f"decision_snapshot_{uuid4().hex}"
    transport = _Transport()
    path = tmp_path / "teacher.db"
    with TeacherDraftQueue(path) as queue:
        queue.enqueue(
            snapshot_id=snapshot_id,
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        report = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=_ApprovalSource(),
            now=lambda: NOW + timedelta(hours=1),
            limit=1,
        )
        assert (report.attempted, report.completed, report.failed, report.blocked) == (1, 1, 0, 0)
        job = queue.page(limit=1).jobs[0]
        assert job.status == "complete"
        assert job.attempts == 1
        draft = queue.draft(job.job_id)
        assert draft is not None
        assert draft.label_origin == "local_model_weak"
        assert draft.export_reviewed is False
        assert draft.synthetic
        assert not queue.retry(job.job_id)
    with TeacherDraftQueue(path) as queue:
        assert queue.draft(job.job_id) == draft
        assert (
            queue.run_page(
                load_request=lambda _: request,
                teacher=_teacher(transport),
                authorizer=_ApprovalSource(),
                now=lambda: NOW + timedelta(hours=2),
                limit=1,
            ).attempted
            == 0
        )
    assert transport.calls == 1


def test_denied_prompt_is_blocked_and_explicit_retry_can_resume(tmp_path: Path) -> None:
    request = _request()
    transport = _Transport()
    source = _ApprovalSource()
    source.deny = True
    with TeacherDraftQueue(tmp_path / "teacher.db") as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        first = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=source,
            now=lambda: NOW + timedelta(hours=1),
        )
        job = queue.page(limit=1).jobs[0]
        assert (first.blocked, first.completed, transport.calls) == (1, 0, 0)
        assert job.failure_code == "authorization_missing"
        assert queue.draft(job.job_id) is None
        source.deny = False
        assert queue.retry(job.job_id)
        second = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=source,
            now=lambda: NOW + timedelta(hours=1),
        )
        assert (second.completed, transport.calls) == (1, 1)


def test_model_failure_is_reported_without_persisting_sensitive_error(tmp_path: Path) -> None:
    request = _request()
    transport = _Transport()
    transport.fail = True
    path = tmp_path / "teacher.db"
    with TeacherDraftQueue(path) as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        report = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=_ApprovalSource(),
            now=lambda: NOW + timedelta(hours=1),
        )
        job = queue.page(limit=1).jobs[0]
        assert (report.failed, report.completed, job.failure_code) == (
            1,
            0,
            "teacher_or_draft_invalid",
        )
        assert queue.draft(job.job_id) is None
        assert queue.retry(job.job_id)
        pending = queue.page(limit=1).jobs[0]
        assert pending.status == "pending"
        assert pending.authorization_id is None
        assert pending.authorization_sha256 is None
    with sqlite3.connect(path) as connection:
        stored = " ".join(str(row) for row in connection.iterdump())
    assert "secret failure text" not in stored
    assert "private symptom" not in stored


def test_changed_frozen_request_blocks_before_authorization_or_inference(tmp_path: Path) -> None:
    request = _request()
    changed = _request(symptom="different private symptom", case_id=request.case_id)
    transport = _Transport()
    source = _ApprovalSource()
    with TeacherDraftQueue(tmp_path / "teacher.db") as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        report = queue.run_page(
            load_request=lambda _: changed,
            teacher=_teacher(transport),
            authorizer=source,
            now=lambda: NOW + timedelta(hours=1),
        )
        assert report.blocked == 1
        assert queue.page(limit=1).jobs[0].failure_code == "source_changed"
        assert source.calls == transport.calls == 0


def test_forged_approval_digest_blocks_model_call(tmp_path: Path) -> None:
    request = _request()
    transport = _Transport()
    with TeacherDraftQueue(tmp_path / "teacher.db") as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        report = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=_ForgedApprovalSource(),
            now=lambda: NOW + timedelta(hours=1),
        )
        assert report.blocked == 1
        assert transport.calls == 0


def test_multiple_candidate_windows_run_as_separate_bounded_jobs(tmp_path: Path) -> None:
    request = _request(candidates=21)
    transport = _Transport()
    source = _ApprovalSource()
    with TeacherDraftQueue(tmp_path / "teacher.db") as queue:
        assert (
            queue.enqueue(
                snapshot_id=f"decision_snapshot_{uuid4().hex}",
                request=request,
                model_id=MODEL,
                model_digest=DIGEST,
                synthetic=True,
            )
            == 2
        )
        first = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=source,
            now=lambda: NOW + timedelta(hours=1),
            limit=1,
        )
        assert (first.completed, first.remaining_pending) == (1, 1)
        second = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=source,
            now=lambda: NOW + timedelta(hours=1),
            limit=1,
        )
        assert (second.completed, second.remaining_pending) == (1, 0)
        jobs = queue.page(limit=10).jobs
        drafts = [queue.draft(job.job_id) for job in jobs]
        assert [draft.candidate_window_index for draft in drafts if draft is not None] == [0, 1]
        assert [len(draft.eligible_candidate_ids) for draft in drafts if draft is not None] == [
            20,
            1,
        ]
        assert transport.calls == 2


def test_queue_refuses_unknown_storage_schema_before_processing(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="schema"):
        TeacherDraftQueue(path)


def test_external_work_does_not_hold_queue_write_lock_or_duplicate_live_job(
    tmp_path: Path,
) -> None:
    request = _request()
    extra = _request()
    path = tmp_path / "teacher.db"
    transport = _Transport()

    class _ConcurrentApproval(_ApprovalSource):
        def authorize(self, **kwargs: str) -> TeacherRunApproval | None:
            with TeacherDraftQueue(path) as second:
                assert second.page(limit=1).jobs[0].status == "running"
                other_report = second.run_page(
                    load_request=lambda _: request,
                    teacher=_teacher(transport),
                    authorizer=_ApprovalSource(),
                    now=lambda: NOW + timedelta(hours=1),
                    limit=1,
                )
                assert other_report.attempted == 0
                second.enqueue(
                    snapshot_id=f"decision_snapshot_{uuid4().hex}",
                    request=extra,
                    model_id=MODEL,
                    model_digest=DIGEST,
                    synthetic=True,
                )
            return super().authorize(**kwargs)

    with TeacherDraftQueue(path) as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        report = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=_ConcurrentApproval(),
            now=lambda: NOW + timedelta(hours=1),
            limit=1,
        )
        assert report.completed == 1
        assert [job.status for job in queue.page(limit=10).jobs] == ["complete", "pending"]
    assert transport.calls == 1


def test_completed_job_keeps_hash_only_approval_provenance(tmp_path: Path) -> None:
    request = _request()
    path = tmp_path / "teacher.db"
    with TeacherDraftQueue(path) as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        assert (
            queue.run_page(
                load_request=lambda _: request,
                teacher=_teacher(_Transport()),
                authorizer=_ApprovalSource(),
                now=lambda: NOW + timedelta(hours=1),
            ).completed
            == 1
        )
        job = queue.page(limit=1).jobs[0]
        assert job.authorization_id == "consent_1"
        assert job.authorization_purpose == "local_teacher_draft"
        assert job.authorization_expires_at == NOW + timedelta(days=2)
        assert len(job.authorization_sha256 or "") == 64
    with sqlite3.connect(path) as connection:
        stored = " ".join(str(row) for row in connection.iterdump())
    assert "private symptom" not in stored


def test_model_specific_run_skips_other_pinned_teacher_jobs(tmp_path: Path) -> None:
    request = _request()
    transport = _Transport()
    with TeacherDraftQueue(tmp_path / "teacher.db") as queue:
        first_id = f"decision_snapshot_{uuid4().hex}"
        queue.enqueue(
            snapshot_id=first_id,
            request=request,
            model_id="qwen3.5:4b",
            model_digest="b" * 64,
            synthetic=True,
        )
        queue.enqueue(
            snapshot_id=first_id,
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        result = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=_ApprovalSource(),
            now=lambda: NOW + timedelta(hours=1),
            limit=1,
        )
        assert result.completed == 1
        assert result.remaining_pending == 0
        assert [job.status for job in queue.page(limit=10).jobs] == ["pending", "complete"]
    assert transport.calls == 1


def test_only_confirmed_dead_owner_is_requeued_after_interruption(tmp_path: Path) -> None:
    request = _request()
    path = tmp_path / "teacher.db"
    transport = _Transport()
    with TeacherDraftQueue(path) as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        with sqlite3.connect(path) as connection:
            connection.execute(
                """UPDATE teacher_draft_jobs SET status = 'running', owner_pid = ?,
                   owner_started_at = ?, claim_token = 'active_claim'""",
                (os.getpid(), psutil.Process().create_time()),
            )
        assert (
            queue.run_page(
                load_request=lambda _: request,
                teacher=_teacher(transport),
                authorizer=_ApprovalSource(),
                now=lambda: NOW + timedelta(hours=1),
            ).attempted
            == 0
        )
        assert queue.page(limit=1).jobs[0].status == "running"
        with sqlite3.connect(path) as connection:
            connection.execute(
                """UPDATE teacher_draft_jobs SET owner_pid = ?,
                   owner_started_at = ?, claim_token = 'dead_claim'""",
                (2_000_000_000, 1.0),
            )
        recovered = queue.run_page(
            load_request=lambda _: request,
            teacher=_teacher(transport),
            authorizer=_ApprovalSource(),
            now=lambda: NOW + timedelta(hours=1),
        )
        assert recovered.completed == 1
        assert queue.page(limit=1).jobs[0].status == "complete"
        assert transport.calls == 1


def test_corrupted_complete_authorization_metadata_fails_closed(tmp_path: Path) -> None:
    request = _request()
    path = tmp_path / "teacher.db"
    with TeacherDraftQueue(path) as queue:
        queue.enqueue(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            request=request,
            model_id=MODEL,
            model_digest=DIGEST,
            synthetic=True,
        )
        assert (
            queue.run_page(
                load_request=lambda _: request,
                teacher=_teacher(_Transport()),
                authorizer=_ApprovalSource(),
                now=lambda: NOW + timedelta(hours=1),
            ).completed
            == 1
        )
        with sqlite3.connect(path) as connection:
            connection.execute(
                "UPDATE teacher_draft_jobs SET authorization_purpose = 'cloud_upload'"
            )
        with pytest.raises(ValueError, match="authorization"):
            queue.page(limit=1)
