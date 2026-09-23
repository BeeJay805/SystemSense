"""Bind one case process from persisted application topology evidence.

Candidate IDs are selection handles, not OS capabilities. This module reads no
live process and never authorizes a probe or a machine change.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import cast

from pydantic import Field, ValidationError

from systemsense.domain.cases import CaseStatus
from systemsense.domain.evidence import EvidenceRecord, FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue, stable_source_id
from systemsense.domain.time import UtcDateTime, ensure_utc, utc_now
from systemsense.storage.sqlite_store import SQLiteStore

_PROBE_ID = "application.snapshot"
_MAX_AGE = timedelta(seconds=300)
_CANDIDATE_ID = re.compile(r"proc_[0-9a-f]{32}\Z")


class TargetSelectionError(ValueError):
    """The requested process identity is absent, stale, or ambiguous."""


class ProcessCandidate(FrozenModel):
    candidate_id: str = Field(pattern=r"^proc_[0-9a-f]{32}$")
    case_id: CaseId
    case_state_version: int = Field(ge=0)
    evidence_id: EvidenceId
    pid: int = Field(gt=0)
    creation_time: UtcDateTime
    name: str = Field(min_length=1, max_length=255)
    collection_started_at: UtcDateTime
    collection_completed_at: UtcDateTime
    omitted_process_count: int = Field(ge=0)


class CandidateInventory(FrozenModel):
    case_id: CaseId
    case_state_version: int = Field(ge=0)
    evidence_id: EvidenceId
    candidates: tuple[ProcessCandidate, ...]
    omitted_process_count: int = Field(ge=0)
    inventory_complete: bool
    collection_started_at: UtcDateTime
    collection_completed_at: UtcDateTime


class ProcessTargetBinding(ProcessCandidate):
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_at: UtcDateTime


class ProcessTargetRepository:
    """Select only a fresh, exact candidate from the latest case snapshot."""

    def __init__(self, store: SQLiteStore, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock

    def list_process_candidates(self, case_id: CaseId, *, limit: int = 64) -> CandidateInventory:
        if not 1 <= limit <= 64:
            raise ValueError("candidate limit must be between 1 and 64")
        with self._store.read_snapshot():
            inventory, _digest = self._inventory(case_id, ensure_utc(self._clock()), limit)
        return inventory

    def selected_process_target(self, case_id: CaseId) -> ProcessTargetBinding | None:
        """Display-only readback; never use this to authorize process sampling."""
        with self._store.read_snapshot():
            exists = self._store.connection.execute(
                "SELECT 1 FROM case_process_targets WHERE case_id = ?", (str(case_id),)
            ).fetchone()
            return None if exists is None else self._binding(case_id)

    def resolve_process_target_for_sampling(self, case_id: CaseId) -> ProcessTargetBinding:
        """Revalidate stored selection; caller must also check live PID and creation time."""
        with self._store.read_snapshot():
            binding = self._binding(case_id)
            inventory, digest = self._inventory(case_id, ensure_utc(self._clock()), 64)
            if digest != binding.evidence_sha256:
                raise TargetSelectionError("process target evidence changed")
            matches = [
                item for item in inventory.candidates if item.candidate_id == binding.candidate_id
            ]
            if (
                len(matches) != 1
                or inventory.case_state_version < binding.case_state_version
                or matches[0].model_dump(exclude={"case_state_version"})
                != binding.model_dump(
                    exclude={"case_state_version", "evidence_sha256", "selected_at"}
                )
            ):
                raise TargetSelectionError("process target binding is stale")
            return binding

    def bind_process_target(self, case_id: CaseId, candidate_id: str) -> ProcessTargetBinding:
        if _CANDIDATE_ID.fullmatch(candidate_id) is None:
            raise TargetSelectionError("invalid process candidate identifier")
        now = ensure_utc(self._clock())
        with self._store.transaction():
            inventory, digest = self._inventory(case_id, now, 64)
            matches = [item for item in inventory.candidates if item.candidate_id == candidate_id]
            if len(matches) != 1:
                raise TargetSelectionError("process candidate is unavailable or stale")
            candidate = matches[0]
            existing = self._store.connection.execute(
                "SELECT candidate_id, case_state_version, evidence_sha256 "
                "FROM case_process_targets WHERE case_id = ?",
                (str(case_id),),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != candidate_id or str(existing[2]) != digest:
                    raise TargetSelectionError("case already has a different process target")
                return self._binding(case_id)
            selected = ProcessTargetBinding(
                **candidate.model_dump(), evidence_sha256=digest, selected_at=now
            )
            try:
                self._store.connection.execute(
                    "INSERT INTO case_process_targets (case_id, candidate_id, "
                    "case_state_version, evidence_id, evidence_sha256, pid, creation_time, "
                    "name, collection_started_at, collection_completed_at, "
                    "omitted_process_count, selected_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(case_id),
                        candidate_id,
                        candidate.case_state_version,
                        str(candidate.evidence_id),
                        digest,
                        candidate.pid,
                        candidate.creation_time.isoformat(),
                        candidate.name,
                        candidate.collection_started_at.isoformat(),
                        candidate.collection_completed_at.isoformat(),
                        candidate.omitted_process_count,
                        selected.selected_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise TargetSelectionError("process target was concurrently selected") from error
            return selected

    def _binding(self, case_id: CaseId) -> ProcessTargetBinding:
        row = self._store.connection.execute(
            "SELECT candidate_id, case_state_version, evidence_id, evidence_sha256, "
            "pid, creation_time, name, collection_started_at, collection_completed_at, "
            "omitted_process_count, selected_at FROM case_process_targets WHERE case_id = ?",
            (str(case_id),),
        ).fetchone()
        if row is None:
            raise TargetSelectionError("process target binding is unavailable")
        return ProcessTargetBinding(
            candidate_id=str(row[0]),
            case_id=case_id,
            case_state_version=int(row[1]),
            evidence_id=EvidenceId(root=str(row[2])),
            evidence_sha256=str(row[3]),
            pid=int(row[4]),
            creation_time=_utc(str(row[5])),
            name=str(row[6]),
            collection_started_at=_utc(str(row[7])),
            collection_completed_at=_utc(str(row[8])),
            omitted_process_count=int(row[9]),
            selected_at=_utc(str(row[10])),
        )

    def _inventory(
        self, case_id: CaseId, now: datetime, limit: int
    ) -> tuple[CandidateInventory, str]:
        case = self._store.case(str(case_id))
        if case is None or case.status in {
            CaseStatus.COMPLETE.value,
            CaseStatus.ARCHIVED.value,
        }:
            raise TargetSelectionError("current case is unavailable")
        checkpoint = self._store.connection.execute(
            "SELECT json_extract(record_json, '$.status') "
            "FROM investigation_checkpoints WHERE case_id = ?",
            (str(case_id),),
        ).fetchone()
        if checkpoint is not None and checkpoint[0] not in {
            "queued",
            "running",
            "awaiting_target",
        }:
            raise TargetSelectionError("investigation is not active")
        rows = self._store.connection.execute(
            "SELECT evidence_id, record_json, observed_at, captured_at, execution_id, "
            "source_id, time_quality FROM evidence WHERE case_id = ? "
            "AND json_extract(record_json, '$.collector.id') = ? "
            "ORDER BY captured_at DESC, evidence_id DESC LIMIT 2",
            (str(case_id), _PROBE_ID),
        ).fetchall()
        if not rows:
            raise TargetSelectionError("application snapshot is unavailable")
        if len(rows) > 1 and str(rows[0][3]) == str(rows[1][3]):
            raise TargetSelectionError("latest application snapshots are ambiguous")
        row = rows[0]
        try:
            record = EvidenceRecord.model_validate_json(str(row[1]))
        except ValidationError as error:
            raise TargetSelectionError("stored application snapshot is invalid") from error
        expected_source = stable_source_id(
            "systemsense.probe",
            {"probe_id": _PROBE_ID, "probe_version": record.collector.version},
        )
        if (
            record.case_id != case_id
            or str(record.evidence_id) != str(row[0])
            or record.collector.id != _PROBE_ID
            or record.collector.version != 1
            or str(record.collector.execution_id) != str(row[4])
            or record.source.type != "systemsense.probe"
            or record.source.locator != {"probe_id": _PROBE_ID}
            or record.source.source_id != expected_source
            or str(row[5]) != expected_source
            or record.statement_kind is not StatementKind.OBSERVED_FACT
            or record.observed_at != _utc(str(row[2]))
            or record.captured_at != _utc(str(row[3]))
            or str(row[6]) != "bounded_interval"
        ):
            raise TargetSelectionError("stored application snapshot binding is invalid")
        if record.captured_at > now or now - record.captured_at > _MAX_AGE:
            raise TargetSelectionError("application snapshot is stale")
        execution = self._store.connection.execute(
            "SELECT probe_id, probe_version, status, state_version, finished_at "
            "FROM probe_executions WHERE execution_id = ? AND case_id = ?",
            (str(record.collector.execution_id), str(case_id)),
        ).fetchone()
        if (
            execution is None
            or str(execution[0]) != _PROBE_ID
            or int(execution[1]) != record.collector.version
            or str(execution[2]) != "ok"
            or int(execution[3]) > case.state_version
            or execution[4] is None
            or _utc(str(execution[4])) > record.captured_at
        ):
            raise TargetSelectionError("application snapshot execution is unverified")
        facts = {fact.name: fact.value for fact in record.facts}
        if len(facts) != len(record.facts):
            raise TargetSelectionError("application snapshot facts are ambiguous")
        started = _utc_fact(facts, "collection_started_at")
        completed = _utc_fact(facts, "collection_completed_at")
        if not started <= completed <= record.observed_at <= record.captured_at:
            raise TargetSelectionError("application snapshot interval is invalid")
        raw_processes = facts.get("processes")
        raw_omitted = facts.get("omitted_counts")
        status = facts.get("collection_status")
        if (
            not isinstance(raw_processes, list)
            or len(raw_processes) > 256
            or not isinstance(raw_omitted, dict)
            or type(raw_omitted.get("processes")) is not int
            or cast("int", raw_omitted["processes"]) < 0
            or not isinstance(status, str)
            or status not in {"available", "partial"}
        ):
            raise TargetSelectionError("application process inventory is invalid")
        omitted = cast("int", raw_omitted["processes"])
        total_omitted = omitted + max(0, len(raw_processes) - limit)
        digest = hashlib.sha256(str(row[1]).encode("utf-8")).hexdigest()
        candidates: list[ProcessCandidate] = []
        seen_pids: set[int] = set()
        for raw in cast("list[JsonValue]", raw_processes):
            if not isinstance(raw, dict):
                raise TargetSelectionError("application process entry is invalid")
            pid = raw.get("pid")
            name = raw.get("name")
            created_raw = raw.get("creation_time")
            if (
                type(pid) is not int
                or not isinstance(name, str)
                or not isinstance(created_raw, str)
            ):
                raise TargetSelectionError("application process identity is incomplete")
            if pid <= 0 or pid in seen_pids or not 1 <= len(name) <= 255:
                raise TargetSelectionError("application process identity is ambiguous")
            created = _utc(created_raw)
            if created > completed:
                raise TargetSelectionError("process creation follows snapshot capture")
            identity = raw.get("identity")
            if identity is not None and identity != f"{pid}@{created.isoformat()}":
                raise TargetSelectionError("application process identity is inconsistent")
            seen_pids.add(pid)
            payload = json.dumps(
                [
                    str(case_id),
                    str(record.evidence_id),
                    digest,
                    pid,
                    created.isoformat(),
                    name,
                    started.isoformat(),
                    completed.isoformat(),
                ],
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            candidate_id = f"proc_{hashlib.sha256(payload).hexdigest()[:32]}"
            candidates.append(
                ProcessCandidate(
                    candidate_id=candidate_id,
                    case_id=case_id,
                    case_state_version=case.state_version,
                    evidence_id=record.evidence_id,
                    pid=pid,
                    creation_time=created,
                    name=name,
                    collection_started_at=started,
                    collection_completed_at=completed,
                    omitted_process_count=total_omitted,
                )
            )
        candidates.sort(key=lambda item: (item.pid, item.creation_time, item.candidate_id))
        inventory = CandidateInventory(
            case_id=case_id,
            case_state_version=case.state_version,
            evidence_id=record.evidence_id,
            candidates=tuple(candidates[:limit]),
            omitted_process_count=total_omitted,
            inventory_complete=(
                status == "available"
                and total_omitted == 0
                and not any("process" in note.casefold() for note in record.limitations)
            ),
            collection_started_at=started,
            collection_completed_at=completed,
        )
        return inventory, digest


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() != timedelta(0):
            raise ValueError("non-UTC timestamp")
        return ensure_utc(parsed)
    except ValueError as error:
        raise TargetSelectionError("stored timestamp is invalid") from error


def _utc_fact(facts: dict[str, JsonValue], name: str) -> datetime:
    value = facts.get(name)
    if not isinstance(value, str):
        raise TargetSelectionError("application snapshot interval is missing")
    return _utc(value)
