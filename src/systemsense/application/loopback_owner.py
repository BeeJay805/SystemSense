"""Resolve one later loopback listener owner from custodied case evidence.

This binds a process measurement target. It does not attribute a prior request
failure to that process or grant the model a PID selector.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from systemsense.application.task_observation import (
    TaskObservationUnavailable,
    resolve_task_observation,
)
from systemsense.domain.affected_task import LOOPBACK_TASK_SCOPES
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, stable_source_id
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True, slots=True)
class LoopbackOwner:
    evidence_id: EvidenceId
    pid: int
    creation_time: datetime
    name: str
    port: int
    nonce: str


def trusted_loopback_owner(store: SQLiteStore, case_id: CaseId) -> LoopbackOwner | None:
    """Accept only one exact-port, exact-owner row after a verified timed-out GET."""

    try:
        state = InvestigationRepository(store).load(str(case_id))
        reference = state.task_observation_reference
        if reference is None or reference.scope not in LOOPBACK_TASK_SCOPES:
            return None
        task = resolve_task_observation(store, case_id=case_id, reference=reference)
        if task.reported_task_relation != "exact_action_replayed" or task.observed != "timeout":
            return None
        port = int(task.target_handle.removeprefix("127.0.0.1:"))
        nonce = task.action.removeprefix("GET /health/")
    except (TaskObservationUnavailable, TypeError, ValueError):
        return None
    rows = store.connection.execute(
        "SELECT e.evidence_id,e.record_json,e.observed_at,e.captured_at,e.execution_id,"
        "e.time_basis,e.time_quality,x.status,x.probe_version "
        "FROM evidence e JOIN probe_executions x "
        "ON x.case_id=e.case_id AND x.execution_id=e.execution_id "
        "WHERE e.case_id=? AND x.probe_id='network.listeners' "
        "ORDER BY e.captured_at DESC,e.evidence_id DESC LIMIT 2",
        (str(case_id),),
    ).fetchall()
    if len(rows) != 1:
        return None
    row = rows[0]
    try:
        record = EvidenceRecord.model_validate_json(str(row[1]))
        facts = {fact.name: fact.value for fact in record.facts}
        if len(facts) != len(record.facts):
            return None
        observed_at = ensure_utc(datetime.fromisoformat(str(row[2])))
        captured_at = ensure_utc(datetime.fromisoformat(str(row[3])))
        if (
            record.case_id != case_id
            or str(record.evidence_id) != str(row[0])
            or record.statement_kind is not StatementKind.OBSERVED_FACT
            or record.collector.id != "network.listeners"
            or record.collector.version != int(row[8])
            or str(record.collector.execution_id) != str(row[4])
            or record.source.type != "systemsense.probe"
            or record.source.locator != {"probe_id": "network.listeners"}
            or record.source.source_id
            != stable_source_id(
                "systemsense.probe",
                {"probe_id": "network.listeners", "probe_version": record.collector.version},
            )
            or row[5] != "collector_upper_bound"
            or row[6] != "bounded_interval"
            or row[7] != "ok"
            or observed_at != record.observed_at
            or captured_at != record.captured_at
            or not task.window_end < observed_at <= captured_at
            or utc_now() - captured_at > timedelta(seconds=120)
        ):
            return None
        listeners = facts.get("listeners")
        if not isinstance(listeners, list):
            return None
        matching = [
            item
            for item in listeners
            if isinstance(item, dict)
            and item.get("local_port") == port
            and item.get("local_address") in {"127.0.0.1", "0.0.0.0"}
            and item.get("protocol") == "tcp4"
        ]
        if len(matching) != 1:
            return None
        owner = matching[0]
        pid = owner.get("pid")
        name = owner.get("process_name")
        created = owner.get("process_creation_time")
        if (
            owner.get("owner_status") != "available"
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
            or not isinstance(name, str)
            or not name
            or not isinstance(created, str)
        ):
            return None
        creation_time = ensure_utc(datetime.fromisoformat(created))
        if creation_time > observed_at:
            return None
        return LoopbackOwner(record.evidence_id, pid, creation_time, name, port, nonce)
    except (TypeError, ValueError):
        return None
