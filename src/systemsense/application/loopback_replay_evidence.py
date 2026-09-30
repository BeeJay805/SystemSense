"""Custody and exact-action validation for a later registered health replay."""

from datetime import datetime
from itertools import pairwise

from systemsense.application.loopback_owner import LoopbackOwner
from systemsense.domain.affected_task import TaskObservationContextV1
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import JsonValue, stable_source_id
from systemsense.domain.time import ensure_utc
from systemsense.packs.runtime import (
    LoopbackOwnerPressureParametersV1,
    LoopbackReplayParametersV1,
)
from systemsense.storage.sqlite_store import SQLiteStore


def verified_replay(
    store: SQLiteStore, task: TaskObservationContextV1, record: EvidenceRecord
) -> dict[str, JsonValue] | None:
    """Accept observations, never a model-projected result or an old task window."""
    probe_id = record.collector.id
    if probe_id not in {"network.loopback_replay", "network.listener_owner_pressure"}:
        return None
    row = store.evidence(case_id=str(task.case_id), evidence_id=str(record.evidence_id))
    execution = store.probe_execution(str(record.collector.execution_id))
    if (
        row is None
        or EvidenceRecord.model_validate_json(row.record_json) != record
        or record.case_id != task.case_id
        or record.statement_kind is not StatementKind.OBSERVED_FACT
        or record.source.type != "systemsense.probe"
        or record.source.source_id
        != stable_source_id(
            "systemsense.probe", {"probe_id": probe_id, "probe_version": record.collector.version}
        )
        or execution is None
        or execution.status != "ok"
        or execution.case_id != str(task.case_id)
        or execution.probe_id != probe_id
        or execution.probe_version != record.collector.version
        or execution.finished_at is None
    ):
        return None
    facts = {fact.name: fact.value for fact in record.facts}
    if len(facts) != len(record.facts):
        return None
    replay = facts.get("loopback_replay")
    if not isinstance(replay, dict):
        return None
    try:
        parameters = (
            LoopbackReplayParametersV1.model_validate_json(execution.parameters_json)
            if probe_id == "network.loopback_replay"
            else LoopbackOwnerPressureParametersV1.model_validate_json(execution.parameters_json)
        )
        if (
            f"127.0.0.1:{parameters.port}" != task.target_handle
            or f"GET /health/{parameters.nonce}" != task.action
        ):
            return None
        execution_start = ensure_utc(datetime.fromisoformat(execution.started_at))
        execution_end = ensure_utc(datetime.fromisoformat(execution.finished_at))
        start = replay.get("request_started_at")
        end = replay.get("request_finished_at")
        if not isinstance(start, str) or not isinstance(end, str):
            return None
        started, finished = (
            ensure_utc(datetime.fromisoformat(start)),
            ensure_utc(datetime.fromisoformat(end)),
        )
    except ValueError:
        return None
    if (
        replay.get("target_handle") != task.target_handle
        or replay.get("action") != task.action
        or not task.window_end < started <= finished <= record.observed_at <= record.captured_at
        or not execution_start <= started <= finished <= record.captured_at <= execution_end
        or replay.get("outcome")
        not in {
            "http_200_nonce_match",
            "http_503",
            "http_other_status",
            "wrong_response",
            "timeout",
            "connection_refused",
            "request_error",
        }
        or (
            replay.get("outcome") == "http_200_nonce_match"
            and (replay.get("http_status") != 200 or replay.get("nonce_match") is not True)
        )
    ):
        return None
    return replay


def ownership_verified_at_boundaries(
    facts: dict[str, JsonValue], *, pid: int, creation_time: datetime, port: int
) -> bool:
    """Legacy/missing/invalid boundary proof cannot authorize owner attribution."""
    ownership, replay = facts.get("listener_ownership"), facts.get("loopback_replay")
    if not isinstance(ownership, dict) or not isinstance(replay, dict):
        return False
    if (
        ownership.get("schema_version") != 1
        or ownership.get("status") != "verified_at_boundaries"
        or ownership.get("target_pid") != pid
        or ownership.get("target_handle") != f"127.0.0.1:{port}"
    ):
        return False
    before, after = ownership.get("before_replay"), ownership.get("after_replay")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if before.get("status") != "verified" or after.get("status") != "verified":
        return False
    timestamps = [
        ownership.get("target_creation_time"),
        before.get("query_started_at"),
        before.get("observed_at"),
        replay.get("request_started_at"),
        replay.get("request_finished_at"),
        after.get("query_started_at"),
        after.get("observed_at"),
    ]
    try:
        times = [
            ensure_utc(datetime.fromisoformat(value))
            for value in timestamps
            if isinstance(value, str)
        ]
    except ValueError:
        return False
    return (
        len(times) == 7
        and times[0] == creation_time
        and all(left <= right for left, right in pairwise(times))
    )


def verified_owner_replay_covers_listener(
    store: SQLiteStore,
    task: TaskObservationContextV1,
    record: EvidenceRecord,
    owner: LoopbackOwner,
) -> bool:
    """Prove a custodied owner replay covers the later listener observation.

    ``owner`` must come from ``trusted_loopback_owner``. The accepted pressure
    receipt must replay this exact task while sampling that same process identity,
    with verified listener ownership at both replay boundaries. CPU values and
    model summaries are deliberately irrelevant to this coverage decision.
    """

    if record.collector.id != "network.listener_owner_pressure":
        return False
    if verified_replay(store, task, record) is None:
        return False
    execution = store.probe_execution(str(record.collector.execution_id))
    if execution is None:
        return False
    try:
        parameters = LoopbackOwnerPressureParametersV1.model_validate_json(
            execution.parameters_json
        )
    except ValueError:
        return False
    if (
        parameters.pid != owner.pid
        or parameters.creation_time != owner.creation_time
        or parameters.port != owner.port
        or parameters.nonce != owner.nonce
    ):
        return False
    facts = {fact.name: fact.value for fact in record.facts}
    if len(facts) != len(record.facts):
        return False
    return ownership_verified_at_boundaries(
        facts,
        pid=owner.pid,
        creation_time=owner.creation_time,
        port=owner.port,
    )
