"""Project verified Basic recurrence observations without inventing request causes."""

import math

from systemsense.application.investigation_state import InvestigationOutcome, InvestigationState
from systemsense.application.loopback_owner import trusted_loopback_owner
from systemsense.application.loopback_replay_evidence import (
    ownership_verified_at_boundaries,
    verified_replay,
)
from systemsense.application.task_observation import (
    TaskObservationUnavailable,
    resolve_task_observation,
)
from systemsense.domain.affected_task import LOOPBACK_TASK_SCOPES
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.owner_cpu import describe_owner_cpu
from systemsense.storage.sqlite_store import SQLiteStore


def basic_loopback_finding(
    store: SQLiteStore, state: InvestigationState, records: tuple[EvidenceRecord, ...]
) -> tuple[str, InvestigationOutcome] | None:
    reference = state.task_observation_reference
    if reference is None or reference.scope not in LOOPBACK_TASK_SCOPES:
        return None
    try:
        task = resolve_task_observation(store, case_id=state.case_id, reference=reference)
    except TaskObservationUnavailable:
        return None
    replays = sorted(
        (
            (record, replay)
            for record in records
            if (replay := verified_replay(store, task, record)) is not None
        ),
        key=lambda pair: pair[0].observed_at,
    )
    if not replays:
        return None
    summary = (
        f"The exact health GET to {task.target_handle} ended in {task.observed} "
        f"at {task.window_end.isoformat()}."
    )
    owner = trusted_loopback_owner(store, state.case_id)
    for record, replay in replays:
        summary += (
            f" A later exact request ended in {replay['outcome']} "
            f"at {record.observed_at.isoformat()}."
        )
        facts = {fact.name: fact.value for fact in record.facts}
        sample = facts.get("target_pressure")
        if (
            owner is None
            or record.collector.id != "network.listener_owner_pressure"
            or replay["outcome"] != "timeout"
            or not isinstance(sample, dict)
            or sample.get("target_pid") != owner.pid
            or sample.get("target_creation_time")
            not in {
                owner.creation_time.isoformat(),
                owner.creation_time.isoformat().replace("+00:00", "Z"),
            }
            or not ownership_verified_at_boundaries(
                facts, pid=owner.pid, creation_time=owner.creation_time, port=owner.port
            )
        ):
            continue
        coincident = facts.get("coincident_owner_cpu")
        if not isinstance(coincident, dict):
            continue
        peak = coincident.get("peak_logical_cores")
        count = coincident.get("sample_count")
        if (
            coincident.get("status") == "measured"
            and type(count) is int
            and count > 0
            and type(peak) in {int, float}
            and isinstance(peak, (int, float))
            and math.isfinite(peak)
            and peak >= 0
        ):
            summary += (
                f" The identity-checked owner process peaked at {peak:.2f} logical cores "
                f"during that request. {describe_owner_cpu(float(peak))}"
            )
    recovered = replays[-1][1]["outcome"] == "http_200_nonce_match"
    if task.observed == "http_200_nonce_match" and recovered:
        summary += (
            " No failure was reproduced in these exact requests; "
            "an earlier or intermittent failure remains unverified."
        )
    elif recovered:
        summary += " The earlier failure did not recur in the latest observation."
    summary += (
        " These observations do not identify the earlier request's cause or an individual handler. "
        "Inspect the service's request logs or traces for this exact path and failure time."
    )
    return summary, InvestigationOutcome.INSUFFICIENT_OBSERVABILITY
