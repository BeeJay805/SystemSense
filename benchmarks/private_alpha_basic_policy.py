"""Evaluation-only stronger deterministic comparator over product candidates.

Call after the normal product records the exact initial task. Inputs must come
from the same verified task resolver, source-bound registry and case budget as
the model arm. The returned candidate ID is advice, never execution authority:
the caller must resolve, admit and dispatch through the ordinary runtime.

This module does not execute probes, fabricate observations, or establish a
measured comparison. It provides the fixed policy for a future matched runner.
"""

from dataclasses import dataclass

from systemsense.decision.contracts import PermissionClass
from systemsense.domain.affected_task import LOOPBACK_TASK_SCOPES, TaskObservationContextV1
from systemsense.domain.probes import SafetyClass
from systemsense.storage.case_candidates import CandidateRecord

_LISTENER = "network.listeners"
_OWNER = "network.listener_owner_pressure"
_REPLAY = "network.loopback_replay"


@dataclass(frozen=True)
class BaselineSelection:
    candidate_id: str | None
    reason: str


def select_loopback_baseline(
    task: TaskObservationContextV1,
    candidates: tuple[CandidateRecord, ...],
    attempted_probe_ids: frozenset[str],
    *,
    verified_owner_available: bool,
    remaining_ms: int,
    remaining_probe_calls: int,
) -> BaselineSelection:
    """Observe listener, then owner pressure for a timeout or one exact replay.

    A successful initial task needs no extra check. Failed attempts are spent
    attempts; unavailable measurements remain gaps instead of repeated work.
    This is deterministic policy advice on the exact same candidate menu.
    """
    if (
        task.scope not in LOOPBACK_TASK_SCOPES
        or task.reported_task_relation != "exact_action_replayed"
    ):
        return BaselineSelection(None, "verified exact loopback task required")
    if task.observed == "http_200_nonce_match":
        return BaselineSelection(None, "initial task succeeded; earlier failure remains unverified")
    if task.observed not in {
        "timeout",
        "connection_refused",
        "request_error",
        "http_503",
        "http_other_status",
        "wrong_response",
    }:
        return BaselineSelection(None, "unsupported task outcome")
    if {_OWNER, _REPLAY} & attempted_probe_ids:
        return BaselineSelection(None, "one bounded discriminator already attempted")
    desired = (
        _LISTENER
        if _LISTENER not in attempted_probe_ids
        else _OWNER
        if task.observed == "timeout" and verified_owner_available
        else _REPLAY
    )
    matches = tuple(item for item in candidates if item.probe_id == desired)
    if len(matches) != 1:
        return BaselineSelection(None, "required source-bound candidate absent or ambiguous")
    candidate = matches[0]
    if (
        candidate.permission_class is not PermissionClass.READ_ONLY
        or candidate.safety_class not in {SafetyClass.R0, SafetyClass.R1}
    ):
        return BaselineSelection(None, "candidate exceeds read-only scope")
    if remaining_probe_calls < 1 or candidate.cost_ms > remaining_ms:
        return BaselineSelection(None, "original matched case budget exhausted")
    return BaselineSelection(candidate.candidate_id, f"fixed sequence selected {desired}")
