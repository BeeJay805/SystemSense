"""Deterministic advice over source-bound candidates, never execution authority.

Use only on the explicit Basic route. The caller resolves task/target custody,
provides the same registered menu and budgets available to advisory models, and
persists this policy's own decision receipt. It must still resolve, admit and
dispatch the returned opaque candidate through the ordinary runtime. This
module does not read the host, manufacture a target, or diagnose a cause.
"""

from dataclasses import dataclass

from systemsense.decision.contracts import PermissionClass
from systemsense.domain.affected_task import LOOPBACK_TASK_SCOPES, TaskObservationContextV1
from systemsense.domain.probes import SafetyClass
from systemsense.storage.case_candidates import CandidateRecord

_LISTENER = "network.listeners"
_OWNER = "network.listener_owner_pressure"
_REPLAY = "network.loopback_replay"
_PROCESS = "application.target_pressure"
_OUTCOMES = frozenset(
    {
        "http_200_nonce_match",
        "http_503",
        "http_other_status",
        "wrong_response",
        "timeout",
        "connection_refused",
        "request_error",
    }
)


@dataclass(frozen=True)
class BasicCandidateChoice:
    """Choice and explanation for a receipt; no parameters or launch permission."""

    candidate_id: str | None
    probe_id: str | None
    reason_code: str
    reason: str
    policy_id: str = "basic-source-bound-v2"


def _stop(code: str, reason: str) -> BasicCandidateChoice:
    return BasicCandidateChoice(None, None, code, reason)


def _choose(
    probe: str,
    candidates: tuple[CandidateRecord, ...],
    remaining_ms: int,
    remaining_probe_calls: int,
    code: str,
    reason: str,
) -> BasicCandidateChoice:
    matches = tuple(candidate for candidate in candidates if candidate.probe_id == probe)
    if len(matches) > 1:
        return _stop(
            "ambiguous_candidate", "More than one candidate matches; no target was chosen."
        )
    if not matches:
        return _stop("candidate_unavailable", "The required source-bound candidate is unavailable.")
    candidate = matches[0]
    if (
        candidate.permission_class is not PermissionClass.READ_ONLY
        or candidate.safety_class not in {SafetyClass.R0, SafetyClass.R1}
    ):
        return _stop("scope_denied", "The candidate exceeds the registered read-only scope.")
    if remaining_probe_calls < 1 or candidate.cost_ms > remaining_ms:
        return _stop("budget_exhausted", "The candidate does not fit the original case budget.")
    return BasicCandidateChoice(candidate.candidate_id, probe, code, reason)


def select_basic_loopback_candidate(
    task: TaskObservationContextV1,
    candidates: tuple[CandidateRecord, ...],
    attempted_probe_ids: frozenset[str],
    *,
    verified_owner_available: bool,
    remaining_ms: int,
    remaining_probe_calls: int,
    verified_later_outcome: str | None = None,
) -> BasicCandidateChoice:
    """Choose listener/owner discrimination or a bounded exact-action recurrence check.

    ``task`` must come from resolve_task_observation; owner availability must
    come from trusted_loopback_owner. A later outcome must be verified against
    this same task by verified_replay. These are observations, not model text.
    Attempts include failures: this policy never retries an attempted probe.
    """
    if (
        task.scope not in LOOPBACK_TASK_SCOPES
        or task.reported_task_relation != "exact_action_replayed"
    ):
        return _stop("unbound_task", "An exact source-bound loopback task is required.")
    if task.observed not in _OUTCOMES or (
        verified_later_outcome is not None and verified_later_outcome not in _OUTCOMES
    ):
        return _stop("invalid_observation", "The task outcome is outside the registered contract.")
    current = verified_later_outcome or task.observed
    if current == "http_200_nonce_match" and verified_later_outcome is not None:
        return _stop(
            "observed_success",
            "The exact action succeeded at an observed time; its earlier cause remains unverified.",
        )
    if remaining_ms <= 0 or remaining_probe_calls <= 0:
        return _stop("budget_exhausted", "The original case budget is exhausted.")
    preferred: list[tuple[str, str, str]] = []
    if current in {"timeout", "connection_refused", "request_error"}:
        if _LISTENER not in attempted_probe_ids:
            preferred.append(
                (
                    _LISTENER,
                    "listener_state",
                    "Observe the exact port's current listener state without backdating it "
                    "to the failed request.",
                )
            )
        elif (
            task.observed == "timeout"
            and verified_owner_available
            and _OWNER not in attempted_probe_ids
        ):
            preferred.append(
                (
                    _OWNER,
                    "owner_activity",
                    "Repeat the exact request while sampling its verified owner; "
                    "process CPU cannot identify a handler cause.",
                )
            )
    if _REPLAY not in attempted_probe_ids:
        preferred.append(
            (
                _REPLAY,
                "recurrence",
                "Repeat only the source-bound exact action to distinguish "
                "a persistent outcome from a changed one; "
                "one success cannot rule out intermittence.",
            )
        )
    if not preferred:
        return _stop(
            "no_useful_candidate",
            "No unused scoped discriminator remains; preserve the evidence and gaps.",
        )
    result = _stop("candidate_unavailable", "No eligible registered candidate is available.")
    for probe, code, reason in preferred:
        result = _choose(probe, candidates, remaining_ms, remaining_probe_calls, code, reason)
        if result.candidate_id is not None or result.reason_code not in {
            "candidate_unavailable",
            "budget_exhausted",
        }:
            return result
    return result


def select_basic_process_candidate(
    candidates: tuple[CandidateRecord, ...],
    attempted_probe_ids: frozenset[str],
    *,
    question: str,
    verified_target_bound: bool,
    decisive: bool,
    remaining_ms: int,
    remaining_probe_calls: int,
) -> BasicCandidateChoice:
    """Select CPU sampling only after an exact process identity is bound locally.

    The existing identity-checked binding resolver supplies target availability;
    a source-verified current answer supplies ``decisive``. A presence question
    does not imply permission or usefulness for additional process sampling.
    """
    if question not in {"presence", "cpu"}:
        return _stop("unsupported_question", "No fixed Basic process policy covers this question.")
    if question == "presence":
        return _stop(
            "presence_only", "Use the current process-inventory result and its coverage limits."
        )
    if decisive:
        return _stop(
            "decisive_evidence",
            "The exact current process question already has a supported answer.",
        )
    if not verified_target_bound:
        return _stop("unbound_target", "An exact source-bound process identity is required.")
    if _PROCESS in attempted_probe_ids:
        return _stop("no_useful_candidate", "The bounded process sample was already attempted.")
    return _choose(
        _PROCESS,
        candidates,
        remaining_ms,
        remaining_probe_calls,
        "process_cpu",
        "Sample the bound process identity to answer its current CPU question; "
        "this does not prove an earlier slowdown cause.",
    )
