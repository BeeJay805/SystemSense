"""Task-specific semantic guard for bounded late-evidence reviews."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import cast

from systemsense.application.deep_worker import DeepWorkerResultV1
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse

_AUTO_OMISSION = re.compile(
    r"Candidate evidence contexts omitted by case brief bounds: \d+", re.IGNORECASE
)
_GRAPH_OMISSION = re.compile(
    r"Graph packet omitted \d+ of \d+ grounded relationships "
    r"because the model edge limit is (\d+)\.",
    re.IGNORECASE,
)

# These fields describe the task-specific inference basis. Request identity,
# budget, prior-hypothesis bookkeeping, and inventory are excluded. Catalog
# changes are handled only when the prior response explicitly requested more.
_SEMANTIC_FIELDS = (
    "objective",
    "reported_task",
    "task_observation",
    "selected_sources",
    "observer_context",
    "fast_concerns",
    "diagnostic_progress",
    "evidence_context",
    "relationships",
    "reference_context",
    "error_references",
    "priority_evidence_ids",
    "pending_probe_ids",
    "available_probes",
)


def _canonical(value: object) -> object:
    if isinstance(value, Mapping):
        mapping = cast(Mapping[str, object], value)
        return tuple(sorted((key, _canonical(item)) for key, item in mapping.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_canonical(item) for item in cast(Sequence[object], value))
    if isinstance(value, (set, frozenset)):
        values = cast(set[object] | frozenset[object], value)
        return tuple(sorted((_canonical(item) for item in values), key=repr))
    return value


def _effective_context(request: ReasoningRequest) -> object:
    entries: list[object] = []
    for item in request.evidence_context:
        payload = item.model_dump(mode="json")
        payload["limitations"] = list(
            dict.fromkeys(
                _GRAPH_OMISSION.sub(
                    r"Graph packet omitted <count> of <count> grounded relationships because "
                    r"the model edge limit is \1.",
                    limitation,
                )
                for limitation in item.limitations
            )
        )
        entries.append(_canonical(payload))
    return tuple(entries)


def _observer_context(request: ReasoningRequest) -> object:
    normalized: list[str] = []
    for item in request.observer_context:
        normalized.append(
            _AUTO_OMISSION.sub(
                "Candidate evidence contexts omitted by case brief bounds: <count>", item
            )
        )
    return tuple(normalized)


def _effective_basis(request: ReasoningRequest) -> tuple[object, ...]:
    result: list[object] = []
    for name in _SEMANTIC_FIELDS:
        if name == "evidence_context":
            result.append(_effective_context(request))
        elif name == "observer_context":
            result.append(_observer_context(request))
        else:
            result.append(_canonical(getattr(request, name)))
    return tuple(result)


def _explicit_request_became_available(
    previous_request: ReasoningRequest,
    candidate_request: ReasoningRequest,
    previous_response: ReasoningResponse,
) -> bool:
    previous_context_ids = {str(item.evidence_id) for item in previous_request.evidence_context}
    candidate_context_ids = {str(item.evidence_id) for item in candidate_request.evidence_context}
    visible_delta = candidate_context_ids - previous_context_ids

    requested_ids = {str(item) for item in previous_response.requested_evidence_ids}
    completed_evidence_delta = {
        str(item) for item in candidate_request.completed_evidence_requests
    } - {str(item) for item in previous_request.completed_evidence_requests}
    previous_catalog_ids = {
        evidence_id
        for entry in previous_request.evidence_catalog
        if isinstance((evidence_id := entry.get("evidence_id")), str)
    }
    candidate_catalog_ids = {
        evidence_id
        for entry in candidate_request.evidence_catalog
        if isinstance((evidence_id := entry.get("evidence_id")), str)
    }
    if requested_ids & (
        visible_delta | completed_evidence_delta | (candidate_catalog_ids - previous_catalog_ids)
    ):
        return True

    requested_probes = {item.probe_id for item in previous_response.distinguishing_probes}
    completed_probe_delta = (
        candidate_request.completed_probe_ids - previous_request.completed_probe_ids
    )
    if requested_probes & completed_probe_delta:
        return True

    requested_details = {item.key() for item in previous_response.requested_details}
    completed_details = {item.key() for item in candidate_request.completed_detail_requests}
    previous_details = {item.key() for item in previous_request.completed_detail_requests}
    if requested_details & (completed_details - previous_details):
        return True

    if previous_response.request_next_catalog_page:
        return (
            _canonical(previous_request.evidence_catalog)
            != _canonical(candidate_request.evidence_catalog)
            or previous_request.catalog_has_more != candidate_request.catalog_has_more
        )
    return False


def should_refresh_late_review(
    previous_request: ReasoningRequest,
    candidate_request: ReasoningRequest,
    previous_response: ReasoningResponse,
) -> bool:
    """Return whether the candidate gives an accepted review material new input.

    The caller must supply a response from an `applied` mailbox result. The
    response is validated against its original request here before comparison.
    """
    previous_response.validate_against(previous_request)
    if previous_response.degraded:
        return True
    return _effective_basis(previous_request) != _effective_basis(
        candidate_request
    ) or _explicit_request_became_available(previous_request, candidate_request, previous_response)


def accepted_late_review_baseline(
    request: ReasoningRequest,
    request_sha256: str,
    status: str,
    result_json: str,
) -> tuple[ReasoningRequest, ReasoningResponse] | None:
    """Only an applied, identity-matched, valid result may avoid a later review."""
    if status != "applied":
        return None
    try:
        result = DeepWorkerResultV1.model_validate_json(result_json)
        response = result.response
        if (
            result.status == "completed"
            and result.request_sha256 == request_sha256
            and result.case_id == request.case_id
            and response is not None
            and not response.degraded
        ):
            response.validate_against(request)
            return request, response
    except (ValueError, TypeError):
        pass
    return None
