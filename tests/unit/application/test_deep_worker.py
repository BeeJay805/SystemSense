"""Deep inference can overlap collection without gaining store or admission authority."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application.deep_worker import (
    DeepResultApplicabilityV1,
    assess_deep_result,
    canonical_reasoning_request_json,
    freeze_deep_task,
    run_deep_worker,
)
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity, ResourceClass
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.control import current_cancellation
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse, ReasoningStatus
from systemsense.storage.presented_read_set import PresentedReadSetCheckV1, PresentedReadSetV1

_NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
_IDENTITY = ProviderIdentity(provider_id="fake-deep", provider_version="1", role="reasoning")


def _empty_read_set(case_id: CaseId) -> PresentedReadSetV1:
    payload: dict[str, object] = {
        "schema_version": 1,
        "case_id": str(case_id),
        "case_generation": 1,
        "entries": [],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return PresentedReadSetV1(
        case_id=case_id, case_generation=1, entries=(), read_set_sha256=digest
    )


def _request() -> ReasoningRequest:
    return ReasoningRequest(
        schema_version=3,
        case_id=CaseId.new(),
        state_version=7,
        correlation_id="deep:one",
        deadline_at=_NOW + timedelta(seconds=10),
        objective="Why did the application fail?",
        reference_context=({"hint": "unchanged"},),
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="Read-only application snapshot",
                keywords=frozenset({"application"}),
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=1000,
        max_probes=1,
    )


class _Provider:
    identity = _IDENTITY

    def __init__(self) -> None:
        self.called = False
        self.cancellation: threading.Event | None = None

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        self.called = True
        self.cancellation = current_cancellation()
        request.reference_context[0]["hint"] = "provider mutation"
        return ReasoningResponse(
            schema_version=3,
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=ReasoningStatus.UNRESOLVED,
            summary="The cause is not yet supported.",
        )


def _check(
    case_id: CaseId, *, generation: int = 1, consistent: bool = True
) -> PresentedReadSetCheckV1:
    return PresentedReadSetCheckV1(
        case_id=case_id,
        frozen_generation=1,
        current_generation=generation,
        consistent=consistent,
        generation_advanced=generation > 1,
        generation_regressed=False,
    )


def test_worker_uses_copied_request_and_no_store(tmp_path: Path) -> None:
    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=3,
    )
    provider = _Provider()
    cancel = threading.Event()
    result = run_deep_worker(provider, task, cancel_event=cancel, clock=lambda: _NOW)
    assert result.status == "completed"
    assert result.response is not None
    assert provider.cancellation is cancel
    assert request.reference_context[0]["hint"] == "unchanged"
    assert task.request.reference_context[0]["hint"] == "unchanged"
    assert not list(tmp_path.iterdir())


def test_result_admission_is_versioned_and_generation_sensitive() -> None:
    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=3,
    )
    result = run_deep_worker(_Provider(), task, cancel_event=threading.Event(), clock=lambda: _NOW)
    current = assess_deep_result(
        task,
        result,
        _check(request.case_id),
        current_hypothesis_revision=3,
        case_terminal=False,
        cancelled=False,
        now=_NOW,
    )
    assert current.applicability == "coordinator_revalidation_required"
    advanced = assess_deep_result(
        task,
        result,
        _check(request.case_id, generation=2),
        current_hypothesis_revision=3,
        case_terminal=False,
        cancelled=False,
        now=_NOW,
    )
    assert advanced.applicability == "historical_only"
    assert advanced.assessed_through_generation == 1


@pytest.mark.parametrize(
    ("consistent", "hypothesis_revision", "terminal", "cancelled", "now", "reason"),
    [
        (False, 3, False, False, _NOW, "presented_evidence_changed"),
        (True, 4, False, False, _NOW, "hypothesis_lineage_advanced"),
        (True, 3, True, False, _NOW, "case_terminal"),
        (True, 3, False, True, _NOW, "cancelled"),
        (True, 3, False, False, _NOW + timedelta(seconds=11), "deadline_expired"),
    ],
)
def test_stale_or_invalid_worker_results_never_admit(
    consistent: bool,
    hypothesis_revision: int,
    terminal: bool,
    cancelled: bool,
    now: datetime,
    reason: str,
) -> None:
    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=3,
    )
    result = run_deep_worker(_Provider(), task, cancel_event=threading.Event(), clock=lambda: _NOW)
    admission: DeepResultApplicabilityV1 = assess_deep_result(
        task,
        result,
        _check(request.case_id, consistent=consistent),
        current_hypothesis_revision=hypothesis_revision,
        case_terminal=terminal,
        cancelled=cancelled,
        now=now,
    )
    assert admission.applicability == "reject"
    assert reason in admission.reasons


def test_cancelled_worker_does_not_call_provider() -> None:
    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=3,
    )
    cancel = threading.Event()
    cancel.set()
    provider = _Provider()
    result = run_deep_worker(provider, task, cancel_event=cancel, clock=lambda: _NOW)
    assert result.status == "cancelled"
    assert result.response is None
    assert not provider.called


def test_wrong_provider_identity_is_rejected_before_call() -> None:
    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=ProviderIdentity(
            provider_id="other-deep", provider_version="1", role="reasoning"
        ),
        hypothesis_revision=3,
    )
    provider = _Provider()
    result = run_deep_worker(provider, task, cancel_event=None, clock=lambda: _NOW)
    assert result.status == "rejected"
    assert result.failure_kind == "ProviderIdentityMismatch"
    assert not provider.called


def test_freeze_rejects_wrong_case_read_set() -> None:
    request = _request()
    with pytest.raises(ValueError, match="read_set_case_mismatch"):
        freeze_deep_task(
            request,
            _empty_read_set(CaseId.new()),
            provider_identity=_IDENTITY,
            hypothesis_revision=3,
        )


def test_request_digest_normalizes_unordered_probe_terms() -> None:
    request = _request()
    first = request.model_dump(mode="json")
    second = request.model_dump(mode="json")
    first["completed_probe_ids"] = ["z", "a"]
    second["completed_probe_ids"] = ["a", "z"]
    first["available_probes"][0]["keywords"] = ["application", "slow"]
    second["available_probes"][0]["keywords"] = ["slow", "application"]
    assert canonical_reasoning_request_json(first) == canonical_reasoning_request_json(second)


def test_unspecified_context_cannot_be_claimed_as_current_case_read_set() -> None:
    request = _request()
    context = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=_NOW,
        captured_at=_NOW,
        probe_id="application.snapshot",
        summary="An unscoped fixture",
        status=EvidenceContextStatus.OBSERVED,
        case_scope="unspecified",
    )
    request = request.model_copy(
        update={"evidence_ids": (context.evidence_id,), "evidence_context": (context,)}
    )
    with pytest.raises(ValueError, match="unscoped_focused_evidence"):
        freeze_deep_task(
            request,
            _empty_read_set(request.case_id),
            provider_identity=_IDENTITY,
            hypothesis_revision=3,
        )
