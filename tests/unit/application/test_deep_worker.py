"""Deep inference can overlap collection without gaining store or admission authority."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from systemsense.application.deep_worker import (
    DeepResultApplicabilityV1,
    FrozenDeepTaskV1,
    assess_deep_result,
    canonical_reasoning_request_json,
    deep_basis_sha256,
    freeze_deep_task,
    run_deep_worker,
)
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity, ResourceClass
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.evidence.retrieval import EvidenceCatalogCursor
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.control import current_cancellation
from systemsense.inference.settings import ProviderStatus
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse, ReasoningStatus
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
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


def test_worker_records_exact_degraded_deterministic_fallback() -> None:
    request = _request()
    provider_identity = ProviderIdentity(
        provider_id="ollama-local-reasoning", provider_version="1", role="reasoning"
    )
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=provider_identity,
        hypothesis_revision=1,
    )

    class Degraded:
        identity = provider_identity
        status = ProviderStatus(
            provider_id="ollama-local-reasoning",
            enabled=True,
            available=False,
            detail="LocalInferenceError:minimal focused evidence exceeds context budget",
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            response = DeterministicReasoningProvider().investigate(request)
            return response.model_copy(update={"degraded": True})

    result = run_deep_worker(Degraded(), task, cancel_event=None, clock=lambda: _NOW)
    assert result.status == "completed"
    assert result.response is not None and result.response.degraded
    assert result.response.provider == DeterministicReasoningProvider().identity
    assert (
        result.failure_kind == "LocalInferenceError:minimal focused evidence exceeds context budget"
    )
    assert type(result).model_validate_json(result.model_dump_json()) == result


def test_worker_rejects_unmarked_deterministic_response_from_pinned_ollama() -> None:
    request = _request()
    provider_identity = ProviderIdentity(
        provider_id="ollama-local-reasoning", provider_version="1", role="reasoning"
    )
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=provider_identity,
        hypothesis_revision=1,
    )

    class Unmarked:
        identity = provider_identity

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return DeterministicReasoningProvider().investigate(request)

    result = run_deep_worker(Unmarked(), task, cancel_event=None, clock=lambda: _NOW)
    assert result.status == "rejected"
    assert result.failure_kind == "ValueError"
    assert result.response is None


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


def test_worker_lane_retains_busy_slot_after_cancel() -> None:
    from systemsense.application import deep_worker

    assert hasattr(deep_worker, "DeepWorkerLane")
    started = threading.Event()
    release = threading.Event()

    class Delayed(_Provider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            started.set()
            assert release.wait(2)
            return super().investigate(request)

    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=0,
    )
    lane = deep_worker.DeepWorkerLane(clock=lambda: _NOW)
    try:
        assert lane.start(Delayed(), task)
        assert started.wait(1)
        assert lane.poll() is None
        lane.cancel()
        assert not lane.start(_Provider(), task)
    finally:
        release.set()
    assert lane.wait(1)
    result = lane.poll()
    assert result is not None and result.status == "cancelled"
    assert lane.start(_Provider(), task)
    assert lane.wait(1)
    assert lane.poll() is not None


def test_failed_worker_thread_start_does_not_leak_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    from systemsense.application.deep_worker import DeepWorkerLane

    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=0,
    )
    lane = DeepWorkerLane(clock=lambda: _NOW)

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("thread start failed")

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    with pytest.raises(RuntimeError, match="thread start failed"):
        lane.start(_Provider(), task)
    assert not lane.occupied
    assert lane.poll() is None


def test_historical_deep_context_requires_source_custody() -> None:
    request = _request()
    context = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=_NOW,
        captured_at=_NOW,
        probe_id="application.snapshot",
        summary="Historical fixture",
        status=EvidenceContextStatus.OBSERVED,
        case_scope="historical",
    )
    request = request.model_copy(
        update={"evidence_ids": (context.evidence_id,), "evidence_context": (context,)}
    )
    with pytest.raises(ValueError, match="historical_read_sets"):
        freeze_deep_task(
            request,
            _empty_read_set(request.case_id),
            provider_identity=_IDENTITY,
            hypothesis_revision=0,
        )


def test_oversized_provider_response_becomes_bounded_failure() -> None:
    class Oversized(_Provider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return (
                super().investigate(request).model_copy(update={"context_notes": ("x" * 100_000,)})
            )

    request = _request()
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=0,
    )
    result = run_deep_worker(Oversized(), task, cancel_event=None, clock=lambda: _NOW)
    assert result.status == "rejected"
    assert result.failure_kind == "ResponseByteLimitExceeded"
    assert result.response is None


def test_deep_delivery_basis_is_frozen_and_digest_bound():
    request = _request()
    cursor = EvidenceCatalogCursor(observed_at=_NOW, evidence_id=EvidenceId.new())
    request = request.model_copy(
        update={
            "evidence_ids": (cursor.evidence_id,),
            "evidence_catalog": (
                {"evidence_id": str(cursor.evidence_id), "observed_at": _NOW.isoformat()},
            ),
            "catalog_has_more": True,
        }
    )
    task = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=0,
        matched_detail_request_keys=("a" * 64,),
        catalog_next_cursor=cursor,
        catalog_generation=1,
        catalog_limit=64,
    )
    assert task.catalog_next_cursor == cursor
    assert task.matched_detail_request_keys == ("a" * 64,)
    altered = task.model_dump(mode="json")
    altered["catalog_limit"] = 32
    with pytest.raises(ValueError, match="digest"):
        FrozenDeepTaskV1.model_validate(altered)
    other = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=0,
        matched_detail_request_keys=("a" * 64,),
        catalog_next_cursor=cursor,
        catalog_generation=1,
        catalog_limit=32,
    )
    assert other.request_sha256 != task.request_sha256
    assert deep_basis_sha256(other) != deep_basis_sha256(task)
    current_cursor = EvidenceCatalogCursor(
        observed_at=_NOW - timedelta(seconds=1), evidence_id=EvidenceId.new()
    )
    shifted = freeze_deep_task(
        request,
        _empty_read_set(request.case_id),
        provider_identity=_IDENTITY,
        hypothesis_revision=0,
        matched_detail_request_keys=("a" * 64,),
        catalog_current_cursor=current_cursor,
        catalog_next_cursor=cursor,
        catalog_generation=1,
        catalog_limit=64,
    )
    assert shifted.catalog_current_cursor == current_cursor
    assert shifted.request_sha256 != task.request_sha256
    assert deep_basis_sha256(shifted) != deep_basis_sha256(task)
    assert FrozenDeepTaskV1.model_validate_json(shifted.model_dump_json()) == shifted


@pytest.mark.parametrize(
    "metadata",
    [
        {"matched_detail_request_keys": ("bad",)},
        {"matched_detail_request_keys": ("a" * 64, "a" * 64)},
        {"matched_detail_request_keys": tuple(str(i) * 64 for i in range(5))},
        {"catalog_generation": 1},
        {"catalog_generation": 2, "catalog_limit": 64},
        {"catalog_generation": 1, "catalog_limit": 65},
        {
            "catalog_generation": 1,
            "catalog_limit": 64,
            "catalog_next_cursor": EvidenceCatalogCursor(
                observed_at=_NOW, evidence_id=EvidenceId.new()
            ),
        },
    ],
)
def test_deep_delivery_basis_rejects_unbounded_or_inconsistent_metadata(
    metadata: dict[str, Any],
) -> None:
    request = _request()
    with pytest.raises(ValueError):
        freeze_deep_task(
            request,
            _empty_read_set(request.case_id),
            provider_identity=_IDENTITY,
            hypothesis_revision=0,
            **metadata,
        )
