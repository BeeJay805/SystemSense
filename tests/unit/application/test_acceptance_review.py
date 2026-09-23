from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import systemsense.application.investigator as investigator_module
from systemsense.application.assessment import AssessmentDisposition, assess_investigation
from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
)
from systemsense.application.investigator import Investigator
from systemsense.decision.contracts import FastSignal, ProbeCapability, ProbeProposal
from systemsense.domain.coverage import CoverageStatus
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.evidence.retrieval import EvidencePacket, RetrievedCoverage
from systemsense.evidence.targets import TargetEvidenceSelection
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
CASE_ID = CaseId(root="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
EVIDENCE_ID = EvidenceId(root="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


def _state(**updates: object) -> InvestigationState:
    state = InvestigationState(
        case_id=CASE_ID,
        objective="Which process owns the listener at 127.0.0.1:18765?",
        created_at=NOW,
        updated_at=NOW,
        deadline_at=NOW + timedelta(minutes=3),
        incident_start=NOW - timedelta(minutes=15),
        incident_end=NOW + timedelta(minutes=5),
        budget_ms=180_000,
    )
    return state.model_copy(update=updates)


class _PacketInvestigator(Investigator):
    packet_value: EvidencePacket

    def packet(self, case_id: str, *, state: InvestigationState | None = None) -> EvidencePacket:
        del case_id, state
        return self.packet_value


class _StateRepository(InvestigationRepository):
    def __init__(self, state: InvestigationState) -> None:
        self._state = state

    def load(self, case_id: str) -> InvestigationState:
        assert case_id == str(self._state.case_id)
        return self._state


def _bare_investigator(packet: EvidencePacket) -> Investigator:
    investigator = object.__new__(_PacketInvestigator)
    investigator.packet_value = packet
    investigator.repository = _StateRepository(_state())
    return investigator


def test_context_discloses_packet_level_record_omissions() -> None:
    packet = EvidencePacket(
        evidence=(),
        coverage=(
            RetrievedCoverage(
                evidence_id=EVIDENCE_ID,
                case_id=CASE_ID,
                category="network",
                status=CoverageStatus.FAILED,
                captured_at=NOW,
                reason="fixture failure",
                limitations=(),
                execution_id=None,
                source_id="src_fixture",
            ),
        ),
        considered_case_ids=(CASE_ID,),
        truncated=True,
        omitted_evidence_count=7,
        omitted_coverage_count=3,
    )

    context = _bare_investigator(packet).context(str(CASE_ID))

    assert any(
        "omitted 7 evidence records and 3 coverage records" in limitation
        for item in context
        for limitation in item.limitations
    )


@pytest.mark.parametrize(
    ("coverage", "expected"),
    [
        (CoverageStatus.COVERED, "observed"),
        (CoverageStatus.PARTIAL, "partial"),
        (CoverageStatus.MISSING, "missing"),
        (CoverageStatus.UNAVAILABLE, "unavailable"),
        (CoverageStatus.DENIED, "denied"),
        (CoverageStatus.FAILED, "failed"),
        (CoverageStatus.TRUNCATED, "truncated"),
        (CoverageStatus.STALE, "stale"),
        (CoverageStatus.UNSUPPORTED, "unsupported"),
    ],
)
def test_context_preserves_coverage_status_semantics(
    coverage: CoverageStatus,
    expected: str,
) -> None:
    packet = EvidencePacket(
        evidence=(),
        coverage=(
            RetrievedCoverage(
                evidence_id=EVIDENCE_ID,
                case_id=CASE_ID,
                category="network",
                status=coverage,
                captured_at=NOW,
                reason="fixture coverage",
                limitations=(),
                execution_id=None,
                source_id="src_fixture",
            ),
        ),
        considered_case_ids=(CASE_ID,),
        truncated=coverage is not CoverageStatus.COVERED,
        omitted_evidence_count=0,
        omitted_coverage_count=0,
    )

    context = _bare_investigator(packet).context(str(CASE_ID))

    assert context[0].status.value == expected


@pytest.mark.parametrize("status", ["partial", "unavailable"])
def test_deterministic_reasoning_keeps_new_coverage_states_as_gaps(status: str) -> None:
    context = EvidenceContext(
        evidence_id=EVIDENCE_ID,
        observed_at=NOW,
        captured_at=NOW,
        probe_id="network.coverage",
        summary="Incomplete network coverage",
        status=EvidenceContextStatus(status),
    )
    request = ReasoningRequest(
        case_id=CASE_ID,
        state_version=1,
        correlation_id="reasoning:fixture:1",
        deadline_at=NOW + timedelta(minutes=1),
        objective="Explain the network failure",
        evidence_ids=(EVIDENCE_ID,),
        evidence_context=(context,),
        available_probes=(
            ProbeCapability(
                probe_id="network.snapshot",
                description="Read network state",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=1_000,
        max_probes=1,
    )

    response = DeterministicReasoningProvider().investigate(request)

    assert any(item.hypothesis_id == "h_observability_gap" for item in response.hypotheses)


class _PendingDetailInvestigator(Investigator):
    calls: int = 0

    def context(
        self, case_id: str, *, state: InvestigationState | None = None
    ) -> tuple[EvidenceContext, ...]:
        del case_id, state
        return ()

    def _reason(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
        *,
        fast_signals: tuple[FastSignal, ...] = (),
    ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
        del context, fast_signals
        self.calls += 1
        return state, ()

    def _remaining_ms(self, state: InvestigationState) -> int:
        del state
        return 1_000


class _FinishInvestigator(Investigator):
    def _save(
        self,
        state: InvestigationState,
        event: str,
        detail: str,
    ) -> InvestigationState:
        del event, detail
        return state


class _FailingFindingInvestigator(_FinishInvestigator):
    def context(
        self, case_id: str, *, state: InvestigationState | None = None
    ) -> tuple[EvidenceContext, ...]:
        del case_id, state
        raise RuntimeError("read failed")


class _SelectedContextInvestigator(_FinishInvestigator):
    context_value: tuple[EvidenceContext, ...]

    def context(
        self, case_id: str, *, state: InvestigationState | None = None
    ) -> tuple[EvidenceContext, ...]:
        del case_id, state
        return self.context_value


def test_truncated_target_selection_blocks_unique_owner_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state(
        objective="The app cannot bind 127.0.0.1:18765 because its address is in use.",
        completed_probe_ids=("network.listeners",),
    )
    observed = EvidenceContext(
        evidence_id=EVIDENCE_ID,
        observed_at=NOW,
        captured_at=NOW,
        probe_id="network.listeners",
        summary="Exact listener row",
        status=EvidenceContextStatus.OBSERVED,
        facts={
            "collection_started_at": (NOW - timedelta(milliseconds=30)).isoformat(),
            "listener_table_started_at": (NOW - timedelta(milliseconds=20)).isoformat(),
            "listener_table_completed_at": (NOW - timedelta(milliseconds=10)).isoformat(),
            "collection_completed_at": NOW.isoformat(),
            "collection_status": "available",
            "omitted_listener_count": 0,
            "listeners": [
                {
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "protocol": "tcp4",
                    "pid": 52,
                    "process_name": "python.exe",
                    "process_creation_time": (NOW - timedelta(minutes=2)).isoformat(),
                    "owner_status": "available",
                }
            ],
        },
    )
    assert assess_investigation(state=state, context=(observed,), relationships=()).disposition is (
        AssessmentDisposition.SUPPORTED_OBSERVED_FINDING
    )
    selection = TargetEvidenceSelection(context=(observed,), truncated=True)

    def selected_target(
        _store: SQLiteStore, _context: tuple[EvidenceContext, ...], _objective: str
    ) -> TargetEvidenceSelection:
        return selection

    monkeypatch.setattr(
        investigator_module,
        "select_target_evidence",
        selected_target,
    )
    with SQLiteStore(tmp_path / "bounded-selection.db") as store:
        investigator = object.__new__(_SelectedContextInvestigator)
        investigator.context_value = (observed,)
        investigator.store = store
        result = investigator._finish(  # pyright: ignore[reportPrivateUsage]
            state,
            InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
            "No eligible unused probe remains.",
        )
    assert result.assessment is None
    assert result.outcome is InvestigationOutcome.INSUFFICIENT_OBSERVABILITY
    assert any("target scan incomplete" in item for item in result.warnings)


def test_optional_observed_finding_failure_does_not_block_terminal_case() -> None:
    state = _state(
        objective="The app cannot bind 127.0.0.1:18765 because its address is in use.",
        completed_probe_ids=("network.listeners",),
    )
    investigator = object.__new__(_FailingFindingInvestigator)

    result = investigator._finish(  # pyright: ignore[reportPrivateUsage]
        state,
        InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
        "No eligible unused probe remains.",
    )

    assert result.outcome is InvestigationOutcome.INSUFFICIENT_OBSERVABILITY
    assert result.assessment is None
    assert any(
        "Observed-finding enrichment unavailable: RuntimeError" in item for item in result.warnings
    )


def test_unrelated_terminal_case_does_not_retrieve_target_evidence() -> None:
    state = _state(objective="Why is this PDF viewer slow?")
    investigator = object.__new__(_FinishInvestigator)

    result = investigator._finish(  # pyright: ignore[reportPrivateUsage]
        state,
        InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
        "No eligible unused probe remains.",
    )

    assert result.outcome is InvestigationOutcome.INSUFFICIENT_OBSERVABILITY
    assert result.assessment is None


def test_detail_followup_skips_when_requested_evidence_is_absent() -> None:
    detail = EvidenceDetailRequest(evidence_id=EVIDENCE_ID, match_literals=("python.exe",))
    state = _state(requested_details=(detail,))
    investigator = object.__new__(_PendingDetailInvestigator)
    investigator.calls = 0

    result, _ = investigator._reason_with_details(  # pyright: ignore[reportPrivateUsage]
        state,
        (),
    )

    assert investigator.calls == 1
    assert any("1 unsatisfied" in warning for warning in result.warnings)
    assert any("No new requested facts reached" in warning for warning in result.warnings)


def test_finish_reports_unsatisfied_request_count_without_changing_cancellation() -> None:
    detail = EvidenceDetailRequest(evidence_id=EVIDENCE_ID, match_literals=("python.exe",))
    state = _state(
        requested_evidence_ids=(EVIDENCE_ID,),
        requested_details=(detail,),
    )
    investigator = object.__new__(_FinishInvestigator)

    result = investigator._finish(  # pyright: ignore[reportPrivateUsage]
        state,
        InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
        "No eligible unused probe remains.",
    )
    cancelled = investigator._finish(  # pyright: ignore[reportPrivateUsage]
        state,
        InvestigationOutcome.CANCELLED,
        "Cancelled by the user.",
    )

    assert result.status is InvestigationStatus.COMPLETE
    assert result.stop_reason is not None and "2 unsatisfied" in result.stop_reason
    assert cancelled.stop_reason == "Cancelled by the user."


def test_pending_detail_prevents_supported_narrow_completion() -> None:
    detail = EvidenceDetailRequest(evidence_id=EVIDENCE_ID, match_literals=("python.exe",))
    hypothesis = Hypothesis(
        hypothesis_id="listener_owner",
        statement="The exact listener row identifies an owner.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(EVIDENCE_ID,),
        distinguishing_probe_ids=("network.listeners",),
    )
    state = _state(
        completed_probe_ids=("network.listeners",),
        hypotheses=(hypothesis,),
        requested_details=(detail,),
    )
    context = EvidenceContext(
        evidence_id=EVIDENCE_ID,
        observed_at=NOW,
        captured_at=NOW,
        probe_id="network.listeners",
        summary="Exact listener owner",
        facts={
            "listeners.0": {
                "local_address": "127.0.0.1",
                "local_port": 18765,
                "protocol": "tcp4",
                "pid": 42,
                "process_name": "python.exe",
                "process_creation_time": NOW.isoformat(),
                "owner_status": "available",
            },
            "omitted_listener_count": 0,
        },
        status=EvidenceContextStatus.OBSERVED,
    )

    assessment = assess_investigation(state=state, context=(context,), relationships=())

    assert assessment.disposition is AssessmentDisposition.UNRESOLVED
    assert any("detail" in limitation.casefold() for limitation in assessment.limitations)
