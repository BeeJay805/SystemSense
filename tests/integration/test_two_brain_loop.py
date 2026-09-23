import time
from dataclasses import replace
from pathlib import Path

import pytest

from systemsense.application.investigation_state import InvestigationOutcome, InvestigationState
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProbeProposal
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.probes import ProbeObservation
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition


def test_baseline_evidence_exists_before_first_fast_brain_call(tmp_path: Path) -> None:
    decision = RecordingDecision()
    base = probe_definition("core")
    definition = replace(
        base, manifest=base.manifest.model_copy(update={"probe_id": "core.system"})
    )
    with SQLiteStore(tmp_path / "baseline.db") as store:
        app = investigator(store, definitions=(definition, probe_definition("network")))
        app.decision = decision
        case = app.create(objective="connection issue", budget_ms=2000)
        app.run(str(case.case_id))
        assert decision.requests
        assert "core.system" in decision.requests[0].completed_probe_ids
        assert decision.requests[0].evidence_context


def test_first_fast_brain_call_gets_focused_network_seed_only(tmp_path: Path) -> None:
    decision = RecordingDecision()
    definitions = tuple(
        replace(
            probe_definition(name),
            manifest=probe_definition(name).manifest.model_copy(update={"probe_id": probe_id}),
        )
        for name, probe_id in (
            ("core", "core.system"),
            ("network", "network.configuration"),
            ("devices", "devices.snapshot"),
            ("storage", "storage.snapshot"),
        )
    )
    with SQLiteStore(tmp_path / "focused.db") as store:
        app = investigator(store, definitions=definitions)
        app.decision = decision
        case = app.create(objective="Wi-Fi will not connect", budget_ms=2000)
        app.run(str(case.case_id))
        assert decision.requests
        assert decision.requests[0].completed_probe_ids == frozenset(
            {"core.system", "network.configuration"}
        )


def test_one_probe_budget_prioritizes_symptom_evidence(tmp_path: Path) -> None:
    decision = RecordingDecision()
    definitions = tuple(
        replace(
            probe_definition(name),
            manifest=probe_definition(name).manifest.model_copy(update={"probe_id": probe_id}),
        )
        for name, probe_id in (("core", "core.system"), ("network", "network.configuration"))
    )
    with SQLiteStore(tmp_path / "one-probe.db") as store:
        app = investigator(store, definitions=definitions)
        app.decision = decision
        case = app.create(objective="Wi-Fi will not connect", budget_ms=2000, max_probes=1)
        app.run(str(case.case_id))
        assert decision.requests
        assert decision.requests[0].completed_probe_ids == frozenset({"network.configuration"})


def test_no_proposal_does_not_scan_unrelated_cheapest_probe(tmp_path: Path) -> None:
    definitions = tuple(
        replace(
            probe_definition(name),
            manifest=probe_definition(name).manifest.model_copy(update={"probe_id": probe_id}),
        )
        for name, probe_id in (
            ("core", "core.system"),
            ("network", "network.connectivity"),
            ("storage", "storage.snapshot"),
        )
    )
    with SQLiteStore(tmp_path / "no-broad-scan.db") as store:
        app = investigator(store, definitions=definitions)
        app.decision = EmptyDecision()
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        case = app.create(objective="Wi-Fi will not connect", budget_ms=3000)
        result = app.run(str(case.case_id))
        attempted = {
            str(row[0])
            for row in store.connection.execute(
                "SELECT probe_id FROM probe_executions WHERE case_id=?", (str(case.case_id),)
            )
        }
        assert attempted == {"core.system", "network.connectivity"}
        assert result.outcome is InvestigationOutcome.INSUFFICIENT_OBSERVABILITY


def test_no_proposal_can_follow_reference_distinguishing_probe(tmp_path: Path) -> None:
    definitions = tuple(
        replace(
            probe_definition(name),
            manifest=probe_definition(name).manifest.model_copy(update={"probe_id": probe_id}),
        )
        for name, probe_id in (
            ("core", "core.system"),
            ("network", "network.connectivity"),
            ("network", "network.configuration"),
        )
    )
    with SQLiteStore(tmp_path / "graph-explore.db") as store:
        app = investigator(store, definitions=definitions)
        app.decision = EmptyDecision()
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        case = app.create(objective="Internet route mismatch", budget_ms=3000)
        app.run(str(case.case_id))
        attempted = {
            str(row[0])
            for row in store.connection.execute(
                "SELECT probe_id FROM probe_executions WHERE case_id=?", (str(case.case_id),)
            )
        }
        assert attempted == {"core.system", "network.connectivity", "network.configuration"}


def test_probe_admission_rechecks_budget_after_fast_provider(tmp_path: Path) -> None:
    class DelayedDecision(EmptyDecision):
        def __init__(self) -> None:
            self.requests: list[DecisionRequest] = []

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.requests.append(request)
            time.sleep(0.08)
            return super().decide(request)

    decision = DelayedDecision()
    with SQLiteStore(tmp_path / "decision-budget.db") as store:
        app = investigator(
            store, definitions=(probe_definition("core"), probe_definition("network"))
        )
        app.decision = decision
        admitted_budgets: list[int] = []
        original = app._eligible  # pyright: ignore[reportPrivateUsage]

        def record_admission(
            proposals: tuple[ProbeProposal, ...], state: InvestigationState, remaining: int
        ) -> tuple[ProbeProposal, ...]:
            if decision.requests:
                admitted_budgets.append(remaining)
            return original(proposals, state, remaining)

        app._eligible = record_admission  # pyright: ignore[reportPrivateUsage]
        case = app.create(objective="Internet route mismatch", budget_ms=3000)
        app.run(str(case.case_id))

    assert decision.requests
    assert admitted_budgets
    assert admitted_budgets[0] < decision.requests[0].budget_ms - 40


class EmptyDecision(KeywordBaselineDecisionProvider):
    def decide(self, request: DecisionRequest) -> DecisionResponse:
        return DecisionResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
        )


class RecordingDecision(KeywordBaselineDecisionProvider):
    def __init__(self) -> None:
        self.requests: list[DecisionRequest] = []

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        self.requests.append(request)
        return super().decide(request)


class DistinguishingReasoner(DeterministicReasoningProvider):
    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        decision = KeywordBaselineDecisionProvider().decide(
            DecisionRequest(
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                symptom=request.objective,
                available_probes=request.available_probes,
                max_probes=1,
                budget_ms=request.budget_ms,
            )
        )
        return ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=ReasoningStatus.UNRESOLVED,
            summary="Compare the service dependency with the network alternative.",
            hypotheses=(
                Hypothesis(
                    hypothesis_id="service_dependency",
                    statement="A service dependency may be unavailable.",
                    status=HypothesisStatus.UNRESOLVED,
                ),
            ),
            distinguishing_probes=decision.proposals,
        )


def test_reasoner_feedback_reaches_fast_model_and_calls_are_durable(tmp_path: Path) -> None:
    decision = RecordingDecision()
    with SQLiteStore(tmp_path / "case.db") as store:
        app = investigator(
            store,
            definitions=tuple(probe_definition(f"domain{i}") for i in range(8)),
            reasoning=DistinguishingReasoner(),
        )
        app.decision = decision
        case = app.create(objective="application cannot connect", budget_ms=2000, max_rounds=3)
        result = app.run(str(case.case_id))
        assert len(decision.requests) >= 2
        feedback = next(
            request.model_dump() for request in decision.requests if request.preferred_probe_ids
        )
        assert "service dependency" in str(feedback.get("hypothesis_briefs", ())).lower()
        assert feedback.get("preferred_probe_ids")
        calls = result.provider_calls
        assert len(calls) >= 4
        assert {call.role for call in calls} == {"fast_decision", "reasoning"}
        assert all(call.elapsed_ms >= 0 for call in calls)
        assert all(call.state_version >= 0 for call in calls)
        assert all(request.deadline_at < case.deadline_at for request in decision.requests)
        assert any(request.attention_only for request in decision.requests)


def test_final_collected_probe_gets_a_reasoning_pass_before_probe_budget_stop(
    tmp_path: Path,
) -> None:
    decision = RecordingDecision()
    with SQLiteStore(tmp_path / "case.db") as store:
        app = investigator(store, reasoning=DeterministicReasoningProvider())
        app.decision = decision
        case = app.create(objective="current observations", budget_ms=2000, max_probes=1)
        result = app.run(str(case.case_id))
        assert len(result.completed_probe_ids) == 1
        assert any(call.role == "reasoning" for call in result.provider_calls)


def test_reasoner_is_not_offered_completed_probes(tmp_path: Path) -> None:
    class InspectingReasoner(DeterministicReasoningProvider):
        def __init__(self) -> None:
            self.seen: list[ReasoningRequest] = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.seen.append(request)
            return super().investigate(request)

    reasoner = InspectingReasoner()
    with SQLiteStore(tmp_path / "case.db") as store:
        app = investigator(store, reasoning=reasoner)
        case = app.create(objective="slow system", budget_ms=2000)
        app.run(str(case.case_id))
        assert reasoner.seen
        assert reasoner.seen[0].model_dump().get("completed_probe_ids") == {
            "core.snapshot",
            "network.snapshot",
            "devices.snapshot",
        }


def test_missing_evidence_citation_survives_next_focused_reasoning_pass(tmp_path: Path) -> None:
    class RecordingReasoner(DeterministicReasoningProvider):
        request: ReasoningRequest | None = None

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.request = request
            return super().investigate(request)

    reasoner = RecordingReasoner()
    now = utc_now()
    context = tuple(
        EvidenceContext(
            evidence_id=EvidenceId.new(),
            observed_at=now,
            captured_at=now,
            probe_id=f"sample.{index}",
            summary="Exact observation",
            status=EvidenceContextStatus.OBSERVED,
            facts={"sample": index},
        )
        for index in range(20)
    )
    previous = Hypothesis(
        hypothesis_id="h_partial",
        statement="A detail is still needed.",
        status=HypothesisStatus.UNRESOLVED,
        missing_evidence_ids=(context[-1].evidence_id,),
    )
    with SQLiteStore(tmp_path / "focus.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="explain current uncertainty", budget_ms=5000)
        state = state.model_copy(update={"hypotheses": (previous,)})
        app._reason(state, context)  # pyright: ignore[reportPrivateUsage]
    assert reasoner.request is not None
    assert previous in reasoner.request.previous_hypotheses
    assert str(context[-1].evidence_id) in {
        str(item.evidence_id) for item in reasoner.request.evidence_context
    }


def test_generic_evidence_request_completes_only_after_facts_are_considered(
    tmp_path: Path,
) -> None:
    class CompletingReasoner(DeterministicReasoningProvider):
        requests: list[ReasoningRequest]

        def __init__(self) -> None:
            self.requests = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.requests.append(request)
            response = super().investigate(request)
            requested = request.priority_evidence_ids[0]
            return response.model_copy(
                update={
                    "considered_evidence_ids": (requested,),
                    "requested_evidence_ids": (requested,),
                }
            )

    reasoner = CompletingReasoner()
    now = utc_now()
    requested = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=now,
        captured_at=now,
        probe_id="network.listeners",
        summary="Requested exact listener facts",
        status=EvidenceContextStatus.OBSERVED,
        facts={"listeners.0": {"local_port": 18765, "pid": 52048}},
    )
    with SQLiteStore(tmp_path / "completed-request.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="identify listener owner", budget_ms=5000)
        state = state.model_copy(update={"requested_evidence_ids": (requested.evidence_id,)})

        result, _ = app._reason(state, (requested,))  # pyright: ignore[reportPrivateUsage]
        absent = EvidenceId.new()
        result_with_absent_history = result.model_copy(
            update={
                "completed_evidence_requests": (
                    absent,
                    *result.completed_evidence_requests,
                )
            }
        )
        app._reason(  # pyright: ignore[reportPrivateUsage]
            result_with_absent_history,
            (requested,),
        )

    assert result.completed_evidence_requests == (requested.evidence_id,)
    assert result.requested_evidence_ids == ()
    assert reasoner.requests[0].priority_evidence_ids == (requested.evidence_id,)
    assert reasoner.requests[1].completed_evidence_requests == (requested.evidence_id,)
    assert absent not in reasoner.requests[1].completed_evidence_requests


@pytest.mark.parametrize("gap", ["degraded", "empty_facts", "not_considered"])
def test_unmet_generic_evidence_request_remains_pending(tmp_path: Path, gap: str) -> None:
    class GapReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            response = super().investigate(request)
            return response.model_copy(
                update={
                    "considered_evidence_ids": ()
                    if gap == "not_considered"
                    else request.priority_evidence_ids,
                    "degraded": gap == "degraded",
                    "requested_evidence_ids": (),
                }
            )

    now = utc_now()
    requested = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=now,
        captured_at=now,
        probe_id="network.listeners",
        summary="Requested listener evidence",
        status=EvidenceContextStatus.OBSERVED,
        facts={} if gap == "empty_facts" else {"listeners.0": {"pid": 52048}},
    )
    with SQLiteStore(tmp_path / f"unmet-{gap}.db") as store:
        app = investigator(store, reasoning=GapReasoner())
        state = app.create(objective="identify listener owner", budget_ms=5000)
        state = state.model_copy(update={"requested_evidence_ids": (requested.evidence_id,)})

        result, _ = app._reason(state, (requested,))  # pyright: ignore[reportPrivateUsage]

    assert result.completed_evidence_requests == ()
    assert result.requested_evidence_ids == (requested.evidence_id,)


def test_packet_omission_signal_is_priority_reasoning_context(tmp_path: Path) -> None:
    class RecordingReasoner(DeterministicReasoningProvider):
        request: ReasoningRequest | None = None

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.request = request
            return super().investigate(request)

    reasoner = RecordingReasoner()
    now = utc_now()
    context = tuple(
        EvidenceContext(
            evidence_id=EvidenceId.new(),
            observed_at=now,
            captured_at=now,
            probe_id=f"sample.{index}",
            summary="Bounded packet item",
            status=EvidenceContextStatus.OBSERVED,
            facts={"sample": "x" * 1800},
            limitations=("Retrieval packet omitted 12 records due to bounds.",)
            if index == 19
            else (),
        )
        for index in range(20)
    )
    with SQLiteStore(tmp_path / "packet-omission.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="explain bounded observations", budget_ms=5000)
        app._reason(state, context)  # pyright: ignore[reportPrivateUsage]

    assert reasoner.request is not None
    assert context[-1].evidence_id in reasoner.request.priority_evidence_ids
    assert str(context[-1].evidence_id) in {
        str(item.evidence_id) for item in reasoner.request.evidence_context
    }


def test_failed_latest_reasoning_retains_prior_assessment_with_explicit_warning(
    tmp_path: Path,
) -> None:
    class FailedReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return super().investigate(request).model_copy(update={"degraded": True})

    previous = Hypothesis(
        hypothesis_id="h_prior",
        statement="Previously investigated branch.",
        status=HypothesisStatus.UNRESOLVED,
    )
    with SQLiteStore(tmp_path / "failed.db") as store:
        app = investigator(store, reasoning=FailedReasoner())
        state = app.create(objective="compare branches", budget_ms=5000)
        state = state.model_copy(update={"hypotheses": (previous,), "summary": "Prior assessment."})
        result, _ = app._reason(state, ())  # pyright: ignore[reportPrivateUsage]
    assert result.hypotheses == (previous,)
    assert result.summary == "Prior assessment."
    assert any(
        "may not account for newly collected evidence" in warning for warning in result.warnings
    )


def test_hypothesis_keeps_exact_fact_page_when_attention_moves_to_another_page(
    tmp_path: Path,
) -> None:
    class CitingReasoner(DeterministicReasoningProvider):
        requests: list[ReasoningRequest]

        def __init__(self) -> None:
            self.requests = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.requests.append(request)
            return (
                super()
                .investigate(request)
                .model_copy(
                    update={
                        "hypotheses": (
                            Hypothesis(
                                hypothesis_id="h_listener",
                                statement="Observed listener owner.",
                                status=HypothesisStatus.UNRESOLVED,
                                supporting_evidence_ids=(request.evidence_context[0].evidence_id,),
                            ),
                        ),
                        "considered_evidence_ids": (request.evidence_context[0].evidence_id,),
                    }
                )
            )

    reasoner = CitingReasoner()
    now = utc_now()
    original = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=now,
        captured_at=now,
        probe_id="network.listeners",
        summary="Listener table",
        status=EvidenceContextStatus.OBSERVED,
        facts={"listeners.28": {"pid": 52048, "process_name": "python.exe", "port": 18765}},
    )
    different_page = original.model_copy(update={"facts": {"listeners.0": {"pid": 4, "port": 445}}})
    with SQLiteStore(tmp_path / "pages.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="identify listener owner", budget_ms=5000)
        state, _ = app._reason(state, (original,))  # pyright: ignore[reportPrivateUsage]
        app._reason(state, (different_page,))  # pyright: ignore[reportPrivateUsage]
    assert (
        reasoner.requests[-1].evidence_context[0].facts.get("listeners.28")
        == original.facts["listeners.28"]
    )


@pytest.mark.parametrize("narrow", [True, False])
def test_loop_can_complete_observed_owner_question_without_claiming_causal_diagnosis(
    tmp_path: Path,
    narrow: bool,
) -> None:
    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = utc_now()
        return ProbeObservation(
            summary="Observed TCP listener ownership",
            observed_at=now,
            captured_at=now,
            facts={
                "omitted_listener_count": 0,
                "listeners": [
                    {
                        "local_address": "127.0.0.1",
                        "local_port": 18765,
                        "protocol": "tcp",
                        "pid": 52,
                        "process_name": "python.exe",
                        "process_creation_time": now.isoformat(),
                        "owner_status": "available",
                    }
                ],
            },
        )

    class OwnerReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return (
                super()
                .investigate(request)
                .model_copy(
                    update={
                        "hypotheses": (
                            Hypothesis(
                                hypothesis_id="h_owner",
                                statement="An observed owner may explain a conflict.",
                                status=HypothesisStatus.UNRESOLVED,
                                supporting_evidence_ids=(request.evidence_context[0].evidence_id,),
                            ),
                        )
                    }
                )
            )

    base = probe_definition("network")
    definition = replace(
        base,
        manifest=base.manifest.model_copy(update={"probe_id": "network.listeners"}),
        handler=collect,
    )
    with SQLiteStore(tmp_path / "supported.db") as store:
        app = investigator(store, definitions=(definition,), reasoning=OwnerReasoner())
        objective = (
            "Which process owns the listener at 127.0.0.1:18765?"
            if narrow
            else "Why does my application crash on port 18765?"
        )
        state = app.create(objective=objective, budget_ms=5000)
        result = app.run(str(state.case_id))
    assert result.completed_probe_ids == ("network.listeners",)
    if narrow:
        assert result.outcome is InvestigationOutcome.SUPPORTED_EXPLANATION
        assert result.assessment is not None and result.assessment.root_cause_proven is False
        assert "python.exe" in result.summary
    else:
        assert result.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
        assert result.assessment is None


def test_deep_brain_retrieves_a_specific_stored_row_without_repeating_collection(
    tmp_path: Path,
) -> None:
    class DetailReasoner(DeterministicReasoningProvider):
        requests: list[ReasoningRequest]

        def __init__(self) -> None:
            self.requests = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.requests.append(request)
            observed = next(
                item for item in request.evidence_context if item.probe_id == "application.snapshot"
            )
            detail = EvidenceDetailRequest(
                evidence_id=observed.evidence_id, match_literals=("row_39",)
            )
            response = super().investigate(request)
            return response.model_copy(
                update={
                    "considered_evidence_ids": tuple(
                        item.evidence_id for item in request.evidence_context
                    ),
                    "requested_details": () if request.completed_detail_requests else (detail,),
                    "hypotheses": (
                        Hypothesis(
                            hypothesis_id="h_row",
                            statement="Need to inspect the specific row.",
                            status=HypothesisStatus.UNRESOLVED,
                            supporting_evidence_ids=(observed.evidence_id,),
                        ),
                    ),
                }
            )

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = utc_now()
        return ProbeObservation(
            summary="Forty complete rows",
            observed_at=now,
            captured_at=now,
            facts={"rows": [{"name": f"row_{i}", "payload": "x" * 180} for i in range(40)]},
        )

    definition = replace(probe_definition("application"), handler=collect)
    reasoner = DetailReasoner()
    with SQLiteStore(tmp_path / "detail.db") as store:
        app = investigator(store, definitions=(definition,), reasoning=reasoner)
        state = app.create(objective="Inspect application uncertainty", budget_ms=5000)
        result = app.run(str(state.case_id))
    assert result.completed_probe_ids == ("application.snapshot",)
    assert len(reasoner.requests) >= 2
    assert any(
        item.facts.get("rows.39") == {"name": "row_39", "payload": "x" * 180}
        for item in reasoner.requests[1].evidence_context
    )
    assert len(result.completed_detail_requests) == 1


def test_unmatched_detail_request_remains_explicitly_pending(tmp_path: Path) -> None:
    class MissingDetailReasoner(DeterministicReasoningProvider):
        requests: list[ReasoningRequest]
        detail: EvidenceDetailRequest | None

        def __init__(self) -> None:
            self.requests = []
            self.detail = None

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.requests.append(request)
            if self.detail is None:
                observed = next(
                    item
                    for item in request.evidence_context
                    if item.probe_id == "application.snapshot"
                )
                self.detail = EvidenceDetailRequest(
                    evidence_id=observed.evidence_id,
                    match_literals=("row_that_does_not_exist",),
                )
            return (
                super()
                .investigate(request)
                .model_copy(update={"requested_details": (self.detail,)})
            )

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = utc_now()
        return ProbeObservation(
            summary="One application row",
            observed_at=now,
            captured_at=now,
            facts={"rows": [{"name": "present_row"}]},
        )

    definition = replace(probe_definition("application"), handler=collect)
    reasoner = MissingDetailReasoner()
    with SQLiteStore(tmp_path / "missing-detail.db") as store:
        app = investigator(store, definitions=(definition,), reasoning=reasoner)
        state = app.create(objective="Inspect an absent application row", budget_ms=5000)
        result = app.run(str(state.case_id))

    assert len(reasoner.requests) >= 2
    assert reasoner.detail is not None
    assert all(
        str(reasoner.detail.evidence_id)
        in {str(item.evidence_id) for item in request.evidence_context}
        for request in reasoner.requests[1:]
    )
    assert all(not request.completed_detail_requests for request in reasoner.requests)
    assert result.completed_detail_requests == ()
    assert len(result.requested_details) == 1, (
        [len(item.completed_detail_requests) for item in reasoner.requests],
        result.warnings,
        result.stop_reason,
    )
    assert any("unsatisfied evidence/detail requests" in item for item in result.warnings)


def test_matched_detail_is_not_completed_when_reasoner_did_not_consider_it(
    tmp_path: Path,
) -> None:
    class NonConsideringReasoner(DeterministicReasoningProvider):
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            observed = next(
                item for item in request.evidence_context if item.probe_id == "application.snapshot"
            )
            detail = EvidenceDetailRequest(
                evidence_id=observed.evidence_id,
                match_literals=("row_39",),
            )
            return (
                super()
                .investigate(request)
                .model_copy(
                    update={
                        "considered_evidence_ids": (),
                        "requested_details": (detail,),
                    }
                )
            )

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = utc_now()
        return ProbeObservation(
            summary="Forty complete rows",
            observed_at=now,
            captured_at=now,
            facts={"rows": [{"name": f"row_{i}"} for i in range(40)]},
        )

    definition = replace(probe_definition("application"), handler=collect)
    reasoner = NonConsideringReasoner()
    with SQLiteStore(tmp_path / "unconsidered-detail.db") as store:
        app = investigator(store, definitions=(definition,), reasoning=reasoner)
        state = app.create(objective="Inspect application uncertainty", budget_ms=5000)
        result = app.run(str(state.case_id))

    assert reasoner.calls >= 2
    assert result.completed_detail_requests == ()
    assert len(result.requested_details) == 1
