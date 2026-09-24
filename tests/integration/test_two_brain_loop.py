import threading
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest

from systemsense.application.assessment import AssessmentDisposition
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationState
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    FastSignal,
    FastSignalKind,
    ProbeProposal,
)
from systemsense.domain.evidence import EvidenceFact
from systemsense.domain.ids import EvidenceId, ExecutionId, JsonValue
from systemsense.domain.time import utc_now
from systemsense.evidence.targets import select_target_evidence
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
from tests.unit.evidence.test_retrieval import _insert_record  # pyright: ignore[reportPrivateUsage]


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


def test_no_proposal_does_not_treat_legacy_screening_hint_as_discriminator(
    tmp_path: Path,
) -> None:
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
        assert attempted == {"core.system", "network.connectivity"}


def test_explicit_v3_discriminator_can_route_coverage_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    with SQLiteStore(tmp_path / "v3-graph-explore.db") as store:
        app = investigator(store, definitions=definitions)
        app.decision = EmptyDecision()
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        packet = app.knowledge.focused_packet(
            objective="Internet route mismatch",
            hypothesis_briefs=(),
            seed_node_ids=(),
            exclude_terms=frozenset({"wireless"}),
            max_relations=6,
            max_chars=6000,
        )
        payload = packet.model_dump(mode="json")
        payload["schema_version"] = 3
        for relation in payload["relations"]:
            legacy = relation.pop("distinguishing_probe_ids")
            relation["probe_roles"] = {
                "screening_probe_ids": [] if relation["relation_id"] == "kr_net_001" else legacy,
                "discriminating_probe_ids": (
                    ["network.configuration"] if relation["relation_id"] == "kr_net_001" else []
                ),
                "unavailable_measurements": [],
            }

        def reference_v3(_state: InvestigationState) -> tuple[dict[str, JsonValue], ...]:
            return (cast("dict[str, JsonValue]", payload),)

        monkeypatch.setattr(app, "reference_context", reference_v3)
        case = app.create(objective="Internet route mismatch", budget_ms=3000)
        app.run(str(case.case_id))
        attempted = {
            str(row[0])
            for row in store.connection.execute(
                "SELECT probe_id FROM probe_executions WHERE case_id=?", (str(case.case_id),)
            )
        }
        assert "network.configuration" in attempted


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
            proposals: tuple[ProbeProposal, ...],
            state: InvestigationState,
            remaining: int,
            *,
            batch_limit: int | None = None,
        ) -> tuple[ProbeProposal, ...]:
            if decision.requests:
                admitted_budgets.append(remaining)
            return original(proposals, state, remaining, batch_limit=batch_limit)

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


def test_successful_prior_batch_can_satisfy_a_new_probe_dependency(tmp_path: Path) -> None:
    class DependentDecision(KeywordBaselineDecisionProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            if request.attention_only or "core.system" not in request.completed_probe_ids:
                return DecisionResponse(
                    provider=self.identity,
                    case_id=request.case_id,
                    state_version=request.state_version,
                    correlation_id=request.correlation_id,
                    deadline_at=request.deadline_at,
                )
            target = next(
                item for item in request.available_probes if item.probe_id == "application.snapshot"
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        probe_id=target.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=target.cost_ms,
                        resource_class=target.resource_class,
                        dedupe_key="application.snapshot:after-core",
                        depends_on=("core.system",),
                    ),
                ),
            )

    definitions = tuple(
        replace(
            probe_definition(name),
            manifest=probe_definition(name).manifest.model_copy(update={"probe_id": probe_id}),
        )
        for name, probe_id in (
            ("core", "core.system"),
            ("application", "application.snapshot"),
        )
    )
    with SQLiteStore(tmp_path / "prior-dependency.db") as store:
        app = investigator(store, definitions=definitions, decision=DependentDecision())
        case = app.create(objective="An unfamiliar application issue", budget_ms=3000)
        result = app.run(str(case.case_id))
        executions = tuple(
            store.connection.execute(
                "SELECT probe_id, status FROM probe_executions WHERE case_id=? ORDER BY rowid",
                (str(case.case_id),),
            )
        )
        assert executions == (("core.system", "ok"), ("application.snapshot", "ok"))
        assert not any("Decision provider rejected" in warning for warning in result.warnings)


def test_failed_baseline_attempt_can_be_retried_once_with_remaining_budget(tmp_path: Path) -> None:
    attempts = 0

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary source failure")
        now = utc_now()
        return ProbeObservation(
            summary="Source recovered",
            facts={"available": True},
            observed_at=now,
            captured_at=now,
        )

    base = probe_definition("core")
    definition = replace(
        base,
        manifest=base.manifest.model_copy(update={"probe_id": "core.system"}),
        handler=collect,
    )
    with SQLiteStore(tmp_path / "bounded-retry.db") as store:
        app = investigator(store, definitions=(definition,))
        case = app.create(
            objective="An unfamiliar intermittent issue",
            budget_ms=3000,
            max_probes=2,
            max_rounds=2,
        )
        app.run(str(case.case_id))
        statuses = tuple(
            row[0]
            for row in store.connection.execute(
                "SELECT status FROM probe_executions WHERE case_id=? ORDER BY rowid",
                (str(case.case_id),),
            )
        )
        assert statuses == ("failed", "ok")
        assert attempts == 2


def test_interrupted_retry_is_not_replayed_after_execution_checkpoint_gap(
    tmp_path: Path,
) -> None:
    definition = probe_definition("core")
    probe_id = definition.manifest.probe_id
    with SQLiteStore(tmp_path / "retry-checkpoint-gap.db") as store:
        app = investigator(store, definitions=(definition,))
        case = app.create(objective="intermittent issue", budget_ms=3000, max_probes=3)
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(ExecutionId.new()),
                case_id=str(case.case_id),
                probe_id=probe_id,
                probe_version=definition.manifest.version,
                status="failed",
                parameters_json="{}",
                started_at=utc_now().isoformat(),
                finished_at=utc_now().isoformat(),
                state_version=case.state_version,
            )
        app.repository.save(
            case.model_copy(
                update={
                    "completed_probe_ids": (probe_id,),
                    "pending_probe_ids": (probe_id,),
                }
            ),
            expected_version=case.state_version,
            event="collecting",
            detail="Second attempt began, but its outcome was not checkpointed.",
        )
        result = app.run(str(case.case_id))
        attempts = tuple(
            store.connection.execute(
                "SELECT status FROM probe_executions WHERE case_id=? ORDER BY rowid",
                (str(case.case_id),),
            )
        )
        consumed = app._attempts_consumed(result)  # pyright: ignore[reportPrivateUsage]

    assert attempts == (("failed",),)
    assert probe_id in result.interrupted_probe_ids
    assert result.unrecorded_attempt_count == 1
    assert consumed == 2


def test_second_connection_cannot_take_over_live_running_collector(tmp_path: Path) -> None:
    database = tmp_path / "live-owner.db"
    entered = threading.Event()
    release = threading.Event()
    worker_errors: list[Exception] = []

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        entered.set()
        if not release.wait(timeout=5):
            raise RuntimeError("collector test barrier timed out")
        now = utc_now()
        return ProbeObservation(
            summary="Live collector completed",
            facts={"sample": True},
            observed_at=now,
            captured_at=now,
        )

    base = probe_definition("core")
    definition = replace(base, handler=collect)
    with SQLiteStore(database) as store:
        case = investigator(store, definitions=(definition,)).create(
            objective="live collection", budget_ms=5000, max_probes=1
        )

    def first_run() -> None:
        try:
            with SQLiteStore(database) as store:
                investigator(store, definitions=(definition,)).run(str(case.case_id))
        except Exception as error:
            worker_errors.append(error)

    worker = threading.Thread(target=first_run)
    worker.start()
    try:
        assert entered.wait(timeout=5)
        with SQLiteStore(database) as store:
            second = investigator(store, definitions=(definition,))
            with pytest.raises(RuntimeError, match="already running"):
                second.run(str(case.case_id))
            assert second.repository.load(str(case.case_id)).pending_probe_ids == (
                definition.manifest.probe_id,
            )
    finally:
        release.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert not worker_errors
    with SQLiteStore(database) as store:
        assert store.probe_execution_count(case_id=str(case.case_id)) == 1


class DistinguishingReasoner(DeterministicReasoningProvider):
    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        unused = tuple(
            probe
            for probe in request.available_probes
            if probe.probe_id not in request.completed_probe_ids
        )
        proposals = ()
        if unused:
            decision = KeywordBaselineDecisionProvider().decide(
                DecisionRequest(
                    case_id=request.case_id,
                    state_version=request.state_version,
                    correlation_id=request.correlation_id,
                    deadline_at=request.deadline_at,
                    symptom=request.objective,
                    available_probes=unused,
                    max_probes=1,
                    budget_ms=request.budget_ms,
                )
            )
            proposals = decision.proposals
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
            distinguishing_probes=proposals,
        )


def test_fast_escalation_redirects_before_next_probe_batch(tmp_path: Path) -> None:
    events: list[str] = []
    concerns_seen: list[str] = []

    def tracked(name: str, probe_id: str):
        def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            events.append(name)
            now = utc_now()
            return ProbeObservation(
                summary=f"Observed {name}",
                facts={"area": name},
                observed_at=now,
                captured_at=now,
            )

        original = probe_definition(name)
        return replace(
            original,
            manifest=original.manifest.model_copy(update={"probe_id": probe_id}),
            handler=collect,
        )

    class EscalatingDecision(KeywordBaselineDecisionProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            alpha = next(p for p in request.available_probes if p.probe_id == "application.alpha")
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        probe_id=alpha.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=alpha.cost_ms,
                        resource_class=alpha.resource_class,
                        dedupe_key="application.alpha:fast",
                    ),
                ),
                requires_reasoning=True,
                signals=(FastSignal(kind=FastSignalKind.NO_PROGRESS_SUSPECTED),),
            )

    class RedirectingReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            events.append("reason")
            concerns_seen.extend(item.kind.value for item in request.fast_concerns)
            beta = next(p for p in request.available_probes if p.probe_id == "application.beta")
            proposals = (
                (
                    ProbeProposal(
                        probe_id=beta.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=beta.cost_ms,
                        resource_class=beta.resource_class,
                        dedupe_key="application.beta:deep",
                    ),
                )
                if beta.probe_id not in request.completed_probe_ids
                else ()
            )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The competing explanations need another observation.",
                distinguishing_probes=proposals,
            )

    with SQLiteStore(tmp_path / "fast-escalation.db") as store:
        app = investigator(
            store,
            definitions=(
                tracked("core", "core.system"),
                tracked("alpha", "application.alpha"),
                tracked("beta", "application.beta"),
            ),
            decision=EscalatingDecision(),
            reasoning=RedirectingReasoner(),
        )
        case = app.create(objective="application issue", budget_ms=3000, max_rounds=1, max_probes=2)
        app.run(str(case.case_id))
        attempted = {
            str(row[0])
            for row in store.connection.execute(
                "SELECT probe_id FROM probe_executions WHERE case_id=?", (str(case.case_id),)
            )
        }
    assert attempted == {"core.system", "application.beta"}
    assert events.index("reason") < events.index("beta")
    assert "no_progress_suspected" in concerns_seen


def test_fast_escalation_without_new_facts_does_not_repeat_deep_call(tmp_path: Path) -> None:
    class EscalatingDecision(EmptyDecision):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return (
                super()
                .decide(request)
                .model_copy(
                    update={
                        "requires_reasoning": True,
                        "signals": (FastSignal(kind=FastSignalKind.NO_PROGRESS_SUSPECTED),),
                    }
                )
            )

    class CountingReasoner(DeterministicReasoningProvider):
        def __init__(self) -> None:
            self.calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Evidence remains insufficient.",
            )

    reasoner = CountingReasoner()
    with SQLiteStore(tmp_path / "one-escalation.db") as store:
        app = investigator(
            store,
            definitions=(probe_definition("core"), probe_definition("unrelated")),
            decision=EscalatingDecision(),
            reasoning=reasoner,
        )
        case = app.create(objective="unknown issue", budget_ms=3000, max_rounds=1)
        app.run(str(case.case_id))
    assert reasoner.calls == 1


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


@pytest.mark.parametrize("cancel_on_supersession", [False, True])
def test_full_deep_probe_batch_supersedes_fast_routing_but_keeps_attention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel_on_supersession: bool
) -> None:
    class FullBatchReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            unused = tuple(
                probe
                for probe in request.available_probes
                if probe.probe_id not in request.completed_probe_ids
            )[: request.max_probes]
            proposals = tuple(
                ProbeProposal(
                    probe_id=probe.probe_id,
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=1.0,
                    estimated_cost_ms=probe.cost_ms,
                    resource_class=probe.resource_class,
                    dedupe_key=f"deep:{probe.probe_id}",
                    safety_class=probe.safety_class,
                )
                for probe in unused
            )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Use the requested distinguishing tests.",
                distinguishing_probes=proposals,
            )

    decision = RecordingDecision()
    cancel_event = threading.Event()
    completed_at_supersession: tuple[str, ...] = ()
    with SQLiteStore(tmp_path / "full-deep-batch.db") as store:
        app = investigator(
            store,
            definitions=tuple(probe_definition(f"domain{i}") for i in range(8)),
            reasoning=FullBatchReasoner(),
        )
        app.decision = decision
        if cancel_on_supersession:
            original_save = app._save  # pyright: ignore[reportPrivateUsage]

            def cancel_after_supersession(
                state: InvestigationState, event: str, detail: str
            ) -> InvestigationState:
                nonlocal completed_at_supersession
                saved = original_save(state, event, detail)
                if event == "routing_superseded":
                    completed_at_supersession = saved.completed_probe_ids
                    cancel_event.set()
                return saved

            monkeypatch.setattr(app, "_save", cancel_after_supersession)
        case = app.create(objective="application cannot connect", budget_ms=5_000, max_rounds=2)
        result = app.run(str(case.case_id), cancel_event=cancel_event)
        steps = app.repository.steps(str(case.case_id))

    normal_routes = [request for request in decision.requests if not request.attention_only]
    assert len(normal_routes) == 1
    assert any(step.event == "routing_superseded" for step in steps)
    assert result.decision_provider == decision.identity.provider_id
    assert sum(call.role == "fast_decision" for call in result.provider_calls) == len(
        decision.requests
    )
    if cancel_on_supersession:
        assert result.outcome is InvestigationOutcome.CANCELLED
        assert result.completed_probe_ids == completed_at_supersession
        events = [step.event for step in steps]
        assert "collecting" not in events[events.index("routing_superseded") + 1 :]
    else:
        assert len([request for request in decision.requests if request.attention_only]) == 2


def test_fast_routing_runs_when_deep_requests_leave_spare_slots(tmp_path: Path) -> None:
    class PartialBatchReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            capability = next(
                probe
                for probe in request.available_probes
                if probe.probe_id not in request.completed_probe_ids
            )
            proposal = ProbeProposal(
                probe_id=capability.probe_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
                estimated_cost_ms=capability.cost_ms,
                resource_class=capability.resource_class,
                dedupe_key=f"partial:{capability.probe_id}",
                safety_class=capability.safety_class,
            )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="One test leaves routing capacity available.",
                distinguishing_probes=(proposal,),
            )

    decision = RecordingDecision()
    with SQLiteStore(tmp_path / "partial-deep-batch.db") as store:
        app = investigator(
            store,
            definitions=tuple(probe_definition(f"domain{i}") for i in range(8)),
            reasoning=PartialBatchReasoner(),
        )
        app.decision = decision
        case = app.create(objective="application cannot connect", budget_ms=5_000, max_rounds=2)
        app.run(str(case.case_id))

    assert len([request for request in decision.requests if not request.attention_only]) == 2


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


@pytest.mark.parametrize("request_kind", ["generic", "detail"])
def test_reasoning_discovers_and_loads_exact_record_omitted_from_initial_packet(
    tmp_path: Path,
    request_kind: str,
) -> None:
    decisive = EvidenceId(root="ev_ffffffffffffffffffffffffffffffff")
    detail_request = EvidenceDetailRequest(evidence_id=decisive, match_literals=("disk_io_error",))

    class CatalogReasoner(DeterministicReasoningProvider):
        requests: list[ReasoningRequest]

        def __init__(self) -> None:
            self.requests = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.requests.append(request)
            response = super().investigate(request)
            if str(decisive) not in {str(item.evidence_id) for item in request.evidence_context}:
                return response.model_copy(
                    update={
                        "requested_evidence_ids": (decisive,) if request_kind == "generic" else (),
                        "requested_details": (detail_request,) if request_kind == "detail" else (),
                    }
                )
            return response.model_copy(update={"considered_evidence_ids": (decisive,)})

    reasoner = CatalogReasoner()
    with SQLiteStore(tmp_path / "catalog-followup.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="investigate disk fault", budget_ms=5000)
        now = utc_now()
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=str(decisive),
            collector_id="disk.health",
            summary="Decisive disk fault",
            observed_at=now - timedelta(minutes=10),
            facts=(EvidenceFact(name="error_code", value="disk_io_error"),),
        )
        for index in range(60):
            _insert_record(
                store,
                case_id=str(state.case_id),
                evidence_id=f"ev_{index + 1:032x}",
                collector_id="disk.health",
                summary=f"Routine disk row {index}",
                observed_at=now - timedelta(seconds=index),
            )
        initial_context = app.context(str(state.case_id))
        assert str(decisive) not in {str(item.evidence_id) for item in initial_context}
        result, _ = app._reason_with_details(  # pyright: ignore[reportPrivateUsage]
            state, initial_context
        )

    assert len(reasoner.requests) == 2, (
        result.requested_evidence_ids,
        result.warnings,
    )
    assert str(decisive) in {
        str(item["evidence_id"]) for item in reasoner.requests[0].evidence_catalog
    }
    assert str(decisive) in {
        str(item.evidence_id) for item in reasoner.requests[1].evidence_context
    }
    if request_kind == "generic":
        assert decisive in result.completed_evidence_requests
    else:
        assert detail_request in result.completed_detail_requests


def test_reasoning_pages_catalog_before_requesting_older_evidence(tmp_path: Path) -> None:
    decisive = EvidenceId(root="ev_ffffffffffffffffffffffffffffffff")

    class PagingReasoner(DeterministicReasoningProvider):
        requests: list[ReasoningRequest]

        def __init__(self) -> None:
            self.requests = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.requests.append(request)
            response = super().investigate(request)
            catalog_ids = {str(item["evidence_id"]) for item in request.evidence_catalog}
            if str(decisive) not in catalog_ids:
                return response.model_copy(
                    update={"schema_version": 3, "request_next_catalog_page": True}
                )
            if str(decisive) not in {str(item.evidence_id) for item in request.evidence_context}:
                return response.model_copy(update={"requested_evidence_ids": (decisive,)})
            return response.model_copy(update={"considered_evidence_ids": (decisive,)})

    reasoner = PagingReasoner()
    with SQLiteStore(tmp_path / "catalog-pagination.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="investigate older disk fault", budget_ms=5000)
        now = utc_now()
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=str(decisive),
            collector_id="disk.health",
            summary="Older decisive disk fault",
            observed_at=now - timedelta(minutes=10),
            facts=(EvidenceFact(name="error_code", value="disk_io_error"),),
        )
        for index in range(70):
            _insert_record(
                store,
                case_id=str(state.case_id),
                evidence_id=f"ev_{index + 1:032x}",
                collector_id="disk.health",
                summary=f"Routine disk row {index}",
                observed_at=now - timedelta(seconds=index),
            )
        result, _ = app._reason_with_details(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id))
        )

    assert len(reasoner.requests) == 3
    assert reasoner.requests[0].catalog_has_more is True
    assert str(decisive) not in {
        str(item["evidence_id"]) for item in reasoner.requests[0].evidence_catalog
    }
    assert str(decisive) in {
        str(item["evidence_id"]) for item in reasoner.requests[1].evidence_catalog
    }
    assert decisive in result.completed_evidence_requests


def test_truncated_catalog_page_retries_without_skipping_hidden_entries(tmp_path: Path) -> None:
    class TruncatingReasoner(DeterministicReasoningProvider):
        calls = 0
        pages: list[tuple[str, ...]]

        def __init__(self) -> None:
            self.pages = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            self.pages.append(tuple(str(item["evidence_id"]) for item in request.evidence_catalog))
            response = super().investigate(request)
            return response.model_copy(
                update={
                    "schema_version": 3,
                    "catalog_page_truncated": self.calls == 1,
                    "request_next_catalog_page": self.calls == 2,
                }
            )

    reasoner = TruncatingReasoner()
    with SQLiteStore(tmp_path / "catalog-retry.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="inspect older records", budget_ms=5000)
        now = utc_now()
        for index in range(70):
            _insert_record(
                store,
                case_id=str(state.case_id),
                evidence_id=f"ev_{index + 1:032x}",
                collector_id="disk.health",
                summary=f"Record {index}",
                observed_at=now - timedelta(seconds=index),
            )
        context = app.context(str(state.case_id))
        first, _ = app._reason(state, context)  # pyright: ignore[reportPrivateUsage]
        assert first.evidence_catalog_cursor is None
        assert first.evidence_catalog_limit == 32
        assert first.evidence_catalog_followup_pending
        second, _ = app._reason(first, context)  # pyright: ignore[reportPrivateUsage]
        assert second.evidence_catalog_cursor is not None
        assert second.evidence_catalog_limit == 32
        assert second.evidence_catalog_followup_pending
        third, _ = app._reason(second, context)  # pyright: ignore[reportPrivateUsage]

    assert reasoner.calls == 3
    assert reasoner.pages[1] == reasoner.pages[0][:32]
    assert reasoner.pages[2] == reasoner.pages[0][32:64]
    assert not third.evidence_catalog_followup_pending


def test_degraded_catalog_followup_does_not_retry_identical_page(tmp_path: Path) -> None:
    class DegradedReasoner(DeterministicReasoningProvider):
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            return (
                super()
                .investigate(request)
                .model_copy(update={"schema_version": 3, "degraded": True})
            )

    reasoner = DegradedReasoner()
    with SQLiteStore(tmp_path / "catalog-degraded.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="inspect case observations", budget_ms=5000)
        state = state.model_copy(update={"evidence_catalog_followup_pending": True})
        result, _ = app._reason_with_details(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id))
        )

    assert reasoner.calls == 1
    assert result.evidence_catalog_cursor is None
    assert result.evidence_catalog_followup_pending
    assert any("degraded" in warning.lower() for warning in result.warnings)


def test_new_case_evidence_resets_catalog_cursor_before_next_page(tmp_path: Path) -> None:
    class PagingReasoner(DeterministicReasoningProvider):
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
                        "schema_version": 3,
                        "request_next_catalog_page": len(self.requests) == 1,
                    }
                )
            )

    reasoner = PagingReasoner()
    newest = EvidenceId(root="ev_ffffffffffffffffffffffffffffffff")
    with SQLiteStore(tmp_path / "catalog-new-row.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="inspect case observations", budget_ms=5000)
        now = utc_now()
        for index in range(70):
            _insert_record(
                store,
                case_id=str(state.case_id),
                evidence_id=f"ev_{index + 1:032x}",
                collector_id="disk.health",
                summary=f"Record {index}",
                observed_at=now - timedelta(seconds=index),
            )
        context = app.context(str(state.case_id))
        first, _ = app._reason(state, context)  # pyright: ignore[reportPrivateUsage]
        assert first.evidence_catalog_cursor is not None
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=str(newest),
            collector_id="disk.health",
            summary="New decisive record",
            observed_at=now + timedelta(seconds=1),
        )
        second, _ = app._reason(first, context)  # pyright: ignore[reportPrivateUsage]

    assert str(newest) in {
        str(item["evidence_id"]) for item in reasoner.requests[1].evidence_catalog
    }
    assert second.evidence_catalog_cursor is None


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
            time_quality="bounded_interval",
            facts={
                "collection_started_at": (now - timedelta(milliseconds=30)).isoformat(),
                "listener_table_started_at": (now - timedelta(milliseconds=20)).isoformat(),
                "listener_table_completed_at": (now - timedelta(milliseconds=10)).isoformat(),
                "collection_completed_at": now.isoformat(),
                "omitted_listener_count": 0,
                "listeners": [
                    {
                        "local_address": "127.0.0.1",
                        "local_port": 18765,
                        "protocol": "tcp",
                        "pid": 52,
                        "process_name": "python.exe",
                        "process_creation_time": (now - timedelta(minutes=2)).isoformat(),
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


def test_broad_bind_failure_persists_cited_owner_finding_without_causal_completion(
    tmp_path: Path,
) -> None:
    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = utc_now()
        return ProbeObservation(
            summary="Observed TCP listener ownership",
            observed_at=now,
            captured_at=now,
            time_quality="bounded_interval",
            facts={
                "collection_started_at": (now - timedelta(milliseconds=30)).isoformat(),
                "listener_table_started_at": (now - timedelta(milliseconds=20)).isoformat(),
                "listener_table_completed_at": (now - timedelta(milliseconds=10)).isoformat(),
                "collection_completed_at": now.isoformat(),
                "omitted_listener_count": 0,
                "collection_status": "available",
                "listeners": [
                    {
                        "local_address": "127.0.0.1",
                        "local_port": 18765,
                        "protocol": "tcp4",
                        "pid": 52,
                        "process_name": "python.exe",
                        "process_creation_time": (now - timedelta(minutes=2)).isoformat(),
                        "owner_status": "available",
                    }
                ],
            },
        )

    base = probe_definition("network")
    definition = replace(
        base,
        manifest=base.manifest.model_copy(update={"probe_id": "network.listeners"}),
        handler=collect,
    )
    with SQLiteStore(tmp_path / "broad-owner-finding.db") as store:
        app = investigator(store, definitions=(definition,))
        state = app.create(
            objective=(
                "Which process owns TCP listener 127.0.0.1:18765? "
                "The target application cannot bind because its address is in use."
            ),
            budget_ms=5000,
            max_probes=1,
        )
        result = app.run(str(state.case_id))
        persisted = app.repository.load(str(state.case_id))
    assert result.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
    assert result.assessment is not None
    assert result.assessment.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_FINDING
    assert result.assessment.root_cause_proven is False
    assert len(result.assessment.evidence_ids) == 1
    assert "python.exe" in result.assessment.explanation
    assert result.summary == "No reasoning provider is available; no diagnosis was produced."
    assert persisted.assessment == result.assessment


def test_truncated_target_selection_cannot_claim_unique_listener_owner(tmp_path: Path) -> None:
    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = utc_now()
        return ProbeObservation(
            summary="Seventeen owners for the target endpoint",
            observed_at=now,
            captured_at=now,
            facts={
                "omitted_listener_count": 0,
                "collection_status": "available",
                "listeners": [
                    {
                        "local_address": "127.0.0.1",
                        "local_port": 18765,
                        "protocol": "tcp4",
                        "pid": 52 if index < 16 else 53,
                        "process_name": "python.exe",
                        "process_creation_time": now.isoformat(),
                        "owner_status": "available",
                    }
                    for index in range(17)
                ],
            },
        )

    base = probe_definition("network")
    definition = replace(
        base,
        manifest=base.manifest.model_copy(update={"probe_id": "network.listeners"}),
        handler=collect,
    )
    objective = "The app cannot bind 127.0.0.1:18765 because its address is in use."
    with SQLiteStore(tmp_path / "truncated-owner-finding.db") as store:
        app = investigator(store, definitions=(definition,))
        state = app.create(objective=objective, budget_ms=5000, max_probes=1)
        result = app.run(str(state.case_id))
        selection = select_target_evidence(store, app.context(str(state.case_id)), objective)
    assert selection.truncated is True
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
    assert result.requested_details == ()
    assert result.hypotheses[0].supporting_evidence_ids == (
        reasoner.requests[1].evidence_context[0].evidence_id,
    )


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
    assert len(reasoner.requests) == 2
    assert any(
        "no new requested facts reached the focused packet" in item.casefold()
        for item in result.warnings
    )
    assert any("unsatisfied evidence/detail requests" in item for item in result.warnings)


def test_already_considered_detail_does_not_repeat_reasoning(tmp_path: Path) -> None:
    class DuplicateDetailReasoner(DeterministicReasoningProvider):
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            observed = request.evidence_context[0]
            detail = EvidenceDetailRequest(
                evidence_id=observed.evidence_id, match_literals=("present_row",)
            )
            return (
                super()
                .investigate(request)
                .model_copy(
                    update={
                        "considered_evidence_ids": (observed.evidence_id,),
                        "requested_details": (detail,),
                    }
                )
            )

    reasoner = DuplicateDetailReasoner()
    now = utc_now()
    context = (
        EvidenceContext(
            evidence_id=EvidenceId.new(),
            observed_at=now,
            captured_at=now,
            probe_id="application.snapshot",
            summary="Already visible row",
            status=EvidenceContextStatus.OBSERVED,
            facts={"rows.0": {"name": "present_row"}},
        ),
    )
    with SQLiteStore(tmp_path / "duplicate-detail.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="Inspect visible row", budget_ms=5000)
        result, _ = app._reason_with_details(state, context)  # pyright: ignore[reportPrivateUsage]

    assert reasoner.calls == 1
    assert len(result.requested_details) == 1
    assert result.completed_detail_requests == ()
    assert any(
        "no new requested facts reached the focused packet" in item.casefold()
        for item in result.warnings
    )
    assert any("unsatisfied evidence/detail requests" in item for item in result.warnings)


def test_detail_only_follow_up_preserves_earlier_measurement_request(tmp_path: Path) -> None:
    class PlanThenDetailsReasoner(DeterministicReasoningProvider):
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            response = super().investigate(request)
            if self.calls > 1:
                return response.model_copy(
                    update={"considered_evidence_ids": (request.evidence_context[-1].evidence_id,)}
                )
            target = next(
                item for item in request.available_probes if item.probe_id == "network.snapshot"
            )
            return response.model_copy(
                update={
                    "considered_evidence_ids": (request.evidence_context[0].evidence_id,),
                    "requested_evidence_ids": (request.evidence_context[-1].evidence_id,),
                    "distinguishing_probes": (
                        ProbeProposal(
                            probe_id=target.probe_id,
                            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                            priority=1.0,
                            estimated_cost_ms=target.cost_ms,
                            resource_class=target.resource_class,
                            dedupe_key="network.snapshot:distinguish",
                        ),
                    ),
                }
            )

    now = utc_now()
    context = tuple(
        EvidenceContext(
            evidence_id=EvidenceId.new(),
            observed_at=now,
            captured_at=now,
            probe_id=f"application.part{index}",
            summary=f"Distinct observation {index}",
            status=EvidenceContextStatus.OBSERVED,
            facts={"value": index},
        )
        for index in range(2)
    )
    reasoner = PlanThenDetailsReasoner()
    with SQLiteStore(tmp_path / "detail-follow-up-plan.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="Compare two possible causes", budget_ms=5000)
        result, proposals = app._reason_with_details(state, context)  # pyright: ignore[reportPrivateUsage]

    assert reasoner.calls == 2
    assert tuple(item.probe_id for item in proposals) == ("network.snapshot",)
    assert tuple(item.probe_id for item in result.pending_distinguishing_probes) == (
        "network.snapshot",
    )


def test_reasoner_must_explicitly_cancel_a_pending_probe(tmp_path: Path) -> None:
    class CancellingReasoner(DeterministicReasoningProvider):
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            response = super().investigate(request)
            if self.calls == 1:
                probe = next(
                    item for item in request.available_probes if item.probe_id == "network.snapshot"
                )
                return response.model_copy(
                    update={
                        "distinguishing_probes": (
                            ProbeProposal(
                                probe_id=probe.probe_id,
                                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                                priority=1.0,
                                estimated_cost_ms=probe.cost_ms,
                                resource_class=probe.resource_class,
                                dedupe_key="network.snapshot:pending",
                            ),
                        )
                    }
                )
            return ReasoningResponse.model_validate(
                {
                    **response.model_dump(mode="json"),
                    "schema_version": 2,
                    "cancelled_probe_ids": ("network.snapshot",),
                }
            )

    with SQLiteStore(tmp_path / "explicit-cancel.db") as store:
        app = investigator(store, reasoning=CancellingReasoner())
        state = app.create(objective="Compare causes", budget_ms=5000)
        state, _ = app._reason(state, ())  # pyright: ignore[reportPrivateUsage]
        assert tuple(item.probe_id for item in state.pending_distinguishing_probes) == (
            "network.snapshot",
        )
        state, _ = app._reason(state, ())  # pyright: ignore[reportPrivateUsage]

    assert state.pending_distinguishing_probes == ()


def test_already_assessed_generic_request_does_not_repeat_reasoning(tmp_path: Path) -> None:
    class RepeatingEvidenceReasoner(DeterministicReasoningProvider):
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            response = super().investigate(request)
            return response.model_copy(
                update={
                    "considered_evidence_ids": (),
                    "requested_evidence_ids": (request.evidence_context[0].evidence_id,),
                }
            )

    reasoner = RepeatingEvidenceReasoner()
    now = utc_now()
    context = (
        EvidenceContext(
            evidence_id=EvidenceId.new(),
            observed_at=now,
            captured_at=now,
            probe_id="application.snapshot",
            summary="Already visible observation",
            status=EvidenceContextStatus.OBSERVED,
            facts={"state": "available"},
        ),
    )
    with SQLiteStore(tmp_path / "duplicate-evidence.db") as store:
        app = investigator(store, reasoning=reasoner)
        state = app.create(objective="Inspect visible observation", budget_ms=5000)
        result, _ = app._reason_with_details(state, context)  # pyright: ignore[reportPrivateUsage]

    assert reasoner.calls == 1
    assert result.requested_evidence_ids == (context[0].evidence_id,)
    assert result.completed_evidence_requests == ()
    assert any(
        "no new requested facts reached the focused packet" in item.casefold()
        for item in result.warnings
    )
    assert any("unsatisfied evidence/detail requests" in item for item in result.warnings)


def test_equal_detail_value_at_new_source_path_is_progress(tmp_path: Path) -> None:
    now = utc_now()
    evidence_id = EvidenceId.new()
    context = (
        EvidenceContext(
            evidence_id=evidence_id,
            observed_at=now,
            captured_at=now,
            probe_id="application.snapshot",
            summary="Two separate equal rows",
            status=EvidenceContextStatus.OBSERVED,
            facts={"rows.0": {"name": "same"}, "rows.1": {"name": "same"}},
        ),
    )
    prior = context[0].model_copy(update={"facts": {"rows.0": {"name": "same"}}})
    detail = EvidenceDetailRequest(evidence_id=evidence_id, match_literals=("same",))
    with SQLiteStore(tmp_path / "equal-rows.db") as store:
        app = investigator(store)
        state = app.create(objective="Inspect second row", budget_ms=5000).model_copy(
            update={"assessed_context": (prior,), "requested_details": (detail,)}
        )
        packet = app._new_requested_fact_packet(state, context)  # pyright: ignore[reportPrivateUsage]

    assert packet is not None


def test_detail_excluded_by_full_assessed_packet_is_not_progress(tmp_path: Path) -> None:
    now = utc_now()
    evidence_id = EvidenceId.new()
    prior_facts = {f"fact.{index}": "x" for index in range(32)}
    context = (
        EvidenceContext(
            evidence_id=evidence_id,
            observed_at=now,
            captured_at=now,
            probe_id="application.snapshot",
            summary="Bounded observation",
            status=EvidenceContextStatus.OBSERVED,
            facts={"rows.0": {"name": "new_row"}},
        ),
    )
    prior = context[0].model_copy(update={"facts": prior_facts})
    detail = EvidenceDetailRequest(evidence_id=evidence_id, match_literals=("new_row",))
    hypothesis = Hypothesis(
        hypothesis_id="h_prior",
        statement="Prior cited facts must remain visible.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(evidence_id,),
    )
    with SQLiteStore(tmp_path / "full-packet.db") as store:
        app = investigator(store)
        state = app.create(objective="Inspect bounded row", budget_ms=5000).model_copy(
            update={
                "assessed_context": (prior,),
                "hypotheses": (hypothesis,),
                "requested_details": (detail,),
            }
        )
        packet = app._new_requested_fact_packet(state, context)  # pyright: ignore[reportPrivateUsage]

    assert packet is None


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
