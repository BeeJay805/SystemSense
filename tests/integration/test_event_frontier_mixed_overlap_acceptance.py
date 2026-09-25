"""One ordinary run must keep mixed attention active across slow work."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.ids import EntityId, EvidenceId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.retrieval import EvidenceRelationRepository
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import default_probe_definitions
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_catalog_attention_loop import (
    _fill_case,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator


class SlowReasoner(DeterministicReasoningProvider):
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.started = threading.Event()
        self.finished = threading.Event()
        self.done = threading.Event()

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        self.events.append("deep_started")
        self.started.set()
        self.finished.wait(1.5)
        self.events.append("deep_finished")
        self.done.set()
        return super().investigate(request)


class ChoosingRanker(MixedFrontierRanker):
    def __init__(
        self, events: list[str], slow_finished: threading.Event, deep: SlowReasoner
    ) -> None:
        super().__init__(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-mixed-overlap", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        self.events = events
        self.slow_finished = slow_finished
        self.deep = deep
        self.requests: list[FrontierRankRequestV1] = []

    def rank(self, request: FrontierRankRequestV1) -> FrontierRankResponseV1:
        self.requests.append(request)
        if len(self.requests) == 1:
            assert not self.slow_finished.is_set(), "first decision waited for unrelated baseline"
        kinds = {item.reference.kind for item in request.items}
        if len(self.requests) == 1:
            assert {"retrieve_evidence", "review_branch", "measure", "consult_deep"} <= kinds
            preferred = "measure"
        elif len(self.requests) == 2:
            assert not self.slow_finished.is_set(), "second decision waited for unrelated baseline"
            assert {"retrieve_evidence", "consult_deep"} <= kinds
            preferred = "consult_deep"
        else:
            assert self.deep.started.is_set() and not self.deep.finished.is_set(), (
                "fast attention waited for deep reasoning"
            )
            assert "retrieve_evidence" in kinds
            preferred = "retrieve_evidence"
        selected = next(item for item in request.items if item.reference.kind == preferred)
        self.events.append(f"rank_{preferred}")
        offered = tuple(item.item_id for item in request.items)
        return (
            MixedFrontierRanker.rank(self, request)
            .model_copy(
                update={
                    "ranked_item_ids": (
                        selected.item_id,
                        *(item for item in offered if item != selected.item_id),
                    ),
                    "considered_item_ids": offered,
                    "ranking_source": "laya",
                    "model_abstained": False,
                    "coverage_complete": True,
                    "degraded_reason": None,
                }
            )
            .validate_against(request)
        )


def test_ordinary_run_redirects_while_baseline_and_deep_are_in_flight(tmp_path: Path) -> None:
    events: list[str] = []
    slow_finished = threading.Event()
    deep = SlowReasoner(events)

    def collect(name: str, *, slow: bool = False) -> ProbeObservation:
        events.append(f"{name}_started")
        if slow:
            threading.Event().wait(1.5)
            slow_finished.set()
        observed = datetime.now(UTC)
        events.append(f"{name}_finished")
        return ProbeObservation(
            summary=f"{name} observed",
            facts={"measurement": name, "pressure_percent": 97},
            observed_at=observed,
            captured_at=observed,
        )

    def handler(_parameters: dict[str, JsonValue], name: str) -> ProbeObservation:
        return collect(name, slow=name == "core.system")

    definitions: list[ProbeDefinition] = []
    for original in default_probe_definitions():
        probe_id = original.manifest.probe_id
        if probe_id in {"core.system", "core.resources", "pressure.sample"}:
            definitions.append(
                replace(
                    original,
                    isolated=False,
                    handler=partial(handler, name=probe_id),
                )
            )
        else:
            definitions.append(original)

    with SQLiteStore(tmp_path / "dual-overlap.db") as store:
        baseline = investigator(store)
        ranker = ChoosingRanker(events, slow_finished, deep)
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, DeterministicPlanner(candidates=())),
            probe_runner=ProbeRunner(definitions=tuple(definitions)),
        )
        app = Investigator(
            store=store,
            runtime=runtime,
            capabilities=tuple(
                ProbeCapability(
                    probe_id=definition.manifest.probe_id,
                    description=definition.manifest.question,
                    common=True,
                    cost_ms=1,
                    resource_class=ResourceClass.CPU,
                )
                for definition in definitions
                if definition.manifest.probe_id in {"core.system", "core.resources"}
            ),
            decision=baseline.decision,
            reasoning=deep,
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=ranker,
        )
        case = app.create(
            objective="Investigate intermittent slow resource pressure", budget_ms=20_000
        )
        _fill_case(store, str(case.case_id), count=80, target_index=70)
        EvidenceRelationRepository(store).append(
            EvidenceRelation(
                relation_id=f"rel_{1:032x}",
                source_entity_id=EntityId(root=f"entity_{1:032x}"),
                target_entity_id=EntityId(root=f"entity_{2:032x}"),
                relationship=RelationKind.DEPENDS_ON,
                memory_layer=MemoryLayer.MACHINE,
                assertion_status=AssertionStatus.OBSERVED,
                relation_version=1,
                evidence_ids=(EvidenceId(root=f"ev_{1:032x}"),),
            )
        )
        try:
            completed = app.run(str(case.case_id))
        finally:
            deep.finished.set()
            deep.done.wait(2)

        assert events.index("core.resources_finished") < events.index("rank_measure")
        assert events.index("rank_measure") < events.index("pressure.sample_started")
        assert events.index("pressure.sample_started") < events.index("core.system_finished")
        assert events.index("deep_started") < events.index("rank_retrieve_evidence")
        assert events.index("rank_retrieve_evidence") < events.index("deep_finished")
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions "
            "WHERE case_id=? AND probe_id='pressure.sample' AND status='ok'",
            (str(case.case_id),),
        ).fetchone() == (1,)
        assert completed.fast_catalog_selected_ids
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_transitions AS t "
                "JOIN search_frontier_items AS i ON i.item_id=t.item_id "
                "WHERE i.case_id=? AND t.to_status='satisfied'",
                (str(case.case_id),),
            ).fetchone()[0]
            >= 2
        )
