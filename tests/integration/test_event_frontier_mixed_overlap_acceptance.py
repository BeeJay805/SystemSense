"""One ordinary run must keep mixed attention active across slow work."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path

import pytest

from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.evidence import EvidenceFact, EvidenceRecord
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import utc_now
from systemsense.evidence.projection import ExplicitRelationProjector
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
from tests.unit.evidence.test_retrieval import _insert_record  # pyright: ignore[reportPrivateUsage]


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
        self,
        events: list[str],
        slow_finished: threading.Event,
        deep: SlowReasoner,
        *,
        first_kind: str = "measure",
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
        self.first_kind = first_kind
        self.requests: list[FrontierRankRequestV1] = []

    def rank(self, request: FrontierRankRequestV1, **_kwargs: object) -> FrontierRankResponseV1:
        self.requests.append(request)
        kinds = {item.reference.kind for item in request.items}
        if (
            self.first_kind == "review_branch"
            and "review_branch" in kinds
            and not any(item.startswith("rank_review_branch") for item in self.events)
        ):
            preferred = "review_branch"
        elif "measure" in kinds and not any(
            item.startswith("rank_measure") for item in self.events
        ):
            preferred = "measure"
        elif "consult_deep" in kinds and not any(
            item.startswith("rank_consult_deep") for item in self.events
        ):
            preferred = "consult_deep"
        else:
            preferred = "retrieve_evidence" if "retrieve_evidence" in kinds else next(iter(kinds))
        selected = next(item for item in request.items if item.reference.kind == preferred)
        suffix = (
            "_during_deep" if self.deep.started.is_set() and not self.deep.finished.is_set() else ""
        )
        self.events.append(f"rank_{preferred}{suffix}")
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


@pytest.mark.parametrize("first_kind", ["measure", "review_branch"])
def test_ordinary_run_redirects_while_baseline_and_deep_are_in_flight(
    tmp_path: Path, first_kind: str
) -> None:
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
        ranker = ChoosingRanker(events, slow_finished, deep, first_kind=first_kind)
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
        service_facts = (
            EvidenceFact(
                name="processes",
                value=[{"pid": 42, "creation_time": "2026-09-24T12:00:00+00:00"}],
            ),
            EvidenceFact(name="services", value=[{"name": "AudioSrv", "process_id": 42}]),
        )
        source_relations = EvidenceRelationRepository(store)
        for number, age in ((81, 1), (82, 120)):
            evidence_id = f"ev_{number:032x}"
            _insert_record(
                store,
                case_id=str(case.case_id),
                evidence_id=evidence_id,
                collector_id="services.snapshot",
                summary="Observed exact service process identity",
                observed_at=utc_now() - timedelta(seconds=age),
                facts=service_facts,
            )
            row = store.evidence(case_id=str(case.case_id), evidence_id=evidence_id)
            assert row is not None
            record = EvidenceRecord.model_validate_json(row.record_json)
            if number == 81:
                with store.transaction() as transaction:
                    transaction.record_probe_execution(
                        execution_id=str(record.collector.execution_id),
                        case_id=str(case.case_id),
                        probe_id="services.snapshot",
                        probe_version=1,
                        status="ok",
                        parameters_json="{}",
                        started_at=(record.observed_at - timedelta(milliseconds=1)).isoformat(),
                        finished_at=record.captured_at.isoformat(),
                        state_version=case.state_version,
                    )
                    store.connection.execute(
                        "UPDATE evidence SET execution_id=?,time_basis='collector_observed',"
                        "time_quality='exact' WHERE evidence_id=?",
                        (str(record.collector.execution_id), evidence_id),
                    )
            for relation in ExplicitRelationProjector().project(record).relations:
                source_relations.append(relation)
        try:
            completed = app.run(str(case.case_id))
        finally:
            deep.finished.set()
            deep.done.wait(2)

        assert "rank_measure" in events, events
        assert events.index("core.resources_finished") < events.index("rank_measure")
        if first_kind == "review_branch":
            assert events.index("rank_review_branch") < events.index("rank_measure")
        assert events.index("rank_measure") < events.index("pressure.sample_started")
        assert events.index("pressure.sample_started") < events.index("core.system_finished")
        assert "rank_retrieve_evidence_during_deep" in events
        assert any(
            {"retrieve_evidence", "review_branch", "measure", "consult_deep"}
            <= {item.reference.kind for item in request.items}
            and any(packet.evidence_id == f"ev_{81:032x}" for packet in request.evidence_packets)
            and all(packet.evidence_id != f"ev_{82:032x}" for packet in request.evidence_packets)
            for request in ranker.requests
        )
        assert any(len(item.evidence_ids) == 2 for item in source_relations.relations(limit=128))
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
