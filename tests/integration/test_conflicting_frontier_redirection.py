"""Later contradictory evidence must redirect the real mixed-frontier coordinator.

The fast ranking here is a deterministic fake oracle. This proves that the
coordinator can act on the changed menu; it does not grade untrained Laya.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import cast

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
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.time import utc_now
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import default_probe_definitions
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator
from tests.unit.application import test_general_candidate_catalog as catalog_fixtures
from tests.unit.application.test_general_candidate_catalog import (
    _gpu_source,  # pyright: ignore[reportPrivateUsage]
)


class ContradictionOracleRanker(MixedFrontierRanker):
    def __init__(self) -> None:
        super().__init__(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-contradiction-oracle", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        self.escalated = False
        self.trace: list[tuple[FrontierRankRequestV1, FrontierRankResponseV1]] = []

    def rank(self, request: FrontierRankRequestV1, **_kwargs: object) -> FrontierRankResponseV1:
        if len(request.items) == 1:
            # A singleton is procedural; this oracle does not claim to have
            # learned a choice where there was no comparison to make.
            response = super().rank(request)
            self.trace.append((request, response))
            return response
        exact_pressure = {
            (packet.get("probe_id"), packet.get("value"))
            for ref in request.evidence_packets
            if (packet := json.loads(ref.description)).get("metric") == "pressure_percent"
            and packet.get("value_quality") == "exact"
        }
        offered = tuple(item.item_id for item in request.items)
        by_probe = {
            semantic.measurement.probe_id: item
            for item, semantic in zip(request.items, request.item_semantics, strict=True)
            if semantic.measurement is not None
        }
        deep_item = next(
            (item for item in request.items if item.reference.kind == "consult_deep"), None
        )
        if ("pressure.sample", 3) in exact_pressure and "gpu.telemetry.sample" in by_probe:
            # Independent test rule: low live pressure contradicts the high
            # baseline, so a GPU throttle reading is the distinguishing test.
            selected = by_probe["gpu.telemetry.sample"]
        elif "pressure.sample" in by_probe:
            selected = by_probe["pressure.sample"]
        elif not self.escalated and deep_item is not None:
            selected = deep_item
            self.escalated = True
        else:
            selected = next(
                (item for item in request.items if item.reference.kind == "retrieve_evidence"),
                request.items[0],
            )
        response = (
            super()
            .rank(request)
            .model_copy(
                update={
                    "ranked_item_ids": (
                        selected.item_id,
                        *(item_id for item_id in offered if item_id != selected.item_id),
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
        self.trace.append((request, response))
        return response


def _high_pressure_source(store: SQLiteStore, case_id: CaseId, epoch: int) -> EvidenceId:
    """A source-bound, observed CPU baseline available before follow-up ranking."""
    evidence_id, execution_id = EvidenceId.new(), ExecutionId.new()
    observed = utc_now() - timedelta(milliseconds=300)
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "core.resources", "probe_version": 1}
    )
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed,
        captured_at=observed,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "core.resources"},
        ),
        collector=CollectorReference(id="core.resources", version=1, execution_id=execution_id),
        summary="Initial CPU pressure is high",
        facts=(EvidenceFact(name="pressure_percent", value=97),),
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="core.resources",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(observed - timedelta(milliseconds=100)).isoformat(),
            finished_at=observed.isoformat(),
            state_version=epoch,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=observed.isoformat(),
            captured_at=observed.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_observed",
            time_quality="exact",
        )
    return evidence_id


def test_conflicting_pressure_redirects_to_independently_justified_gpu_sample(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gpu_started = threading.Event()
    ranker = ContradictionOracleRanker()
    probe_events: list[str] = []
    gpu_started_at: list[float] = []
    deep_finished_at: list[float] = []

    class SlowReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            if not deep_finished_at:
                time.sleep(2)
                deep_finished_at.append(time.monotonic())
            return super().investigate(request)

    def observed(_parameters: dict[str, JsonValue], name: str) -> ProbeObservation:
        probe_events.append(f"{name}_started")
        if name == "gpu.telemetry.sample":
            gpu_started_at.append(time.monotonic())
            gpu_started.set()
        facts = cast(
            dict[str, JsonValue],
            {
                "core.system": {"os": "Windows"},
                "core.resources": {"pressure_percent": 97},
                "pressure.sample": {"pressure_percent": 3},
                "gpu.telemetry.sample": {
                    "temperature_c": 92,
                    "clock_mhz": 300,
                    "throttle_state": "thermal",
                },
            }[name],
        )
        now = datetime.now(UTC)
        probe_events.append(f"{name}_finished")
        return ProbeObservation(
            summary=f"{name} observed", facts=facts, observed_at=now, captured_at=now
        )

    definitions: list[ProbeDefinition] = []
    registered = {"core.system", "core.resources", "pressure.sample", "gpu.telemetry.sample"}
    for original in default_probe_definitions():
        name = original.manifest.probe_id
        definitions.append(
            replace(original, isolated=False, handler=partial(observed, name=name))
            if name in registered
            else original
        )

    with SQLiteStore(tmp_path / "contradiction.db") as store:
        base = investigator(store)
        app = Investigator(
            store=store,
            runtime=DiagnosticRuntime(
                store=store,
                case_service=CaseService(store, DeterministicPlanner(candidates=())),
                probe_runner=ProbeRunner(definitions=tuple(definitions)),
            ),
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
            decision=base.decision,
            reasoning=SlowReasoner(),
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=ranker,
        )
        case = app.create(objective="Game runs slowly despite a capable GPU", budget_ms=60_000)
        monkeypatch.setattr(catalog_fixtures, "NOW", utc_now())
        _gpu_source(store, case.case_id, age_seconds=0.5, epoch=case.state_version)
        high_source_id = _high_pressure_source(store, case.case_id, case.state_version)

        gpu_launched = False
        try:
            final = app.run(str(case.case_id))
            gpu_launched = gpu_started.is_set()
        finally:
            gpu_started.set()

        choice_trace = [
            (
                tuple(item.reference.kind for item in request.items),
                next(
                    item.reference.kind
                    for item in request.items
                    if item.item_id == response.ranked_item_ids[0]
                ),
                tuple(
                    (packet.get("probe_id"), packet.get("metric"), packet.get("value"))
                    for ref in request.evidence_packets
                    if (packet := json.loads(ref.description)).get("metric") == "pressure_percent"
                ),
            )
            for request, response in ranker.trace
        ]
        assert gpu_launched, (
            f"GPU distinguishing measurement was never launched: {choice_trace}; "
            f"probe_events={probe_events}; status={final.status} "
            f"stop={final.stop_reason} warnings={final.warnings}"
        )
        assert deep_finished_at and gpu_started_at[0] < deep_finished_at[0], (
            "the pending mixed measurement waited for unrelated deep reasoning"
        )

        measurements = store.connection.execute(
            "SELECT c.probe_id,a.snapshot_id,a.candidate_id "
            "FROM candidate_dispatch_admissions AS a "
            "JOIN case_measurement_candidates AS c ON c.candidate_id=a.candidate_id "
            "WHERE a.case_id=? ORDER BY a.admitted_at",
            (str(case.case_id),),
        ).fetchall()
        assert [str(row[0]) for row in measurements[:2]] == [
            "pressure.sample",
            "gpu.telemetry.sample",
        ]
        for probe_id, snapshot_id, candidate_id in measurements[:2]:
            snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(
                str(snapshot_id)
            )
            selected = next(
                item
                for item in snapshot.request.items
                if item.item_id == snapshot.response.ranked_item_ids[0]
            )
            assert selected.reference.candidate_id == candidate_id
            assert any(
                item.reference.kind == "measure" and item.reference.candidate_id == candidate_id
                for item in snapshot.request.items
            )
            assert store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions "
                "WHERE case_id=? AND probe_id=? AND status='ok'",
                (str(case.case_id), str(probe_id)),
            ).fetchone() == (1,)

        pressure_request = next(
            request
            for request, response in ranker.trace
            if any(
                item.reference.kind == "measure"
                and item.reference.candidate_id == measurements[0][2]
                and item.item_id == response.ranked_item_ids[0]
                for item in request.items
            )
        )
        gpu_request = next(
            request
            for request, response in ranker.trace
            if any(
                item.reference.kind == "measure"
                and item.reference.candidate_id == measurements[1][2]
                and item.item_id == response.ranked_item_ids[0]
                for item in request.items
            )
        )
        assert {
            semantic.measurement.probe_id
            for semantic in pressure_request.item_semantics
            if semantic.measurement is not None
        } == {"pressure.sample", "gpu.telemetry.sample"}
        # The later parent-bound menu has only the surviving GPU test. This
        # proves that the coordinator revisited contradictory evidence and
        # preserved a viable branch, not that Laya learned to prefer GPU over
        # several alternatives at that turn.
        assert len(gpu_request.items) == 1
        gpu_response = next(
            response for request, response in ranker.trace if request is gpu_request
        )
        assert gpu_response.ranking_source == "deterministic_fallback"
        assert any(
            json.loads(ref.description).get("probe_id") == "core.resources"
            and json.loads(ref.description).get("value") == 97
            for ref in pressure_request.evidence_packets
        )
        assert any(
            json.loads(ref.description).get("probe_id") == "pressure.sample"
            and json.loads(ref.description).get("value") == 3
            for ref in gpu_request.evidence_packets
        )
        assert all(
            item.reference.candidate_id != measurements[0][2]
            for item in gpu_request.items
            if item.reference.kind == "measure"
        ), "the contradicted exact measurement was offered again"
        high_source_row = store.evidence(case_id=str(case.case_id), evidence_id=str(high_source_id))
        assert high_source_row is not None
        high_source = EvidenceRecord.model_validate_json(high_source_row.record_json)
        pressure_observations = [
            EvidenceRecord.model_validate_json(str(row[0]))
            for row in store.connection.execute(
                "SELECT record_json FROM evidence WHERE case_id=? AND execution_id IN ("
                "SELECT execution_id FROM probe_executions WHERE case_id=? "
                "AND probe_id='pressure.sample')",
                (str(case.case_id), str(case.case_id)),
            )
        ]
        assert len(pressure_observations) == 1
        assert {fact.name: fact.value for fact in high_source.facts}["pressure_percent"] == 97
        assert {fact.name: fact.value for fact in pressure_observations[0].facts}[
            "pressure_percent"
        ] == 3
        assert high_source.observed_at < pressure_observations[0].observed_at
        gpu_observations = [
            EvidenceRecord.model_validate_json(str(row[0]))
            for row in store.connection.execute(
                "SELECT record_json FROM evidence WHERE case_id=? AND execution_id IN ("
                "SELECT execution_id FROM probe_executions WHERE case_id=? "
                "AND probe_id='gpu.telemetry.sample')",
                (str(case.case_id), str(case.case_id)),
            )
        ]
        assert len(gpu_observations) == 1
        assert {fact.name: fact.value for fact in gpu_observations[0].facts} == {
            "temperature_c": 92,
            "clock_mhz": 300,
            "throttle_state": "thermal",
        }
