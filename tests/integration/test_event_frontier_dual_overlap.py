"""Same-case probe coverage must not masquerade as unchanged event attention."""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from systemsense.application.investigation_state import InvestigationState
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    EvidenceContext,
    ProbeProposal,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.evidence import EvidenceFact
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import utc_now
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.probes import ProbeObservation
from systemsense.reasoning.contracts import (
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.search_frontier import FrontierStatus, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition
from tests.unit.evidence.test_retrieval import _insert_record  # pyright: ignore[reportPrivateUsage]


def test_run_records_stale_event_gap_when_failed_probe_overlaps_deep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "dual-overlap.db"
    deep_started = threading.Event()
    deep_release = threading.Event()
    stale_gap_during_deep = threading.Event()
    probe_during_deep = threading.Event()

    class DelayedDeep:
        identity = ProviderIdentity(
            provider_id="fixture-delayed-deep", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            deep_started.set()
            try:
                if probe_during_deep.wait(4):
                    with SQLiteStore(database) as reader:
                        deadline = time.monotonic() + 4
                        while time.monotonic() < deadline:
                            row = reader.connection.execute(
                                "SELECT 1 FROM search_frontier_investigator_turn_outcomes "
                                "WHERE case_id=? AND json_extract(record_json,'$.reason_code')="
                                "'stale_context' LIMIT 1",
                                (str(request.case_id),),
                            ).fetchone()
                            if row is not None:
                                stale_gap_during_deep.set()
                                break
                            time.sleep(0.01)
                return ReasoningResponse(
                    provider=self.identity,
                    case_id=request.case_id,
                    state_version=request.state_version,
                    correlation_id=request.correlation_id,
                    deadline_at=request.deadline_at,
                    status=ReasoningStatus.UNRESOLVED,
                    summary="The synthetic observations do not establish a cause.",
                )
            finally:
                deep_release.set()

    class SerialDecision:
        identity = ProviderIdentity(
            provider_id="fixture-serial-fast", provider_version="1", role="fast_decision"
        )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            next_probe = next(
                (
                    f"fault{index}.snapshot"
                    for index in range(4)
                    if f"fault{index}.snapshot" not in request.completed_probe_ids
                ),
                None,
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        probe_id=next_probe,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1,
                        estimated_cost_ms=1,
                        resource_class=ResourceClass.CPU,
                        dedupe_key=next_probe,
                    ),
                )
                if next_probe is not None
                else (),
            )

    class RetrievalRanker(MixedFrontierRanker):
        def __init__(self) -> None:
            super().__init__(
                ranker=None,
                provider=ProviderIdentity(
                    provider_id="fixture-event-attention",
                    provider_version="1",
                    role="fast_decision",
                ),
                model_weight_sha256="a" * 64,
            )
            self.ranked_while_deep: list[str] = []

        def rank(self, request: FrontierRankRequestV1) -> FrontierRankResponseV1:
            selected = next(
                item for item in request.items if item.reference.kind == "retrieve_evidence"
            )
            if deep_started.is_set() and not deep_release.is_set():
                self.ranked_while_deep.append(selected.item_id)
            fallback = super().rank(request)
            offered = tuple(item.item_id for item in request.items)
            return fallback.model_copy(
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
            ).validate_against(request)

    def fail_read_only_probe(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if deep_started.is_set() and not deep_release.is_set():
            probe_during_deep.set()
        raise RuntimeError("synthetic read-only probe failure")

    core = probe_definition("core")
    core = replace(
        core,
        manifest=core.manifest.model_copy(
            update={"probe_id": "core.system", "implementation_id": "builtin.core.system"}
        ),
    )
    failed = tuple(
        replace(probe_definition(f"fault{index}"), handler=fail_read_only_probe)
        for index in range(4)
    )
    with SQLiteStore(database) as store:
        app = investigator(
            store,
            definitions=(core, *failed),
            decision=SerialDecision(),
            reasoning=DelayedDeep(),
        )
        ranker = RetrievalRanker()
        app.frontier_ranker = ranker
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        case = app.create(
            objective="Investigate an unfamiliar desktop issue",
            budget_ms=12_000,
            max_rounds=4,
            max_probes=5,
        )
        now = utc_now()
        for index in range(3):
            _insert_record(
                store,
                case_id=str(case.case_id),
                evidence_id=f"ev_{index + 1:032x}",
                collector_id="fixture.stored",
                summary=f"Stored fact {index + 1}",
                observed_at=now - timedelta(seconds=index + 1),
                facts=(EvidenceFact(name="stored_marker", value=index + 1),),
            )
        original_context = app.context

        def focused_context(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused_context)
        try:
            result = app.run(str(case.case_id))
        finally:
            deep_release.set()
        assert deep_started.is_set(), "ordinary run never submitted deep reasoning"
        assert probe_during_deep.is_set(), "read-only probe did not overlap deep reasoning"
        assert stale_gap_during_deep.is_set(), "stale gap did not persist while deep was in flight"
        frontier = SearchFrontierRepository(store)
        session_rows = store.connection.execute(
            "SELECT event_id FROM search_frontier_investigator_sessions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchall()
        turns = (
            frontier.investigator_turns(case.case_id, str(session_rows[0][0]))
            if session_rows
            else ()
        )
        outcomes = tuple(frontier.read_investigator_turn_outcome(turn.turn_id) for turn in turns)
        assert result.state_version > case.state_version
        assert len(session_rows) == 1
        assert len(turns) == 2
        assert outcomes[0] is not None and outcomes[0].outcome == "focused_delivery"
        assert outcomes[1] is not None and outcomes[1].outcome == "gap"
        assert outcomes[1].reason_code == "stale_context"
        assert outcomes[1].frontier_item_ids == ()
        assert outcomes[1].remaining_item_ids == outcomes[0].remaining_item_ids
        assert len(outcomes[1].remaining_item_ids) == 3
        assert turns[1].catalog_generation > turns[0].catalog_generation
        assert (
            frontier.readback(outcomes[0].frontier_item_ids[0]).status is FrontierStatus.SATISFIED
        )
        assert all(
            frontier.readback(item_id).status is not FrontierStatus.SATISFIED
            for item_id in outcomes[1].remaining_item_ids
        )
        assert ranker.ranked_while_deep == []
        assert any("frontier_catalog_changed" in warning for warning in result.warnings)
        failed_rows = store.connection.execute(
            "SELECT status FROM probe_executions WHERE case_id=? AND probe_id LIKE 'fault%'",
            (str(case.case_id),),
        ).fetchall()
        assert failed_rows and all(str(row[0]) == "failed" for row in failed_rows)
