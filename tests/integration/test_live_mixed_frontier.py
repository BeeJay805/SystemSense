"""The live coordinator must consume source-bound mixed frontier decisions."""

import hashlib
import json
import time
import warnings
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from threading import Event
from typing import Any, cast

import pytest

import systemsense.application.investigator as investigator_module
from systemsense.application.case_service import CaseService
from systemsense.application.deep_worker import FrozenDeepTaskV1
from systemsense.application.investigation_state import InvestigationOutcome
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import (
    CandidateFollowupSelection,
    DiagnosticRuntime,
    FrontierDeepFollowupSelection,
    PersistedProbeResult,
)
from systemsense.decision.catalog_attention import CatalogAttentionRequest, CatalogAttentionResponse
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, ExecutionId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.retrieval import EvidenceCatalogCursor, EvidenceRelationRepository
from systemsense.inference.laya_runtime import LayaRanker, LayaWorkerPresentation
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import BoundedScheduler, ResourceBudget, ResourceClass
from systemsense.packs.runtime import default_probe_definitions
from systemsense.storage.search_frontier import (
    FrontierBranchReferenceV2,
    FrontierStatus,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_catalog_attention_loop import (
    _fill_case,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator


class SelectingFrontierRanker(MixedFrontierRanker):
    """A complete test ranking that chooses one offered reference kind."""

    def __init__(self, kind: str) -> None:
        super().__init__(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-mixed-frontier",
                provider_version="1",
                role="fast_decision",
            ),
            model_weight_sha256="a" * 64,
        )
        self.kind = kind
        self.requests: list[FrontierRankRequestV1] = []
        self.selected_item_ids: list[str] = []

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        del capture_worker_batch
        self.requests.append(request)
        selected = next((item for item in request.items if item.reference.kind == self.kind), None)
        fallback = super().rank(request)
        if selected is None:
            return fallback
        self.selected_item_ids.append(selected.item_id)
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


def _app(
    store: SQLiteStore,
    ranker: SelectingFrontierRanker,
) -> Investigator:
    base = investigator(store)
    return Investigator(
        store=store,
        runtime=base.runtime,
        capabilities=base.capabilities,
        decision=base.decision,
        reasoning=base.reasoning,
        knowledge=ReferenceKnowledgeGraph.load_default(),
        frontier_ranker=ranker,
    )


@pytest.mark.parametrize("reason_code", ("parent_over_capacity", "parent_unavailable"))
def test_streaming_parent_gap_is_retained_without_raw_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str
) -> None:
    gap_type = getattr(investigator_module, "_StreamingParentReceiptGap", None)
    assert gap_type is not None, "typed parent receipt gap is missing"

    def reject_parent(*_args: object) -> None:
        raise gap_type(reason_code, "private exception text must not persist")

    monkeypatch.setattr(investigator_module, "_streaming_parent_source_ids", reject_parent)
    with SQLiteStore(tmp_path / "parent-capacity-gap.db") as store:
        ranker = SelectingFrontierRanker("retrieve_evidence")
        app = _app(store, ranker)
        case = app.create(objective="Investigate slow network", budget_ms=10_000, max_rounds=1)

        final = app.run(str(case.case_id))

        assert any(f"streaming_{reason_code}" in item for item in final.warnings)
        assert all("private exception text" not in item for item in final.warnings)
        assert app.repository.load(str(case.case_id)).warnings == final.warnings


def _persist_parent_records(
    store: SQLiteStore, case_id: CaseId, execution_id: ExecutionId, count: int
) -> tuple[EvidenceId, ...]:
    now = datetime.now(UTC)
    evidence_ids: list[EvidenceId] = []
    for index in range(count):
        evidence_id = EvidenceId(root=f"ev_{index + 1:032x}")
        evidence_ids.append(evidence_id)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=now,
            captured_at=now,
            source=EvidenceSource(
                type="test.fixture",
                source_id=f"src_{index + 1:064x}",
                locator={},
            ),
            collector=CollectorReference(
                id="incident.events", version=1, execution_id=execution_id
            ),
            summary=("decisive later event" if index == count - 1 else f"routine event {index}"),
            facts=(EvidenceFact(name="event_index", value=index),),
            extraction=Extraction(confidence=1.0, parser="test.fixture", parser_version=1),
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=record.source.source_id,
                record_json=record.model_dump_json(),
                observed_at=now.isoformat(),
                captured_at=now.isoformat(),
                execution_id=str(execution_id),
            )
    return tuple(evidence_ids)


def test_large_parent_keeps_later_record_retrievable_in_bounded_streaming_turn(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "large-parent.db") as store:
        ranker = SelectingFrontierRanker("retrieve_evidence")
        app = _app(store, ranker)
        state = app.create(objective="Investigate a specific later event", budget_ms=10_000)
        with store.transaction():
            store.connection.execute(
                "UPDATE cases SET status='collecting' WHERE case_id=?",
                (str(state.case_id),),
            )
        execution_id = ExecutionId.new()
        evidence_ids = _persist_parent_records(store, state.case_id, execution_id, 17)
        parent = PersistedProbeResult(
            task_id="parent",
            case_id=str(state.case_id),
            epoch_state_version=state.state_version,
            probe_id="incident.events",
            execution_id=execution_id,
            evidence_generation=17,
            trigger_evidence_sha256="a" * 64,
        )
        gap_codes: list[str] = []
        handled, selection, delivery = app._offer_streaming_mixed_frontier(  # pyright: ignore[reportPrivateUsage]
            state, parent, app, store, None, gap_codes
        )

        assert handled and selection is None
        assert delivery is not None and delivery[1] == evidence_ids[-1], (
            gap_codes,
            [tuple(item.reference.kind for item in request.items) for request in ranker.requests],
        )
        assert "parent_page_deferred" in gap_codes
        request = ranker.requests[0]
        assert str(evidence_ids[-1]) not in {
            packet.evidence_id for packet in request.evidence_packets
        }
        assert any(
            item.reference.kind == "retrieve_evidence"
            and item.reference.evidence_id == evidence_ids[-1]
            for item in request.items
        )


@pytest.mark.parametrize("count", (130, 181))
def test_ordinary_mixed_loop_reaches_relevant_catalog_record_after_128_rows(
    tmp_path: Path,
    count: int,
) -> None:
    target = EvidenceId(root=f"ev_{count:032x}")

    class TailSeekingRanker(SelectingFrontierRanker):
        target_deferred = False

        def rank(
            self,
            request: FrontierRankRequestV1,
            *,
            capture_worker_batch: Callable[
                [str, int, dict[str, object], LayaWorkerPresentation], None
            ]
            | None = None,
        ) -> FrontierRankResponseV1:
            ranked = super().rank(request, capture_worker_batch=capture_worker_batch)
            chosen = next(
                (
                    item
                    for item in request.items
                    if item.reference.kind == "retrieve_evidence"
                    and item.reference.evidence_id == target
                ),
                None,
            )
            if chosen is None:
                return ranked
            if not self.target_deferred:
                self.target_deferred = True
                alternate = next(
                    item
                    for item in request.items
                    if item.reference.kind == "retrieve_evidence"
                    and item.reference.evidence_id != target
                )
                chosen = alternate
            offered = tuple(item.item_id for item in request.items)
            return ranked.model_copy(
                update={
                    "ranked_item_ids": (
                        chosen.item_id,
                        *(item_id for item_id in offered if item_id != chosen.item_id),
                    ),
                    "considered_item_ids": offered,
                }
            ).validate_against(request)

    with SQLiteStore(tmp_path / "mixed-tail-130.db") as store:
        ranker = TailSeekingRanker("retrieve_evidence")
        app = _app(store, ranker)
        metadata_requests: list[CatalogAttentionRequest] = []

        class TailCatalogAttention:
            def rank_catalog(self, request: CatalogAttentionRequest) -> CatalogAttentionResponse:
                metadata_requests.append(request)
                ranked = sorted(
                    (item.evidence_id for item in request.entries),
                    key=lambda item: (item != target, str(item)),
                )[: request.max_requests]
                return CatalogAttentionResponse(
                    case_id=request.case_id,
                    case_evidence_generation=request.case_evidence_generation,
                    page_digest=request.page_digest,
                    deadline_at=request.deadline_at,
                    ranked_evidence_ids=tuple(ranked),
                ).validate_against(request)

        app.catalog_attention = TailCatalogAttention()
        state = app.create(
            objective="Find the older disk fault in the case catalog",
            budget_ms=30_000,
            max_rounds=2,
        )
        assert _fill_case(store, str(state.case_id), count=count, target_index=count) == target

        app.run(str(state.case_id))

        judged = {
            str(item.evidence_id) for request in metadata_requests for item in request.entries
        }
        assert {str(EvidenceId(root=f"ev_{index:032x}")) for index in range(1, count + 1)} <= judged
        assert all(len(request.entries) <= 20 for request in metadata_requests)
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?", (str(state.case_id),)
            ).fetchone()[0]
            < 128
        )
        assert any(
            item.reference.evidence_id == target
            for request in ranker.requests
            for item in request.items
            if item.reference.kind == "retrieve_evidence"
        ), "the bounded mixed loop never offered the relevant tail record"
        assert any(
            receipt.evidence_id == target
            for receipt in SearchFrontierRepository(store).focus_delivery_receipts(state.case_id)
        )
        first_target_menu = next(
            index
            for index, request in enumerate(ranker.requests)
            if any(item.reference.evidence_id == target for item in request.items)
        )
        assert ranker.target_deferred
        assert any(
            item.reference.evidence_id == target
            for request in ranker.requests[first_target_menu + 1 :]
            for item in request.items
        ), "an unselected metadata finalist was lost when the catalog cursor advanced"


@pytest.mark.parametrize("degraded", (False, True))
def test_large_catalog_attention_gap_keeps_independent_deep_choice(
    tmp_path: Path, degraded: bool
) -> None:
    with SQLiteStore(tmp_path / f"large-catalog-gap-{degraded}.db") as store:
        ranker = SelectingFrontierRanker("consult_deep")
        app = _app(store, ranker)
        if degraded:

            class DegradedCatalogAttention:
                def rank_catalog(
                    self, request: CatalogAttentionRequest
                ) -> CatalogAttentionResponse:
                    return CatalogAttentionResponse(
                        case_id=request.case_id,
                        case_evidence_generation=request.case_evidence_generation,
                        page_digest=request.page_digest,
                        deadline_at=request.deadline_at,
                        degraded=True,
                    ).validate_against(request)

            app.catalog_attention = DegradedCatalogAttention()
        state = app.create(objective="Investigate a case with older records", budget_ms=10_000)
        _fill_case(store, str(state.case_id), count=130, target_index=130)

        final = app.run(str(state.case_id))

        assert any(
            item.reference.kind == "consult_deep"
            for request in ranker.requests
            for item in request.items
        ), "catalog uncertainty must not suppress an unrelated sourced deep question"
        expected_gap = "catalog_attention_degraded" if degraded else "catalog_attention_unavailable"
        assert any(expected_gap in warning for warning in final.warnings)
        assert final.outcome is not InvestigationOutcome.INSUFFICIENT_OBSERVABILITY


def test_unselected_catalog_retrieval_backlog_is_not_observability_closure(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "large-catalog-backlog.db") as store:
        ranker = SelectingFrontierRanker("consult_deep")
        app = _app(store, ranker)

        class HeadCatalogAttention:
            def rank_catalog(self, request: CatalogAttentionRequest) -> CatalogAttentionResponse:
                return CatalogAttentionResponse(
                    case_id=request.case_id,
                    case_evidence_generation=request.case_evidence_generation,
                    page_digest=request.page_digest,
                    deadline_at=request.deadline_at,
                    ranked_evidence_ids=tuple(
                        item.evidence_id for item in request.entries[: request.max_requests]
                    ),
                ).validate_against(request)

        app.catalog_attention = HeadCatalogAttention()
        state = app.create(objective="Investigate older process history", budget_ms=10_000)
        _fill_case(store, str(state.case_id), count=130, target_index=130)

        final = app.run(str(state.case_id))

        requested = [
            item
            for (item_id,) in store.connection.execute(
                "SELECT item_id FROM search_frontier_items WHERE case_id=?",
                (str(state.case_id),),
            )
            if (item := SearchFrontierRepository(store).readback(str(item_id))).status
            is FrontierStatus.REQUESTED
            and item.reference.kind == "retrieve_evidence"
        ]
        assert requested, "fixture did not leave a valid retrieval backlog"
        assert final.outcome is not InvestigationOutcome.INSUFFICIENT_OBSERVABILITY


@pytest.mark.parametrize("count", (181, 641))
def test_unselected_first_catalog_window_continues_before_case_closure(
    tmp_path: Path, count: int
) -> None:
    target = EvidenceId(root=f"ev_{count:032x}")
    with SQLiteStore(tmp_path / "catalog-empty-first-window.db") as store:
        ranker = SelectingFrontierRanker("retrieve_evidence")
        app = _app(store, ranker)
        judged: set[str] = set()

        class SparseCatalogAttention:
            def rank_catalog(self, request: CatalogAttentionRequest) -> CatalogAttentionResponse:
                judged.update(str(item.evidence_id) for item in request.entries)
                selected = (
                    (target,) if any(item.evidence_id == target for item in request.entries) else ()
                )
                return CatalogAttentionResponse(
                    case_id=request.case_id,
                    case_evidence_generation=request.case_evidence_generation,
                    page_digest=request.page_digest,
                    deadline_at=request.deadline_at,
                    ranked_evidence_ids=selected,
                ).validate_against(request)

        app.catalog_attention = SparseCatalogAttention()
        state = app.create(
            objective="Investigate an older disk observation",
            budget_ms=20_000,
            max_rounds=2,
        )
        _fill_case(store, str(state.case_id), count=count, target_index=count)

        final = app.run(str(state.case_id))

        if count == 641:
            assert str(target) not in judged
            assert any("catalog_more_pages_unscanned" in warning for warning in final.warnings)
            assert final.outcome is InvestigationOutcome.NO_PROGRESS
            return
        assert str(target) in judged, final.warnings
        assert any(
            receipt.evidence_id == target
            for receipt in SearchFrontierRepository(store).focus_delivery_receipts(state.case_id)
        ), final.warnings


def test_streaming_owner_rechecks_deferred_catalog_without_an_unrelated_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "catalog-deferred-owner.db") as store:
        app = _app(store, SelectingFrontierRanker("retrieve_evidence"))
        calls_by_parent: dict[str, int] = {}

        def deferred_once(
            _state: object,
            parent: PersistedProbeResult,
            _worker: object,
            _worker_store: object,
            _cancel_event: object,
            gap_codes: list[str],
            cursor_holder: list[tuple[int, EvidenceCatalogCursor | None]],
            _metadata_stats: object,
            *,
            admitted_followups: object = None,
        ) -> tuple[bool, None, None]:
            del admitted_followups
            key = str(parent.execution_id)
            calls_by_parent[key] = calls_by_parent.get(key, 0) + 1
            if calls_by_parent[key] == 1:
                cursor_holder[0] = (
                    parent.evidence_generation,
                    EvidenceCatalogCursor(
                        observed_at=datetime.now(UTC),
                        evidence_id=EvidenceId(root=f"ev_{1:032x}"),
                    ),
                )
                gap_codes.append("catalog_more_pages_unscanned")
            return True, None, None

        monkeypatch.setattr(app, "_offer_streaming_mixed_frontier", deferred_once)
        state = app.create(
            objective="Investigate a bounded catalog",
            budget_ms=10_000,
            max_rounds=1,
        )

        app.run(str(state.case_id))

        assert calls_by_parent
        assert any(count >= 2 for count in calls_by_parent.values()), (
            "the owner closed the callback after a deferred catalog page",
            calls_by_parent,
        )


class PartialWorkerFallbackRanker(MixedFrontierRanker):
    """A worker may emit one callback, then the complete ranking falls back."""

    def __init__(self) -> None:
        super().__init__(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-partial-frontier",
                provider_version="1",
                role="fast_decision",
            ),
            model_weight_sha256="a" * 64,
        )
        self.partial_callbacks = 0
        self.offered_kinds: list[tuple[str, ...]] = []

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        self.offered_kinds.append(tuple(item.reference.kind for item in request.items))
        if capture_worker_batch is not None and request.items[0].reference.kind == "measure":
            # A failed worker may have emitted an incomplete callback before
            # the deterministic fallback; its proof must never be persisted.
            capture_worker_batch("probe", 0, {"partial": True}, None)  # type: ignore[arg-type]
            self.partial_callbacks += 1
        return super().rank(request)


def test_partial_worker_callback_is_not_retained_after_fallback(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "partial-capture.db") as store:
        ranker = PartialWorkerFallbackRanker()
        base = investigator(store)

        def observed(_parameters: dict[str, JsonValue], name: str) -> ProbeObservation:
            now = datetime.now(UTC)
            return ProbeObservation(
                summary=f"{name} observed",
                facts={"measurement": name, "pressure_percent": 97},
                observed_at=now,
                captured_at=now,
            )

        definitions: list[ProbeDefinition] = []
        for original in default_probe_definitions():
            name = original.manifest.probe_id
            definitions.append(
                replace(original, isolated=False, handler=partial(observed, name=name))
                if name in {"core.system", "core.resources", "pressure.sample"}
                else original
            )
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
            reasoning=base.reasoning,
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=ranker,
            capture_frontier_worker_inputs=True,
        )
        case = app.create(
            objective="Investigate intermittent slow resource pressure",
            budget_ms=20_000,
            max_rounds=1,
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            app.run(str(case.case_id))
        assert ranker.partial_callbacks > 0, ranker.offered_kinds
        assert not any("worker capture was not retained" in str(item.message) for item in caught)
        assert store.connection.execute(
            "SELECT count(*) FROM frontier_worker_capture_drafts"
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    ("pressure_in_baseline", "owner_task_limit", "late_callback"),
    ((False, None, False), (True, None, False), (False, 2, False), (False, 2, True)),
)
def test_streaming_measurement_respects_owner_followup_catalog_and_closes_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pressure_in_baseline: bool,
    owner_task_limit: int | None,
    late_callback: bool,
) -> None:
    with SQLiteStore(tmp_path / "streaming-measurement-custody.db") as store:
        base = investigator(store)
        ranker = SelectingFrontierRanker("measure")

        def observed(_parameters: dict[str, JsonValue], *, name: str) -> ProbeObservation:
            now = datetime.now(UTC)
            facts: dict[str, JsonValue] = {"fixture": "streaming-measurement-custody"}
            if name == "application.snapshot":
                created = now.replace(microsecond=0)
                facts.update(
                    collection_started_at=now.isoformat(),
                    collection_completed_at=now.isoformat(),
                    collection_status="available",
                    omitted_counts={"processes": 0, "services": 0, "startup": 0},
                    processes=[
                        {
                            "pid": 4242,
                            "ppid": 1,
                            "name": "viewer.exe",
                            "creation_time": created.isoformat(),
                            "identity": f"4242@{created.isoformat()}",
                        }
                    ],
                )
            return ProbeObservation(
                summary=f"Synthetic {name} observation",
                facts=facts,
                observed_at=now,
                captured_at=now,
            )

        names = {
            "core.system",
            "core.resources",
            "pressure.sample",
            "application.snapshot",
            "application.target_pressure",
        }
        definitions = tuple(
            replace(
                original,
                isolated=False,
                handler=partial(observed, name=original.manifest.probe_id),
            )
            for original in default_probe_definitions()
            if original.manifest.probe_id in names
        )
        baseline_names = {"core.system", "core.resources", "application.snapshot"}
        if pressure_in_baseline:
            baseline_names.add("pressure.sample")
        app = Investigator(
            store=store,
            runtime=DiagnosticRuntime(
                store=store,
                case_service=CaseService(store, DeterministicPlanner(candidates=())),
                probe_runner=ProbeRunner(definitions=definitions),
                scheduler=(
                    None
                    if owner_task_limit is None
                    else BoundedScheduler(budget=ResourceBudget(max_tasks=owner_task_limit))
                ),
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
                if definition.manifest.probe_id in baseline_names
            ),
            decision=base.decision,
            reasoning=base.reasoning,
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=ranker,
        )
        case = app.create(
            objective=(
                "Check current Windows health and resource pressure without changing settings"
            ),
            budget_ms=15_000,
            max_probes=16,
            max_rounds=1,
        )

        callback_claimed = Event()
        release_callback = Event()
        if late_callback:
            original_offer = app._offer_streaming_mixed_frontier  # pyright: ignore[reportPrivateUsage]

            def hold_after_claim(*args: Any, **kwargs: Any) -> Any:
                result = original_offer(*args, **kwargs)
                if isinstance(result[1], CandidateFollowupSelection):
                    callback_claimed.set()
                    assert release_callback.wait(25), "held model callback was not released"
                return result

            monkeypatch.setattr(app, "_offer_streaming_mixed_frontier", hold_after_claim)
        try:
            app.run(str(case.case_id))
            if late_callback:
                assert callback_claimed.wait(5), "model callback never claimed a measurement"
                assert any(
                    SearchFrontierRepository(store).readback(item_id).status
                    is FrontierStatus.CLAIMED
                    for item_id in ranker.selected_item_ids
                )
        finally:
            release_callback.set()
        if late_callback:
            until = time.monotonic() + 5
            while time.monotonic() < until and any(
                SearchFrontierRepository(store).readback(item_id).status is FrontierStatus.CLAIMED
                for item_id in ranker.selected_item_ids
            ):
                Event().wait(0.01)

        frontier = SearchFrontierRepository(store)
        items = tuple(
            frontier.readback(str(row[0]))
            for row in store.connection.execute(
                "SELECT item_id FROM search_frontier_items WHERE case_id=?",
                (str(case.case_id),),
            )
        )
        assert all(item.status is not FrontierStatus.CLAIMED for item in items)
        admitted = store.connection.execute(
            "SELECT count(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchone()[0]
        assert all(
            semantic.measurement is None
            or semantic.measurement.probe_id != "application.target_pressure"
            for request in ranker.requests
            for semantic in request.item_semantics
        )
        if pressure_in_baseline or owner_task_limit is not None:
            assert admitted == 0
            if pressure_in_baseline:
                assert all(
                    semantic.measurement is None
                    or semantic.measurement.probe_id
                    not in {"pressure.sample", "application.target_pressure"}
                    for request in ranker.requests
                    for semantic in request.item_semantics
                )
            else:
                assert any(
                    semantic.measurement is not None
                    and semantic.measurement.probe_id == "pressure.sample"
                    for request in ranker.requests
                    for semantic in request.item_semantics
                )
                assert (
                    store.connection.execute(
                        "SELECT COUNT(*) FROM search_frontier_transitions AS t "
                        "JOIN search_frontier_items AS i ON i.item_id=t.item_id "
                        "WHERE i.case_id=? AND t.from_status='claimed' "
                        "AND t.to_status='obsolete' "
                        "AND t.reason='candidate_rejected_before_admission' "
                        "AND json_extract(i.identity_json, '$.reference.kind')='measure'",
                        (str(case.case_id),),
                    ).fetchone()[0]
                    >= 1
                )
        else:
            assert admitted >= 1
            assert any(
                item.reference.kind == "measure" and item.status is FrontierStatus.SATISFIED
                for item in items
            ), "a completed admitted measurement must not remain RUNNING"


def _source_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def test_live_branch_selection_reaches_exact_omitted_neighbor(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "mixed-branch.db") as store:
        ranker = SelectingFrontierRanker("review_branch")
        app = _app(store, ranker)
        legacy_calls: list[str] = []

        class ForbiddenLegacyRanker:
            def attend(self, **_kwargs: object) -> None:
                legacy_calls.append("attend")
                raise AssertionError("mixed frontier must own fast-model routing")

        app.decision = LayaDecisionProvider(ranker=cast(LayaRanker, ForbiddenLegacyRanker()))
        case = app.create(objective="Investigate slow network", budget_ms=10_000, max_rounds=1)
        target = _fill_case(store, str(case.case_id), count=60)
        before = app.context(str(case.case_id))
        visible_ids = {
            str(item.evidence_id) for item in before if item.case_scope == "current_case"
        }
        assert str(target) not in visible_ids
        source = next(item.evidence_id for item in before if str(item.evidence_id) in visible_ids)
        relation = EvidenceRelation(
            relation_id=f"rel_{'b' * 32}",
            source_entity_id=EntityId(root=f"entity_{'1' * 32}"),
            target_entity_id=EntityId(root=f"entity_{'2' * 32}"),
            relationship=RelationKind.USES_DRIVER,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(source, target),
        )
        assert EvidenceRelationRepository(store).append(relation)
        # Ordinary graph-priority retrieval cannot use this edge yet: one of
        # its cited records is not in the focused packet. A selected branch
        # must use exact durable provenance to expand it.
        assert str(target) not in {str(item.evidence_id) for item in app.context(str(case.case_id))}

        app.run(str(case.case_id))
        assert legacy_calls == []

        branch_requests = [
            request
            for request in ranker.requests
            if any(item.reference.kind == "review_branch" for item in request.items)
        ]
        assert branch_requests, "live ranking must include persisted graph branches"
        assert len(branch_requests[0].evidence_packets) <= 16
        assert any(
            json.loads(packet.description).get("pages_omitted", 0) > 0
            for packet in branch_requests[0].evidence_packets
        )
        offered = next(
            item for item in branch_requests[0].items if item.reference.kind == "review_branch"
        )
        assert offered.reference == FrontierBranchReferenceV2.from_relation(relation)
        semantic = next(
            item for item in branch_requests[0].item_semantics if item.item_id == offered.item_id
        )
        assert semantic.source_record_sha256 == _source_digest(relation.model_dump(mode="json"))
        assert semantic.relation_id == relation.relation_id
        assert ranker.selected_item_ids[0] == offered.item_id
        assert (
            SearchFrontierRepository(store).readback(offered.item_id).status
            is FrontierStatus.SATISFIED
        )
        assert any(
            step.event == "frontier_branch_retrieved"
            for step in app.repository.steps(str(case.case_id))
        )
        assert {
            row[0] for row in store.connection.execute("SELECT probe_id FROM probe_executions")
        } <= {capability.probe_id for capability in app.capabilities}


def test_live_deep_selection_creates_explicit_sourced_handoff(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "mixed-deep.db") as store:
        ranker = SelectingFrontierRanker("consult_deep")
        app = _app(store, ranker)
        case = app.create(objective="Investigate slow network", budget_ms=10_000, max_rounds=1)
        _fill_case(store, str(case.case_id), count=60)

        result = app.run(str(case.case_id))

        deep_requests = [
            request
            for request in ranker.requests
            if any(item.reference.kind == "consult_deep" for item in request.items)
        ]
        assert deep_requests, "live ranking must include a frozen current-case question"
        request = deep_requests[0]
        offered = next(item for item in request.items if item.reference.kind == "consult_deep")
        semantic = next(item for item in request.item_semantics if item.item_id == offered.item_id)
        row = store.connection.execute(
            "SELECT symptom,created_at FROM cases WHERE case_id=?", (str(case.case_id),)
        ).fetchone()
        assert row is not None
        assert semantic.source_record_sha256 == _source_digest(
            {
                "case_id": str(case.case_id),
                "symptom": row[0],
                "created_at": row[1],
                "objective_version": offered.versions.objective,
                "evidence_generation": offered.versions.evidence,
            }
        )
        assert ranker.selected_item_ids[0] == offered.item_id
        expected_question_id = (
            "question_v1_"
            + hashlib.sha256(
                f"{case.case_id}|{row[0]}|{offered.versions.objective}|"
                f"{offered.versions.evidence}".encode()
            ).hexdigest()[:32]
        )
        assert offered.reference.question_id == expected_question_id
        handoffs = [
            step
            for step in app.repository.steps(str(case.case_id))
            if step.event == "frontier_deep_handoff"
        ]
        question_id = offered.reference.question_id
        assert question_id is not None
        assert handoffs and question_id in handoffs[0].detail
        mailbox_rows = store.connection.execute(
            "SELECT task_json,status FROM deep_mailbox WHERE case_id=?", (str(case.case_id),)
        ).fetchall()
        tasks = [FrozenDeepTaskV1.model_validate_json(str(row[0])) for row in mailbox_rows]
        assert len({task.question_id for task in tasks}) == len(tasks), (
            "one frozen deep question must not be admitted twice"
        )
        selected_rows = [
            (task, status)
            for task, (_payload, status) in zip(tasks, mailbox_rows, strict=True)
            if task.question_id == question_id
        ]
        assert len(selected_rows) == 1, "a selected deep question must admit one real frozen task"
        task, selected_status = selected_rows[0]
        assert task.request.case_id == case.case_id
        assert task.request.objective == case.objective
        assert task.request_sha256 in handoffs[0].detail
        assert selected_status in {"applied", "rejected", "cancelled", "failed"}
        frontier_status = SearchFrontierRepository(store).readback(offered.item_id).status
        if selected_status == "applied":
            assert frontier_status is FrontierStatus.SATISFIED
        else:
            assert frontier_status in {
                FrontierStatus.CANCELLED,
                FrontierStatus.FAILED,
                FrontierStatus.INTERRUPTED,
                FrontierStatus.OBSOLETE,
            }
        assert result.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION


def test_late_deep_selection_is_closed_without_owner_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "late-deep-selection.db") as store:
        ranker = SelectingFrontierRanker("consult_deep")
        app = _app(store, ranker)
        case = app.create(objective="Investigate slow network", budget_ms=10_000, max_rounds=1)
        _fill_case(store, str(case.case_id), count=60)
        callback_claimed = Event()
        release_callback = Event()
        selected_item_ids: list[str] = []
        original_offer = app._offer_streaming_mixed_frontier  # pyright: ignore[reportPrivateUsage]

        def hold_after_claim(*args: Any, **kwargs: Any) -> Any:
            result = original_offer(*args, **kwargs)
            if isinstance(result[1], FrontierDeepFollowupSelection):
                selected_item_ids.append(result[1].item_id)
                callback_claimed.set()
                assert release_callback.wait(20), "held deep callback was not released"
            return result

        monkeypatch.setattr(app, "_offer_streaming_mixed_frontier", hold_after_claim)
        try:
            app.run(str(case.case_id))
            assert callback_claimed.wait(5), "callback did not claim a deep item"
            assert SearchFrontierRepository(store).readback(selected_item_ids[0]).status is (
                FrontierStatus.CLAIMED
            )
        finally:
            release_callback.set()

        until = time.monotonic() + 5
        while (
            time.monotonic() < until
            and SearchFrontierRepository(store).readback(selected_item_ids[0]).status
            is FrontierStatus.CLAIMED
        ):
            Event().wait(0.01)
        assert SearchFrontierRepository(store).readback(selected_item_ids[0]).status is (
            FrontierStatus.OBSOLETE
        )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_transitions WHERE item_id=? "
            "AND reason='deep_selection_not_admitted'",
            (selected_item_ids[0],),
        ).fetchone() == (1,)
