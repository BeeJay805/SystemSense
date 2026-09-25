"""The live coordinator must consume source-bound mixed frontier decisions."""

import hashlib
import json
import warnings
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

import pytest

import systemsense.application.investigator as investigator_module
from systemsense.application.case_service import CaseService
from systemsense.application.deep_worker import FrozenDeepTaskV1
from systemsense.application.investigation_state import InvestigationOutcome
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.ids import EntityId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.retrieval import EvidenceRelationRepository
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
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
        selected = next(item for item in request.items if item.reference.kind == self.kind)
        self.selected_item_ids.append(selected.item_id)
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


def _source_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def test_live_branch_selection_reaches_exact_omitted_neighbor(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "mixed-branch.db") as store:
        ranker = SelectingFrontierRanker("review_branch")
        app = _app(store, ranker)
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

        result = app.run(str(case.case_id))

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
        assert str(target) in {str(item) for item in result.fast_catalog_selected_ids}
        assert str(target) in {str(item.evidence_id) for item in app.context(str(case.case_id))}
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
