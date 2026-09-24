"""Opt-in frontier attention must expand exact persisted case evidence."""

from pathlib import Path

from systemsense.application.investigator import Investigator
from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.ids import EvidenceId
from systemsense.domain.time import utc_now
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.storage.search_frontier import FrontierStatus
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_catalog_attention_loop import (
    _fill_case,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator
from tests.unit.evidence.test_retrieval import (
    _insert_record,  # pyright: ignore[reportPrivateUsage]
)

PROVIDER = ProviderIdentity(
    provider_id="laya-local-decision", provider_version="1", role="fast_decision"
)


class ObservedFrontierRanker(MixedFrontierRanker):
    def __init__(self, store: SQLiteStore) -> None:
        super().__init__(ranker=None, provider=PROVIDER, model_weight_sha256="a" * 64)
        self.store = store
        self.calls: list[FrontierRankRequestV1] = []

    def rank(self, request: FrontierRankRequestV1) -> FrontierRankResponseV1:
        assert not self.store.connection.in_transaction
        self.calls.append(request)
        return super().rank(request)


class CaseChangingRanker(ObservedFrontierRanker):
    def rank(self, request: FrontierRankRequestV1) -> FrontierRankResponseV1:
        _insert_record(
            self.store,
            case_id=str(request.case_id),
            evidence_id=f"ev_{9999:032x}",
            collector_id="disk.health",
            summary="new observation during frontier inference",
            observed_at=utc_now(),
        )
        return super().rank(request)


def test_opt_in_frontier_retrieves_exact_omitted_case_record_without_probe(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-live.db") as store:
        base = investigator(store)
        ranker = ObservedFrontierRanker(store)
        app = Investigator(
            store=store,
            runtime=base.runtime,
            capabilities=base.capabilities,
            decision=base.decision,
            reasoning=base.reasoning,
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=ranker,
        )
        state = app.create(objective="Investigate slow network", budget_ms=10_000)
        _fill_case(store, str(state.case_id), count=60)
        before = app.context(str(state.case_id))
        before_ids = {str(item.evidence_id) for item in before}
        assert app._retrieval_omitted_evidence(before)  # pyright: ignore[reportPrivateUsage]
        assert len(before_ids) < 60

        updated, after, delivered = app._frontier_retrieval(  # pyright: ignore[reportPrivateUsage]
            state, before
        )

        after_ids = {str(item.evidence_id) for item in after}
        added = after_ids - before_ids
        assert delivered is True
        assert len(ranker.calls) == 1
        assert all(item.reference.kind == "retrieve_evidence" for item in ranker.calls[0].items)
        assert 1 <= len(ranker.calls[0].evidence_packets) <= 24
        assert updated.provider_calls[-1].degraded is True
        assert updated.provider_calls[-1].detail == "frontier_worker_unavailable"
        assert len(added) == 1
        assert any(item.evidence_id == EvidenceId(root=next(iter(added))) for item in after)
        assert updated.fast_catalog_selected_ids
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_transitions WHERE to_status=?",
                (FrontierStatus.SATISFIED.value,),
            ).fetchone()[0]
            == 1
        )

        newer, twice, second_delivered = app._frontier_retrieval(  # pyright: ignore[reportPrivateUsage]
            updated, after
        )
        second_added = {str(item.evidence_id) for item in twice} - after_ids
        assert second_delivered is True
        assert len(second_added) == 1
        assert second_added.isdisjoint(added)
        assert len(ranker.calls) == 2
        assert newer.fast_catalog_selected_ids[0] != updated.fast_catalog_selected_ids[0]


def test_run_path_actually_mounts_opt_in_frontier(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-loop.db") as store:
        base = investigator(store)
        ranker = ObservedFrontierRanker(store)
        app = Investigator(
            store=store,
            runtime=base.runtime,
            capabilities=base.capabilities,
            decision=base.decision,
            reasoning=base.reasoning,
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=ranker,
        )
        state = app.create(objective="Investigate slow network", budget_ms=10_000, max_rounds=1)
        _fill_case(store, str(state.case_id), count=60)

        app.run(str(state.case_id))

        assert ranker.calls
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_transitions WHERE to_status=?",
                (FrontierStatus.SATISFIED.value,),
            ).fetchone()[0]
            >= 1
        )


def test_generation_change_during_rank_cannot_claim_or_deliver(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-stale.db") as store:
        base = investigator(store)
        ranker = CaseChangingRanker(store)
        app = Investigator(
            store=store,
            runtime=base.runtime,
            capabilities=base.capabilities,
            decision=base.decision,
            reasoning=base.reasoning,
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=ranker,
        )
        state = app.create(objective="Investigate slow network", budget_ms=10_000)
        _fill_case(store, str(state.case_id), count=60)
        before = app.context(str(state.case_id))

        updated, after, delivered = app._frontier_retrieval(  # pyright: ignore[reportPrivateUsage]
            state, before
        )

        assert len(ranker.calls) == 1
        assert delivered is False
        assert after == before
        assert "Frontier attention unavailable: ValueError." in updated.warnings
        assert (
            store.connection.execute("SELECT COUNT(*) FROM search_frontier_transitions").fetchone()[
                0
            ]
            == 0
        )


def test_frontier_is_off_by_default(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-default.db") as store:
        app = investigator(store)
        state = app.create(objective="Investigate slow network", budget_ms=10_000)
        _fill_case(store, str(state.case_id), count=60)
        app.context(str(state.case_id))
        assert app.frontier_ranker is None
        assert (
            store.connection.execute("SELECT COUNT(*) FROM search_frontier_items").fetchone()[0]
            == 0
        )
