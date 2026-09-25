"""Opt-in event-turn measurement captures exact local worker calls only."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from systemsense.application.investigator import Investigator
from systemsense.decision.frontier_ranker import FrontierRankRequestV1, FrontierRankResponseV1
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_event_frontier_loop import (
    MeasurementFirstRanker,
    _app_with_registered_host_probes,  # pyright: ignore[reportPrivateUsage]
    _omit_until_selected,  # pyright: ignore[reportPrivateUsage]
    _started_with_event,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.application.test_general_candidate_catalog import (
    _source,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.evaluation.test_frontier_pilot_export import (
    _fixture_worker_capture,  # pyright: ignore[reportPrivateUsage]
)


class ExactCaptureMeasurementRanker(MeasurementFirstRanker):
    def __init__(self) -> None:
        super().__init__()
        self.callback_offered: list[bool] = []
        self.callback_counts: list[int] = []

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        self.callback_offered.append(capture_worker_batch is not None)
        response = super().rank(request, capture_worker_batch=capture_worker_batch)
        attention, calls = _fixture_worker_capture(request)
        attention = attention.model_copy(update={"ranked_probe_ids": response.ranked_item_ids})
        if capture_worker_batch is not None:
            for batch in attention.microbatches:
                phase, index = batch.phase, batch.batch_index
                proof = batch.worker_presentation
                assert proof is not None
                capture_worker_batch(phase, index, calls[(phase, index)], proof)
                self.callback_counts.append(index)
        return response.model_copy(
            update={
                "attention_notes": attention.attention_notes,
                "presentation_trace": attention,
            }
        ).validate_against(request)


@pytest.mark.parametrize("capture", [False, True])
def test_event_measurement_worker_draft_is_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture: bool
) -> None:
    with SQLiteStore(tmp_path / f"event-worker-{capture}.db") as store:
        ranker = ExactCaptureMeasurementRanker()
        base = _app_with_registered_host_probes(store, ranker)
        app = Investigator(
            store=store,
            runtime=base.runtime,
            capabilities=base.capabilities,
            decision=base.decision,
            reasoning=base.reasoning,
            knowledge=base.knowledge,
            frontier_ranker=ranker,
            capture_frontier_worker_inputs=capture,
        )
        state, _event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)

        _updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )

        assert handled
        assert ranker.callback_offered == [capture]
        row = store.connection.execute(
            "SELECT snapshot_id FROM candidate_decision_snapshots WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert row is not None
        drafts = store.connection.execute(
            "SELECT count(*) FROM frontier_worker_capture_drafts WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert drafts == (int(capture),)
        if capture:
            assert ranker.callback_counts
            readback = CandidateDecisionSnapshotRepository(store).readback_frontier_worker_draft(
                str(row[0])
            )
            assert len(readback.captured_calls) == len(ranker.callback_counts)
        else:
            assert ranker.callback_counts == []
