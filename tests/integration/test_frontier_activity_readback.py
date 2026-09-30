"""Saved streaming decisions remain visible without fabricating inference calls."""

from collections.abc import Callable
from pathlib import Path
from typing import Literal, cast

import pytest

from systemsense.application import service as service_module
from systemsense.application.bootstrap import default_investigator
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.runtime import PersistedProbeResult
from systemsense.application.service import ApplicationService
from systemsense.decision.frontier_ranker import FrontierRankRequestV1, FrontierRankResponseV1
from systemsense.domain.ids import ExecutionId
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_generic_process_frontier_selection import (
    _generic_case,  # pyright: ignore[reportPrivateUsage]
    _set_frontier_owner,  # pyright: ignore[reportPrivateUsage]
)


def _streamed_case(
    database: Path, monkeypatch: pytest.MonkeyPatch, mode: Literal["laya", "cache", "fallback"]
) -> tuple[str, str]:
    with SQLiteStore(database) as store:
        store.initialize()
        app, state = _generic_case(store, max_probes=2)
        state = state.model_copy(update={"status": InvestigationStatus.RUNNING})
        with store.transaction():
            store.connection.execute(
                "UPDATE cases SET status='collecting' WHERE case_id=?", (str(state.case_id),)
            )
            store.connection.execute(
                "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
                (state.model_dump_json(), str(state.case_id)),
            )
        row = store.connection.execute(
            "SELECT execution_id FROM evidence WHERE case_id=? "
            "AND json_extract(record_json, '$.collector.id')='application.snapshot'",
            (str(state.case_id),),
        ).fetchone()
        assert row is not None
        execution = ExecutionId(root=str(row[0]))
        parent = PersistedProbeResult(
            task_id="parent",
            case_id=str(state.case_id),
            epoch_state_version=state.state_version,
            probe_id="application.snapshot",
            execution_id=execution,
            evidence_generation=1,
            trigger_evidence_sha256=FollowupAdmissionRepository(store).parent_evidence_digest(
                str(state.case_id), str(execution)
            ),
        )
        ranker = _set_frontier_owner(app, select_pressure=mode != "fallback")
        if mode == "cache":
            rank = ranker.rank

            def cached_rank(
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                return rank(request, capture_worker_batch=capture_worker_batch).model_copy(
                    update={"cache_hit": True}
                )

            monkeypatch.setattr(ranker, "rank", cached_rank)
        handled, _selection, _delivery = app._offer_streaming_mixed_frontier(  # pyright: ignore[reportPrivateUsage]
            state, parent, app, store, None, []
        )
        assert handled and len(ranker.requests) == 1
        assert not app.repository.load(str(state.case_id)).provider_calls
        rows = store.connection.execute(
            "SELECT snapshot_id FROM candidate_decision_snapshots WHERE case_id=?",
            (str(state.case_id),),
        ).fetchall()
        assert len(rows) == 1
        return str(state.case_id), str(rows[0][0])


@pytest.mark.parametrize("mode", ["laya", "cache", "fallback"])
def test_service_exposes_one_validated_streaming_decision_after_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: Literal["laya", "cache", "fallback"]
) -> None:
    database = tmp_path / "streamed.db"
    case_id, snapshot_id = _streamed_case(database, monkeypatch, mode)
    service = ApplicationService(database, factory=default_investigator)
    try:
        report = service.get_case(case_id)
        activity = cast(dict[str, object], report["frontier_decisions"])
        assert activity["invalid_count"] == activity["omitted_count"] == 0
        records = cast(list[dict[str, object]], activity["records"])
        assert len(records) == 1
        assert records[0]["snapshot_id"] == snapshot_id
        assert records[0]["ranking_source"] == (
            "deterministic_fallback" if mode == "fallback" else "laya"
        )
        assert records[0]["cache_hit"] is (mode == "cache")
        assert records[0]["model_abstained"] is (mode == "fallback")
        assert "elapsed_ms" not in records[0]
        assert report["provider_calls"] == []
        assert service.get_case(case_id)["frontier_decisions"] == activity
    finally:
        service.close()


def test_invalid_frontier_snapshot_is_a_gap_not_a_model_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "tampered.db"
    case_id, snapshot_id = _streamed_case(database, monkeypatch, "laya")
    with SQLiteStore(database) as store, store.transaction():
        # Corrupt only this disposable fixture below the normal immutable writer.
        store.connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        store.connection.execute(
            "UPDATE candidate_decision_snapshots SET response_sha256=? WHERE snapshot_id=?",
            ("0" * 64, snapshot_id),
        )
    service = ApplicationService(database, factory=default_investigator)
    try:
        assert service.get_case(case_id)["frontier_decisions"] == {
            "schema_version": 1,
            "records": [],
            "invalid_count": 1,
            "omitted_count": 0,
        }
    finally:
        service.close()


def test_frontier_readback_does_not_leak_another_cases_decisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "case-scope.db"
    case_id, _snapshot_id = _streamed_case(database, monkeypatch, "laya")
    with SQLiteStore(database) as store:
        other = default_investigator(store).create(objective="Another saved case")
    service = ApplicationService(database, factory=default_investigator)
    try:
        assert service.get_case(str(other.case_id))["frontier_decisions"] == {
            "schema_version": 1,
            "records": [],
            "invalid_count": 0,
            "omitted_count": 0,
        }
        own = cast(dict[str, object], service.get_case(case_id)["frontier_decisions"])
        assert len(cast(list[dict[str, object]], own["records"])) == 1
    finally:
        service.close()


def test_omitted_decisions_are_reported_as_incomplete_not_an_empty_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "bounded.db"
    case_id, _snapshot_id = _streamed_case(database, monkeypatch, "laya")
    monkeypatch.setattr(service_module, "_FRONTIER_DECISION_LIMIT", 0)
    service = ApplicationService(database, factory=default_investigator)
    try:
        assert service.get_case(case_id)["frontier_decisions"] == {
            "schema_version": 1,
            "records": [],
            "invalid_count": 0,
            "omitted_count": 1,
        }
    finally:
        service.close()
