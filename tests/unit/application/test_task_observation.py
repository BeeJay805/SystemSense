"""A fixture task reaches advisory input only from an exact executed source."""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from benchmarks.source_backed_full_run import (
    _CASES,  # pyright: ignore[reportPrivateUsage]
    _WORLDS,  # pyright: ignore[reportPrivateUsage]
    FrozenMenuRanker,
    _app,  # pyright: ignore[reportPrivateUsage]
    _cell,  # pyright: ignore[reportPrivateUsage]
    _checkpoint,  # pyright: ignore[reportPrivateUsage]
    _evidence_id,  # pyright: ignore[reportPrivateUsage]
    _seed_world_sources,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.investigation_state import InvestigationState
from systemsense.application.task_observation import resolve_task_observation
from systemsense.decision.frontier_ranker import FrontierRankRequestV1
from systemsense.domain.affected_task import (
    TaskObservationFactPathsV1,
    TaskObservationReferenceV1,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import RelevantVersionsV1, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore


def _reference(checkpoint: dict[str, object], record_json: str) -> TaskObservationReferenceV1:
    task = cast(dict[str, object], checkpoint["task_observation"])
    return TaskObservationReferenceV1(
        case_id=CaseId(root=str(checkpoint["case_id"])),
        evidence_id=EvidenceId(root=str(task["evidence_id"])),
        source_id=str(task["source_id"]),
        collector_id=str(task["collector_id"]),
        collector_version=1,
        execution_id=ExecutionId(root=str(task["execution_id"])),
        record_sha256=hashlib.sha256(record_json.encode("utf-8")).hexdigest(),
        fact_paths=TaskObservationFactPathsV1(
            target_handle="target_handle",
            action="action",
            expected="expected",
            observed="observed",
            window_start="synthetic_window_start_utc",
            window_end="synthetic_window_end_utc",
            window_ms="sample_window_ms",
        ),
    )


def test_only_exact_executed_synthetic_task_record_can_make_context(tmp_path: Path) -> None:
    database = tmp_path / "case.db"
    checkpoint = _checkpoint(database, _CASES[0])
    task = cast(dict[str, object], checkpoint["task_observation"])
    case_id = CaseId(root=str(checkpoint["case_id"]))
    with SQLiteStore(database) as store:
        row = store.evidence(case_id=str(case_id), evidence_id=str(task["evidence_id"]))
        assert row is not None
        reference = _reference(checkpoint, row.record_json)
        context = resolve_task_observation(store, case_id=case_id, reference=reference)
        visible = context.model_visible()
        assert visible["target_handle"] == "synthetic:browser-profile:one"
        assert visible["expected"] == "page_loaded"
        assert visible["observed"] == "timeout"
        assert visible["scope"] == "synthetic_fixture"
        assert "no Windows" in str(visible["limitation"])
        assert visible["evidence_id"] == str(task["evidence_id"])
        assert visible["case_id"] == str(case_id)
        assert visible["source_id"] == str(task["source_id"])
        assert visible["sample_window_ms"] == 500
        assert visible["time_quality"] == "exact"
        with pytest.raises(ValueError, match="duration conflicts"):
            type(context).model_validate(
                {
                    **context.model_dump(mode="json"),
                    "window_start": (context.window_start + timedelta(microseconds=1)).isoformat(),
                }
            )

        with pytest.raises(ValueError, match="source record changed"):
            resolve_task_observation(
                store,
                case_id=case_id,
                reference=reference.model_copy(update={"record_sha256": "0" * 64}),
            )
        with pytest.raises(ValueError, match="source record is unavailable"):
            resolve_task_observation(
                store,
                case_id=case_id,
                reference=reference.model_copy(update={"execution_id": ExecutionId.new()}),
            )
        with pytest.raises(ValueError, match="not the registered fixture contract"):
            resolve_task_observation(
                store,
                case_id=case_id,
                reference=reference.model_copy(
                    update={
                        "fact_paths": reference.fact_paths.model_copy(
                            update={"target_handle": "no_such_target"}
                        )
                    }
                ),
            )


@pytest.mark.parametrize("event_path", [False, True])
def test_invalid_persisted_task_is_quarantined_with_visible_gap(
    tmp_path: Path, event_path: bool
) -> None:
    database = tmp_path / "case.db"
    checkpoint = _checkpoint(database, _CASES[0])
    case_id = CaseId(root=str(checkpoint["case_id"]))
    task = cast(dict[str, object], checkpoint["task_observation"])
    with SQLiteStore(database) as store:
        row = store.evidence(case_id=str(case_id), evidence_id=str(task["evidence_id"]))
        assert row is not None
        bad = _reference(checkpoint, row.record_json).model_copy(update={"record_sha256": "0" * 64})
        app = _app(store, _CASES[0], FrozenMenuRanker(0))
        state = InvestigationRepository(store).load(str(case_id))
        assert isinstance(state, InvestigationState)
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"task_observation_reference": bad}),
            "test_bad_fixture_binding",
            "Fixture-only invalid reference for recovery regression.",
        )
        _seed_world_sources(store, case_id, _WORLDS[0], datetime.now(UTC))
        if event_path:
            generation = (
                EvidenceRetriever(store)
                .discover(EvidenceCatalogQuery(case_id=case_id, limit=1))
                .case_evidence_generation
            )
            with store.transaction():
                SearchFrontierRepository(store).append_result_event(
                    case_id,
                    source_evidence_id=_evidence_id(49),
                    source_execution_id=None,
                    versions=RelevantVersionsV1(objective=1, evidence=generation),
                )
            final = app.run(str(case_id))
        else:
            final, _, _ = app._frontier_retrieval(  # pyright: ignore[reportPrivateUsage]
                state, app.context(str(case_id), state=state)
            )
        assert final.task_observation_reference is None
        assert any(
            "task_context_unavailable" in warning or "Task context unavailable" in warning
            for warning in final.warnings
        )
        assert InvestigationRepository(store).load(str(case_id)).task_observation_reference is None


def test_task_bearing_snapshot_rechecks_current_binding(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "checkpoint.db"
    checkpoint = _checkpoint(checkpoint_path, _CASES[0])
    cell_path = tmp_path / "cell.db"
    shutil.copyfile(checkpoint_path, cell_path)
    attempt = _cell(
        cell_path,
        _WORLDS[0],
        0,
        str(checkpoint["case_id"]),
        datetime.now(UTC),
    )
    request = FrontierRankRequestV1.model_validate(attempt["rank_request"])
    assert request.task_context is not None
    with SQLiteStore(cell_path) as store:
        snapshots = CandidateDecisionSnapshotRepository(store)
        snapshots._verify_task_context_current(request)  # pyright: ignore[reportPrivateUsage]
        state = InvestigationRepository(store).load(str(request.case_id))
        assert state.task_observation_reference is not None
        InvestigationRepository(store).save(
            state.model_copy(update={"task_observation_reference": None}),
            expected_version=state.state_version,
            event="test_task_unbound",
            detail="Fixture binding changed after ranking.",
        )
        with pytest.raises(ValueError, match="task observation changed"):
            snapshots._verify_task_context_current(request)  # pyright: ignore[reportPrivateUsage]
