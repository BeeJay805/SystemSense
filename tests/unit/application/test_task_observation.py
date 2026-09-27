"""A fixture task reaches advisory input only from an exact executed source."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

import pytest

from benchmarks.source_backed_full_run import (
    _CASES,  # pyright: ignore[reportPrivateUsage]
    _checkpoint,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.task_observation import resolve_task_observation
from systemsense.domain.affected_task import (
    TaskObservationFactPathsV1,
    TaskObservationReferenceV1,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
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
