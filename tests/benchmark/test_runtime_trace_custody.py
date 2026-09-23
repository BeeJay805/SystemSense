"""A real coordinator episode can enter host custody before raw-row retention."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from benchmarks import runtime_trace_custody as bridge
from benchmarks.lab_episodes import ArmKind
from benchmarks.runtime_trace_custody import (
    capture_runtime_episode_trace,
    read_runtime_episode_trace,
)
from benchmarks.vm_lab_custody import CaptureKind, capture_bytes, verify_capture
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.evaluation.models import EpisodeSpec, EvaluationMode, MeasurementSource
from systemsense.evaluation.recorder import EpisodeRecorder
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_evaluation_recorder import (
    _investigator,  # pyright: ignore[reportPrivateUsage]
)


def _episode(store: SQLiteStore):
    investigator, decision, reasoning = _investigator(store)
    artifact = EpisodeRecorder().record(
        investigator=investigator,
        decision=decision,
        reasoning=reasoning,
        spec=EpisodeSpec(
            scenario_id="synthetic.host-custody",
            objective="private customer objective: secret-token-123",
            measurement_source=MeasurementSource.SIMULATION,
            synthetic=True,
            mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
            budget_ms=2000,
            max_rounds=2,
            max_probes=1,
        ),
    )
    return artifact


def test_real_episode_is_captured_with_exact_artifact_and_trace_but_no_raw_facts(
    tmp_path: Path,
) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
    with SQLiteStore(database) as reopened:
        captured = capture_runtime_episode_trace(
            root,
            reopened,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
            capture_id="runtime-trace-1",
            controller_id="arm.controller",
        )
    receipt = captured.receipt
    assert receipt.kind is CaptureKind.RUNTIME_EPISODE_TRACE
    assert verify_capture(root, receipt)
    binding = read_runtime_episode_trace(
        root,
        receipt,
        artifact,
        episode_id="episode-1",
        arm_kind=ArmKind.KEYWORD_BASELINE,
    )
    assert binding.classification == "host_runtime_trace_consistency_only"
    assert binding.trace_digest_verified is False
    assert binding.case_id == str(artifact.case_id)
    assert binding.artifact_sha256 == artifact.integrity_sha256()
    assert binding.trace_sha256 == captured.binding.trace_sha256
    payload = (root / "episode-1" / "arm" / "runtime-trace-1.bin").read_bytes()
    assert b"secret-token-123" not in payload
    assert b"Synthetic memory pressure observation" not in payload
    assert b"96.0" not in payload


def test_readback_rejects_artifact_episode_and_arm_relabeling(tmp_path: Path) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        captured = capture_runtime_episode_trace(
            root,
            store,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
            capture_id="runtime-trace-1",
            controller_id="arm.controller",
        )
    with pytest.raises(ValueError, match="artifact"):
        read_runtime_episode_trace(
            root,
            captured.receipt,
            artifact.model_copy(update={"objective": "relabelled"}),
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
        )
    with pytest.raises(ValueError, match="artifact"):
        read_runtime_episode_trace(
            root,
            captured.receipt,
            artifact.model_copy(update={"scenario_id": "synthetic.relabelled"}),
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
        )
    with pytest.raises(ValueError, match="episode"):
        read_runtime_episode_trace(
            root,
            captured.receipt,
            artifact,
            episode_id="episode-2",
            arm_kind=ArmKind.KEYWORD_BASELINE,
        )
    with pytest.raises(ValueError, match="arm"):
        read_runtime_episode_trace(
            root,
            captured.receipt,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.DUAL_BRAIN,
        )
    with pytest.raises(ValueError, match="receipt"):
        read_runtime_episode_trace(
            root,
            replace(captured.receipt, sha256="0" * 64),
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
        )


def test_retention_before_capture_fails_without_writing_sidecar(tmp_path: Path) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        assert store.delete_oldest_raw_evidence(limit=1) == 1
    with SQLiteStore(database) as reopened:
        with pytest.raises(ValueError, match="source binding"):
            capture_runtime_episode_trace(
                root,
                reopened,
                artifact,
                episode_id="episode-1",
                arm_kind=ArmKind.KEYWORD_BASELINE,
                capture_id="runtime-trace-1",
                controller_id="arm.controller",
            )
    assert not root.exists()


def test_resumed_case_cannot_be_captured_as_original_episode(tmp_path: Path) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        repo = InvestigationRepository(store)
        state = repo.load(str(artifact.case_id))
        repo.save(
            state.model_copy(
                update={
                    "status": InvestigationStatus.RUNNING,
                    "outcome": InvestigationOutcome.INVESTIGATING,
                }
            ),
            expected_version=state.state_version,
            event="resumed",
            detail="Host resumed the case after its original terminal.",
        )
        with pytest.raises(ValueError, match="terminal differs"):
            capture_runtime_episode_trace(
                root,
                store,
                artifact,
                episode_id="episode-1",
                arm_kind=ArmKind.KEYWORD_BASELINE,
                capture_id="runtime-trace-1",
                controller_id="arm.controller",
            )
    assert not root.exists()


def test_capture_is_write_once(tmp_path: Path) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        capture_runtime_episode_trace(
            root,
            store,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
            capture_id="runtime-trace-1",
            controller_id="arm.controller",
        )
        with pytest.raises(FileExistsError):
            capture_runtime_episode_trace(
                root,
                store,
                artifact,
                episode_id="episode-1",
                arm_kind=ArmKind.KEYWORD_BASELINE,
                capture_id="runtime-trace-1",
                controller_id="arm.controller",
            )


def test_retention_after_capture_does_not_erase_host_readback(tmp_path: Path) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        captured = capture_runtime_episode_trace(
            root,
            store,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
            capture_id="runtime-trace-1",
            controller_id="arm.controller",
        )
        assert store.delete_oldest_raw_evidence(limit=1) == 1
    assert (
        read_runtime_episode_trace(
            root,
            captured.receipt,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
        ).trace_sha256
        == captured.binding.trace_sha256
    )


@pytest.mark.parametrize("mutation", ["drop_evidence", "duplicate_id", "reverse_time"])
def test_readback_rejects_well_formed_trace_that_disagrees_with_artifact(
    tmp_path: Path,
    mutation: str,
) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        capture_runtime_episode_trace(
            root,
            store,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
            capture_id="runtime-trace-1",
            controller_id="arm.controller",
        )
        assert store.delete_oldest_raw_evidence(limit=1) == 1
    original = root / "episode-1" / "arm" / "runtime-trace-1.bin"
    payload = json.loads(original.read_text(encoding="utf-8"))
    trace = json.loads(payload["trace_json"])
    if mutation == "drop_evidence":
        assert artifact.evidence_count > 0
        trace["events"] = [event for event in trace["events"] if event["kind"] != "evidence"]
    elif mutation == "duplicate_id":
        trace["events"][1]["event_id"] = trace["events"][0]["event_id"]
    else:
        assert trace["events"][0]["observed_at"] < trace["events"][-1]["observed_at"]
        trace["events"][0]["observed_at"] = trace["events"][-1]["observed_at"]
    altered = json.dumps(trace, sort_keys=True, separators=(",", ":"))
    payload["trace_json"] = altered
    payload["trace_sha256"] = hashlib.sha256(altered.encode()).hexdigest()
    payload["trace_byte_count"] = len(altered.encode())
    forged = capture_bytes(
        root,
        episode_id="episode-1",
        capture_id="runtime-trace-forged",
        kind=CaptureKind.RUNTIME_EPISODE_TRACE,
        controller_id="arm.controller",
        source_observed_at=artifact.finished_at,
        data=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )
    with pytest.raises(ValueError, match="trace does not match episode"):
        read_runtime_episode_trace(
            root,
            forged,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
        )


def test_late_capture_is_rejected_and_exclusive_orphan_is_left_for_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    original = bridge.capture_bytes

    def delayed_capture(
        root_arg: Path,
        *,
        episode_id: str,
        capture_id: str,
        kind: CaptureKind,
        controller_id: str,
        source_observed_at: datetime,
        data: bytes,
    ):
        return original(
            root_arg,
            episode_id=episode_id,
            capture_id=capture_id,
            kind=kind,
            controller_id=controller_id,
            source_observed_at=source_observed_at,
            data=data,
            collected_at=source_observed_at + timedelta(minutes=6),
        )

    monkeypatch.setattr(bridge, "capture_bytes", delayed_capture)
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        with pytest.raises(ValueError, match="lag"):
            capture_runtime_episode_trace(
                root,
                store,
                artifact,
                episode_id="episode-1",
                arm_kind=ArmKind.KEYWORD_BASELINE,
                capture_id="runtime-trace-1",
                controller_id="arm.controller",
            )
    assert (root / "episode-1" / "arm" / "runtime-trace-1.bin").exists()


def test_readback_rejects_negative_collection_lag_even_with_matching_receipt(
    tmp_path: Path,
) -> None:
    database = tmp_path / "episode.db"
    root = tmp_path / "custody"
    with SQLiteStore(database) as store:
        artifact = _episode(store)
        captured = capture_runtime_episode_trace(
            root,
            store,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
            capture_id="runtime-trace-1",
            controller_id="arm.controller",
        )
    altered_receipt = replace(
        captured.receipt,
        collected_at=artifact.finished_at - timedelta(seconds=1),
    )
    receipt_path = root / "episode-1" / "arm" / "runtime-trace-1.json"
    receipt_path.write_text(json.dumps(altered_receipt.as_json()), encoding="utf-8")
    assert verify_capture(root, altered_receipt)
    with pytest.raises(ValueError, match="receipt is stale"):
        read_runtime_episode_trace(
            root,
            altered_receipt,
            artifact,
            episode_id="episode-1",
            arm_kind=ArmKind.KEYWORD_BASELINE,
        )
