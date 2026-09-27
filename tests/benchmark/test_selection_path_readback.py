"""Selection-path readback requires durable linkage rather than assumptions."""

from __future__ import annotations

from pathlib import Path

from benchmarks.selection_path_readback import (
    ExecutionFact,
    PathReference,
    StepFact,
    classify_execution,
    readback_artifact,
    verify_readback,
)
from benchmarks.sequential_hypothesis_episodes import run_hypothesis_suite


def _execution(probe_id: str, state_version: int = 14) -> ExecutionFact:
    return ExecutionFact(
        execution_id="exec_test",
        case_id="case_test",
        probe_id=probe_id,
        state_version=state_version,
    )


def test_durable_baseline_fast_and_deep_paths() -> None:
    baseline = classify_execution(
        _execution("core.system", 3),
        steps={3: StepFact(3, "baseline_collecting", ("core.system",), ())},
    )
    assert baseline["selection_path"] == "initial_baseline"

    fast = classify_execution(
        _execution("browser.route_attempt", 7),
        steps={7: StepFact(7, "collecting", ("browser.route_attempt",), ())},
        fast=PathReference("snapshot_1", valid=True),
    )
    assert fast["selection_path"] == "fast_snapshot_linked"
    assert fast["admission_recorded"] is False

    deep_steps = {
        13: StepFact(13, "routing_superseded", (), ("browser.direct_control",)),
        14: StepFact(14, "collecting", ("browser.direct_control",), ()),
    }
    deep = classify_execution(_execution("browser.direct_control"), steps=deep_steps)
    assert deep["selection_path"] == "trusted_deep_requested_batch"
    assert deep["admission_recorded"] is False


def test_unproven_or_conflicting_paths_stay_unknown() -> None:
    no_route = classify_execution(
        _execution("browser.direct_control"),
        steps={14: StepFact(14, "collecting", ("browser.direct_control",), ())},
    )
    assert no_route["selection_path"] == "unknown"

    invalid_fast = classify_execution(
        _execution("browser.route_attempt"),
        steps={7: StepFact(7, "collecting", ("browser.route_attempt",), ())},
        fast=PathReference("snapshot_missing", valid=False),
    )
    assert invalid_fast["selection_path"] == "unknown"
    assert invalid_fast["reason"] == "invalid_recorded_link"

    conflict = classify_execution(
        _execution("browser.route_attempt"),
        steps={7: StepFact(7, "collecting", ("browser.route_attempt",), ())},
        fast=PathReference("snapshot_1", valid=True),
        adaptive=PathReference("admission_1", valid=True),
    )
    assert conflict["selection_path"] == "unknown"
    assert conflict["reason"] == "conflicting_recorded_paths"


def test_recorded_adaptive_admission_is_not_synthesized() -> None:
    admitted = classify_execution(
        _execution("browser.direct_control"),
        steps={},
        adaptive=PathReference("admission_1", valid=True),
    )
    assert admitted["selection_path"] == "adaptive_admission_recorded"
    assert admitted["admission_recorded"] is True


def test_private_one_case_readback_verifies_executions(tmp_path: Path) -> None:
    artifact = tmp_path / "episode"
    run = run_hypothesis_suite(artifact, case_ids=("toy-network-002",))
    output = tmp_path / "paths.json"
    readback = readback_artifact(artifact, output)
    assert len(readback["cases"][0]["executions"]) == len(run["runs"][0]["executions"])
    assert verify_readback(artifact, output)["integrity_verified"] is True
