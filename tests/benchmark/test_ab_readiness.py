from datetime import UTC, datetime
from pathlib import Path

import pytest

from benchmarks.ab.contracts import (
    FINGERPRINT_STATE_KEYS,
    ExperimentArm,
    MachineFingerprint,
)
from benchmarks.ab.readiness import (
    ArmPreflightEvidence,
    ExperimentConfig,
    ReadinessError,
    ScenarioQualification,
    build_canary_ready_artifact,
    build_ready_artifact,
    load_ready_artifact,
    write_ready_artifact,
)
from benchmarks.ab.tools import (
    SYSTEMSENSE_TOOL_NAMES,
    ToolDefinition,
    ToolManifest,
    shared_repair_tools,
)
from benchmarks.models import BenchmarkFamily


def _system_tools() -> tuple[ToolDefinition, ...]:
    return tuple(
        ToolDefinition(
            name=name,
            description=f"{name} test schema",
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
        )
        for name in sorted(SYSTEMSENSE_TOOL_NAMES)
    )


def _fingerprint(arm: ExperimentArm, clone_id: str) -> MachineFingerprint:
    return MachineFingerprint(
        arm=arm,
        clone_id=clone_id,
        parent_snapshot_id="snapshot-1",
        state={key: f"sha256:{key}" for key in FINGERPRINT_STATE_KEYS},
    )


def _config() -> ExperimentConfig:
    return ExperimentConfig(
        experiment_id="port-conflict-canary",
        scenario_id="application.port_conflict",
        family=BenchmarkFamily.APPLICATION,
        scenario_hash="a" * 64,
        requested_model="gpt-5.6-sol",
        human_prompt="My local development app stopped starting with a socket error.",
        instructions="Diagnose, repair, and verify using only the provided tools.",
    )


def _qualification() -> ScenarioQualification:
    return ScenarioQualification(
        broken_reproductions=3,
        required_broken_reproductions=3,
        reference_repair_passed=True,
        restore_reproduced_broken=True,
        hidden_oracle_scored=True,
        systemsense_signal_or_coverage=True,
        systemsense_doctor_ok=True,
        systemsense_case_audit_ok=True,
        recorder_calibrated=True,
        discovered_mcp_tools=tuple(sorted(SYSTEMSENSE_TOOL_NAMES)),
    )


def _arm(arm: ExperimentArm) -> ArmPreflightEvidence:
    treatment = arm is ExperimentArm.SYSTEMSENSE
    tools = shared_repair_tools() + (_system_tools() if treatment else ())
    return ArmPreflightEvidence(
        arm=arm,
        fingerprint=_fingerprint(arm, f"{arm.value}-clone"),
        prompt_hash=_config().prompt_hash(),
        tool_manifest=ToolManifest(arm=arm, tools=tools),
        conversation_items_before=0,
        database_case_count_before=0,
        discovered_agent_mcp_tools=(tuple(sorted(SYSTEMSENSE_TOOL_NAMES)) if treatment else ()),
        study_answer_files_found=0,
        canary_trace_complete=True,
        canary_oracle_passed=True,
        cleanup_passed=True,
        state_leakage_detected=False,
    )


def test_ready_artifact_requires_exact_parity_and_all_gates(tmp_path: Path) -> None:
    config = _config()
    artifact = build_ready_artifact(
        config=config,
        qualification=_qualification(),
        baseline=_arm(ExperimentArm.BASELINE),
        systemsense=_arm(ExperimentArm.SYSTEMSENSE),
        generated_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
    )
    ready_path = tmp_path / "READY_TO_BENCHMARK.json"

    write_ready_artifact(artifact, ready_path)
    loaded = load_ready_artifact(ready_path, expected_config=config)

    assert loaded.readiness_digest == artifact.readiness_digest
    assert loaded.baseline_fingerprint_hash == loaded.systemsense_fingerprint_hash
    assert set(loaded.gates_passed) >= {
        "clone_fingerprints_match",
        "repair_tools_match",
        "treatment_adds_exact_six_mcp_tools",
        "nonstudy_canary_passed",
    }
    assert loaded.stage == "benchmark"


def test_canary_gate_does_not_require_a_canary_that_has_not_run() -> None:
    baseline = _arm(ExperimentArm.BASELINE).model_copy(
        update={
            "canary_trace_complete": False,
            "canary_oracle_passed": False,
            "cleanup_passed": False,
        }
    )
    systemsense = _arm(ExperimentArm.SYSTEMSENSE).model_copy(
        update={
            "canary_trace_complete": False,
            "canary_oracle_passed": False,
            "cleanup_passed": False,
        }
    )

    artifact = build_canary_ready_artifact(
        config=_config(),
        qualification=_qualification(),
        baseline=baseline,
        systemsense=systemsense,
    )

    assert artifact.stage == "canary"
    assert "ready_for_nonstudy_canary" in artifact.gates_passed


def test_ready_artifact_rejects_vm_drift() -> None:
    systemsense = _arm(ExperimentArm.SYSTEMSENSE)
    systemsense = systemsense.model_copy(
        update={
            "fingerprint": systemsense.fingerprint.model_copy(
                update={
                    "state": {
                        **systemsense.fingerprint.state,
                        "packages": "drifted",
                    }
                }
            )
        }
    )

    with pytest.raises(ReadinessError, match="clone fingerprints differ"):
        build_ready_artifact(
            config=_config(),
            qualification=_qualification(),
            baseline=_arm(ExperimentArm.BASELINE),
            systemsense=systemsense,
        )


def test_ready_artifact_rejects_extra_treatment_tool() -> None:
    systemsense = _arm(ExperimentArm.SYSTEMSENSE)
    extra = ToolDefinition(
        name="secret_answer",
        description="Invalid treatment-only hint",
        parameters={"type": "object", "properties": {}},
    )
    systemsense = systemsense.model_copy(
        update={
            "tool_manifest": systemsense.tool_manifest.model_copy(
                update={"tools": (*systemsense.tool_manifest.tools, extra)}
            )
        }
    )

    with pytest.raises(ReadinessError, match="exact six"):
        build_ready_artifact(
            config=_config(),
            qualification=_qualification(),
            baseline=_arm(ExperimentArm.BASELINE),
            systemsense=systemsense,
        )


def test_ready_loader_rejects_tampering(tmp_path: Path) -> None:
    artifact = build_ready_artifact(
        config=_config(),
        qualification=_qualification(),
        baseline=_arm(ExperimentArm.BASELINE),
        systemsense=_arm(ExperimentArm.SYSTEMSENSE),
    )
    path = tmp_path / "READY_TO_BENCHMARK.json"
    write_ready_artifact(artifact, path)
    raw = path.read_text(encoding="utf-8").replace("gpt-5.6-sol", "gpt-5.6-terra")
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ReadinessError, match="digest"):
        load_ready_artifact(path, expected_config=_config())
