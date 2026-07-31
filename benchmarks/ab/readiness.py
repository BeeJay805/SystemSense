"""Fail-closed preflight gates for any paid A/B run."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from benchmarks.ab.contracts import (
    ExperimentArm,
    ExperimentModel,
    MachineFingerprint,
    canonical_sha256,
)
from benchmarks.ab.tools import (
    SYSTEMSENSE_TOOL_NAMES,
    ToolManifest,
    shared_repair_tools,
)
from benchmarks.models import BenchmarkFamily


class ReadinessError(RuntimeError):
    """The experiment is not safe or comparable enough to start."""


class ExperimentConfig(ExperimentModel):
    schema_version: int = 1
    experiment_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    family: BenchmarkFamily
    scenario_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_model: str = Field(min_length=1, max_length=200)
    human_prompt: str = Field(min_length=20, max_length=2000)
    instructions: str = Field(min_length=20, max_length=4000)
    max_api_rounds: int = Field(default=20, ge=1, le=100)
    max_elapsed_seconds: int = Field(default=900, ge=30, le=7200)
    max_output_tokens: int = Field(default=4096, ge=256, le=32_768)

    def prompt_hash(self) -> str:
        return canonical_sha256(self.human_prompt)

    def config_hash(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class ScenarioQualification(ExperimentModel):
    broken_reproductions: int = Field(ge=0)
    required_broken_reproductions: int = Field(ge=3)
    reference_repair_passed: bool
    restore_reproduced_broken: bool
    hidden_oracle_scored: bool
    systemsense_signal_or_coverage: bool
    systemsense_doctor_ok: bool
    systemsense_case_audit_ok: bool
    recorder_calibrated: bool
    discovered_mcp_tools: tuple[str, ...]


class ArmPreflightEvidence(ExperimentModel):
    schema_version: int = 1
    arm: ExperimentArm
    fingerprint: MachineFingerprint
    prompt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_manifest: ToolManifest
    conversation_items_before: int = Field(ge=0)
    database_case_count_before: int = Field(ge=0)
    discovered_agent_mcp_tools: tuple[str, ...]
    study_answer_files_found: int = Field(ge=0)
    canary_trace_complete: bool
    canary_oracle_passed: bool
    cleanup_passed: bool
    state_leakage_detected: bool


class ReadyArtifact(ExperimentModel):
    schema_version: int = 1
    stage: Literal["canary", "benchmark"]
    experiment_id: str
    scenario_id: str
    scenario_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_model: str
    generated_at: datetime
    baseline_fingerprint_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    systemsense_fingerprint_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_tool_manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    systemsense_tool_manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    gates_passed: tuple[str, ...] = Field(min_length=1)
    readiness_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    def calculated_digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json", exclude={"readiness_digest"}))


def build_ready_artifact(
    *,
    config: ExperimentConfig,
    qualification: ScenarioQualification,
    baseline: ArmPreflightEvidence,
    systemsense: ArmPreflightEvidence,
    generated_at: datetime | None = None,
) -> ReadyArtifact:
    return _build_artifact(
        config=config,
        qualification=qualification,
        baseline=baseline,
        systemsense=systemsense,
        stage="benchmark",
        generated_at=generated_at,
    )


def build_canary_ready_artifact(
    *,
    config: ExperimentConfig,
    qualification: ScenarioQualification,
    baseline: ArmPreflightEvidence,
    systemsense: ArmPreflightEvidence,
    generated_at: datetime | None = None,
) -> ReadyArtifact:
    return _build_artifact(
        config=config,
        qualification=qualification,
        baseline=baseline,
        systemsense=systemsense,
        stage="canary",
        generated_at=generated_at,
    )


def _build_artifact(
    *,
    config: ExperimentConfig,
    qualification: ScenarioQualification,
    baseline: ArmPreflightEvidence,
    systemsense: ArmPreflightEvidence,
    stage: Literal["canary", "benchmark"],
    generated_at: datetime | None,
) -> ReadyArtifact:
    errors: list[str] = []
    _check_qualification(qualification, errors)
    _check_arm_basics(
        config,
        baseline,
        ExperimentArm.BASELINE,
        errors,
        include_canary=stage == "benchmark",
    )
    _check_arm_basics(
        config,
        systemsense,
        ExperimentArm.SYSTEMSENSE,
        errors,
        include_canary=stage == "benchmark",
    )
    _check_pair(baseline, systemsense, errors)
    if errors:
        raise ReadinessError("readiness gates failed: " + "; ".join(errors))

    provisional = ReadyArtifact(
        stage=stage,
        experiment_id=config.experiment_id,
        scenario_id=config.scenario_id,
        scenario_hash=config.scenario_hash,
        config_hash=config.config_hash(),
        prompt_hash=config.prompt_hash(),
        requested_model=config.requested_model,
        generated_at=generated_at or datetime.now(UTC),
        baseline_fingerprint_hash=baseline.fingerprint.comparison_hash(),
        systemsense_fingerprint_hash=systemsense.fingerprint.comparison_hash(),
        baseline_tool_manifest_hash=baseline.tool_manifest.manifest_hash(),
        systemsense_tool_manifest_hash=systemsense.tool_manifest.manifest_hash(),
        gates_passed=_gates(stage),
        readiness_digest="0" * 64,
    )
    return provisional.model_copy(update={"readiness_digest": provisional.calculated_digest()})


def write_ready_artifact(artifact: ReadyArtifact, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        artifact.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )


def load_ready_artifact(
    path: Path,
    *,
    expected_config: ExperimentConfig,
    expected_stage: Literal["canary", "benchmark"] = "benchmark",
) -> ReadyArtifact:
    if not path.is_file():
        raise ReadinessError(f"readiness artifact is missing: {path}")
    try:
        artifact = ReadyArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ReadinessError("readiness artifact is invalid") from error
    if artifact.readiness_digest != artifact.calculated_digest():
        raise ReadinessError("readiness artifact digest does not match its contents")
    if artifact.stage != expected_stage:
        raise ReadinessError(
            f"readiness artifact is for {artifact.stage}, expected {expected_stage}"
        )
    if artifact.config_hash != expected_config.config_hash():
        raise ReadinessError("readiness artifact does not match the current experiment config")
    return artifact


def _check_qualification(
    qualification: ScenarioQualification,
    errors: list[str],
) -> None:
    if qualification.broken_reproductions < qualification.required_broken_reproductions:
        errors.append("broken-state reproduction count is too low")
    boolean_gates = {
        "reference repair failed": qualification.reference_repair_passed,
        "restore did not reproduce the fault": qualification.restore_reproduced_broken,
        "hidden oracle could not score the repair": qualification.hidden_oracle_scored,
        "SystemSense found neither a signal nor explicit coverage": (
            qualification.systemsense_signal_or_coverage
        ),
        "SystemSense doctor failed": qualification.systemsense_doctor_ok,
        "SystemSense case audit failed": qualification.systemsense_case_audit_ok,
        "usage recorder calibration failed": qualification.recorder_calibrated,
    }
    errors.extend(message for message, passed in boolean_gates.items() if not passed)
    if set(qualification.discovered_mcp_tools) != set(SYSTEMSENSE_TOOL_NAMES):
        errors.append("SystemSense MCP discovery did not return the exact six tools")


def _check_arm_basics(
    config: ExperimentConfig,
    evidence: ArmPreflightEvidence,
    expected_arm: ExperimentArm,
    errors: list[str],
    *,
    include_canary: bool,
) -> None:
    if evidence.arm is not expected_arm or evidence.fingerprint.arm is not expected_arm:
        errors.append(f"{expected_arm.value} evidence has the wrong arm identity")
    if evidence.tool_manifest.arm is not expected_arm:
        errors.append(f"{expected_arm.value} tool manifest has the wrong arm identity")
    if evidence.prompt_hash != config.prompt_hash():
        errors.append(f"{expected_arm.value} prompt hash differs")
    if evidence.conversation_items_before != 0:
        errors.append(f"{expected_arm.value} conversation is not empty")
    if evidence.database_case_count_before != 0:
        errors.append(f"{expected_arm.value} SystemSense database is not fresh")
    if evidence.study_answer_files_found != 0:
        errors.append(f"{expected_arm.value} contains study answers")
    if include_canary:
        if not (
            evidence.canary_trace_complete
            and evidence.canary_oracle_passed
            and evidence.cleanup_passed
        ):
            errors.append(f"{expected_arm.value} nonstudy canary did not pass")
        if evidence.state_leakage_detected:
            errors.append(f"{expected_arm.value} state leakage was detected")


def _check_pair(
    baseline: ArmPreflightEvidence,
    systemsense: ArmPreflightEvidence,
    errors: list[str],
) -> None:
    if baseline.fingerprint.comparison_hash() != systemsense.fingerprint.comparison_hash():
        errors.append("clone fingerprints differ")

    shared = {tool.name: tool for tool in shared_repair_tools()}
    baseline_tools = baseline.tool_manifest.by_name()
    systemsense_tools = systemsense.tool_manifest.by_name()
    if baseline_tools != shared:
        errors.append("baseline repair tools differ from the frozen shared manifest")
    if any(systemsense_tools.get(name) != definition for name, definition in shared.items()):
        errors.append("repair tools match gate failed")

    treatment_only = set(systemsense_tools) - set(baseline_tools)
    if treatment_only != set(SYSTEMSENSE_TOOL_NAMES):
        errors.append("treatment must add the exact six SystemSense tools")
    if set(baseline.discovered_agent_mcp_tools):
        errors.append("baseline unexpectedly exposes MCP tools")
    if set(systemsense.discovered_agent_mcp_tools) != set(SYSTEMSENSE_TOOL_NAMES):
        errors.append("treatment agent did not discover the exact six MCP tools")


def _gates(stage: Literal["canary", "benchmark"]) -> tuple[str, ...]:
    common = (
        "scenario_qualification_passed",
        "clone_fingerprints_match",
        "prompt_and_empty_state_match",
        "repair_tools_match",
        "treatment_adds_exact_six_mcp_tools",
        "systemsense_health_and_audit_passed",
    )
    if stage == "canary":
        return (*common, "ready_for_nonstudy_canary")
    return (
        *common,
        "nonstudy_canary_passed",
        "cleanup_and_isolation_passed",
    )
