"""Operator CLI for the gated live A/B experiment."""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, NoReturn, cast

import typer
from pydantic import BaseModel

from benchmarks.ab.agent import OpenAIDebugger
from benchmarks.ab.analysis import (
    PairedAnalysis,
    RunOutcome,
    analyze_paired_runs,
    outcome_from_trace,
    recommend_final_pair_count,
)
from benchmarks.ab.contracts import ExperimentArm
from benchmarks.ab.executors import ExperimentToolExecutor, PowerShellExecutor
from benchmarks.ab.fingerprint import (
    capture_fingerprint,
    fingerprint_differences,
    load_fingerprint,
    write_fingerprint,
)
from benchmarks.ab.live_runner import PaidRunLockedError, authorize_paid_run
from benchmarks.ab.openai_transport import OpenAIResponsesTransport
from benchmarks.ab.readiness import (
    ArmPreflightEvidence,
    ExperimentConfig,
    ReadinessError,
    ScenarioQualification,
    build_canary_ready_artifact,
    build_ready_artifact,
    write_ready_artifact,
)
from benchmarks.ab.recorder import RunTrace, TraceRecorder, calibrate_recorder
from benchmarks.ab.scenario import load_scenario
from benchmarks.ab.scenario_execution import (
    ScenarioScriptError,
    qualify_scenario_scripts,
    run_scenario_script,
)
from benchmarks.ab.schedule import create_balanced_schedule
from benchmarks.ab.systemsense_bridge import MCPToolBridge, qualify_systemsense
from benchmarks.ab.tools import ToolDefinition, ToolManifest, shared_repair_tools
from systemsense.application.case_service import CaseService
from systemsense.mcp_server import (
    MCPWorkspace,
    default_case_runtime,
    default_planner,
)
from systemsense.storage.sqlite_store import SQLiteStore

app = typer.Typer(
    name="systemsense-ab",
    help="Build, verify, run, and analyze controlled SystemSense A/B experiments.",
    no_args_is_help=True,
)
_INSTRUCTIONS = (
    "You are the Windows debugger. Diagnose the reported problem, make only safe "
    "local changes needed to repair it, preserve user files and installed "
    "applications, and verify the original action works. Use only the provided "
    "tools. Do not claim success without verification."
)


@app.command("init")
def initialize(
    scenario: Annotated[Path, typer.Option(exists=True, file_okay=True, dir_okay=True)],
    requested_model: Annotated[str, typer.Option("--model")],
    experiment_id: Annotated[str, typer.Option()],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Freeze the scenario, prompt, model request, and agent instructions."""

    loaded = load_scenario(scenario)
    config = ExperimentConfig(
        experiment_id=experiment_id,
        scenario_id=loaded.manifest.scenario_id,
        family=loaded.manifest.family,
        scenario_hash=loaded.content_hash,
        requested_model=requested_model,
        human_prompt=loaded.manifest.human_prompt,
        instructions=_INSTRUCTIONS,
    )
    _write_model(config, output)
    _emit(config)


@app.command("meter-check")
def meter_check() -> None:
    """Calibrate usage aggregation against a fixed synthetic response."""

    result = calibrate_recorder()
    _emit(result)
    if not result.passed:
        raise typer.Exit(1)


@app.command("scenario-check")
def scenario_check(
    scenario: Annotated[Path, typer.Option(exists=True)],
    state_directory: Annotated[Path, typer.Option()],
) -> None:
    """Run the fault, broken oracle, reference repair, and fixed oracle three times."""

    try:
        result = qualify_scenario_scripts(
            load_scenario(scenario),
            state_directory=state_directory,
            python_executable=Path(sys.executable),
        )
    except ScenarioScriptError as error:
        _fail(str(error))
    _emit(result)


@app.command("capture-fingerprint")
def capture_fingerprint_command(
    scenario: Annotated[Path, typer.Option(exists=True)],
    arm: Annotated[ExperimentArm, typer.Option()],
    clone_id: Annotated[str, typer.Option()],
    parent_snapshot_id: Annotated[str, typer.Option()],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Capture the ten parity categories from one faulted clone."""

    loaded = load_scenario(scenario)
    fingerprint = capture_fingerprint(
        script_path=Path(__file__).with_name("capture-fingerprint.ps1"),
        arm=arm,
        clone_id=clone_id,
        parent_snapshot_id=parent_snapshot_id,
        scenario_root=loaded.root,
        python_executable=Path(sys.executable),
    )
    write_fingerprint(fingerprint, output)
    _emit(fingerprint)


@app.command("compare-fingerprints")
def compare_fingerprints_command(
    baseline: Annotated[Path, typer.Option(exists=True)],
    systemsense: Annotated[Path, typer.Option(exists=True)],
) -> None:
    """Report all parity categories that differ between clones."""

    differences = fingerprint_differences(
        load_fingerprint(baseline),
        load_fingerprint(systemsense),
    )
    _emit({"match": not differences, "differences": differences})
    if differences:
        raise typer.Exit(1)


@app.command("qualify")
def qualify(
    scenario: Annotated[Path, typer.Option(exists=True)],
    state_directory: Annotated[Path, typer.Option()],
    database: Annotated[Path, typer.Option()],
    original_broken_fingerprint: Annotated[Path, typer.Option(exists=True)],
    restored_broken_fingerprint: Annotated[Path, typer.Option(exists=True)],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Qualify reproducibility, hidden oracles, MCP health, evidence, and metering."""

    loaded = load_scenario(scenario)
    script_result = qualify_scenario_scripts(
        loaded,
        state_directory=state_directory,
        python_executable=Path(sys.executable),
    )
    inject = run_scenario_script(
        loaded.script_paths["inject"],
        state_directory=state_directory,
        python_executable=Path(sys.executable),
    )
    if inject.exit_code != 0:
        _fail(inject.stderr or inject.stdout)
    try:
        broken = run_scenario_script(
            loaded.script_paths["verify_broken"],
            state_directory=state_directory,
            python_executable=Path(sys.executable),
        )
        if broken.exit_code != 0:
            _fail(broken.stderr or broken.stdout)
        with SQLiteStore(database) as store:
            if store.case_count() or any(store.record_counts().values()):
                _fail("qualification requires a fresh SystemSense database")
            workspace = _workspace(store)
            systemsense = qualify_systemsense(
                workspace=workspace,
                store=store,
                symptom=loaded.manifest.human_prompt,
                expected_evidence_terms=loaded.manifest.expected_evidence_terms,
                expected_coverage_categories=(loaded.manifest.expected_coverage_categories),
            )
    finally:
        repair = run_scenario_script(
            loaded.script_paths["repair_reference"],
            state_directory=state_directory,
            python_executable=Path(sys.executable),
        )
    fixed = run_scenario_script(
        loaded.script_paths["verify_fixed"],
        state_directory=state_directory,
        python_executable=Path(sys.executable),
    )
    calibration = calibrate_recorder()
    qualification = ScenarioQualification(
        broken_reproductions=script_result.broken_reproductions,
        required_broken_reproductions=loaded.manifest.qualification_repetitions,
        reference_repair_passed=(
            script_result.reference_repairs == loaded.manifest.qualification_repetitions
            and repair.exit_code == 0
        ),
        restore_reproduced_broken=not fingerprint_differences(
            load_fingerprint(original_broken_fingerprint),
            load_fingerprint(restored_broken_fingerprint),
        ),
        hidden_oracle_scored=(
            script_result.fixed_oracle_passes == loaded.manifest.qualification_repetitions
            and fixed.exit_code == 0
        ),
        systemsense_signal_found=systemsense.signal_found,
        systemsense_explicit_coverage_found=systemsense.explicit_coverage_found,
        systemsense_doctor_ok=systemsense.doctor_ok,
        systemsense_case_audit_ok=systemsense.case_audit_ok,
        recorder_calibrated=calibration.passed,
        discovered_mcp_tools=systemsense.discovered_tool_names,
    )
    _write_model(qualification, output)
    _emit(qualification)


@app.command("arm-evidence")
def arm_evidence(
    config_path: Annotated[Path, typer.Option("--config", exists=True)],
    fingerprint_path: Annotated[Path, typer.Option("--fingerprint", exists=True)],
    database: Annotated[Path, typer.Option()],
    arm: Annotated[ExperimentArm, typer.Option()],
    study_answer_directory: Annotated[Path, typer.Option()],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Capture pre-canary arm state and the exact tool manifest."""

    config = _read_model(config_path, ExperimentConfig)
    fingerprint = load_fingerprint(fingerprint_path)
    if fingerprint.arm is not arm:
        _fail("fingerprint arm does not match --arm")
    with SQLiteStore(database) as store:
        count_before = store.case_count()
        tools, discovered = _tool_definitions(arm, store)
    answer_count = (
        sum(1 for path in study_answer_directory.rglob("*") if path.is_file())
        if study_answer_directory.exists()
        else 0
    )
    evidence = ArmPreflightEvidence(
        arm=arm,
        fingerprint=fingerprint,
        prompt_hash=config.prompt_hash(),
        tool_manifest=ToolManifest(arm=arm, tools=tools),
        conversation_items_before=0,
        database_case_count_before=count_before,
        discovered_agent_mcp_tools=discovered,
        study_answer_files_found=answer_count,
        canary_trace_complete=False,
        canary_oracle_passed=False,
        cleanup_passed=False,
        state_leakage_detected=False,
    )
    _write_model(evidence, output)
    _emit(evidence)


@app.command("finalize-arm")
def finalize_arm(
    evidence_path: Annotated[Path, typer.Option("--evidence", exists=True)],
    canary_trace_path: Annotated[Path, typer.Option("--canary-trace", exists=True)],
    restored_fingerprint_path: Annotated[Path, typer.Option("--restored-fingerprint", exists=True)],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Bind a scored canary and clean-restore proof to existing arm evidence."""

    evidence = _read_model(evidence_path, ArmPreflightEvidence)
    trace = _read_model(canary_trace_path, RunTrace)
    restored = load_fingerprint(restored_fingerprint_path)
    if trace.arm is not evidence.arm or restored.arm is not evidence.arm:
        _fail("canary trace or restored fingerprint has the wrong arm")
    if trace.prompt_hash != evidence.prompt_hash:
        _fail("canary prompt hash differs from preflight")
    if trace.tool_manifest_hash != evidence.tool_manifest.manifest_hash():
        _fail("canary tool manifest differs from preflight")
    leakage = fingerprint_differences(evidence.fingerprint, restored)
    finalized = evidence.model_copy(
        update={
            "canary_trace_complete": trace.response_count > 0,
            "canary_oracle_passed": trace.oracle_passed is True,
            "cleanup_passed": not leakage,
            "state_leakage_detected": bool(leakage),
        }
    )
    _write_model(finalized, output)
    _emit(finalized)


@app.command("build-ready")
def build_ready(
    stage: Annotated[Literal["canary", "benchmark"], typer.Option()],
    config_path: Annotated[Path, typer.Option("--config", exists=True)],
    qualification_path: Annotated[Path, typer.Option("--qualification", exists=True)],
    baseline_path: Annotated[Path, typer.Option("--baseline", exists=True)],
    systemsense_path: Annotated[Path, typer.Option("--systemsense", exists=True)],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Emit the hash-bound artifact that unlocks only the requested next stage."""

    config = _read_model(config_path, ExperimentConfig)
    qualification = _read_model(qualification_path, ScenarioQualification)
    baseline = _read_model(baseline_path, ArmPreflightEvidence)
    systemsense = _read_model(systemsense_path, ArmPreflightEvidence)
    try:
        artifact = (
            build_canary_ready_artifact(
                config=config,
                qualification=qualification,
                baseline=baseline,
                systemsense=systemsense,
            )
            if stage == "canary"
            else build_ready_artifact(
                config=config,
                qualification=qualification,
                baseline=baseline,
                systemsense=systemsense,
            )
        )
    except ReadinessError as error:
        _fail(str(error))
    write_ready_artifact(artifact, output)
    _emit(artifact)


@app.command("run-arm")
def run_arm(
    mode: Annotated[Literal["canary", "study"], typer.Option()],
    arm: Annotated[ExperimentArm, typer.Option()],
    pair_id: Annotated[str, typer.Option()],
    config_path: Annotated[Path, typer.Option("--config", exists=True)],
    ready_path: Annotated[Path, typer.Option("--ready", exists=True)],
    scenario: Annotated[Path, typer.Option(exists=True)],
    before_fingerprint_path: Annotated[Path, typer.Option("--before-fingerprint", exists=True)],
    database: Annotated[Path, typer.Option()],
    state_directory: Annotated[Path, typer.Option()],
    output: Annotated[Path, typer.Option()],
    allow_paid_run: Annotated[bool, typer.Option()] = False,
) -> None:
    """Run one fresh debugger arm, hidden oracle, collateral check, and trace."""

    config = _read_model(config_path, ExperimentConfig)
    loaded = load_scenario(scenario)
    if loaded.content_hash != config.scenario_hash:
        _fail("scenario bytes differ from the frozen experiment config")
    expected_stage: Literal["canary", "benchmark"] = "canary" if mode == "canary" else "benchmark"
    try:
        ready = authorize_paid_run(
            ready_path=ready_path,
            config=config,
            allow_paid_run=allow_paid_run,
            api_key=os.environ.get("OPENAI_API_KEY"),
            expected_stage=expected_stage,
        )
    except PaidRunLockedError as error:
        _fail(str(error))
    before = load_fingerprint(before_fingerprint_path)
    expected_fingerprint = (
        ready.baseline_fingerprint_hash
        if arm is ExperimentArm.BASELINE
        else ready.systemsense_fingerprint_hash
    )
    if before.arm is not arm or before.comparison_hash() != expected_fingerprint:
        _fail("run fingerprint does not match the authorized arm")
    broken = run_scenario_script(
        loaded.script_paths["verify_broken"],
        state_directory=state_directory,
        python_executable=Path(sys.executable),
    )
    if broken.exit_code != 0:
        _fail("fault is not active immediately before the model run")

    with SQLiteStore(database) as store:
        if store.case_count() != 0:
            _fail("model run requires a fresh SystemSense database")
        tools, _discovered = _tool_definitions(arm, store)
        manifest = ToolManifest(arm=arm, tools=tools)
        expected_tool_hash = (
            ready.baseline_tool_manifest_hash
            if arm is ExperimentArm.BASELINE
            else ready.systemsense_tool_manifest_hash
        )
        if manifest.manifest_hash() != expected_tool_hash:
            _fail("current tool manifest differs from the authorized manifest")
        bridge = MCPToolBridge(_workspace(store)) if arm is ExperimentArm.SYSTEMSENSE else None
        executor = ExperimentToolExecutor(
            powershell=PowerShellExecutor(
                working_directory=loaded.root,
                environment={"SYSTEMSENSE_AB_STATE_DIR": str(state_directory.resolve())},
            ),
            systemsense=bridge,
        )
        transport = OpenAIResponsesTransport(
            api_key=cast("str", os.environ.get("OPENAI_API_KEY")),
            timeout_seconds=min(180, config.max_elapsed_seconds),
        )
        trace = OpenAIDebugger(
            transport=transport,
            executor=executor,
            config=config,
            arm=arm,
            tool_manifest=manifest,
            run_id=f"run_{uuid.uuid4().hex}",
            pair_id=pair_id,
        ).run()

    oracle = run_scenario_script(
        loaded.script_paths["verify_fixed"],
        state_directory=state_directory,
        python_executable=Path(sys.executable),
    )
    oracle_finished_at = datetime.now(UTC)
    cleanup = run_scenario_script(
        loaded.script_paths["repair_reference"],
        state_directory=state_directory,
        python_executable=Path(sys.executable),
    )
    collateral_started = time.perf_counter()
    after = capture_fingerprint(
        script_path=Path(__file__).with_name("capture-fingerprint.ps1"),
        arm=arm,
        clone_id=before.clone_id,
        parent_snapshot_id=before.parent_snapshot_id,
        scenario_root=loaded.root,
        python_executable=Path(sys.executable),
    )
    collateral_elapsed_ms = round((time.perf_counter() - collateral_started) * 1000)
    collateral_differences = tuple(
        item for item in fingerprint_differences(before, after) if item != "state.fault_state"
    )
    scored = trace.model_copy(
        update={
            "finished_at": oracle_finished_at,
            "elapsed_ms": max(
                0,
                round((oracle_finished_at - trace.started_at).total_seconds() * 1000),
            ),
            "oracle_elapsed_ms": oracle.elapsed_ms,
            "oracle_result": oracle.model_dump(mode="json"),
            "oracle_passed": oracle.exit_code == 0,
            "collateral_check_elapsed_ms": collateral_elapsed_ms,
            "collateral_change_detected": bool(collateral_differences),
            "collateral_differences": collateral_differences,
        }
    )
    TraceRecorder.write(scored, output)
    write_fingerprint(after, output.with_suffix(".post-fingerprint.json"))
    _write_model(outcome_from_trace(scored), output.with_suffix(".outcome.json"))
    _emit(
        {
            "trace": str(output),
            "oracle_passed": scored.oracle_passed,
            "collateral_differences": collateral_differences,
            "cleanup_exit_code": cleanup.exit_code,
            "usage": scored.usage.model_dump(mode="json"),
        }
    )


@app.command("analyze")
def analyze(
    results_directory: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    output: Annotated[Path, typer.Option()],
    required_pair_count: Annotated[int, typer.Option(min=2)],
    bootstrap_resamples: Annotated[int, typer.Option(min=100)] = 10_000,
    random_seed: Annotated[int, typer.Option()] = 0,
) -> None:
    """Analyze every paired outcome without dropping failures or timeouts."""

    paths = sorted(results_directory.glob("*.outcome.json"))
    if not paths:
        _fail("no *.outcome.json files were found")
    runs = tuple(_read_model(path, RunOutcome) for path in paths)
    report: PairedAnalysis = analyze_paired_runs(
        runs,
        required_pair_count=required_pair_count,
        bootstrap_resamples=bootstrap_resamples,
        random_seed=random_seed,
    )
    _write_model(report, output)
    _emit(report)


@app.command("schedule")
def schedule(
    scenario_id: Annotated[list[str], typer.Option("--scenario-id")],
    repetitions: Annotated[int, typer.Option(min=1)],
    random_seed: Annotated[int, typer.Option()],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Freeze a seeded, balanced order for paired arm runs."""

    result = create_balanced_schedule(
        scenario_ids=tuple(scenario_id),
        repetitions=repetitions,
        random_seed=random_seed,
    )
    _write_model(result, output)
    _emit(result)


@app.command("pilot-size")
def pilot_size(
    paired_savings_file: Annotated[Path, typer.Option(exists=True)],
    observed_failure_rate: Annotated[float, typer.Option(min=0, max=0.999999)],
    minimum_detectable_savings_pct: Annotated[float, typer.Option(min=0.000001)],
    minimum_final_pairs: Annotated[int, typer.Option(min=2)],
    output: Annotated[Path, typer.Option()],
) -> None:
    """Convert pilot variance and failures into a frozen final pair count."""

    raw: object = json.loads(paired_savings_file.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        _fail("paired savings file must be a JSON array of numbers")
    raw_values = cast("list[object]", raw)
    if not all(
        isinstance(value, (int, float)) and not isinstance(value, bool) for value in raw_values
    ):
        _fail("paired savings file must be a JSON array of numbers")
    result = recommend_final_pair_count(
        paired_savings_pct=tuple(float(cast("int | float", value)) for value in raw_values),
        observed_failure_rate=observed_failure_rate,
        minimum_detectable_savings_pct=minimum_detectable_savings_pct,
        minimum_final_pairs=minimum_final_pairs,
    )
    _write_model(result, output)
    _emit(result)


def _workspace(store: SQLiteStore) -> MCPWorkspace:
    service = CaseService(store, default_planner())
    return MCPWorkspace(
        store=store,
        case_service=service,
        case_runtime=default_case_runtime(store, case_service=service),
    )


def _tool_definitions(
    arm: ExperimentArm,
    store: SQLiteStore,
) -> tuple[tuple[ToolDefinition, ...], tuple[str, ...]]:
    shared = shared_repair_tools()
    if arm is ExperimentArm.BASELINE:
        return shared, ()
    definitions = MCPToolBridge(_workspace(store)).definitions()
    return shared + definitions, tuple(tool.name for tool in definitions)


def _read_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    try:
        return model.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        _fail(f"{path.name} is invalid: {error}")


def _write_model(model: BaseModel, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _emit(value: object) -> None:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    typer.echo(
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _fail(message: str) -> NoReturn:
    typer.echo(json.dumps({"error": message}, separators=(",", ":")), err=True)
    raise typer.Exit(2)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
