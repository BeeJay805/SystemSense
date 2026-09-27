"""Exercise frozen toy worlds through the public read-only Investigator loop.

Probe closures hold the evaluator's toy world. The investigator receives the
same symptom, baseline and ordered menu within each family. This captures
runtime behavior and custody; it does not validate Windows diagnosis.
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import subprocess
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict

from benchmarks.sequential_visible_matrix import (
    _WORLDS,  # pyright: ignore[reportPrivateUsage]
    _compatible_worlds,  # pyright: ignore[reportPrivateUsage]
    _file_digest,  # pyright: ignore[reportPrivateUsage]
    _toy_probe_closures,  # pyright: ignore[reportPrivateUsage]
    build_matrix,
)
from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import ProbeCapability
from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeOutputFieldV1,
    ProbeSafety,
    ProbeToolMetadataV1,
    SafetyClass,
    SelfWrite,
)
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_ROOT = Path(__file__).resolve().parents[1]
_SELECTED = (
    "toy-network-001",
    "toy-network-002",
    "toy-network-003",
    "toy-network-007",
    "toy-application-001",
    "toy-application-002",
    "toy-application-003",
    "toy-application-007",
)
_BASELINE_ID = "core.system"
_SELF_WRITES = (SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD)


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _git_head(path: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _registered_case(store: SQLiteStore, *, initial: dict[str, Any], world: Any) -> Investigator:
    closures = _toy_probe_closures(world)
    menu = [
        {
            "probe_id": _BASELINE_ID,
            "description": "Read frozen toy baseline",
            "access": "read_only_toy",
        },
        *initial["ordered_probe_menu"],
    ]
    definitions: list[ProbeDefinition] = []
    capabilities: list[ProbeCapability] = []
    for item in menu:
        probe_id = str(item["probe_id"])
        description = str(item["description"])

        def collect(
            _parameters: dict[str, JsonValue], *, selected: str = probe_id
        ) -> ProbeObservation:
            now = datetime.now(UTC)
            if selected == _BASELINE_ID:
                return ProbeObservation(
                    summary="Frozen toy baseline report",
                    facts={"baseline_facts": initial["baseline_facts"]},
                    observed_at=now,
                    captured_at=now,
                )
            value = closures[selected]()
            return ProbeObservation(
                summary=f"Frozen toy {selected} measurement",
                facts={
                    "measurement_status": "unavailable" if value is None else "observed",
                    "observation": value,
                },
                limitations=("Toy measurement unavailable.",) if value is None else (),
                observed_at=now,
                captured_at=now,
            )

        manifest = ProbeManifest(
            probe_id=probe_id,
            version=1,
            implementation_id=f"builtin.toy.sequential.{probe_id}",
            question=description,
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
                self_writes=_SELF_WRITES,
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=1_000, max_output_bytes=32_768, max_records=64),
            category=probe_id.split(".")[0],
        )
        discovery = ProbeToolMetadataV1(
            probe_id=probe_id,
            probe_version=1,
            observable_ids=(probe_id,),
            parameter_fields=(),
            supports_window=False,
            outputs=(ProbeOutputFieldV1(name="observation"),),
            estimated_cost_ms=25,
            resource_class="cpu",
            sensitivity=Sensitivity.SYSTEM_METADATA,
            network_effect="none",
            io_intensity="light",
            target_state_effect="none",
            self_writes=_SELF_WRITES,
            purpose=description,
        )
        definitions.append(
            ProbeDefinition(
                manifest=manifest,
                parameter_model=_NoParameters,
                handler=collect,
                isolated=False,
                discovery=discovery,
            )
        )
        capabilities.append(
            ProbeCapability(
                probe_id=probe_id,
                description=description,
                keywords=frozenset(re.findall(r"[a-z0-9]+", description.casefold())),
                common=probe_id == _BASELINE_ID,
                cost_ms=25,
                resource_class=ResourceClass.CPU,
            )
        )
    planner = DeterministicPlanner(
        candidates=tuple(
            ProbeCandidate(
                probe_id=str(item["probe_id"]),
                cost_ms=25,
                value=1,
                common=item["probe_id"] == _BASELINE_ID,
            )
            for item in menu
        )
    )
    runtime = DiagnosticRuntime(
        store=store,
        case_service=CaseService(store, planner),
        probe_runner=ProbeRunner(definitions=tuple(definitions)),
    )
    return Investigator(
        store=store,
        runtime=runtime,
        capabilities=tuple(capabilities),
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
        knowledge=ReferenceKnowledgeGraph.load_default(),
    )


def _facts(record: dict[str, Any]) -> dict[str, JsonValue]:
    return {str(item["name"]): cast(JsonValue, item["value"]) for item in record["facts"]}


def _readback(store: SQLiteStore, state: Any, initial: dict[str, Any]) -> dict[str, Any]:
    case_id = str(state.case_id)
    offered = [
        {
            "snapshot_id": str(row[0]),
            "captured_at": str(row[1]),
            "request_sha256": str(row[2]),
            "probe_ids": json.loads(str(row[3])),
        }
        for row in store.connection.execute(
            "SELECT snapshot_id,captured_at,request_sha256,candidate_probe_ids_json "
            "FROM decision_snapshots WHERE case_id=? ORDER BY captured_at,snapshot_id",
            (case_id,),
        )
    ]
    selected = [
        {"snapshot_id": str(row[0]), "probe_id": str(row[1]), "execution_id": str(row[2])}
        for row in store.connection.execute(
            "SELECT snapshot_id,probe_id,execution_id FROM decision_execution_links "
            "WHERE case_id=? ORDER BY snapshot_id,execution_id",
            (case_id,),
        )
    ]
    admissions: list[dict[str, Any]] = []
    for table in ("candidate_dispatch_admissions", "collection_followup_admissions"):
        columns = [str(item[1]) for item in store.connection.execute(f"PRAGMA table_info({table})")]
        if "case_id" not in columns:
            continue
        for row in store.connection.execute(f"SELECT * FROM {table} WHERE case_id=?", (case_id,)):
            admissions.append({"table": table, "row": dict(zip(columns, row, strict=True))})
    executions = [
        {
            "execution_id": str(row[0]),
            "probe_id": str(row[1]),
            "status": str(row[2]),
            "started_at": str(row[3]),
            "finished_at": row[4],
            "state_version": row[5],
        }
        for row in store.connection.execute(
            "SELECT execution_id,probe_id,status,started_at,finished_at,state_version "
            "FROM probe_executions WHERE case_id=? ORDER BY started_at,execution_id",
            (case_id,),
        )
    ]
    evidence: list[dict[str, Any]] = []
    for row in store.connection.execute(
        "SELECT evidence_id,source_id,record_json,observed_at,captured_at,execution_id "
        "FROM evidence WHERE case_id=? ORDER BY captured_at,evidence_id",
        (case_id,),
    ):
        record = cast(dict[str, Any], json.loads(str(row[2])))
        evidence.append(
            {
                "evidence_id": str(row[0]),
                "source_id": str(row[1]),
                "observed_at": str(row[3]),
                "captured_at": str(row[4]),
                "execution_id": row[5],
                "statement_kind": record.get("statement_kind"),
                "facts": record.get("facts", []),
                "limitations": record.get("limitations", []),
            }
        )
    steps: list[dict[str, Any]] = [
        cast(dict[str, Any], json.loads(str(row[0])))
        for row in store.connection.execute(
            "SELECT record_json FROM investigation_steps WHERE case_id=? ORDER BY state_version",
            (case_id,),
        )
    ]
    requests = {
        "measurement_gaps": [item.model_dump(mode="json") for item in state.measurement_gaps],
        "pending_distinguishing_probes": [
            item.model_dump(mode="json") for item in state.pending_distinguishing_probes
        ],
        "unmet_evidence_ids": sorted(
            set(map(str, state.requested_evidence_ids))
            - set(map(str, state.completed_evidence_requests))
        ),
        "requested_details": [item.model_dump(mode="json") for item in state.requested_details],
    }
    return {
        "runtime_case_id": case_id,
        "incident_window": {
            "start": state.incident_start.isoformat(),
            "end": state.incident_end.isoformat(),
        },
        "target_binding_status": "unverified_toy_scope",
        "target_binding": None,
        "objective": str(initial["symptom"]),
        "status": state.status.value,
        "outcome": state.outcome.value,
        "stop_reason": state.stop_reason,
        "round_count": state.round_count,
        "offered": offered,
        "selected": selected,
        "admissions": admissions,
        "admission_custody": "recorded" if admissions else "no_separate_admission_rows",
        "executions": executions,
        "evidence": evidence,
        "steps": steps,
        "hypotheses": [item.model_dump(mode="json") for item in state.hypotheses],
        "requests": requests,
        "assessment": state.assessment.model_dump(mode="json") if state.assessment else None,
        "provider_calls": [item.model_dump(mode="json") for item in state.provider_calls],
    }


def _score_after_run(run: dict[str, Any], world: Any) -> dict[str, Any]:
    observations: dict[str, str] = {}
    compatible_before = len(_compatible_worlds(world.domain, observations))
    first_useful_ms: int | None = None
    effects: list[dict[str, Any]] = []
    evidence_by_execution = {
        item["execution_id"]: item
        for item in run["evidence"]
        if item["execution_id"] is not None and item["statement_kind"] == "observed_fact"
    }
    for execution in run["executions"]:
        probe_id = execution["probe_id"]
        if probe_id == _BASELINE_ID:
            continue
        evidence = evidence_by_execution.get(execution["execution_id"])
        utility = "unknown"
        reason = "failed_or_missing_observation"
        if execution["status"] == "ok" and evidence is not None:
            facts = _facts(evidence)
            value = facts.get("observation")
            expected = _toy_probe_closures(world)[probe_id]()
            if value == expected and facts.get("measurement_status") == (
                "unavailable" if expected is None else "observed"
            ):
                if isinstance(value, str) and probe_id not in observations:
                    observations[probe_id] = value
                    compatible_after = len(_compatible_worlds(world.domain, observations))
                    utility = "useful" if compatible_after < compatible_before else "negative"
                    compatible_before = compatible_after
                    reason = "observed_toy_world_elimination"
                else:
                    reason = "unavailable_or_repeated_observation"
            else:
                reason = "evidence_does_not_match_frozen_toy_world"
        elapsed_ms = None
        if execution["finished_at"] is not None:
            elapsed_ms = max(
                0,
                round(
                    (
                        datetime.fromisoformat(str(execution["finished_at"]))
                        - datetime.fromisoformat(str(run["created_at"]))
                    ).total_seconds()
                    * 1000
                ),
            )
        if utility == "useful" and first_useful_ms is None:
            first_useful_ms = elapsed_ms
        effects.append(
            {
                "probe_id": probe_id,
                "execution_id": execution["execution_id"],
                "utility": utility,
                "review_reason": reason,
                "compatible_worlds_after": compatible_before,
                "finished_ms": elapsed_ms,
            }
        )
    no_claim_to_review = not run["hypotheses"] and run["assessment"] is None
    counter_ids = {
        str(run["registered_probe_ids"][index]) for index in world.counterevidence_stage_indices
    }
    observed_ids = {item["probe_id"] for item in effects if item["utility"] != "unknown"}
    return {
        "case_id": world.case_id,
        "role": world.role,
        "root_causes": list(world.root_causes) if world.causal_answer_review != "unknown" else None,
        "causal_answer_review": world.causal_answer_review,
        "observed_effects": effects,
        "first_useful_evidence_ms": first_useful_ms,
        "counterevidence_observed_probe_ids": sorted(counter_ids & observed_ids),
        "counterevidence_unrun_or_unknown_probe_ids": sorted(counter_ids - observed_ids),
        "false_causal_claim_count": 0 if no_claim_to_review else None,
        "false_claim_review_reason": (
            "no_hypotheses_or_assessment"
            if no_claim_to_review
            else "assessment_or_hypothesis_not_adjudicated"
        ),
        "diagnostic_performance_admissible": False,
    }


def run_episode_suite(output_dir: Path, *, case_ids: tuple[str, ...] = _SELECTED) -> dict[str, Any]:
    """Run each case in a fresh DB; unrun and failed probes stay unknown."""

    worlds = {world.case_id: world for world in _WORLDS}
    if not case_ids or len(case_ids) != len(set(case_ids)) or not set(case_ids) <= set(_SELECTED):
        raise ValueError("selection must be unique and within the frozen B-006 set")
    matrix = build_matrix()
    visible = {case["case_id"]: case for case in matrix.visible}
    output_dir.mkdir(parents=False, exist_ok=False)
    (output_dir / "cases").mkdir()
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    report: dict[str, Any] = {
        "classification": "synthetic_investigator_mechanics_only",
        "planned_cases": len(case_ids),
        "runs": [],
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
    }
    labels: list[dict[str, Any]] = []
    for case_id in case_ids:
        world = worlds[case_id]
        initial = visible[case_id]["initial_input"]
        database = output_dir / "cases" / f"{case_id}.db"
        started = time.monotonic()
        failure_stage = "case_setup"
        try:
            with SQLiteStore(database) as store:
                app = _registered_case(store, initial=initial, world=world)
                state = app.create(
                    objective=str(initial["symptom"]),
                    budget_ms=int(initial["budget"]["budget_ms"]),
                    max_rounds=int(initial["budget"]["max_rounds"]),
                    max_probes=int(initial["budget"]["max_probes"]),
                )
                created_at = state.created_at.isoformat()
                failure: str | None = None
                failure_stage = "investigator_run"
                try:
                    state = app.run(str(state.case_id))
                except Exception as error:
                    failure = type(error).__name__
                    state = app.repository.load(str(state.case_id))
                failure_stage = "readback_or_independent_review"
                run = _readback(store, state, initial)
                run.update(
                    {
                        "case_id": case_id,
                        "domain": world.domain,
                        "initial_input_sha256": visible[case_id]["initial_sha256"],
                        "created_at": created_at,
                        "wall_ms": round((time.monotonic() - started) * 1000),
                        "failure_type": failure,
                        "failure_stage": "investigator_run" if failure else None,
                        "runtime_complete": state.status is InvestigationStatus.COMPLETE,
                        "registered_probe_ids": [
                            _BASELINE_ID,
                            *(item["probe_id"] for item in initial["ordered_probe_menu"]),
                        ],
                        "model_cost_usd": 0.0,
                        "host_impact_ms": None,
                    }
                )
                executed_ids = {item["probe_id"] for item in run["executions"]}
                run["unrun_probe_ids"] = [
                    item["probe_id"]
                    for item in initial["ordered_probe_menu"]
                    if item["probe_id"] not in executed_ids
                ]
                label = _score_after_run(run, world)
        except Exception as error:
            run: dict[str, Any] = {
                "case_id": case_id,
                "domain": world.domain,
                "initial_input_sha256": visible[case_id]["initial_sha256"],
                "runtime_complete": False,
                "failure_stage": failure_stage,
                "failure_type": type(error).__name__,
                "wall_ms": round((time.monotonic() - started) * 1000),
                "offered": [],
                "selected": [],
                "admissions": [],
                "executions": [],
                "evidence": [],
                "hypotheses": [],
                "assessment": None,
                "requests": None,
                "stop_reason": None,
                "target_binding_status": "unverified_toy_scope",
                "incident_window": None,
                "unrun_probe_ids": [item["probe_id"] for item in initial["ordered_probe_menu"]],
                "model_cost_usd": 0.0,
                "host_impact_ms": None,
            }
            label = {
                "case_id": case_id,
                "role": world.role,
                "root_causes": (
                    list(world.root_causes) if world.causal_answer_review != "unknown" else None
                ),
                "causal_answer_review": world.causal_answer_review,
                "observed_effects": [],
                "first_useful_evidence_ms": None,
                "counterevidence_observed_probe_ids": [],
                "counterevidence_unrun_or_unknown_probe_ids": [
                    initial["ordered_probe_menu"][index - 1]["probe_id"]
                    for index in world.counterevidence_stage_indices
                ],
                "false_causal_claim_count": None,
                "false_claim_review_reason": "case_failed_before_independent_review",
                "diagnostic_performance_admissible": False,
            }
        run["database_sha256"] = _file_digest(database) if database.is_file() else None
        report["runs"].append(run)
        labels.append(label)
    policy_file = output_dir / "policy-visible/run-report.json"
    evaluator_file = output_dir / "evaluator-only/outcomes.json"
    policy_file.write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
    evaluator_file.write_text(
        json.dumps({"cases": labels}, sort_keys=True, indent=2), encoding="utf-8"
    )
    runtime_source = Path(inspect.getfile(Investigator)).resolve()
    manifest = {
        "schema_version": 1,
        "runner_git_sha": _git_head(_ROOT),
        "runner_sha256": _file_digest(Path(__file__)),
        "runtime_investigator_path": str(runtime_source),
        "runtime_investigator_sha256": _file_digest(runtime_source),
        "runtime_git_sha": _git_head(runtime_source.parent),
        "matrix_contract_sha256": matrix.contract_sha256,
        "case_ids": case_ids,
        "initial_input_sha256": {
            case_id: visible[case_id]["initial_sha256"] for case_id in case_ids
        },
        "policy_report_sha256": _file_digest(policy_file),
        "evaluator_only_sha256": _file_digest(evaluator_file),
        "database_sha256": {run["case_id"]: run["database_sha256"] for run in report["runs"]},
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
        "runtime_request_byte_parity_verified": False,
        "target_identity_verified": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8"
    )
    return report


def verify_episode_suite(output_dir: Path) -> dict[str, Any]:
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    report_path = output_dir / "policy-visible/run-report.json"
    evaluator_path = output_dir / "evaluator-only/outcomes.json"
    matrix = build_matrix()
    if (
        manifest.get("runner_sha256") != _file_digest(Path(__file__))
        or manifest.get("matrix_contract_sha256") != matrix.contract_sha256
        or manifest.get("policy_report_sha256") != _file_digest(report_path)
        or manifest.get("evaluator_only_sha256") != _file_digest(evaluator_path)
    ):
        raise ValueError("episode integrity check failed")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    labels = json.loads(evaluator_path.read_text(encoding="utf-8"))["cases"]
    if (
        len(report["runs"]) != len(labels)
        or tuple(item["case_id"] for item in report["runs"]) != tuple(manifest["case_ids"])
        or tuple(item["case_id"] for item in labels) != tuple(manifest["case_ids"])
        or any(
            (
                _file_digest(output_dir / "cases" / f"{run['case_id']}.db")
                if (output_dir / "cases" / f"{run['case_id']}.db").is_file()
                else None
            )
            != manifest["database_sha256"][run["case_id"]]
            for run in report["runs"]
        )
    ):
        raise ValueError("episode integrity case/database mismatch")
    return {
        "integrity_verified": True,
        "case_count": len(report["runs"]),
        "completed": sum(run["runtime_complete"] for run in report["runs"]),
        "diagnostic_performance_admissible": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    result = (
        verify_episode_suite(args.output_dir) if args.verify else run_episode_suite(args.output_dir)
    )
    if args.verify:
        summary = result
    else:
        summary = {
            "planned_cases": result["planned_cases"],
            "completed": sum(run["runtime_complete"] for run in result["runs"]),
            "failed": sum(not run["runtime_complete"] for run in result["runs"]),
            "outcomes": {run["case_id"]: run.get("outcome") for run in result["runs"]},
            "diagnostic_performance_admissible": False,
        }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
