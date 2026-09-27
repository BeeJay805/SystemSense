"""Replay frozen toy episodes with two label-blind advisory rivals per family.

The provider sees only a normal ReasoningRequest. Toy closure bindings and
evaluator labels stay in this runner and are scored after the case ends.
"""

from __future__ import annotations

import argparse
import inspect
import json
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from benchmarks.fixed_rival_provider import FixedRivalReasoningProvider
from benchmarks.sequential_investigator_episodes import (
    _ROOT,  # pyright: ignore[reportPrivateUsage]
    _SELECTED,  # pyright: ignore[reportPrivateUsage]
    _file_digest,  # pyright: ignore[reportPrivateUsage]
    _git_head,  # pyright: ignore[reportPrivateUsage]
    _readback,  # pyright: ignore[reportPrivateUsage]
    _registered_case,  # pyright: ignore[reportPrivateUsage]
    _score_after_run,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.sequential_visible_matrix import (
    _WORLDS,  # pyright: ignore[reportPrivateUsage]
    build_matrix,
)
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.storage.sqlite_store import SQLiteStore


def run_hypothesis_suite(
    output_dir: Path, *, case_ids: tuple[str, ...] = _SELECTED
) -> dict[str, Any]:
    """Run fresh toy DBs with unchanged menus and budgets; keep failures visible."""
    worlds = {world.case_id: world for world in _WORLDS}
    if not case_ids or len(case_ids) != len(set(case_ids)) or not set(case_ids) <= set(_SELECTED):
        raise ValueError("selection must be unique and within the frozen eight-case pilot")
    matrix = build_matrix()
    visible = {case["case_id"]: case for case in matrix.visible}
    runtime_source = Path(inspect.getfile(Investigator)).resolve()
    runtime_sha_before = _git_head(runtime_source.parent)
    runtime_source_sha_before = _file_digest(runtime_source)
    output_dir.mkdir(parents=False, exist_ok=False)
    (output_dir / "cases").mkdir()
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    report: dict[str, Any] = {
        "classification": "synthetic_hypothesis_investigator_mechanics_only",
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
                app.reasoning = FixedRivalReasoningProvider()
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
                            "core.system",
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
            run = {
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
                "provider_calls": [],
                "unrun_probe_ids": [item["probe_id"] for item in initial["ordered_probe_menu"]],
                "model_cost_usd": 0.0,
                "host_impact_ms": None,
            }
            label = {
                "case_id": case_id,
                "causal_answer_review": world.causal_answer_review,
                "root_causes": (
                    list(world.root_causes) if world.causal_answer_review != "unknown" else None
                ),
                "observed_effects": [],
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
    runtime_sha_after = _git_head(runtime_source.parent)
    runtime_source_sha_after = _file_digest(runtime_source)
    manifest = {
        "schema_version": 1,
        "runner_git_sha": _git_head(_ROOT),
        "runner_sha256": _file_digest(Path(__file__)),
        "provider_sha256": _file_digest(Path(inspect.getfile(FixedRivalReasoningProvider))),
        "provider_identity": FixedRivalReasoningProvider().identity.model_dump(mode="json"),
        "runtime_investigator_path": str(runtime_source),
        "runtime_investigator_sha256_before": runtime_source_sha_before,
        "runtime_investigator_sha256_after": runtime_source_sha_after,
        "runtime_git_sha_before": runtime_sha_before,
        "runtime_git_sha_after": runtime_sha_after,
        "runtime_revision_stable": (
            runtime_sha_before == runtime_sha_after
            and runtime_source_sha_before == runtime_source_sha_after
        ),
        "matrix_contract_sha256": matrix.contract_sha256,
        "case_ids": case_ids,
        "initial_input_sha256": {
            case_id: visible[case_id]["initial_sha256"] for case_id in case_ids
        },
        "ordered_probe_ids": {
            case_id: [
                item["probe_id"] for item in visible[case_id]["initial_input"]["ordered_probe_menu"]
            ]
            for case_id in case_ids
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


def verify_hypothesis_suite(output_dir: Path) -> dict[str, Any]:
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    policy_file = output_dir / "policy-visible/run-report.json"
    evaluator_file = output_dir / "evaluator-only/outcomes.json"
    if (
        manifest.get("runner_sha256") != _file_digest(Path(__file__))
        or manifest.get("provider_sha256")
        != _file_digest(Path(inspect.getfile(FixedRivalReasoningProvider)))
        or manifest.get("matrix_contract_sha256") != build_matrix().contract_sha256
        or manifest.get("policy_report_sha256") != _file_digest(policy_file)
        or manifest.get("evaluator_only_sha256") != _file_digest(evaluator_file)
    ):
        raise ValueError("hypothesis episode integrity mismatch")
    report = json.loads(policy_file.read_text(encoding="utf-8"))
    if tuple(run["case_id"] for run in report["runs"]) != tuple(manifest["case_ids"]) or any(
        (
            _file_digest(output_dir / "cases" / f"{run['case_id']}.db")
            if (output_dir / "cases" / f"{run['case_id']}.db").is_file()
            else None
        )
        != manifest["database_sha256"][run["case_id"]]
        for run in report["runs"]
    ):
        raise ValueError("hypothesis episode database or case mismatch")
    return {
        "integrity_verified": True,
        "case_count": len(report["runs"]),
        "completed": sum(run["runtime_complete"] for run in report["runs"]),
        "runtime_revision_stable": manifest["runtime_revision_stable"],
        "diagnostic_performance_admissible": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    result = (
        verify_hypothesis_suite(args.output_dir)
        if args.verify
        else run_hypothesis_suite(args.output_dir)
    )
    summary = (
        result
        if args.verify
        else {
            "planned_cases": result["planned_cases"],
            "completed": sum(run["runtime_complete"] for run in result["runs"]),
            "failed": sum(not run["runtime_complete"] for run in result["runs"]),
            "outcomes": {run["case_id"]: run.get("outcome") for run in result["runs"]},
            "diagnostic_performance_admissible": False,
        }
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
