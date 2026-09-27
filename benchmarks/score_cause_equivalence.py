"""Independently score toy cause equivalence from observed probe records.

This evaluator reads frozen world labels only after an Investigator run. A
single compatible toy cause label is not a supported Windows diagnosis.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from benchmarks.sequential_visible_matrix import (
    _WORLDS,  # pyright: ignore[reportPrivateUsage]
    _compatible_worlds,  # pyright: ignore[reportPrivateUsage]
    _file_digest,  # pyright: ignore[reportPrivateUsage]
    _initial_input,  # pyright: ignore[reportPrivateUsage]
    build_matrix,
)


def _cause_key(world: Any) -> tuple[str, ...] | None:
    if world.causal_answer_review == "unknown":
        return None
    return tuple(world.root_causes)


def _cause_labels(worlds: Sequence[Any]) -> tuple[list[list[str]], bool, int]:
    keys = {_cause_key(world) for world in worlds}
    known = sorted(key for key in keys if key is not None)
    return [list(key) for key in known], None in keys, len(keys)


def _facts(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {str(item["name"]): item.get("value") for item in evidence.get("facts", ())}


def score_case_cause_equivalence(run: Mapping[str, Any]) -> dict[str, Any]:
    """Score only actual observed facts; failed and unrun measurements stay unknown."""
    case_id = str(run["case_id"])
    case = next((world for world in _WORLDS if world.case_id == case_id), None)
    if case is None:
        raise ValueError(f"case is absent from the frozen evaluator: {case_id}")
    evidence_by_execution = {
        str(item["execution_id"]): item
        for item in run.get("evidence", ())
        if item.get("execution_id") is not None and item.get("statement_kind") == "observed_fact"
    }
    observations: dict[str, str] = {}
    unknown = set(map(str, run.get("unrun_probe_ids", ())))
    effects: list[dict[str, Any]] = []
    worlds = _compatible_worlds(case.domain, observations)
    executions = cast(list[dict[str, Any]], list(run.get("executions", ())))
    if executions and all(isinstance(item.get("state_version"), int) for item in executions):
        menu = [
            "core.system",
            *(item["probe_id"] for item in _initial_input(case.domain)["ordered_probe_menu"]),
        ]
        menu_order = {str(probe_id): index for index, probe_id in enumerate(menu)}
        # Concurrent probes share one state version. Review them in frozen
        # menu order so scheduling cannot change which one receives credit.
        executions.sort(
            key=lambda item: (
                int(item["state_version"]),
                menu_order.get(str(item["probe_id"]), 10**9),
            )
        )
    for execution in executions:
        probe_id = str(execution["probe_id"])
        if probe_id == "core.system":
            continue
        execution_id = str(execution["execution_id"])
        evidence = evidence_by_execution.get(execution_id)
        facts = _facts(evidence) if evidence is not None else {}
        if (
            execution.get("status") != "ok"
            or facts.get("measurement_status") != "observed"
            or not isinstance(facts.get("observation"), str)
        ):
            unknown.add(probe_id)
            effects.append({"probe_id": probe_id, "status": "unknown"})
            continue
        value = str(facts["observation"])
        if probe_id in observations and observations[probe_id] != value:
            unknown.add(probe_id)
            effects.append({"probe_id": probe_id, "status": "contradictory_repeat"})
            continue
        _, _, before_causes = _cause_labels(worlds)
        before_worlds = len(worlds)
        observations[probe_id] = value
        worlds = _compatible_worlds(case.domain, observations)
        _, _, after_causes = _cause_labels(worlds)
        effects.append(
            {
                "probe_id": probe_id,
                "status": "observed" if worlds else "inconsistent_observation",
                "world_reduced": len(worlds) < before_worlds,
                "cause_reduced": 0 < after_causes < before_causes,
                "compatible_worlds_after": len(worlds),
                "compatible_cause_count_after": after_causes,
            }
        )
        if not worlds:
            break
    labels, unknown_world, cause_count = _cause_labels(worlds)
    return {
        "case_id": case_id,
        "status": "scored" if worlds else "inconsistent_observation",
        "observed_probe_ids": list(observations),
        "unknown_probe_ids": sorted(unknown),
        "compatible_world_ids": [world.case_id for world in worlds],
        "compatible_world_count": len(worlds),
        "compatible_cause_labels": labels,
        "unknown_world_compatible": unknown_world,
        "compatible_cause_count": cause_count,
        "single_known_cause_label": cause_count == 1 and not unknown_world,
        "cause_reducing_probe_ids": [
            item["probe_id"] for item in effects if item.get("cause_reduced") is True
        ],
        "probe_effects": effects,
        "supported_answer_inferred": False,
    }


def score_artifact(input_dir: Path, output_file: Path) -> dict[str, Any]:
    """Verify frozen inputs and write a separate evaluator-only score artifact."""
    manifest_path = input_dir / "manifest.json"
    policy_path = input_dir / "policy-visible/run-report.json"
    evaluator_path = input_dir / "evaluator-only/outcomes.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    matrix = build_matrix()
    if (
        manifest.get("matrix_contract_sha256") != matrix.contract_sha256
        or manifest.get("policy_report_sha256") != _file_digest(policy_path)
        or manifest.get("evaluator_only_sha256") != _file_digest(evaluator_path)
    ):
        raise ValueError("frozen episode artifact integrity mismatch")
    report = json.loads(policy_path.read_text(encoding="utf-8"))
    runs = report["runs"]
    if tuple(run["case_id"] for run in runs) != tuple(manifest["case_ids"]):
        raise ValueError("run order differs from frozen manifest")
    cases = [score_case_cause_equivalence(run) for run in runs]
    result = {
        "schema_version": 1,
        "classification": "evaluator_only_toy_cause_equivalence",
        "source_manifest_sha256": _file_digest(manifest_path),
        "source_policy_sha256": _file_digest(policy_path),
        "matrix_contract_sha256": matrix.contract_sha256,
        "scorer_sha256": _file_digest(Path(__file__)),
        "cases": cases,
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
    }
    output_file.parent.mkdir(parents=True, exist_ok=True)
    if output_file.exists():
        raise FileExistsError(output_file)
    output_file.write_text(json.dumps(result, sort_keys=True, indent=2), encoding="utf-8")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = score_artifact(args.artifact_dir, args.output)
    print(
        json.dumps(
            {
                "cases": len(result["cases"]),
                "single_known_cause_labels": sum(
                    item["single_known_cause_label"] for item in result["cases"]
                ),
                "diagnostic_performance_admissible": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
