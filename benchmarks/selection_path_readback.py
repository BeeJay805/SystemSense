"""Classify toy probe selection paths from persisted rows and step events.

This readback establishes a selection path, not permission or causal proof.
Missing or contradictory custody stays ``unknown``. It never creates an
admission row or changes the original episode artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExecutionFact:
    execution_id: str
    case_id: str
    probe_id: str
    state_version: int
    followup_admission_id: str | None = None


@dataclass(frozen=True)
class StepFact:
    state_version: int
    event: str
    probe_ids: tuple[str, ...]
    hypothesis_probe_ids: tuple[str, ...]


@dataclass(frozen=True)
class PathReference:
    reference_id: str
    valid: bool


def classify_execution(
    execution: ExecutionFact,
    *,
    steps: Mapping[int, StepFact],
    fast: PathReference | None = None,
    adaptive: PathReference | None = None,
    unclassified_admission_link: bool = False,
) -> dict[str, Any]:
    """Classify one execution only when its durable path evidence agrees."""
    base: dict[str, Any] = {
        "execution_id": execution.execution_id,
        "probe_id": execution.probe_id,
        "state_version": execution.state_version,
        "admission_recorded": False,
    }
    if (
        (fast is not None and not fast.valid)
        or (adaptive is not None and not adaptive.valid)
        or (execution.followup_admission_id is not None and adaptive is None)
    ):
        return {
            **base,
            "selection_path": "unknown",
            "reason": "invalid_recorded_link",
            "evidence_refs": [],
        }
    if unclassified_admission_link:
        return {
            **base,
            "selection_path": "unknown",
            "reason": "unclassified_admission_link",
            "evidence_refs": [],
        }
    paths: list[tuple[str, list[str]]] = []
    current = steps.get(execution.state_version)
    previous = steps.get(execution.state_version - 1)
    if (
        current is not None
        and current.event == "baseline_collecting"
        and execution.probe_id in current.probe_ids
    ):
        paths.append(
            (
                "initial_baseline",
                [f"investigation_steps:{current.state_version}:baseline_collecting"],
            )
        )
    if fast is not None:
        paths.append(
            (
                "fast_snapshot_linked",
                [
                    f"decision_execution_links:{fast.reference_id}",
                    f"decision_snapshots:{fast.reference_id}",
                ],
            )
        )
    if adaptive is not None:
        paths.append(
            (
                "adaptive_admission_recorded",
                [f"adaptive_admission:{adaptive.reference_id}"],
            )
        )
    if (
        current is not None
        and current.event == "collecting"
        and execution.probe_id in current.probe_ids
        and previous is not None
        and previous.event == "routing_superseded"
        and execution.probe_id in previous.hypothesis_probe_ids
    ):
        paths.append(
            (
                "trusted_deep_requested_batch",
                [
                    f"investigation_steps:{previous.state_version}:routing_superseded",
                    f"investigation_steps:{current.state_version}:collecting",
                ],
            )
        )
    if not paths:
        return {
            **base,
            "selection_path": "unknown",
            "reason": "unproven_selection_path",
            "evidence_refs": [],
        }
    if len(paths) != 1:
        return {
            **base,
            "selection_path": "unknown",
            "reason": "conflicting_recorded_paths",
            "evidence_refs": [ref for _, refs in paths for ref in refs],
        }
    path, refs = paths[0]
    return {
        **base,
        "selection_path": path,
        "reason": "supported_by_recorded_path",
        "evidence_refs": [f"probe_executions:{execution.execution_id}", *refs],
        "admission_recorded": path == "adaptive_admission_recorded",
    }


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _step_facts(connection: sqlite3.Connection, case_id: str) -> dict[int, StepFact]:
    steps: dict[int, StepFact] = {}
    for version, raw in connection.execute(
        "SELECT state_version,record_json FROM investigation_steps "
        "WHERE case_id=? ORDER BY state_version",
        (case_id,),
    ):
        record = json.loads(str(raw))
        hypotheses = record.get("hypotheses", ())
        probe_ids = tuple(
            dict.fromkeys(
                str(probe_id)
                for hypothesis in hypotheses
                for probe_id in hypothesis.get("distinguishing_probe_ids", ())
            )
        )
        step = StepFact(
            state_version=int(version),
            event=str(record["event"]),
            probe_ids=tuple(map(str, record.get("probe_ids", ()))),
            hypothesis_probe_ids=probe_ids,
        )
        if step.state_version in steps:
            raise ValueError("duplicate investigation step version")
        steps[step.state_version] = step
    return steps


def _fast_links(
    connection: sqlite3.Connection, case_id: str, execution_by_id: Mapping[str, ExecutionFact]
) -> dict[str, PathReference]:
    links: dict[str, list[PathReference]] = defaultdict(list)
    for (
        execution_id,
        probe_id,
        snapshot_id,
        snapshot_case,
        request_json,
        request_sha,
        menu,
    ) in connection.execute(
        "SELECT l.execution_id,l.probe_id,l.snapshot_id,s.case_id,s.request_json,"
        "s.request_sha256,s.candidate_probe_ids_json FROM decision_execution_links l "
        "LEFT JOIN decision_snapshots s ON s.snapshot_id=l.snapshot_id "
        "WHERE l.case_id=?",
        (case_id,),
    ):
        execution = execution_by_id.get(str(execution_id))
        valid = (
            execution is not None
            and str(probe_id) == execution.probe_id
            and snapshot_case == case_id
            and isinstance(request_json, str)
            and hashlib.sha256(request_json.encode("utf-8")).hexdigest() == request_sha
            and isinstance(menu, str)
            and execution.probe_id in json.loads(menu)
        )
        links[str(execution_id)].append(PathReference(str(snapshot_id), valid=bool(valid)))
    return {
        execution_id: refs[0]
        if len(refs) == 1
        else PathReference("multiple_fast_links", valid=False)
        for execution_id, refs in links.items()
    }


def _adaptive_links(
    connection: sqlite3.Connection, case_id: str, execution_by_id: Mapping[str, ExecutionFact]
) -> tuple[dict[str, PathReference], set[str]]:
    links: dict[str, list[PathReference]] = defaultdict(list)
    for execution_id, admission_id, admission_case in connection.execute(
        "SELECT l.execution_id,l.admission_id,a.case_id "
        "FROM collection_followup_execution_links l "
        "LEFT JOIN collection_followup_admissions a ON a.admission_id=l.admission_id"
    ):
        execution = execution_by_id.get(str(execution_id))
        if execution is None:
            continue
        valid = admission_case == case_id and (
            execution.followup_admission_id is None
            or execution.followup_admission_id == admission_id
        )
        links[execution.execution_id].append(PathReference(str(admission_id), valid=valid))
    for (
        execution_id,
        snapshot_id,
        candidate_id,
        epoch,
        invocation_sha,
        admission_id,
        admission_case,
        admission_snapshot,
        admission_candidate,
        admission_epoch,
        admission_invocation_sha,
        snapshot_case,
    ) in connection.execute(
        "SELECT l.execution_id,l.snapshot_id,l.candidate_id,l.epoch_state_version,"
        "l.executed_invocation_sha256,a.admission_id,a.case_id,a.snapshot_id,"
        "a.candidate_id,a.epoch_state_version,a.invocation_sha256,s.case_id "
        "FROM candidate_decision_execution_links l "
        "LEFT JOIN candidate_dispatch_admissions a ON a.case_id=l.case_id "
        "AND a.snapshot_id=l.snapshot_id AND a.candidate_id=l.candidate_id "
        "LEFT JOIN candidate_decision_snapshots s ON s.snapshot_id=l.snapshot_id "
        "WHERE l.case_id=?",
        (case_id,),
    ):
        execution = execution_by_id.get(str(execution_id))
        if execution is None:
            continue
        valid = (
            admission_id is not None
            and admission_case == case_id
            and snapshot_case == case_id
            and snapshot_id == admission_snapshot
            and candidate_id == admission_candidate
            and epoch == admission_epoch
            and invocation_sha == admission_invocation_sha
        )
        links[execution.execution_id].append(PathReference(str(admission_id), valid=valid))
    unclassified = {
        str(execution_id)
        for (execution_id,) in connection.execute(
            "SELECT execution_id FROM diagnostic_intent_execution_links"
        )
        if str(execution_id) in execution_by_id
    }
    return (
        {
            execution_id: refs[0]
            if len(refs) == 1
            else PathReference("multiple_admission_links", valid=False)
            for execution_id, refs in links.items()
        },
        unclassified,
    )


def classify_case_database(database: Path, case_id: str) -> list[dict[str, Any]]:
    """Read exact persisted execution, step, snapshot, and admission rows."""
    with _read_only_connection(database) as connection:
        executions = [
            ExecutionFact(
                execution_id=str(execution_id),
                case_id=str(execution_case),
                probe_id=str(probe_id),
                state_version=int(state_version),
                followup_admission_id=(str(admission_id) if admission_id is not None else None),
            )
            for execution_id, execution_case, probe_id, state_version, admission_id in (
                connection.execute(
                    "SELECT execution_id,case_id,probe_id,state_version,followup_admission_id "
                    "FROM probe_executions WHERE case_id=? ORDER BY started_at,execution_id",
                    (case_id,),
                )
            )
        ]
        execution_by_id = {item.execution_id: item for item in executions}
        if len(execution_by_id) != len(executions):
            raise ValueError("duplicate probe execution identity")
        steps = _step_facts(connection, case_id)
        fast = _fast_links(connection, case_id, execution_by_id)
        adaptive, unclassified = _adaptive_links(connection, case_id, execution_by_id)
        return [
            classify_execution(
                execution,
                steps=steps,
                fast=fast.get(execution.execution_id),
                adaptive=adaptive.get(execution.execution_id),
                unclassified_admission_link=execution.execution_id in unclassified,
            )
            for execution in executions
        ]


def _build_readback(artifact_dir: Path) -> dict[str, Any]:
    manifest_path = artifact_dir / "manifest.json"
    policy_path = artifact_dir / "policy-visible/run-report.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("policy_report_sha256") != _digest(policy_path):
        raise ValueError("policy report differs from frozen manifest")
    report = json.loads(policy_path.read_text(encoding="utf-8"))
    if tuple(run["case_id"] for run in report["runs"]) != tuple(manifest["case_ids"]):
        raise ValueError("case order differs from frozen manifest")
    cases: list[dict[str, Any]] = []
    for run in report["runs"]:
        case_id = str(run["case_id"])
        database = artifact_dir / "cases" / f"{case_id}.db"
        if _digest(database) != manifest["database_sha256"][case_id]:
            raise ValueError("case database differs from frozen manifest")
        runtime_case_id = run.get("runtime_case_id")
        if not isinstance(runtime_case_id, str):
            raise ValueError("policy report lacks runtime case identity")
        executions = classify_case_database(database, runtime_case_id)
        if {item["execution_id"]: item["probe_id"] for item in executions} != {
            item["execution_id"]: item["probe_id"] for item in run["executions"]
        }:
            raise ValueError("policy execution identities differ from database")
        cases.append({"case_id": case_id, "executions": executions})
    counts = {
        path: 0
        for path in (
            "initial_baseline",
            "trusted_deep_requested_batch",
            "fast_snapshot_linked",
            "adaptive_admission_recorded",
            "unknown",
        )
    }
    for case in cases:
        for execution in case["executions"]:
            counts[execution["selection_path"]] += 1
    return {
        "schema_version": 1,
        "classification": "selection_path_readback_only",
        "source_manifest_sha256": _digest(manifest_path),
        "source_policy_sha256": _digest(policy_path),
        "classifier_sha256": _digest(Path(__file__)),
        "cases": cases,
        "counts": counts,
        "admission_authority_verified": False,
        "diagnostic_performance_admissible": False,
    }


def readback_artifact(artifact_dir: Path, output_file: Path) -> dict[str, Any]:
    result = _build_readback(artifact_dir)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    if output_file.exists():
        raise FileExistsError(output_file)
    output_file.write_text(json.dumps(result, sort_keys=True, indent=2), encoding="utf-8")
    return result


def verify_readback(artifact_dir: Path, output_file: Path) -> dict[str, Any]:
    saved = json.loads(output_file.read_text(encoding="utf-8"))
    if saved != _build_readback(artifact_dir):
        raise ValueError("selection path readback differs from durable artifact")
    return {
        "integrity_verified": True,
        "cases": len(saved["cases"]),
        "counts": saved["counts"],
        "admission_authority_verified": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    result = (
        verify_readback(args.artifact_dir, args.output)
        if args.verify
        else readback_artifact(args.artifact_dir, args.output)
    )
    print(json.dumps(result["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
