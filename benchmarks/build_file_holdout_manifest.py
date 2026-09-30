"""Build a non-secret frozen manifest for consumed selected-JSON holdouts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from benchmarks.private_alpha_scorecard import canonical_digest, sha256_file, source_tree_digest

RULES = (
    "v1: accepted=>healthy_control;\n"
    "rejected utf8/syntax/empty/nonfinite=>supported_task_explanation;\n"
    "unavailable missing/read_denied=>specific_access_gap;\n"
    "unavailable too_large=>specific_limit_gap;\n"
    "rejected nesting_limit/number_limit=>specific_limit_gap"
)


def classify(case: dict[str, Any]) -> str:
    task, error, capture = (
        case.get("expected_task"),
        case.get("expected_error"),
        case.get("expected_capture"),
    )
    if task == "accepted":
        return "healthy_control"
    if task == "rejected" and error in {
        "invalid_utf8",
        "json_syntax",
        "empty_document",
        "non_finite_number",
    }:
        return "supported_task_explanation"
    if task == "unavailable" and capture in {"missing", "read_denied"}:
        return "specific_access_gap"
    if (task == "unavailable" and capture == "too_large") or error in {
        "nesting_limit",
        "number_limit",
    }:
        return "specific_limit_gap"
    raise ValueError(f"no frozen classification rule for {case.get('case_id')}")


def plan_attempts(case_ids: list[str], arm: str, run_dirs: list[Path]) -> list[dict[str, Any]]:
    """Retain each planned repeat as a cell, including missing and extra attempts."""
    rows: list[dict[str, Any]] = []
    for run_index, root in enumerate(run_dirs, start=1):
        present = sorted(
            (path for path in root.iterdir() if path.is_dir()) if root.is_dir() else ()
        )
        unassigned = list(present)
        for case_id in case_ids:
            matching = sorted(
                (path for path in present if path.name.startswith(f"{case_id}-{arm}-")),
                key=_attempt_order,
            )
            unassigned = [path for path in unassigned if path not in matching]
            if not matching:
                rows.append(
                    {
                        "case_id": case_id,
                        "arm": arm,
                        "attempt_id": f"missing-{root.name}-{arm}-{case_id}",
                        "planned_repeat_index": run_index,
                    }
                )
            for index, case_dir in enumerate(matching, start=1):
                result_path = case_dir / "result.json"
                result_value = (
                    json.loads(result_path.read_text(encoding="utf-8"))
                    if result_path.is_file()
                    else None
                )
                result = (
                    cast(dict[str, Any], result_value) if isinstance(result_value, dict) else None
                )
                attempt_id = (
                    result.get("attempt_id")
                    if result is not None and isinstance(result.get("attempt_id"), str)
                    else case_dir.name
                )
                artifacts = {
                    "result": str(result_path),
                    "report": str(case_dir / "report.json"),
                    "database": str(case_dir / "case.db"),
                }
                failure_path = case_dir / "failure.json"
                if failure_path.is_file():
                    artifacts["failure"] = str(failure_path)
                rows.append(
                    {
                        "case_id": case_id,
                        "arm": arm,
                        "attempt_id": attempt_id,
                        **(
                            {"planned_repeat_index": run_index}
                            if index == 1
                            else {"extra_attempt_index": index - 1}
                        ),
                        "artifacts": artifacts,
                    }
                )
        if unassigned:
            names = sorted(path.name for path in unassigned)
            raise ValueError(f"run contains unassignable case directories: {names}")
    return rows


def _attempt_order(directory: Path) -> tuple[datetime, str]:
    """Unknown-time failures sort first; a retry can never erase them by UUID order."""
    for name in ("result.json", "failure.json"):
        path = directory / name
        if not path.is_file():
            continue
        raw: object = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            continue
        value = cast(dict[str, Any], raw).get("started_at")
        if isinstance(value, str):
            try:
                started = datetime.fromisoformat(value)
            except ValueError:
                continue
            if started.tzinfo is not None and started.utcoffset() is not None:
                return started.astimezone(UTC), directory.name
    return datetime.min.replace(tzinfo=UTC), directory.name


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    fixture = args.repo / "benchmarks/fixtures/selected_json_v1"
    protocol_path, truth_path = fixture / "protocol.json", fixture / "ground_truth.json"
    protocol_value, truth_value = (
        json.loads(protocol_path.read_text(encoding="utf-8")),
        json.loads(truth_path.read_text(encoding="utf-8")),
    )
    if not isinstance(protocol_value, dict) or not isinstance(truth_value, list):
        raise TypeError("frozen protocol object and ground-truth list are required")
    protocol = cast(dict[str, Any], protocol_value)
    truth_rows = cast(list[object], truth_value)
    if any(not isinstance(row, dict) for row in truth_rows):
        raise ValueError("each ground-truth row must be an object")
    truth = cast(list[dict[str, Any]], truth_rows)
    protocol_sha = sha256_file(protocol_path)
    expected_file_digest = protocol.get("files", {}).get("ground_truth.json")
    if not isinstance(expected_file_digest, str):
        raise TypeError("protocol must bind ground_truth.json")
    if expected_file_digest != sha256_file(truth_path):
        raise ValueError("ground_truth.json does not match the public freeze receipt")
    case_ids = protocol.get("case_ids")
    if not isinstance(case_ids, list):
        raise TypeError("protocol must define string case_ids")
    case_id_values = cast(list[object], case_ids)
    if any(not isinstance(item, str) for item in case_id_values):
        raise ValueError("protocol must define string case_ids")
    case_ids = cast(list[str], case_id_values)
    classes = {row["case_id"]: classify(row) for row in truth if row.get("split") == "holdout"}
    if set(classes) != set(case_ids):
        raise ValueError("frozen cases do not exactly cover protocol case_ids")
    attempt_rows: list[dict[str, Any]] = []
    source_tree: str | None = None
    revision: str | None = None
    arm_dirs = {
        "basic": [args.evidence / f"file-holdout-fb84567-basic-{index:02d}" for index in (1, 2)],
        "laya_sol": [
            args.evidence / f"file-holdout-fb84567-laya_sol-{index:02d}" for index in (1, 2)
        ],
    }
    for arm, roots in arm_dirs.items():
        attempt_rows.extend(plan_attempts(case_ids, arm, roots))
    for row in attempt_rows:
        artifacts = row.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        artifacts = cast(dict[str, Any], artifacts)
        result_path = Path(str(artifacts["result"]))
        if not result_path.is_file():
            continue
        result_value = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(result_value, dict):
            raise TypeError(f"result artifact must be a JSON object: {result_path}")
        source_value = cast(dict[str, Any], result_value).get("source")
        if not isinstance(source_value, dict):
            continue
        source = cast(dict[str, Any], source_value)
        digest = source_tree_digest(source.get("source_hashes"))
        current_revision = source.get("revision")
        if source_tree is not None and (digest != source_tree or current_revision != revision):
            raise ValueError("frozen holdout attempts differ in source identity")
        if digest is not None and isinstance(current_revision, str):
            source_tree, revision = digest, current_revision
    if source_tree is None or revision is None:
        raise ValueError("at least one saved result is required to bind cohort source identity")
    access_contract = {
        "read_only": True,
        "budget_ms": protocol["budget_ms"],
        "max_rounds": protocol["max_rounds"],
        "max_probes": protocol["max_probes"],
        "offered_probes": protocol["offered_probes"],
        "scope": protocol["scope"],
    }
    manifest = {
        "schema_version": 1,
        "cohort_id": "selected-json-holdout-fb84567-two-repeats",
        "family": "file",
        "protocol_sha256": protocol_sha,
        "case_ids": case_ids,
        "case_classifications": classes,
        "case_classifications_sha256": canonical_digest(classes),
        "case_classification_source": {
            "artifact_sha256": sha256_file(truth_path),
            "protocol_sha256": protocol_sha,
            "derivation_rule_sha256": hashlib.sha256(RULES.encode("utf-8")).hexdigest(),
            "rule_id": "selected-json-v1-ground-truth-classification-v1",
        },
        "arms": list(arm_dirs),
        "paired_contract": {
            "source_revision": revision,
            "source_tree_sha256": source_tree,
            "access_contract": access_contract,
            "access_sha256": canonical_digest(access_contract),
            "budget_ms": protocol["budget_ms"],
            "max_rounds": protocol["max_rounds"],
            "max_probes": protocol["max_probes"],
        },
        "expected_attempts": attempt_rows,
        "planned_repeats_per_case_arm": len(next(iter(arm_dirs.values()))),
    }
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
