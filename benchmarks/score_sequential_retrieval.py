"""Read-only score of a frozen retrieval artifact against sealed toy labels.

The output describes packet responsiveness and collisions, not source truth or
diagnostic accuracy. Run only after the retrieval artifact has been frozen and
its SHA256 communicated to an independent evaluator.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

_ARMS = ("all_relations", "reviewed_only")


def _read_exact(path: Path, expected_sha256: str) -> dict[str, Any]:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError(f"input hash mismatch: {path.name}")
    value: Any = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"input is not an object: {path.name}")
    return cast(dict[str, Any], value)


def _index_stages(cases: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for case in cases:
        for stage in case["stages"]:
            key = str(case["case_id"]), int(stage["stage_index"])
            if key in indexed:
                raise ValueError("duplicate case/stage")
            indexed[key] = {**stage, "domain": case["domain"]}
    return indexed


def score_retrieval(
    policy_path: Path,
    evaluator_path: Path,
    retrieval_path: Path,
    *,
    expected_sha256: Mapping[str, str],
) -> dict[str, Any]:
    """Require exact custody and count every eligible visible follow-up."""

    if set(expected_sha256) != {"policy", "labels", "retrieval"}:
        raise ValueError("three pinned input hashes are required")
    policy = _read_exact(policy_path, expected_sha256["policy"])
    labels = _read_exact(evaluator_path, expected_sha256["labels"])
    retrieval = _read_exact(retrieval_path, expected_sha256["retrieval"])
    if retrieval.get("input_sha256") != expected_sha256["policy"]:
        raise ValueError("retrieval used a different policy-visible input hash")
    visible_cases = policy["cases"]
    label_cases = labels["cases"]
    visible = _index_stages(visible_cases)
    truth = _index_stages(label_cases)
    if set(visible) != set(truth):
        raise ValueError("policy/evaluator stage sets differ")
    records: dict[tuple[str, int], dict[str, Any]] = {}
    for record in retrieval["records"]:
        key = str(record["case_id"]), int(record["stage_index"])
        if key in records:
            raise ValueError("duplicate retrieval case/stage")
        records[key] = record
    if set(records) != set(visible):
        raise ValueError("retrieval stage set is incomplete or contains extras")
    for key, stage in visible.items():
        record = records[key]
        if (
            record["visible_state_sha256"] != stage["visible_state_sha256"]
            or record["visible_state_sha256"] != truth[key]["visible_state_sha256"]
            or record["domain"] != stage["domain"]
            or truth[key]["domain"] != stage["domain"]
        ):
            raise ValueError("retrieval stage identity or source hash differs")
    followups = [key for key in visible if key[1] > 0]
    discriminating = sum(truth[key]["discriminated_by_latest_probe"] is True for key in followups)
    counter_stages = {
        (str(case["case_id"]), int(index))
        for case in label_cases
        for index in case["counterevidence_stage_indices"]
    }
    if not counter_stages <= set(followups):
        raise ValueError("counterevidence label points outside visible follow-ups")
    result: dict[str, Any] = {
        "classification": "synthetic_retrieval_mechanics_only",
        "input_sha256": dict(expected_sha256),
        "case_count": len(visible_cases),
        "stages": len(visible),
        "followups": len(followups),
        "discriminating_followups": discriminating,
        "nondiscriminating_followups": len(followups) - discriminating,
        "counterevidence_followups": len(counter_stages),
        "arms": {},
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
        "interpretation_limit": (
            "A changed relation set is responsiveness, not a useful or supported causal answer; "
            "conditional reference text is not observed counterevidence."
        ),
    }
    for arm in _ARMS:
        changed_on_discriminating = 0
        changed_on_nondiscriminating = 0
        counter_changes = 0
        counter_text = 0
        order_only = 0
        for case_id, index in followups:
            current = records[(case_id, index)][arm]
            previous = records[(case_id, index - 1)][arm]
            current_ids = current["relation_ids"]
            previous_ids = previous["relation_ids"]
            changed = set(current_ids) != set(previous_ids)
            order_only += current_ids != previous_ids and not changed
            if truth[(case_id, index)]["discriminated_by_latest_probe"]:
                changed_on_discriminating += changed
            else:
                changed_on_nondiscriminating += changed
            if (case_id, index) in counter_stages:
                counter_changes += changed
                counter_text += bool(current["counterevidence_relation_ids"])
        label_by_case = {str(case["case_id"]): case for case in label_cases}
        final = {
            str(case["case_id"]): records[
                (str(case["case_id"]), max(stage["stage_index"] for stage in case["stages"]))
            ][arm]
            for case in visible_cases
        }
        distinct_truth_pairs = 0
        collisions = 0
        for first, second in itertools.combinations(final, 2):
            if label_by_case[first]["domain"] != label_by_case[second]["domain"]:
                continue
            if label_by_case[first]["root_causes"] == label_by_case[second]["root_causes"]:
                continue
            distinct_truth_pairs += 1
            collisions += set(final[first]["relation_ids"]) == set(final[second]["relation_ids"])
        result["arms"][arm] = {
            "changed_on_discriminating": changed_on_discriminating,
            "missed_discriminating_changes": discriminating - changed_on_discriminating,
            "changed_on_nondiscriminating": changed_on_nondiscriminating,
            "unchanged_on_nondiscriminating": (
                len(followups) - discriminating - changed_on_nondiscriminating
            ),
            "order_only_changes": order_only,
            "counterevidence_packet_changes": counter_changes,
            "counterevidence_conditional_text_stages": counter_text,
            "distinct_truth_pairs": distinct_truth_pairs,
            "distinct_truth_pair_collisions": collisions,
            "truncated_stages": sum(record[arm]["truncated"] for record in records.values()),
            "omitted_relation_total": sum(
                record[arm]["omitted_relation_count"] for record in records.values()
            ),
        }
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--retrieval", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--labels-sha256", required=True)
    parser.add_argument("--retrieval-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = score_retrieval(
        args.policy,
        args.labels,
        args.retrieval,
        expected_sha256={
            "policy": args.policy_sha256,
            "labels": args.labels_sha256,
            "retrieval": args.retrieval_sha256,
        },
    )
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "arms": result["arms"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
