"""Replayable CPU-only 16-cell synthetic task-source discrimination pilot.

All choices use real Investigator.run, equal per-domain checkpoints, and fake
adapter transports. The evaluator reads exact selected source bytes afterward.
No installed model, Windows fault, causal diagnosis, or policy speed claim.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import statistics
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from benchmarks.source_backed_frontier_pilot import (
    _canonical,  # pyright: ignore[reportPrivateUsage]
    _git_head,  # pyright: ignore[reportPrivateUsage]
    _sha,  # pyright: ignore[reportPrivateUsage]
    _source_sha,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_full_run import (
    _prechoice_request_digest,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_paired_input_audit import (
    _Agent,  # pyright: ignore[reportPrivateUsage]
    _blind_summary,  # pyright: ignore[reportPrivateUsage]
    _capture,  # pyright: ignore[reportPrivateUsage]
    _fake_model_input,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_task_discrimination_oracle import review_cell
from benchmarks.source_task_relation_red import run_balanced_relation_probe
from systemsense.application.investigator import Investigator
from systemsense.decision.frontier_ranker import FrontierRankRequestV1
from systemsense.evidence.retrieval import EvidenceRetriever
from systemsense.inference import laya_worker
from systemsense.inference.laya_runtime import LayaSubprocessRuntime
from tests.unit.inference.test_laya_runtime import (
    _config,  # pyright: ignore[reportPrivateUsage]
    _factory,  # pyright: ignore[reportPrivateUsage]
    _FakeProcess,  # pyright: ignore[reportPrivateUsage]
)

_EXPECTED_CAUSE = {
    "network-proxy-route": "browser_profile_proxy_route",
    "network-external-outage": "external_origin_unreachable",
    "application-viewer-rendering": "viewer_rendering_delay",
    "application-external-source": "external_document_source_delay",
}
_UNOPENED_FACT_NAMES = (
    "browser_proxy_enabled",
    "direct_same_origin_reachable",
    "viewer_render_p95_ms",
    "external_fetch_p95_ms",
    "cpu_peak_percent",
    "storage_warning_count",
)


def _baseline_scores(cells: list[dict[str, Any]], reviews: list[dict[str, Any]]) -> dict[str, Any]:
    """Reindex executed scripted alternatives; no separate baseline run claim."""

    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, cell in enumerate(cells):
        request = cast(FrontierRankRequestV1, cell["request"])
        groups[(cell["domain"], _prechoice_request_digest(request.model_dump(mode="json")))].append(
            index
        )
    rows: dict[str, list[str]] = defaultdict(list)
    for members in groups.values():
        if len(members) != 2:
            raise ValueError("baseline group lacks both executed scripted selections")
        first = cells[members[0]]
        request = cast(FrontierRankRequestV1, first["request"])
        source_items = [
            (item, semantic)
            for item, semantic in zip(request.items, request.item_semantics, strict=True)
            if item.reference.kind == "retrieve_evidence"
            and str(item.reference.evidence_id) in first["source_locators"]
        ]
        if len(source_items) != 2:
            raise ValueError("baseline source menu is incomplete")
        by_chosen = {cells[index]["chosen_evidence_id"]: reviews[index] for index in members}
        first_id = str(source_items[0][0].reference.evidence_id)
        titles = [semantic.information_goal for _, semantic in source_items]
        if len(set(titles)) != 1:
            raise ValueError("lexical title cue escaped balanced fixture")
        full = [
            str(item.reference.evidence_id)
            for item, semantic in source_items
            if semantic.source_task_relation is not None
            and semantic.source_task_relation.status == "same_target_full_window"
        ]
        if len(full) != 1:
            raise ValueError("coverage baseline lacks unique full-window candidate")
        rows["first_item"].append(by_chosen[first_id]["observed_effect"])
        rows["lexical_title_only_abstain"].append("abstained_equal_titles")
        rows["lexical_title_tie_first"].append(by_chosen[first_id]["observed_effect"])
        rows["coverage_rule"].append(by_chosen[full[0]]["observed_effect"])
    return {
        name: {
            "opportunities": len(outcomes),
            "useful": outcomes.count("reduces_toy_rivals"),
            "wasted": outcomes.count("does_not_reduce_toy_rivals"),
            "unknown": outcomes.count("unknown"),
            "abstained": outcomes.count("abstained_equal_titles"),
            "basis": "reindexed_exact_executed_scripted_readback_no_separate_policy_run",
        }
        for name, outcomes in rows.items()
    }


def _claim_accounting(reviews: list[dict[str, Any]]) -> dict[str, int | None]:
    """Keep unjudged claims unknown instead of folding None into zero."""

    unknown = sum(review["false_causal_claims"] is None for review in reviews)
    known_false = sum(
        int(review["false_causal_claims"])
        for review in reviews
        if review["false_causal_claims"] is not None
    )
    return {
        "causal_claims_emitted": sum(int(review["causal_claims_emitted"]) for review in reviews),
        "known_false_causal_claims": known_false,
        "false_causal_claims_unknown_cells": unknown,
        "false_causal_claims": known_false if unknown == 0 else None,
    }


def run_pilot(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    cells = run_balanced_relation_probe(output_dir / "cases", world_scope="all")
    if len(cells) != 16:
        raise ValueError("frozen pilot requires all sixteen scripted choices")
    agent = cast(laya_worker._LayaAgent, _Agent())  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(
        response=lambda request: laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            agent, request
        )
    )
    fake_install = tempfile.TemporaryDirectory(prefix="systemsense-discrimination-")
    runtime = LayaSubprocessRuntime(
        _config(Path(fake_install.name)),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    blind_cells: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    try:
        with patch.object(laya_worker, "_predict_with_model_input_capture", _fake_model_input):
            for index, cell in enumerate(cells):
                request = cast(FrontierRankRequestV1, cell["request"])
                capture = _blind_summary(request, _capture(request, runtime))
                raw_request = request.model_dump(mode="json")
                actual_payload = {
                    key: capture[key]
                    for key in ("laya_attend", "laya_fitted_worker", "local_deep_prompt")
                }
                if any(
                    name in json.dumps((raw_request, actual_payload))
                    for name in _UNOPENED_FACT_NAMES
                ):
                    raise ValueError("unopened source fact leaked before ranking")
                review = review_cell(cell)
                if review["source_task_coverage_independent"] != next(
                    semantic.source_task_relation.status
                    for semantic in request.item_semantics
                    if semantic.reference_id == cell["chosen_evidence_id"]
                    and semantic.source_task_relation is not None
                ):
                    raise ValueError("independent source coverage disagrees with frontier")
                if review["observed_effect"] == "reduces_toy_rivals" and review[
                    "toy_rivals_after"
                ] != (_EXPECTED_CAUSE[cell["world_key"]],):
                    raise ValueError("frozen synthetic world contradicts independent rival rubric")
                blind_cells.append(
                    {
                        "anonymous_cell_id": f"cell_{index:02d}",
                        "domain": cell["domain"],
                        "rank_request_envelope": raw_request,
                        "actual_adapter_inputs_fake_transports": actual_payload,
                    }
                )
                attempts.append(
                    {
                        key: value.model_dump(mode="json")
                        if isinstance(value, FrontierRankRequestV1)
                        else value
                        for key, value in cell.items()
                        if key != "database"
                    }
                    | {
                        "anonymous_cell_id": f"cell_{index:02d}",
                        "database": str(Path(cell["database"]).relative_to(output_dir)),
                        "raw_prechoice_request_sha256": _prechoice_request_digest(raw_request),
                        "actual_adapter_payload_sha256": _sha(actual_payload),
                    }
                )
                reviews.append({"anonymous_cell_id": f"cell_{index:02d}", **review})
    finally:
        runtime.close()
        fake_install.cleanup()
    parity: list[dict[str, Any]] = []
    pairs: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for cell in attempts:
        pairs[(cell["domain"], cell["matched_evidence_id"], cell["chosen_evidence_id"])].append(
            cell
        )
    for key, members in sorted(pairs.items()):
        if len(members) != 2:
            raise ValueError("hidden-world paired input is incomplete")
        parity.append(
            {
                "domain_and_position_choice": key,
                "raw_request_commitment_parity": (
                    "matched"
                    if len({item["raw_prechoice_request_sha256"] for item in members}) == 1
                    else "mismatched"
                ),
                "actual_adapter_payload_parity": (
                    "matched"
                    if len({item["actual_adapter_payload_sha256"] for item in members}) == 1
                    else "mismatched"
                ),
                "comparison_admissible": False,
            }
        )
    if any(
        item["raw_request_commitment_parity"] != "mismatched"
        or item["actual_adapter_payload_parity"] != "matched"
        for item in parity
    ):
        raise ValueError("hidden-world raw/model-visible parity contract failed")
    baselines = _baseline_scores(cells, reviews)
    protocol = {
        "schema_version": 1,
        "classification": "synthetic_cpu_development_pilot_not_holdout",
        "expected_cells": 16,
        "dimensions": {
            "domains": 2,
            "hidden_fact_variants_per_domain": 2,
            "covered_source_positions": 2,
            "scripted_selected_sources": 2,
        },
        "same_task_and_initial_checkpoint_within_domain": True,
        "related_episode_group": "domain_and_hidden_fact_variant_before_source_position_or_choice",
        "holdout_status": "development_fixture_no_holdout_claim",
        "prechoice_facts_hidden": True,
        "source_coverage_is_advisory_not_causal_proof": True,
        "fake_adapter_transport": "split_tokenizer_and_fake_tensors_no_installed_model",
        "actual_model_or_policy_comparison_admissible": False,
        "baseline_basis": "reindexed_executed_scripted_choice_not_separate_policy_run",
        "resource_scope": "cpu_only_no_model_gpu_vm_fault_training",
        "actual_providers": {
            "decision": "keyword-baseline",
            "frontier": "scripted-source-frontier-v1",
            "adapter_capture": "fake_Laya_worker_and_fake_LocalDeep_no_installed_weights",
        },
        "code_sha": _git_head(),
    }
    summary = {
        "schema_version": 1,
        "eligible_scripted_choices": len(cells),
        "executed_scripted_choices": len(reviews),
        "capture_failures": 0,
        "review_failures": 0,
        "unknown_effects": sum(review["observed_effect"] == "unknown" for review in reviews),
        "useful_evidence": sum(
            review["observed_effect"] == "reduces_toy_rivals" for review in reviews
        ),
        "wasted_retrievals": sum(
            review["observed_effect"] == "does_not_reduce_toy_rivals" for review in reviews
        ),
        **_claim_accounting(reviews),
        "supported_causal_answers": 0,
        "actual_model_calls": 0,
        "invalid_advice_count": 0,
        "model_cost": "not_applicable_no_model",
        "host_impact": "synthetic_fixture_no_host_probe_beyond_one_scripted_task_baseline_per_case",
        "prefetch": "disabled_not_applicable",
        "latency_comparison": "not_admissible_cpu_fixture_setup_and_fake_adapter_only",
        "app_run_elapsed_ms_median": statistics.median(
            cell["app_run_elapsed_ms"] for cell in cells
        ),
        "app_run_elapsed_ms_range": [
            min(cell["app_run_elapsed_ms"] for cell in cells),
            max(cell["app_run_elapsed_ms"] for cell in cells),
        ],
        "registered_synthetic_baseline_probe_attempts": sum(
            cell["probe_attempt_count"] for cell in cells
        ),
        "postbaseline_source_probe_attempts": sum(
            cell["probe_attempt_count"] - 1 for cell in cells
        ),
        "baseline_selection_scores": baselines,
        "hidden_world_pairs": len(parity),
        "raw_commitment_mismatch_pairs": sum(
            item["raw_request_commitment_parity"] == "mismatched" for item in parity
        ),
        "actual_adapter_visible_match_pairs": sum(
            item["actual_adapter_payload_parity"] == "matched" for item in parity
        ),
        "comparison_admissible": False,
    }
    (output_dir / "protocol.json").write_bytes(_canonical(protocol))
    (output_dir / "policy-visible" / "inputs.json").write_bytes(
        _canonical({"schema_version": 1, "cells": blind_cells})
    )
    (output_dir / "evaluator-only" / "attempts.json").write_bytes(
        _canonical({"schema_version": 1, "cells": attempts})
    )
    (output_dir / "evaluator-only" / "reviews.json").write_bytes(
        _canonical({"schema_version": 1, "reviews": reviews})
    )
    (output_dir / "evaluator-only" / "parity.json").write_bytes(
        _canonical({"schema_version": 1, "pairs": parity})
    )
    (output_dir / "evaluator-only" / "summary.json").write_bytes(_canonical(summary))
    db_names = [
        str(path.relative_to(output_dir)).replace("\\", "/")
        for path in sorted((output_dir / "cases").glob("*.db"))
    ]
    file_names = [
        "protocol.json",
        "policy-visible/inputs.json",
        "evaluator-only/attempts.json",
        "evaluator-only/reviews.json",
        "evaluator-only/parity.json",
        "evaluator-only/summary.json",
        *db_names,
    ]
    manifest = {
        "schema_version": 1,
        "source_sha256_normalized": {
            "runner": _source_sha(Path(__file__)),
            "oracle": _source_sha(Path(review_cell.__code__.co_filename)),
            "fixture": _source_sha(Path(run_balanced_relation_probe.__code__.co_filename)),
            "investigator": _source_sha(Path(inspect.getfile(Investigator))),
            "frontier_request": _source_sha(Path(inspect.getfile(FrontierRankRequestV1))),
            "retriever": _source_sha(Path(inspect.getfile(EvidenceRetriever))),
            "fake_laya_runtime": _source_sha(Path(inspect.getfile(LayaSubprocessRuntime))),
        },
        "files": {
            name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest()
            for name in file_names
        },
    }
    (output_dir / "manifest.json").write_bytes(_canonical(manifest))
    return summary


def verify_pilot(output_dir: Path) -> dict[str, Any]:
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    expected_sources = {
        "runner": _source_sha(Path(__file__)),
        "oracle": _source_sha(Path(review_cell.__code__.co_filename)),
        "fixture": _source_sha(Path(run_balanced_relation_probe.__code__.co_filename)),
        "investigator": _source_sha(Path(inspect.getfile(Investigator))),
        "frontier_request": _source_sha(Path(inspect.getfile(FrontierRankRequestV1))),
        "retriever": _source_sha(Path(inspect.getfile(EvidenceRetriever))),
        "fake_laya_runtime": _source_sha(Path(inspect.getfile(LayaSubprocessRuntime))),
    }
    if manifest["source_sha256_normalized"] != expected_sources:
        raise ValueError("pilot source revision mismatch")
    for name, digest in manifest["files"].items():
        if hashlib.sha256((output_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"pilot artifact hash mismatch: {name}")
    summary = json.loads((output_dir / "evaluator-only" / "summary.json").read_text())
    blind = json.loads((output_dir / "policy-visible" / "inputs.json").read_text())
    reviews = json.loads((output_dir / "evaluator-only" / "reviews.json").read_text())
    attempts = json.loads((output_dir / "evaluator-only" / "attempts.json").read_text())
    if len(blind["cells"]) != 16 or len(reviews["reviews"]) != 16 or len(attempts["cells"]) != 16:
        raise ValueError("pilot cells or reviews incomplete")
    rebuilt: list[dict[str, Any]] = []
    for attempt, saved_review in zip(attempts["cells"], reviews["reviews"], strict=True):
        cell = {
            **attempt,
            "request": FrontierRankRequestV1.model_validate(attempt["request"]),
            "database": str(output_dir / attempt["database"]),
        }
        current_review = review_cell(cell)
        if _canonical(current_review) != _canonical(
            {key: value for key, value in saved_review.items() if key != "anonymous_cell_id"}
        ):
            raise ValueError("pilot exact source review changed")
        rebuilt.append(cell)
    if _baseline_scores(rebuilt, reviews["reviews"]) != summary["baseline_selection_scores"]:
        raise ValueError("pilot baseline score changed")
    claim_totals = _claim_accounting(reviews["reviews"])
    if any(summary.get(key) != value for key, value in claim_totals.items()):
        raise ValueError("pilot causal claim accounting changed")
    return {"integrity_verified": True, **summary}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    result = verify_pilot(args.output_dir) if args.verify else run_pilot(args.output_dir)
    print(json.dumps(result, sort_keys=True))
