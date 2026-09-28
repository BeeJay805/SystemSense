"""Frozen-suite custody tests use scripted callbacks only; no model is started."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.overnight_suite import (
    RunStamp,
    VisibleCase,
    collect_case_custody,
    compare_frozen_contracts,
    load_frozen_suite,
    run_attempt,
    score_attempt,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _suite(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "visible-suite.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": [
                    {
                        "case_id": "case-0123456789ab",
                        "split": "development",
                        "family_group": "synthetic_pressure",
                        "source": "synthetic",
                        "visible_input_sha256": _sha("visible"),
                        "initial_evidence_sha256": _sha("evidence"),
                        "action_contract_sha256": _sha("actions"),
                        "budget_ms": 10000,
                    },
                    {
                        "case_id": "case-abcdef012345",
                        "split": "holdout",
                        "family_group": "synthetic_network",
                        "source": "synthetic",
                        "visible_input_sha256": _sha("visible2"),
                        "initial_evidence_sha256": _sha("evidence2"),
                        "action_contract_sha256": _sha("actions2"),
                        "budget_ms": 10000,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _capture(case_id: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "status": "completed",
        "contract": {
            "visible_input_sha256": _sha("visible"),
            "initial_evidence_sha256": _sha("evidence"),
            "action_contract_sha256": _sha("actions"),
        },
        "runtime": {
            "provider_calls": [
                {
                    "role": "catalog_attention",
                    "provider_id": "laya-local-decision",
                    "degraded": False,
                },
                {
                    "role": "reasoning",
                    "provider_id": "codex-subscription-reasoning",
                    "degraded": False,
                },
            ],
            "raw_invalid_retries": 1,
            "startup_ms": 1200,
            "resource_observations": [{"at": "2026-09-28T00:00:00+00:00", "rss_bytes": 42}],
        },
        "model_inputs": ["visible prompt with no answer"],
        "custody": {
            "snapshots": [
                {
                    "snapshot_id": "snap-1",
                    "request": {
                        "provider": {
                            "provider_id": "laya-local-decision",
                            "provider_version": "1",
                            "role": "fast_decision",
                        },
                        "items": [
                            {
                                "item_id": "item-1",
                                "reference": {"kind": "measure", "candidate_id": "pressure"},
                            }
                        ],
                    },
                    "response": {
                        "provider": {
                            "provider_id": "laya-local-decision",
                            "provider_version": "1",
                            "role": "fast_decision",
                        },
                        "ranking_source": "laya",
                        "ranked_item_ids": ["item-1"],
                        "considered_item_ids": ["item-1"],
                        "coverage_complete": True,
                        "model_abstained": False,
                        "degraded_reason": None,
                    },
                }
            ],
            "executions": [
                {
                    "snapshot_id": "snap-1",
                    "candidate_id": "pressure",
                    "execution_id": "execution-1",
                    "admission_id": "admission-1",
                    "probe_id": "core.resources",
                    "target_handle": "affected-process",
                    "parameters": {"window_seconds": 5},
                    "status": "ok",
                    "finished_at": "2026-09-28T00:00:02+00:00",
                    "evidence_ids": ["ev-1"],
                }
            ],
            "mailbox": [
                {
                    "request_sha256": _sha("deep2"),
                    "status": "applied",
                    "created_at": "2026-09-28T00:00:03+00:00",
                    "updated_at": "2026-09-28T00:00:05+00:00",
                    "task": {
                        "request": {
                            "evidence_ids": ["ev-1"],
                            "evidence_context": [{"evidence_id": "ev-1", "status": "observed"}],
                        }
                    },
                    "result": {
                        "response": {
                            "provider": {"provider_id": "codex-subscription-reasoning"},
                            "degraded": False,
                            "considered_evidence_ids": ["ev-1"],
                            "summary": "Pressure measurement seen; cause remains unknown",
                        }
                    },
                }
            ],
        },
    }


def _stamp(phase: str = "development_baseline") -> RunStamp:
    return RunStamp(
        phase=phase,
        arm="laya_sol",
        code_revision="a" * 40,
        baseline_revision="a" * 40,
        candidate_revision="b" * 40 if phase.startswith("heldout") else None,
    )


def test_manifest_is_frozen_partitioned_and_oracle_free(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    assert suite.sha256 == digest
    assert suite.cases[0].split == "development"
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="digest"):
        load_frozen_suite(path, digest)

    path, _ = _suite(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["cases"][0]["expected_outcome"] = "pressure"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match=r"unknown|oracle"):
        load_frozen_suite(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_attempts_are_create_only_and_hidden_oracle_never_reaches_callback(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    seen: list[object] = []

    def scripted(visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        seen.append(visible)
        return _capture("case-0123456789ab")

    first = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "attempts", scripted)
    second = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "attempts", scripted)
    assert first != second
    assert (first / "start.json").exists()
    assert (first / "capture.json").exists()
    assert (
        first.joinpath("capture.json").read_bytes() == second.joinpath("capture.json").read_bytes()
    )
    assert "oracle" not in repr(seen)
    assert "family_group" not in repr(seen)
    assert not (first / "score.json").exists()


def test_failed_attempt_is_retained_and_cannot_be_scored_as_pass(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)

    def fail(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        raise RuntimeError("transport failed")

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "attempts", fail)
    assert (attempt / "start.json").exists()
    assert (attempt / "failure.json").exists()
    assert not (attempt / "capture.json").exists()


def test_score_requires_exact_execution_and_later_response(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    capture = _capture("case-0123456789ab")

    def return_capture(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return capture

    attempt = run_attempt(
        suite,
        "case-0123456789ab",
        _stamp(),
        tmp_path / "attempts",
        return_capture,
    )
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["mechanical_choice_execution_response"] is True
    assert score["useful_choice_observed"] is True
    assert score["semantic_correctness"] == "human_review_pending"
    metrics = score["metrics"]
    assert isinstance(metrics, dict)
    assert metrics["completed_mailbox_durations_ms"] == [2000]
    assert metrics["raw_invalid_retries"] == 1

    broken = _capture("case-0123456789ab")
    broken["custody"]["executions"][0]["status"] = "failed"

    def return_broken(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return broken

    failed_attempt = run_attempt(
        suite,
        "case-0123456789ab",
        _stamp(),
        tmp_path / "attempts",
        return_broken,
    )
    failed_score = score_attempt(
        failed_attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest()
    )
    assert failed_score["mechanical_choice_execution_response"] is False
    assert failed_score["useful_choice_observed"] is False


def test_holdout_partition_and_revision_guard(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)

    def return_capture(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-0123456789ab")

    def holdout(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-abcdef012345")

    with pytest.raises(ValueError, match=r"phase|split"):
        run_attempt(
            suite,
            "case-abcdef012345",
            _stamp(),
            tmp_path / "attempts",
            holdout,
        )
    with pytest.raises(ValueError, match="revision"):
        run_attempt(
            suite,
            "case-0123456789ab",
            RunStamp("development_candidate", "laya_sol", "a" * 40, "a" * 40, "b" * 40),
            tmp_path / "attempts",
            return_capture,
        )


def test_missing_response_leakage_and_repeated_scoring_fail_closed(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {
                    "case-0123456789ab": {
                        "useful_candidate_ids": ["pressure"],
                        "leak_markers": ["secret-cause"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    missing = _capture("case-0123456789ab")
    missing["custody"]["mailbox"] = []

    def return_missing(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return missing

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", return_missing)
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["mechanical_choice_execution_response"] is False
    assert score["useful_choice_observed"] is False
    with pytest.raises(FileExistsError):
        score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())

    leaked = _capture("case-0123456789ab")
    leaked["model_inputs"] = ["Visible prompt secret-cause"]

    def return_leaked(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return leaked

    leaked_attempt = run_attempt(
        suite, "case-0123456789ab", _stamp(), tmp_path / "runs", return_leaked
    )
    leaked_score = score_attempt(
        leaked_attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest()
    )
    assert leaked_score["model_input_leakage_audit"] == "failed_hidden_marker_present"
    assert leaked_score["mechanical_choice_execution_response"] is False


def test_route_attribution_and_contract_comparison(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    bad_route = _capture("case-0123456789ab")
    bad_route["runtime"]["provider_calls"] = [
        {"role": "reasoning", "provider_id": "codex-subscription-reasoning", "degraded": False}
    ]
    bad_route["custody"]["snapshots"][0]["response"]["provider"]["provider_id"] = "other"

    def return_bad(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return bad_route

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", return_bad)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["mechanical_choice_execution_response"] is False
    assert score["route_realization"]["status"] == "not_demonstrated"  # type: ignore[index]
    parity = compare_frozen_contracts([attempt, attempt])
    assert parity["matched_normalized_starting_contract"] is True
    assert parity["full_runtime_request_byte_parity"] == "not_claimed"


def test_frontier_snapshot_proves_laya_route_without_catalog_attention_call(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )
    capture = _capture("case-0123456789ab")
    capture["runtime"]["provider_calls"] = [
        {"role": "reasoning", "provider_id": "codex-subscription-reasoning", "degraded": False}
    ]

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return capture

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", invoke)
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["route_realization"]["status"] == "demonstrated"
    assert score["mechanical_choice_execution_response"] is True


@pytest.mark.parametrize("corruption", ["absent", "degraded", "fallback", "wrong_provider"])
def test_claimed_laya_configuration_without_valid_frontier_readback_is_not_proof(
    corruption: str,
) -> None:
    from benchmarks.overnight_suite import _route_realization

    capture = _capture("case-0123456789ab")
    if corruption == "absent":
        capture["custody"]["snapshots"] = []
    elif corruption == "degraded":
        capture["custody"]["snapshots"][0]["response"]["degraded_reason"] = "invalid"
    elif corruption == "fallback":
        capture["custody"]["snapshots"][0]["response"]["ranking_source"] = "deterministic_fallback"
    else:
        capture["custody"]["snapshots"][0]["response"]["provider"]["provider_id"] = "other"
    assert _route_realization(capture, "laya_sol")["status"] == "not_demonstrated"


def test_rescore_preserves_original_and_uses_revision_named_file(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-0123456789ab")

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", invoke)
    oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
    score_attempt(attempt, suite, oracle, oracle_sha)
    original = (attempt / "score.json").read_bytes()
    revision = "b" * 40
    rescored = score_attempt(attempt, suite, oracle, oracle_sha, score_revision=revision)
    assert rescored["scorer_revision"] == revision
    assert (attempt / f"score-{revision}.json").exists()
    assert (attempt / "score.json").read_bytes() == original
    with pytest.raises(FileExistsError):
        score_attempt(attempt, suite, oracle, oracle_sha, score_revision=revision)
    with pytest.raises(ValueError, match="revision"):
        score_attempt(attempt, suite, oracle, oracle_sha, score_revision="../unsafe")


def test_holdout_rescore_preserves_original_consumption_receipt(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-abcdef012345": {"useful_candidate_ids": []}},
            }
        ),
        encoding="utf-8",
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        capture = _capture("case-abcdef012345")
        capture["contract"] = {
            "visible_input_sha256": _sha("visible2"),
            "initial_evidence_sha256": _sha("evidence2"),
            "action_contract_sha256": _sha("actions2"),
        }
        return capture

    attempt = run_attempt(
        suite,
        "case-abcdef012345",
        RunStamp("heldout_baseline", "laya_sol", "a" * 40, "a" * 40, "b" * 40),
        tmp_path / "runs",
        invoke,
    )
    oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
    score_attempt(attempt, suite, oracle, oracle_sha)
    original = (attempt / "holdout_consumption.json").read_bytes()
    score_attempt(attempt, suite, oracle, oracle_sha, score_revision="b" * 40)
    assert (attempt / "holdout_consumption.json").read_bytes() == original


def test_readback_uses_existing_case_tables_without_running_models(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        custody = collect_case_custody(store, "absent-case")
    assert custody["case_id"] == "absent-case"
    assert custody["snapshots"] == []
    assert custody["next_probe_execution_links"] == []
    assert custody["followup_admissions"] == []
    assert custody["probe_executions"] == []


@pytest.mark.parametrize(
    ("probe_id", "target_handle", "window_seconds", "expected"),
    [
        ("core.resources", "affected-process", 5, True),
        ("gpu.telemetry.sample", "affected-process", 5, False),
        ("core.resources", "other-process", 5, False),
        ("core.resources", "affected-process", 10, False),
    ],
)
def test_dynamic_candidate_requires_frozen_registered_invocation_scope(
    tmp_path: Path, probe_id: str, target_handle: str, window_seconds: int, expected: bool
) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {
                    "case-0123456789ab": {
                        "useful_candidate_ids": [],
                        "useful_probe_ids": ["core.resources"],
                        "useful_registered_checks": [
                            {
                                "probe_id": "core.resources",
                                "target_handle": "affected-process",
                                "parameter_equals": {"window_seconds": 5},
                            }
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    capture = _capture("case-0123456789ab")
    execution = capture["custody"]["executions"][0]
    execution["probe_id"] = probe_id
    execution["target_handle"] = target_handle
    execution["parameters"] = {"window_seconds": window_seconds}

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return capture

    stamp = RunStamp(
        "development_baseline",
        "laya_sol",
        "a" * 40,
        "a" * 40,
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
    )
    attempt = run_attempt(suite, "case-0123456789ab", stamp, tmp_path / "runs", invoke)
    score = score_attempt(attempt, suite, oracle, stamp.oracle_sha256 or "")
    assert score["mechanical_choice_execution_response"] is True
    assert score["useful_choice_observed"] is expected
    assert score["oracle_preregistered_with_attempt"] is True


def test_oracle_change_after_preregistration_is_rejected(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_probe_ids": ["core.resources"]}},
            }
        ),
        encoding="utf-8",
    )
    frozen_oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
    stamp = RunStamp(
        "development_baseline", "laya_sol", "a" * 40, "a" * 40, oracle_sha256=frozen_oracle_sha
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-0123456789ab")

    attempt = run_attempt(suite, "case-0123456789ab", stamp, tmp_path / "runs", invoke)
    oracle.write_text(oracle.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="oracle digest"):
        score_attempt(attempt, suite, oracle, frozen_oracle_sha)
