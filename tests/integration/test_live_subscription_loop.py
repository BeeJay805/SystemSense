"""CPU custody negatives plus explicitly opted-in actual subscription trial."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from benchmarks.subscription_loop import collect_artifact, run_trial, score_custody
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator


def _artifact() -> dict[str, Any]:
    return {
        "snapshots": [
            {
                "snapshot_id": "s",
                "request": {
                    "items": [
                        {"item_id": "i", "reference": {"kind": "measure", "candidate_id": "c"}}
                    ]
                },
                "response": {
                    "ranking_source": "laya",
                    "degraded_reason": None,
                    "ranked_item_ids": ["i"],
                },
            }
        ],
        "executions": [
            {
                "snapshot_id": "s",
                "candidate_id": "c",
                "admission_id": "a",
                "execution_id": "x",
                "status": "ok",
                "finished_at": "2026-09-27T12:00:00+00:00",
                "evidence_ids": ["e"],
            }
        ],
        "mailbox": [
            {
                "request_sha256": "r",
                "status": "applied",
                "created_at": "2026-09-27T12:00:01+00:00",
                "task": {
                    "request": {
                        "evidence_ids": ["e"],
                        "evidence_context": [{"evidence_id": "e", "status": "observed"}],
                    }
                },
                "result": {
                    "response": {
                        "degraded": False,
                        "considered_evidence_ids": ["e"],
                        "provider": {"provider_id": "codex-subscription-reasoning"},
                        "hypotheses": [{"hypothesis_id": "h", "supporting_evidence_ids": ["e"]}],
                    }
                },
            }
        ],
    }


def test_custody_reports_link_without_semantic_claim() -> None:
    score = score_custody(_artifact())
    assert score["mechanical_pass"]
    assert score["semantic_correctness"] == "not_evaluated"
    assert score["selection_execution_later_response_links"][0]["evidence_ids"] == ["e"]


@pytest.mark.parametrize(
    "broken", ["failed_execution", "catalog_only", "unobserved", "not_considered"]
)
def test_custody_requires_successful_execution_and_shown_observation(broken: str) -> None:
    artifact = _artifact()
    if broken == "failed_execution":
        artifact["executions"][0]["status"] = "failed"
    elif broken == "catalog_only":
        artifact["mailbox"][0]["task"]["request"]["evidence_context"] = []
    elif broken == "unobserved":
        artifact["mailbox"][0]["task"]["request"]["evidence_context"][0]["status"] = "failed"
    else:
        artifact["mailbox"][0]["result"]["response"]["considered_evidence_ids"] = []
    assert not score_custody(artifact)["mechanical_pass"]


@pytest.mark.parametrize(
    "broken",
    [
        "fallback",
        "unselected",
        "unexecuted",
        "earlier",
        "rejected",
        "other_provider",
        "unknown",
        "considered_only",
    ],
)
def test_custody_rejects_broken_chain(broken: str) -> None:
    artifact = _artifact()
    if broken == "fallback":
        artifact["snapshots"][0]["response"]["ranking_source"] = "fallback"
    elif broken == "unselected":
        artifact["executions"][0]["candidate_id"] = "other"
    elif broken == "unexecuted":
        artifact["executions"][0]["finished_at"] = None
    elif broken == "earlier":
        artifact["mailbox"][0]["created_at"] = "2026-09-27T11:59:59+00:00"
    elif broken == "rejected":
        artifact["mailbox"][0]["status"] = "rejected"
    elif broken == "other_provider":
        artifact["mailbox"][0]["result"]["response"]["provider"]["provider_id"] = "qwen"
    elif broken == "unknown":
        artifact["mailbox"][0]["task"]["request"]["evidence_ids"] = []
    else:
        artifact["mailbox"][0]["result"]["response"]["hypotheses"] = []
        artifact["mailbox"][0]["result"]["response"]["considered_evidence_ids"] = ["e"]
    assert not score_custody(artifact)["mechanical_pass"]


def test_explicit_missing_id_is_reported_separately() -> None:
    artifact = _artifact()
    hypothesis = artifact["mailbox"][0]["result"]["response"]["hypotheses"][0]
    hypothesis["missing_evidence_ids"] = hypothesis.pop("supporting_evidence_ids")
    score = score_custody(artifact)
    assert score["mechanical_pass"]
    assert (
        score["selection_execution_later_response_links"][0]["citation_field"]
        == "missing_evidence_ids"
    )


@pytest.mark.parametrize(
    "summary,passes",
    [
        ("Observation e is missing target and time-window linkage.", True),
        ("Missing target and time-window linkage.", False),
        ("Observation e establishes the cause.", False),
    ],
)
def test_id_bound_missing_link_summary(summary: str, passes: bool) -> None:
    artifact = _artifact()
    response = artifact["mailbox"][0]["result"]["response"]
    response["hypotheses"] = []
    response["summary"] = summary
    assert score_custody(artifact)["mechanical_pass"] is passes


def test_export_queries_current_schema_without_models(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case = investigator(store).create(objective="Synthetic fixture", budget_ms=1000)
        artifact = collect_artifact(store, str(case.case_id))
    assert artifact["mailbox"] == []
    assert artifact["snapshots"] == []
    assert not score_custody(artifact)["mechanical_pass"]


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_RUN_LIVE_SUBSCRIPTION") != "1",
    reason="explicit opt-in actual Laya and subscription model trial",
)
def test_actual_laya_and_subscription_loop() -> None:
    executable = Path(os.environ["SYSTEMSENSE_CODEX_EXECUTABLE"])
    directory = Path(os.environ["SYSTEMSENSE_SUBSCRIPTION_ARTIFACT_DIRECTORY"])
    score = run_trial(executable=executable, artifact_directory=directory)
    assert score["mechanical_pass"], f"Inspect durable artifacts in {directory}"
