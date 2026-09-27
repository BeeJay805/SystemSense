"""Score first selected source separately from later linked advisory evidence."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from benchmarks.postretrieval_advisory_pilot import run_postretrieval_pilot


def test_first_choice_revises_only_source_supported_toy_rivals(tmp_path: Path) -> None:
    rows = run_postretrieval_pilot(tmp_path / "postretrieval")
    assert len(rows) == 16
    assert Counter(row["domain"] for row in rows) == {
        "network_browser": 8,
        "application_performance": 8,
    }
    assert Counter(row["first_relation_status"] for row in rows) == {
        "same_target_full_window": 8,
        "different_target": 4,
        "insufficient_window": 4,
    }
    for row in rows:
        request = row["first_request"]
        response = row["first_response"]
        review = row["review"]
        assert request["schema_version"] == 5
        assert request["task_observation"] is not None
        assert len(request["previous_hypotheses"]) == 2
        assert all(
            not h["supporting_evidence_ids"] and not h["contradicting_evidence_ids"]
            for h in request["previous_hypotheses"]
        )
        assert response["status"] == "unresolved"
        assert len(response["hypotheses"]) == 2
        assert all(h["status"] != "supported" for h in response["hypotheses"])
        assert row["terminal_status"] == "complete"
        assert row["terminal_outcome"] == "no_progress"
        assert row["terminal_assessment"] is None
        assert len(row["terminal_hypotheses"]) == 2
        assert all(h["status"] != "supported" for h in row["terminal_hypotheses"])
        assert row["last_response"]["status"] == "unresolved"
        assert review["source_task_coverage_independent"] == row["first_relation_status"]
        assert review["supported_causal_answer"] is False
        assert review["causal_claims_emitted"] == 0
        cited = [
            h
            for h in response["hypotheses"]
            if h["supporting_evidence_ids"] or h["contradicting_evidence_ids"]
        ]
        if review["observed_effect"] == "reduces_toy_rivals":
            assert len(cited) == 2
            favored = next(h for h in cited if h["supporting_evidence_ids"])
            contested = next(h for h in cited if h["contradicting_evidence_ids"])
            assert favored["hypothesis_id"] == "h_" + review["toy_rivals_after"][0]
            assert favored["supporting_evidence_ids"] == [row["chosen_evidence_id"]]
            assert contested["contradicting_evidence_ids"] == [row["chosen_evidence_id"]]
        else:
            assert review["observed_effect"] == "does_not_reduce_toy_rivals"
            assert cited == []
