"""Fixture-only command boundaries; no test label admits model training."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

import pytest

from benchmarks import laya_fixture_rehearsal as rehearsal


def _request() -> dict[str, object]:
    return {
        "items": [
            {"item_id": "first", "reference": {"kind": "measure", "window": "first-window"}},
            {"item_id": "second", "reference": {"kind": "measure", "window": "second-window"}},
            {
                "item_id": "lookup",
                "reference": {"kind": "retrieve_evidence", "window": "first-window"},
            },
        ],
        "item_semantics": [
            {
                "item_id": "first",
                "measurement": {
                    "probe_id": "application.target_pressure",
                    "invocation_sha256": "a" * 64,
                },
            },
            {
                "item_id": "second",
                "measurement": {
                    "probe_id": "application.target_pressure",
                    "invocation_sha256": "b" * 64,
                },
            },
            {"item_id": "lookup", "measurement": None},
        ],
    }


def test_selects_two_distinct_target_measurements_without_claiming_usefulness() -> None:
    ids = rehearsal.select_synthetic_pair_ids(
        _request(),
        {
            "questions": [
                {"item_id": "first", "question": {"type": "noul"}},
                {"item_id": "second", "question": {"type": "noul"}},
                {"item_id": "lookup", "question": {"type": "noul"}},
            ]
        },
        observable="application.target_pressure",
    )
    assert ids == ("first", "second")
    pair = rehearsal.synthetic_marker_pair(
        snapshot_id="snapshot-one",
        candidate_ids=ids,
        split="train",
        source_group_id="episode-one",
    )
    assert pair.useful_candidate_id == "first"
    assert pair.uninformative_candidate_id == "second"
    assert rehearsal.verify_synthetic_marker_pair(pair)
    assert pair.positive_fixture_sha256 != pair.negative_fixture_sha256


def test_target_digest_report_follows_captured_question_order() -> None:
    request = _request()
    semantics = request["item_semantics"]
    assert isinstance(semantics, list)
    request["item_semantics"] = list(reversed(cast(list[object], semantics)))
    assert rehearsal.ordered_invocation_digests(request, ("first", "second")) == (
        "a" * 64,
        "b" * 64,
    )


def test_rejects_same_target_and_disconnected_question() -> None:
    request = _request()
    semantics = request["item_semantics"]
    assert isinstance(semantics, list)
    assert isinstance(semantics[1], dict)
    assert isinstance(semantics[0], dict)
    assert isinstance(semantics[0]["measurement"], dict)
    semantics[1]["measurement"] = semantics[0]["measurement"]
    with pytest.raises(ValueError, match="distinct target"):
        rehearsal.select_synthetic_pair_ids(
            request,
            {
                "questions": [
                    {"item_id": "first", "question": {"type": "noul"}},
                    {"item_id": "second", "question": {"type": "noul"}},
                ]
            },
            observable="application.target_pressure",
        )
    request = _request()
    with pytest.raises(ValueError, match="same complete comparison"):
        rehearsal.select_synthetic_pair_ids(
            request,
            {"questions": [{"item_id": "first", "question": {"type": "noul"}}]},
            observable="application.target_pressure",
        )


def test_read_only_snapshot_store_cannot_modify_capture(tmp_path: Path) -> None:
    database = tmp_path / "capture.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE immutable_capture(value TEXT NOT NULL)")
        connection.execute("INSERT INTO immutable_capture VALUES ('original')")
    with rehearsal.ReadOnlySnapshotStore(database) as store:
        assert store.connection.execute("SELECT value FROM immutable_capture").fetchone() == (
            "original",
        )
        with pytest.raises(sqlite3.OperationalError):
            store.connection.execute("UPDATE immutable_capture SET value='altered'")
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT value FROM immutable_capture").fetchone() == ("original",)


def test_report_cannot_be_written_into_checkout(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[3]
    with pytest.raises(ValueError, match="outside the checkout"):
        rehearsal.ensure_private_report_path(checkout / "fixture-report.json")
    destination = tmp_path / "fixture-report.json"
    assert rehearsal.ensure_private_report_path(destination) == destination.resolve()


def test_synthetic_marker_cannot_be_presented_as_observed_outcome() -> None:
    pair = rehearsal.synthetic_marker_pair(
        snapshot_id="snapshot-one",
        candidate_ids=("first", "second"),
        split="train",
        source_group_id="episode-one",
    )
    development_pair = rehearsal.synthetic_marker_pair(
        snapshot_id="snapshot-two",
        candidate_ids=("third", "fourth"),
        split="development",
        source_group_id="episode-two",
    )
    result: dict[str, object] = {
        "status": "fixture_only",
        "trainable": False,
        "weight_updates_performed": False,
        "train_pairs": 1,
        "development_pairs": 1,
        "parameters_sha256_before": "a" * 64,
        "parameters_sha256_after": "a" * 64,
    }
    report = rehearsal.fixture_admission_report(
        train_pair=pair,
        development_pair=development_pair,
        rehearsal_result=result,
    )
    assert report["trainable"] is False
    assert report["training_admission"] == "rejected_no_observed_outcomes"
    assert report["weight_updates_performed"] is False
    assert report["synthetic_signs_are_outcome_labels"] is False
    with pytest.raises(ValueError, match="unchanged parameters"):
        rehearsal.fixture_admission_report(
            train_pair=pair,
            development_pair=development_pair,
            rehearsal_result={**result, "parameters_sha256_after": "b" * 64},
        )


def test_capture_loader_rejects_missing_source_without_creating_a_database(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        rehearsal.load_capture_fixture(
            missing,
            "frontier_decision_snapshot_" + "a" * 32,
            observable="application.target_pressure",
            split="train",
        )
    assert not missing.exists()


def test_command_exposes_explicit_fixture_only_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        rehearsal.main(["--help"])
    assert result.value.code == 0
    help_text = capsys.readouterr().out
    assert "--train-db" in help_text
    assert "--development-db" in help_text
    assert "--report-dir" in help_text
    assert "fixture" in help_text.lower()
