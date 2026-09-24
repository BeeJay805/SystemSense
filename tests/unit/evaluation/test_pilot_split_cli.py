"""Offline CLI must preserve pilot custody without exposing its source JSON."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from systemsense.evaluation.pilot_fixture import (
    _replay_fixture,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.evaluation.pilot_split_cli import admit_pilot_corpus_file, main
from systemsense.evaluation.pilot_split_ledger import (
    PilotSplitLedger,
    PilotSplitLedgerManifest,
)


def _source(path: Path) -> None:
    path.write_text(_replay_fixture().model_dump_json(), encoding="utf-8")


def test_cli_admits_existing_corpus_and_writes_replayable_exclusive_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_path = tmp_path / "corpus.json"
    ledger_path = tmp_path / "split.db"
    first_path = tmp_path / "split-manifest-1.json"
    replay_path = tmp_path / "split-manifest-2.json"
    _source(corpus_path)

    first = admit_pilot_corpus_file(
        corpus_path=corpus_path,
        ledger_path=ledger_path,
        corpus_id="pilot_fixture_v1",
        output_path=first_path,
    )
    assert PilotSplitLedgerManifest.model_validate_json(first_path.read_bytes()) == first
    assert first.total_episodes == 1
    assert first.shard_count == 1
    assert first.source_authenticity == "not_verified"
    assert first.training_admissible is False
    assert first.diagnostic_performance_admissible is False
    with PilotSplitLedger(ledger_path, corpus_id="pilot_fixture_v1") as ledger:
        ledger.verify_manifest(expected_sha256=first.manifest_sha256)

    assert (
        main(
            [
                "--corpus",
                str(corpus_path),
                "--ledger-db",
                str(ledger_path),
                "--corpus-id",
                "pilot_fixture_v1",
                "--output-manifest",
                str(replay_path),
            ]
        )
        == 0
    )
    assert json.loads(first_path.read_text(encoding="utf-8")) == json.loads(
        replay_path.read_text(encoding="utf-8")
    )
    output = capsys.readouterr()
    assert "Synthetic slow PDF process" not in output.out + output.err
    assert "source_artifact_sha256" not in output.out + output.err


def test_existing_manifest_is_rejected_before_ledger_mutation(tmp_path: Path) -> None:
    corpus_path = tmp_path / "corpus.json"
    ledger_path = tmp_path / "split.db"
    output_path = tmp_path / "split-manifest.json"
    _source(corpus_path)
    output_path.write_text("must not overwrite", encoding="utf-8")
    with pytest.raises(FileExistsError):
        admit_pilot_corpus_file(
            corpus_path=corpus_path,
            ledger_path=ledger_path,
            corpus_id="pilot_fixture_v1",
            output_path=output_path,
        )
    assert output_path.read_text(encoding="utf-8") == "must not overwrite"
    assert not ledger_path.exists()


def test_invalid_corpus_fails_closed_without_ledger_or_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_path = tmp_path / "corpus.json"
    ledger_path = tmp_path / "split.db"
    output_path = tmp_path / "split-manifest.json"
    corpus_path.write_text('{"private":"SENSITIVE_MARKER"}', encoding="utf-8")
    assert (
        main(
            [
                "--corpus",
                str(corpus_path),
                "--ledger-db",
                str(ledger_path),
                "--corpus-id",
                "pilot_fixture_v1",
                "--output-manifest",
                str(output_path),
            ]
        )
        == 2
    )
    output = capsys.readouterr()
    assert "SENSITIVE_MARKER" not in output.out + output.err
    assert not ledger_path.exists()
    assert not output_path.exists()


def test_manifest_path_inside_repository_is_rejected(tmp_path: Path) -> None:
    corpus_path = tmp_path / "corpus.json"
    ledger_path = tmp_path / "split.db"
    _source(corpus_path)
    repository_root = Path(__file__).resolve().parents[3]
    with pytest.raises(ValueError, match="outside repository"):
        admit_pilot_corpus_file(
            corpus_path=corpus_path,
            ledger_path=ledger_path,
            corpus_id="pilot_fixture_v1",
            output_path=repository_root / "pilot-manifest-should-not-exist.json",
        )
    assert not ledger_path.exists()


def test_ledger_database_path_inside_repository_is_rejected(tmp_path: Path) -> None:
    corpus_path = tmp_path / "corpus.json"
    output_path = tmp_path / "split-manifest.json"
    _source(corpus_path)
    repository_root = Path(__file__).resolve().parents[3]
    with pytest.raises(ValueError, match="outside repository"):
        admit_pilot_corpus_file(
            corpus_path=corpus_path,
            ledger_path=repository_root / "pilot-splits-should-not-exist.db",
            corpus_id="pilot_fixture_v1",
            output_path=output_path,
        )
    assert not output_path.exists()


def test_source_corpus_cannot_be_reused_as_ledger_database(tmp_path: Path) -> None:
    corpus_path = tmp_path / "corpus.json"
    output_path = tmp_path / "split-manifest.json"
    _source(corpus_path)
    original = corpus_path.read_bytes()
    with pytest.raises(ValueError, match="distinct"):
        admit_pilot_corpus_file(
            corpus_path=corpus_path,
            ledger_path=corpus_path,
            corpus_id="pilot_fixture_v1",
            output_path=output_path,
        )
    assert corpus_path.read_bytes() == original
    assert not output_path.exists()


def test_invalid_existing_ledger_is_rejected_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_path = tmp_path / "corpus.json"
    ledger_path = tmp_path / "invalid-ledger.db"
    output_path = tmp_path / "split-manifest.json"
    _source(corpus_path)
    ledger_path.write_bytes(b"not a SQLite database SENSITIVE_MARKER")
    assert (
        main(
            [
                "--corpus",
                str(corpus_path),
                "--ledger-db",
                str(ledger_path),
                "--corpus-id",
                "pilot_fixture_v1",
                "--output-manifest",
                str(output_path),
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert "SENSITIVE_MARKER" not in captured.err
    assert "Traceback" not in captured.err
    assert not output_path.exists()
