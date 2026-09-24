"""The replay is a fixture-contract custody check, never a performance result."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from systemsense.evaluation.pilot_corpus import PilotCorpus, verify_pilot_corpus
from systemsense.evaluation.pilot_fixture import write_fixture_corpus


def test_fixture_replay_writes_exclusive_honest_manifest(tmp_path: Path) -> None:
    destination = tmp_path / "pilot-fixture"

    manifest = write_fixture_corpus(destination)
    corpus = PilotCorpus.model_validate_json((destination / "corpus.json").read_text())
    on_disk = json.loads((destination / "run_manifest.json").read_text())

    assert manifest == on_disk
    assert corpus.source_counts == {"fixture_contract": 1}
    assert corpus.label_quality_counts == {"unknown": 2}
    assert len(corpus.episodes[0].candidates) == 2
    assert {item.utility for item in corpus.episodes[0].candidates} == {"unknown"}
    assert manifest["source_kind"] == "fixture_contract"
    assert manifest["source_authenticity"] == "not_verified"
    assert manifest["worker_input_parity"] == "not_proven"
    assert manifest["training_admissible"] is False
    assert manifest["diagnostic_performance_admissible"] is False
    assert manifest["corpus_manifest_sha256"] == verify_pilot_corpus(corpus)
    with pytest.raises(FileExistsError):
        write_fixture_corpus(destination)


def test_fixture_replay_rejects_missing_parent(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        write_fixture_corpus(tmp_path / "missing" / "pilot")
