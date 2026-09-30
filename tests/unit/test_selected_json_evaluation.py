"""Frozen evaluation controls, independent oracle, and privacy scans."""

import json
from pathlib import Path

import pytest

from benchmarks.private_alpha_selected_json import (
    frozen_suite,
    independent_oracle,
    load_cases,
    privacy_failures,
)
from systemsense.storage.sqlite_store import SQLiteStore


def test_frozen_holdouts_require_explicit_release_without_reading_answers() -> None:
    protocol, digest = frozen_suite()
    assert len(protocol["case_ids"]) >= 10
    assert len(digest) == 64
    with pytest.raises(ValueError, match="sealed"):
        load_cases("holdout")
    with pytest.raises(ValueError, match="sealed"):
        load_cases("holdout", release_digest="0" * 64)


def test_independent_oracle_and_privacy_scan(tmp_path: Path) -> None:
    selected = tmp_path / "private-filename.json"
    content = '{"PRIVATE_EVALUATION_CANARY":true}'
    selected.write_text(content, encoding="utf-8")
    assert independent_oracle(selected)["task"] == "accepted"
    selected.write_bytes(b"\xff")
    assert independent_oracle(selected)["error"] == "invalid_utf8"
    database = tmp_path / "case.db"
    with SQLiteStore(database):
        pass
    spec = {"recipe": {"text": content}}
    assert privacy_failures(database, {"summary": "Parser accepted"}, selected, spec) == []
    assert privacy_failures(database, {"private": str(selected)}, selected, spec)
    assert privacy_failures(database, {"private": content}, selected, spec)
    assert privacy_failures(database, json.dumps({"private": selected.name}), selected, spec)
