"""The CPU feasibility fixture is bounded and never treated as IT ground truth."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import benchmarks.laya_cpu_attention as benchmark
from benchmarks.laya_cpu_attention import representative_batch
from systemsense.application.bootstrap import default_capabilities


def test_representative_batch_covers_distinct_preview_pages_and_real_probe_catalog() -> None:
    state, evidence, candidates = representative_batch("A game feels slow")

    assert state["coverage_notes"] == (
        "evidence_pages_are_bounded_previews",
        "synthetic_runtime_only",
    )
    assert len(evidence) == 54
    assert len({item["page_id"] for item in evidence}) == 54
    assert len({item["fragment_id"] for item in evidence}) == 54
    assert all(len(item["description"]) <= 650 for item in evidence)
    assert all(
        json.loads(item["description"])["projection"] == "bounded_preview_not_full_page"
        for item in evidence
    )
    assert {item["probe_id"] for item in candidates} == {
        capability.probe_id for capability in default_capabilities()
    }


def test_measure_refuses_to_overwrite_existing_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.json"
    output.write_text("preserved", encoding="utf-8")
    monkeypatch.setattr(
        benchmark.psutil, "virtual_memory", lambda: SimpleNamespace(available=9 * 1024**3)
    )
    with pytest.raises(FileExistsError):
        benchmark.measure(tmp_path / "unused-profile.json", output)
    assert output.read_text(encoding="utf-8") == "preserved"
