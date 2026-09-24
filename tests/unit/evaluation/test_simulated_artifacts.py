"""Reproducible toy artifacts validate contracts, never diagnostic quality."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from systemsense.evaluation import simulated_artifacts as artifacts


def test_repeated_writes_are_byte_identical_and_replayable(tmp_path: Path) -> None:
    selections = {"wifi_dns": ("wifi.gateway", "wifi.dns")}
    first = tmp_path / "first"
    second = tmp_path / "second"

    artifacts.write_simulated_artifacts(first, selections=selections)
    artifacts.write_simulated_artifacts(second, selections=selections)

    for name in ("corpus.json", "run_manifest.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    manifest = artifacts.verify_simulated_artifacts(first)
    assert manifest["training_admissible"] is False
    assert manifest["diagnostic_performance_admissible"] is False
    assert manifest["source_kind"] == "deterministic_toy_simulator"
    assert manifest["scenario_ids"] == sorted(manifest["scenario_ids"])


def test_selected_alternatives_and_unknown_counts_are_frozen(tmp_path: Path) -> None:
    output = tmp_path / "pilot"
    artifacts.write_simulated_artifacts(
        output, selections={"wifi_missing_measurement": ("wifi.gateway", "wifi.dns")}
    )

    corpus = json.loads((output / "corpus.json").read_text(encoding="utf-8"))
    manifest = artifacts.verify_simulated_artifacts(output)
    record = next(
        item for item in corpus["records"] if item["scenario_id"] == "wifi_missing_measurement"
    )
    assert record["selected_probe_ids"] == ["wifi.gateway", "wifi.dns"]
    labels = {item["probe_id"]: item for item in record["episode"]["adjudications"]}
    assert labels["wifi.dns"]["status"] == "unavailable"
    assert labels["wifi.dns"]["utility"] == "unknown"
    assert labels["wifi.radio"]["status"] == "unrun"
    assert manifest["label_quality_counts"]["unavailable_unknown"] == 1
    assert manifest["label_quality_counts"]["observed_useful"] >= 1
    assert manifest["label_quality_counts"]["unrun_unknown"] > 0
    assert all("value_sha256" in group for group in manifest["split_group_manifest"])


@pytest.mark.parametrize("file_name", ("corpus.json", "run_manifest.json"))
def test_verifier_rejects_tampering(tmp_path: Path, file_name: str) -> None:
    output = tmp_path / "pilot"
    artifacts.write_simulated_artifacts(output, selections={"wifi_dns": ("wifi.gateway",)})
    path = output / file_name
    payload = json.loads(path.read_text(encoding="utf-8"))
    if file_name == "corpus.json":
        payload["records"][0]["episode"]["model_input"]["symptom"] = "tampered"
    else:
        payload["label_quality_counts"]["unrun_unknown"] = 0
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        artifacts.verify_simulated_artifacts(output)


def test_invalid_selection_and_cross_split_family_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown simulated scenario"):
        artifacts.write_simulated_artifacts(
            tmp_path / "invalid", selections={"unknown": ("wifi.radio",)}
        )
    with pytest.raises(ValueError, match="group crosses"):
        artifacts.write_simulated_artifacts(
            tmp_path / "cross",
            splits={"wifi_dns": "train", "wifi_healthy": "test"},
        )
    assert not (tmp_path / "invalid").exists()
    assert not (tmp_path / "cross").exists()


def test_writer_never_overwrites_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "pilot"
    artifacts.write_simulated_artifacts(output)
    original = (output / "corpus.json").read_bytes()

    with pytest.raises(FileExistsError):
        artifacts.write_simulated_artifacts(output)

    assert (output / "corpus.json").read_bytes() == original


def test_writer_rejects_oversized_payload_before_creating_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "oversized"
    monkeypatch.setattr(artifacts, "_MAX_ARTIFACT_BYTES", 64)

    with pytest.raises(ValueError, match="size bound"):
        artifacts.write_simulated_artifacts(output)

    assert not output.exists()


def test_cli_freezes_explicit_probe_selection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "cli"
    artifacts.main(
        [
            "--output-dir",
            str(output),
            "--select",
            "wifi_dns:wifi.gateway",
            "--select",
            "wifi_dns:wifi.dns",
        ]
    )

    reported = json.loads(capsys.readouterr().out)
    corpus = json.loads((output / "corpus.json").read_text(encoding="utf-8"))
    record = next(item for item in corpus["records"] if item["scenario_id"] == "wifi_dns")
    assert record["selected_probe_ids"] == ["wifi.gateway", "wifi.dns"]
    assert (
        reported["corpus_sha256"] == artifacts.verify_simulated_artifacts(output)["corpus_sha256"]
    )
