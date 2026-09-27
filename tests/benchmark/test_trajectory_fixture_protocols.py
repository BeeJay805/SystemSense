"""Fixture plans pin visible inputs without promoting toy cases to outcomes."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from benchmarks.trajectory_fixture_protocols import build_fixture_protocols, main
from benchmarks.trajectory_protocol import main as score_main
from benchmarks.trajectory_protocol import score_trajectories


def test_network_and_application_families_are_frozen_without_leaking_recipes() -> None:
    export = build_fixture_protocols()
    network = export.protocols["network_browser"]
    application = export.protocols["application_performance"]
    assert len(network.cases) == 7
    assert len(application.cases) == 7
    assert {case.split for case in network.cases} == {"development"}
    assert {case.family_group for case in network.cases} == {"toy_wifi"}
    assert {(case.split, case.family_group) for case in application.cases} == {
        ("development", "toy_pdf"),
        ("holdout", "toy_game"),
    }
    assert len({case.visible_input_sha256 for case in network.cases}) == 1
    assert len({case.ordered_tools_sha256 for case in network.cases}) == 1
    assert len({case.visible_input_sha256 for case in application.cases[:3]}) == 1
    assert len({case.visible_input_sha256 for case in application.cases[3:]}) == 1
    for domain, protocol in export.protocols.items():
        for case in protocol.cases:
            visible = export.visible_inputs[domain][case.case_id]
            assert "oracle" not in visible and "adjudications" not in visible
            assert "scenario_id" not in visible and "root_causes" not in visible
            assert case.objective == visible["symptom"]
            assert (
                case.visible_input_sha256
                == sha256(
                    json.dumps(
                        visible, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    ).encode("utf-8")
                ).hexdigest()
            )
        score = score_trajectories(protocol, ())
        assert score["complete_paired_cases"] == 0
        assert all(arm["unrun"] == len(protocol.cases) for arm in score["arms"].values())


def test_browser_proxy_objective_is_explicitly_unfrozen() -> None:
    export = build_fixture_protocols()
    assert not any(
        case.scenario_role == "network_proxy_fault"
        for protocol in export.protocols.values()
        for case in protocol.cases
    )
    assert export.unfrozen_objectives == (
        {
            "source": "benchmarks/scenarios/network_proxy.json",
            "objective": "The application cannot reach its service while the browser works.",
            "reason": "engineering fixture has no exact predecision evidence and ordered menu",
        },
    )
    assert export.arm_command_gaps == {
        "deterministic": "no matched simulator trajectory adapter",
        "deep_only": "no executable deep-only CLI arm",
        "fast_deep_scout_off": "no controlled Scout-off CLI arm",
        "fast_deep_scout_on": "no controlled Scout-on CLI arm",
    }
    assert "network_family_disjoint_holdout" in export.case_gaps
    assert "adaptive_counterevidence" in export.case_gaps


def test_cli_writes_exclusive_replay_bundle_without_changing_fixture_source(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = Path(__file__).resolve().parents[2] / "src/systemsense/evaluation/simulated_pilot.py"
    before = sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "bundle"
    assert main(["--output-dir", str(output)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["source_sha256"] == before
    assert set(report["protocol_digests"]) == {"network_browser", "application_performance"}
    assert (output / "network_browser-protocol.json").is_file()
    assert (output / "network_browser-visible-inputs.json").is_file()
    visible_bytes = (output / "network_browser-visible-inputs.json").read_text(encoding="utf-8")
    assert "wifi_dns" not in visible_bytes and "root_causes" not in visible_bytes
    assert (output / "evaluator-only/network_browser-index.json").is_file()
    assert not (output / "network_browser-evaluator-index.json").exists()
    assert (output / "application_performance-protocol.json").is_file()
    assert json.loads((output / "empty-trajectories.json").read_text(encoding="utf-8")) == []
    assert (output / "manifest.json").is_file()
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["model_identity"] is None
    assert (
        manifest["exporter_sha256"]
        == sha256(
            (
                Path(__file__).resolve().parents[2] / "benchmarks/trajectory_fixture_protocols.py"
            ).read_bytes()
        ).hexdigest()
    )
    assert manifest["runtime_parity_admissible"] is False
    assert "network_family_disjoint_holdout" in manifest["case_gaps"]
    capsys.readouterr()
    assert (
        score_main(
            [
                "score",
                "--protocol",
                str(output / "network_browser-protocol.json"),
                "--trajectories",
                str(output / "empty-trajectories.json"),
            ]
        )
        == 0
    )
    empty_score = json.loads(capsys.readouterr().out)
    assert empty_score["planned_cases"] == 7
    assert empty_score["complete_paired_cases"] == 0
    assert sha256(source.read_bytes()).hexdigest() == before
    with pytest.raises(FileExistsError):
        main(["--output-dir", str(output)])
