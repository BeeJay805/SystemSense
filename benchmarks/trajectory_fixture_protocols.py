"""Freeze nonprivate toy inputs for future matched-arm mechanics checks.

This exporter never invokes an investigator, model, VM, probe, or training job.
Its evaluator index must not be passed to a policy. The visible-input files
contain only the simulator's exact initial worker payloads and offered order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from benchmarks.trajectory_protocol import CasePlan, FrozenProtocol, freeze_protocol
from systemsense.evaluation.simulated_pilot import (
    SimulatedEpisode,
    generate_simulated_episode,
    validate_simulated_splits,
)

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "src/systemsense/evaluation/simulated_pilot.py"
_PROXY_FIXTURE = _ROOT / "benchmarks/scenarios/network_proxy.json"

type Domain = Literal["network_browser", "application_performance"]


@dataclass(frozen=True, slots=True)
class _FixtureCase:
    scenario_id: str
    domain: Domain
    split: Literal["development", "holdout"]
    family_group: str
    scenario_role: str


# All Wi-Fi variants are one simulator machine/application/fault family. They
# therefore stay in development together. PDF and game are distinct groups.
_CASES = (
    _FixtureCase(
        "wifi_healthy", "network_browser", "development", "toy_wifi", "network_fixture_wifi"
    ),
    _FixtureCase("wifi_dns", "network_browser", "development", "toy_wifi", "network_fixture_wifi"),
    _FixtureCase(
        "wifi_radio", "network_browser", "development", "toy_wifi", "network_fixture_wifi"
    ),
    _FixtureCase(
        "wifi_external", "network_browser", "development", "toy_wifi", "network_fixture_wifi"
    ),
    _FixtureCase(
        "wifi_irrelevant_abnormality",
        "network_browser",
        "development",
        "toy_wifi",
        "network_fixture_wifi",
    ),
    _FixtureCase(
        "wifi_missing_measurement",
        "network_browser",
        "development",
        "toy_wifi",
        "network_fixture_wifi",
    ),
    _FixtureCase(
        "wifi_competing_causes",
        "network_browser",
        "development",
        "toy_wifi",
        "network_fixture_wifi",
    ),
    _FixtureCase(
        "pdf_healthy",
        "application_performance",
        "development",
        "toy_pdf",
        "application_fixture_pdf",
    ),
    _FixtureCase(
        "pdf_slow_storage",
        "application_performance",
        "development",
        "toy_pdf",
        "application_fixture_pdf",
    ),
    _FixtureCase(
        "pdf_render_mode",
        "application_performance",
        "development",
        "toy_pdf",
        "application_fixture_pdf",
    ),
    _FixtureCase(
        "game_healthy",
        "application_performance",
        "holdout",
        "toy_game",
        "application_fixture_game",
    ),
    _FixtureCase(
        "game_thermal_limit",
        "application_performance",
        "holdout",
        "toy_game",
        "application_fixture_game",
    ),
    _FixtureCase(
        "game_power_limit",
        "application_performance",
        "holdout",
        "toy_game",
        "application_fixture_game",
    ),
    _FixtureCase(
        "game_driver_fallback",
        "application_performance",
        "holdout",
        "toy_game",
        "application_fixture_game",
    ),
)


@dataclass(frozen=True, slots=True)
class FixtureProtocols:
    source_sha256: str
    protocols: dict[Domain, FrozenProtocol]
    visible_inputs: dict[Domain, dict[str, dict[str, object]]]
    evaluator_index: dict[Domain, dict[str, str]]
    unfrozen_objectives: tuple[dict[str, str], ...]
    arm_command_gaps: dict[str, str]
    case_gaps: dict[str, str]


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_fixture_protocols() -> FixtureProtocols:
    """Freeze exact simulator starting inputs, never hidden outcomes or recipe labels."""

    episodes: list[SimulatedEpisode] = []
    plans: dict[Domain, list[CasePlan]] = {"network_browser": [], "application_performance": []}
    visible_inputs: dict[Domain, dict[str, dict[str, object]]] = {
        "network_browser": {},
        "application_performance": {},
    }
    evaluator_index: dict[Domain, dict[str, str]] = {
        "network_browser": {},
        "application_performance": {},
    }
    counts: dict[Domain, int] = {"network_browser": 0, "application_performance": 0}
    for spec in _CASES:
        episode = generate_simulated_episode(spec.scenario_id, split=spec.split)
        episodes.append(episode)
        counts[spec.domain] += 1
        case_id = f"toy-{spec.domain.replace('_', '-')}-{counts[spec.domain]:03d}"
        visible = cast(dict[str, object], episode.model_input.model_dump(mode="json"))
        visible_inputs[spec.domain][case_id] = visible
        evaluator_index[spec.domain][case_id] = spec.scenario_id
        plans[spec.domain].append(
            CasePlan(
                case_id=case_id,
                source="synthetic",
                split=spec.split,
                family_group=spec.family_group,
                scenario_role=spec.scenario_role,
                objective=episode.model_input.symptom,
                visible_input_sha256=_sha256_json(visible),
                initial_evidence_sha256=_sha256_json(
                    {
                        "symptom": episode.model_input.symptom,
                        "baseline_facts": episode.model_input.baseline_facts,
                    }
                ),
                ordered_tools_sha256=_sha256_json(
                    [
                        candidate.model_dump(mode="json")
                        for candidate in episode.model_input.candidates
                    ]
                ),
                budget_ms=30_000,
                max_probes=8,
                max_model_calls=5,
            )
        )
    validate_simulated_splits(tuple(episodes))
    raw_proxy = cast(object, json.loads(_PROXY_FIXTURE.read_text(encoding="utf-8")))
    if not isinstance(raw_proxy, dict):
        raise ValueError("network proxy objective source is not an object")
    proxy_fixture = cast(dict[str, object], raw_proxy)
    if proxy_fixture.get("measurement_source") != "engineering_fixture":
        raise ValueError("network proxy objective source is not the expected engineering fixture")
    objective = proxy_fixture.get("symptom")
    if not isinstance(objective, str):
        raise ValueError("network proxy objective is unavailable")
    return FixtureProtocols(
        source_sha256=hashlib.sha256(_SOURCE.read_bytes()).hexdigest(),
        protocols={domain: freeze_protocol(tuple(items)) for domain, items in plans.items()},
        visible_inputs=visible_inputs,
        evaluator_index=evaluator_index,
        unfrozen_objectives=(
            {
                "source": "benchmarks/scenarios/network_proxy.json",
                "objective": objective,
                "reason": "engineering fixture has no exact predecision evidence and ordered menu",
            },
        ),
        arm_command_gaps={
            "deterministic": "no matched simulator trajectory adapter",
            "deep_only": "no executable deep-only CLI arm",
            "fast_deep_scout_off": "no controlled Scout-off CLI arm",
            "fast_deep_scout_on": "no controlled Scout-on CLI arm",
        },
        case_gaps={
            "network_family_disjoint_holdout": (
                "all available Wi-Fi variants share toy machine, application, and fault-family keys"
            ),
            "browser_proxy_exact_menu": (
                "network_proxy engineering fixture has aggregate answers, no predecision menu"
            ),
            "adaptive_counterevidence": (
                "toy probes reset independently; no changed-evidence trajectory is captured"
            ),
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    export = build_fixture_protocols()
    output_dir = cast(Path, args.output_dir)
    output_dir.mkdir(parents=False, exist_ok=False)
    evaluator_dir = output_dir / "evaluator-only"
    evaluator_dir.mkdir()
    for domain, protocol in export.protocols.items():
        (output_dir / f"{domain}-protocol.json").write_text(
            protocol.model_dump_json(indent=2), encoding="utf-8"
        )
        (output_dir / f"{domain}-visible-inputs.json").write_text(
            json.dumps(export.visible_inputs[domain], sort_keys=True, indent=2), encoding="utf-8"
        )
        (evaluator_dir / f"{domain}-index.json").write_text(
            json.dumps(export.evaluator_index[domain], sort_keys=True, indent=2), encoding="utf-8"
        )
    (output_dir / "empty-trajectories.json").write_text("[]", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "source_kind": "deterministic_toy_simulator",
        "source_path": "src/systemsense/evaluation/simulated_pilot.py",
        "source_sha256": export.source_sha256,
        "exporter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "protocol_digests": {
            domain: protocol.digest for domain, protocol in export.protocols.items()
        },
        "unfrozen_objectives": export.unfrozen_objectives,
        "arm_command_gaps": export.arm_command_gaps,
        "case_gaps": export.case_gaps,
        "model_identity": None,
        "runtime_parity_admissible": False,
        "training_admissible": False,
        "diagnostic_performance_admissible": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "source_sha256": export.source_sha256,
                "protocol_digests": manifest["protocol_digests"],
                "output_dir": str(output_dir),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
