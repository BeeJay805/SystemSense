"""Freeze staged toy observations for retrieval and investigation evaluation.

The policy-visible export contains only an initial symptom, the offered probe
menu, and facts released after each probe. Evaluator-only labels are predeclared
toy worlds. They are mechanics checks, not Windows truth or training examples.
No probe, model, VM, network request, or host diagnostic is executed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

_ROOT = Path(__file__).resolve().parents[1]
_CLASSIFICATION = "synthetic_mechanics_only"
_NETWORK_PROBES = (
    ("browser.route_attempt", "Observe the affected browser request route"),
    ("browser.proxy_settings", "Read configured browser proxy settings"),
    ("browser.direct_control", "Observe a separate direct-route control"),
    ("browser.external_control", "Observe an independent external origin control"),
    ("system.battery_wear", "Read incidental battery wear indicator"),
)
_APPLICATION_PROBES = (
    ("application.task_timing", "Observe the affected document opening task"),
    ("application.storage_latency", "Measure document storage latency"),
    ("application.renderer_mode", "Read active document renderer mode"),
    ("application.external_control", "Observe an independent document source control"),
    ("system.battery_wear", "Read incidental battery wear indicator"),
)


@dataclass(frozen=True, slots=True)
class _World:
    case_id: str
    domain: Literal["network_browser", "application_performance"]
    role: str
    root_causes: tuple[str, ...]
    observations: tuple[str | None, ...]
    causal_answer_review: Literal["known_toy_world", "unknown"] = "known_toy_world"
    counterevidence_stage_indices: tuple[int, ...] = ()


# This sealed list is the evaluator's toy world declaration. It is not loaded
# from the policy-visible output or inferred from a worker's favored answer.
# Every row in a domain starts with the same symptom, baseline and tool order.
_WORLDS = (
    _World(
        "toy-network-001",
        "network_browser",
        "healthy",
        (),
        ("direct_204", "disabled", "http_204", "http_204", "normal"),
    ),
    _World(
        "toy-network-002",
        "network_browser",
        "proxy_fault",
        ("wrong_browser_proxy",),
        ("proxy_denied", "enabled_127.0.0.1:9", "http_204", "http_204", "normal"),
    ),
    _World(
        "toy-network-003",
        "network_browser",
        "dns_fault",
        ("dns_configuration",),
        ("dns_failure", "disabled", "dns_failure", "http_204", "normal"),
    ),
    _World(
        "toy-network-004",
        "network_browser",
        "external",
        ("external_origin_failure",),
        ("origin_503", "disabled", "origin_503", "origin_503", "normal"),
    ),
    _World(
        "toy-network-005",
        "network_browser",
        "irrelevant_abnormality",
        ("dns_configuration",),
        ("dns_failure", "disabled", "dns_failure", "http_204", "high"),
    ),
    _World(
        "toy-network-006",
        "network_browser",
        "unknown",
        (),
        (None, None, "http_204", "http_204", "normal"),
        "unknown",
    ),
    _World(
        "toy-network-007",
        "network_browser",
        "counterevidence",
        (),
        ("direct_204", "enabled_127.0.0.1:9", "http_204", "http_204", "normal"),
        counterevidence_stage_indices=(1, 2),
    ),
    _World(
        "toy-application-001",
        "application_performance",
        "healthy",
        (),
        ("normal", "normal", "accelerated", "normal", "normal"),
    ),
    _World(
        "toy-application-002",
        "application_performance",
        "storage_fault",
        ("storage_saturation",),
        ("slow", "high", "accelerated", "normal", "normal"),
    ),
    _World(
        "toy-application-003",
        "application_performance",
        "renderer_fault",
        ("software_rendering",),
        ("slow", "normal", "software", "normal", "normal"),
    ),
    _World(
        "toy-application-004",
        "application_performance",
        "external",
        ("external_document_source",),
        ("slow", "normal", "accelerated", "slow", "normal"),
    ),
    _World(
        "toy-application-005",
        "application_performance",
        "irrelevant_abnormality",
        ("software_rendering",),
        ("slow", "normal", "software", "normal", "high"),
    ),
    _World(
        "toy-application-006",
        "application_performance",
        "unknown",
        (),
        ("slow", None, None, "normal", "normal"),
        "unknown",
    ),
    _World(
        "toy-application-007",
        "application_performance",
        "counterevidence",
        (),
        ("normal", "high", "accelerated", "normal", "normal"),
        counterevidence_stage_indices=(1, 2),
    ),
)


@dataclass(frozen=True, slots=True)
class SequentialMatrix:
    visible: tuple[dict[str, Any], ...]
    evaluator: tuple[dict[str, Any], ...]
    contract_sha256: str


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_head() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _initial_input(domain: str) -> dict[str, Any]:
    if domain == "network_browser":
        symptom = "Browser cannot reliably open the requested site"
        baseline = ["User reported a browser connection failure; not independently reproduced"]
        probes = _NETWORK_PROBES
    else:
        symptom = "Document opens slowly"
        baseline = ["User reported a slow document opening task; not independently timed"]
        probes = _APPLICATION_PROBES
    return {
        "symptom": symptom,
        "baseline_facts": baseline,
        "ordered_probe_menu": [
            {"probe_id": probe_id, "description": description, "access": "read_only_toy"}
            for probe_id, description in probes
        ],
        "budget": {"max_probes": 5, "max_rounds": 5, "budget_ms": 30_000},
    }


def _compatible_worlds(domain: str, observations: Mapping[str, str]) -> tuple[_World, ...]:
    probe_ids = [item["probe_id"] for item in _initial_input(domain)["ordered_probe_menu"]]
    return tuple(
        world
        for world in _WORLDS
        if world.domain == domain
        and all(
            world.observations[probe_ids.index(probe_id)] == value
            for probe_id, value in observations.items()
        )
    )


def _toy_probe_closures(world: _World) -> dict[str, Callable[[], str | None]]:
    """Bind the frozen menu to a hidden world without exposing the binding."""

    menu = _initial_input(world.domain)["ordered_probe_menu"]
    return {
        str(item["probe_id"]): (lambda index=index: world.observations[index])
        for index, item in enumerate(menu)
    }


def build_matrix() -> SequentialMatrix:
    """Replay each declared world through the same staged menu, without models."""

    visible_rows: list[dict[str, Any]] = []
    label_rows: list[dict[str, Any]] = []
    for world in _WORLDS:
        initial = _initial_input(world.domain)
        initial_hash = _digest(initial)
        menu = initial["ordered_probe_menu"]
        if len(menu) != len(world.observations):
            raise ValueError("toy world and frozen probe menu differ")
        probes = _toy_probe_closures(world)
        observations: dict[str, str] = {}
        visible_stages: list[dict[str, Any]] = []
        labels: list[dict[str, Any]] = []
        for stage_index in range(len(menu) + 1):
            probe_id: str | None = None
            latest: dict[str, Any] | None = None
            if stage_index:
                probe_id = str(menu[stage_index - 1]["probe_id"])
                observed = probes[probe_id]()
                latest = {
                    "probe_id": probe_id,
                    "status": "unavailable" if observed is None else "observed",
                    "value": observed,
                    "source": "frozen_toy_probe_closure",
                    "limitation": "measurement unavailable" if observed is None else None,
                }
                if observed is not None:
                    observations[probe_id] = observed
            state = {
                "stage_index": stage_index,
                "probe_id": probe_id,
                "latest_observation": latest,
                "observed_facts": [
                    {"probe_id": key, "value": value, "source": "frozen_toy_probe_closure"}
                    for key, value in observations.items()
                ],
                "unavailable_probe_ids": [
                    str(menu[index]["probe_id"])
                    for index in range(stage_index)
                    if world.observations[index] is None
                ],
                "remaining_probe_ids": [str(item["probe_id"]) for item in menu[stage_index:]],
            }
            state["visible_state_sha256"] = _digest(state)
            visible_stages.append(state)
            compatible = _compatible_worlds(world.domain, observations)
            if world not in compatible:
                raise ValueError("declared world contradicts its own toy observation")
            labels.append(
                {
                    "stage_index": stage_index,
                    "visible_state_sha256": state["visible_state_sha256"],
                    "compatible_world_count": len(compatible),
                    "compatible_root_cause_sets": sorted(
                        {
                            tuple(item.root_causes)
                            if item.causal_answer_review != "unknown"
                            else None
                            for item in compatible
                        },
                        key=str,
                    ),
                    "discriminated_by_latest_probe": (
                        len(compatible) < labels[-1]["compatible_world_count"] if labels else None
                    ),
                    "causal_answer_status": (
                        "unknown"
                        if world.causal_answer_review == "unknown"
                        else "fixture_oracle_only"
                    ),
                }
            )
        visible_rows.append(
            {
                "case_id": world.case_id,
                "domain": world.domain,
                "split": "development",
                "initial_input": initial,
                "initial_sha256": initial_hash,
                "stages": visible_stages,
            }
        )
        label_rows.append(
            {
                "case_id": world.case_id,
                "domain": world.domain,
                "role": world.role,
                "root_causes": (
                    world.root_causes if world.causal_answer_review != "unknown" else None
                ),
                "causal_answer_review": world.causal_answer_review,
                "counterevidence_stage_indices": world.counterevidence_stage_indices,
                "stages": labels,
                "training_admissible": False,
                "diagnostic_performance_admissible": False,
            }
        )
    contract = {
        "classification": _CLASSIFICATION,
        "visible": visible_rows,
        "evaluator": label_rows,
    }
    return SequentialMatrix(
        visible=tuple(visible_rows),
        evaluator=tuple(label_rows),
        contract_sha256=_digest(contract),
    )


def export_matrix(output_dir: Path) -> dict[str, Any]:
    """Write a new private export; never overwrite an earlier decision fixture."""

    matrix = build_matrix()
    output_dir.mkdir(parents=False, exist_ok=False)
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    visible_path = output_dir / "policy-visible/sequential-states.json"
    evaluator_path = output_dir / "evaluator-only/labels.json"
    visible_path.write_text(
        json.dumps({"cases": matrix.visible}, sort_keys=True, indent=2), encoding="utf-8"
    )
    evaluator_path.write_text(
        json.dumps({"cases": matrix.evaluator}, sort_keys=True, indent=2), encoding="utf-8"
    )
    manifest = {
        "schema_version": 1,
        "classification": _CLASSIFICATION,
        "contract_sha256": matrix.contract_sha256,
        "code_sha": _git_head(),
        "exporter_sha256": _file_digest(Path(__file__)),
        "policy_visible_sha256": _file_digest(visible_path),
        "evaluator_only_sha256": _file_digest(evaluator_path),
        "case_count": len(matrix.visible),
        "stage_count_per_case": 6,
        "split_scope": "development_same_family_only",
        "training_admissible": False,
        "diagnostic_performance_admissible": False,
        "model_or_vm_executed": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8"
    )
    return manifest


def verify_export(output_dir: Path) -> dict[str, Any]:
    """Read only: compare exported files with hashes and current frozen source."""

    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    expected = build_matrix()
    visible_path = output_dir / "policy-visible/sequential-states.json"
    evaluator_path = output_dir / "evaluator-only/labels.json"
    if (
        manifest.get("contract_sha256") != expected.contract_sha256
        or manifest.get("exporter_sha256") != _file_digest(Path(__file__))
        or manifest.get("policy_visible_sha256") != _file_digest(visible_path)
        or manifest.get("evaluator_only_sha256") != _file_digest(evaluator_path)
        or json.loads(visible_path.read_text(encoding="utf-8"))
        != json.loads(json.dumps({"cases": expected.visible}))
        or json.loads(evaluator_path.read_text(encoding="utf-8"))
        != json.loads(json.dumps({"cases": expected.evaluator}))
    ):
        raise ValueError("sequential matrix integrity check failed")
    return {
        "integrity_verified": True,
        "classification": _CLASSIFICATION,
        "contract_sha256": expected.contract_sha256,
        "case_count": len(expected.visible),
        "training_admissible": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    result = verify_export(args.output_dir) if args.verify else export_matrix(args.output_dir)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
