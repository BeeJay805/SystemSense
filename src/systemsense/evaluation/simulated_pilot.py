"""Deterministic toy investigation episodes for contract testing only.

This is not a Windows emulator, authenticated outcome source, training corpus,
or diagnostic benchmark. Hidden causal worlds and their read-only measurements
are separate from the predecision payload. Every selected alternative is run
against a fresh copy of the same world; unrun choices stay unknown.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from pydantic import Field, ValidationError

from systemsense.domain.evidence import FrozenModel

_DIGEST = r"^[0-9a-f]{64}$"
_PROBE_ID = r"^[a-z][a-z0-9_.-]*$"
GroupKind = Literal["case", "machine", "application", "application_version", "fault_family"]


class SimCandidate(FrozenModel):
    probe_id: str = Field(pattern=_PROBE_ID)
    description: str = Field(min_length=1, max_length=160)
    expected_cost_ms: int = Field(ge=1, le=5000)


class SimModelInput(FrozenModel):
    """The only simulator structure permitted to reach a decision worker."""

    schema_version: Literal[1] = 1
    symptom: str = Field(min_length=1, max_length=160)
    baseline_facts: tuple[str, ...] = Field(min_length=1, max_length=8)
    candidates: tuple[SimCandidate, ...] = Field(min_length=1, max_length=16)


class SimSplitKey(FrozenModel):
    kind: GroupKind
    value_sha256: str = Field(pattern=_DIGEST)


class SimOracle(FrozenModel):
    """Evaluator-only outcome; not inferred from the candidate descriptions."""

    symptom_reproduced: bool
    root_causes: tuple[str, ...]
    exact_repairs_required: tuple[str, ...]
    compatible_root_cause_sets: tuple[tuple[str, ...], ...] = Field(min_length=1)
    exact_diagnosis_abstain_required: bool


class SimAdjudication(FrozenModel):
    probe_id: str = Field(pattern=_PROBE_ID)
    status: Literal["observed", "unavailable", "unrun"]
    observation: str | None
    utility: Literal["useful", "negative", "unknown"]
    compatible_causes_before: int | None = None
    compatible_causes_after: int | None = None


class SimulatedEpisode(FrozenModel):
    schema_version: Literal[1] = 1
    classification: Literal["simulated_contract_only"] = "simulated_contract_only"
    source_kind: Literal["deterministic_toy_simulator"] = "deterministic_toy_simulator"
    training_admissible: Literal[False] = False
    diagnostic_performance_admissible: Literal[False] = False
    utility_scope: Literal["independent_single_probe_from_frozen_baseline"] = (
        "independent_single_probe_from_frozen_baseline"
    )
    scenario_id: str
    split: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")
    split_keys: tuple[SimSplitKey, ...] = Field(min_length=5, max_length=5)
    model_input: SimModelInput
    oracle: SimOracle
    adjudications: tuple[SimAdjudication, ...]


@dataclass(frozen=True)
class _Family:
    symptom: str
    baseline: tuple[str, ...]
    candidates: tuple[SimCandidate, ...]
    # The first field is the root cause set; the second is a probe-result map.
    causes: dict[str, tuple[tuple[str, ...], dict[str, str]]]


@dataclass(frozen=True)
class _Scenario:
    family: str
    cause: str
    battery_high: bool = False
    missing_probe: str | None = None


_BATTERY = SimCandidate(
    probe_id="system.battery_wear",
    description="Read battery wear indicator, which may be incidental",
    expected_cost_ms=25,
)
_FAMILIES: dict[str, _Family] = {
    "wifi": _Family(
        symptom="Wi-Fi connection is unreliable",
        baseline=("User reports intermittent connection failure",),
        candidates=(
            SimCandidate(
                probe_id="wifi.radio",
                description="Read Wi-Fi radio enable state",
                expected_cost_ms=15,
            ),
            SimCandidate(
                probe_id="wifi.gateway",
                description="Measure local gateway reachability",
                expected_cost_ms=80,
            ),
            SimCandidate(
                probe_id="wifi.dns", description="Measure DNS lookup result", expected_cost_ms=100
            ),
            _BATTERY,
        ),
        causes={
            "healthy": (
                (),
                {"wifi.radio": "enabled", "wifi.gateway": "reachable", "wifi.dns": "resolved"},
            ),
            "dns": (
                ("dns_misconfiguration",),
                {"wifi.radio": "enabled", "wifi.gateway": "reachable", "wifi.dns": "failed"},
            ),
            "radio": (
                ("radio_disabled",),
                {"wifi.radio": "disabled", "wifi.gateway": "unreachable", "wifi.dns": "failed"},
            ),
            "external": (
                ("external_router_outage",),
                {"wifi.radio": "enabled", "wifi.gateway": "unreachable", "wifi.dns": "failed"},
            ),
            "dual": (
                ("dns_misconfiguration", "radio_disabled"),
                {"wifi.radio": "disabled", "wifi.gateway": "unreachable", "wifi.dns": "failed"},
            ),
        },
    ),
    "pdf": _Family(
        symptom="PDF opens slowly",
        baseline=("User reports delayed document rendering",),
        candidates=(
            SimCandidate(
                probe_id="pdf.storage",
                description="Measure document storage latency",
                expected_cost_ms=90,
            ),
            SimCandidate(
                probe_id="pdf.renderer", description="Read PDF renderer mode", expected_cost_ms=25
            ),
            _BATTERY,
        ),
        causes={
            "healthy": ((), {"pdf.storage": "normal", "pdf.renderer": "accelerated"}),
            "storage": (
                ("storage_saturation",),
                {"pdf.storage": "high", "pdf.renderer": "accelerated"},
            ),
            "renderer": (
                ("software_rendering",),
                {"pdf.storage": "normal", "pdf.renderer": "software"},
            ),
        },
    ),
    "game": _Family(
        symptom="Game frame rate is unexpectedly low",
        baseline=("User reports low frame rate despite capable GPU",),
        candidates=(
            SimCandidate(
                probe_id="game.temperature",
                description="Measure GPU thermal state",
                expected_cost_ms=100,
            ),
            SimCandidate(
                probe_id="game.power", description="Read GPU power limit state", expected_cost_ms=50
            ),
            SimCandidate(
                probe_id="game.driver",
                description="Read active GPU driver mode",
                expected_cost_ms=35,
            ),
            _BATTERY,
        ),
        causes={
            "healthy": (
                (),
                {"game.temperature": "normal", "game.power": "normal", "game.driver": "hardware"},
            ),
            "thermal": (
                ("gpu_thermal_limit",),
                {"game.temperature": "limited", "game.power": "normal", "game.driver": "hardware"},
            ),
            "power": (
                ("gpu_power_limit",),
                {"game.temperature": "normal", "game.power": "limited", "game.driver": "hardware"},
            ),
            "driver": (
                ("gpu_driver_fallback",),
                {"game.temperature": "normal", "game.power": "normal", "game.driver": "fallback"},
            ),
        },
    ),
}
_SCENARIOS: dict[str, _Scenario] = {
    "wifi_healthy": _Scenario("wifi", "healthy"),
    "wifi_dns": _Scenario("wifi", "dns"),
    "wifi_radio": _Scenario("wifi", "radio"),
    "wifi_external": _Scenario("wifi", "external"),
    "wifi_irrelevant_abnormality": _Scenario("wifi", "dns", battery_high=True),
    "wifi_missing_measurement": _Scenario("wifi", "dns", missing_probe="wifi.dns"),
    "wifi_competing_causes": _Scenario("wifi", "dual"),
    "pdf_healthy": _Scenario("pdf", "healthy"),
    "pdf_slow_storage": _Scenario("pdf", "storage"),
    "pdf_render_mode": _Scenario("pdf", "renderer"),
    "game_healthy": _Scenario("game", "healthy"),
    "game_thermal_limit": _Scenario("game", "thermal"),
    "game_power_limit": _Scenario("game", "power"),
    "game_driver_fallback": _Scenario("game", "driver"),
}


def scenario_ids() -> tuple[str, ...]:
    return tuple(sorted(_SCENARIOS))


def simulated_symptom_after_hypothetical_repair(
    scenario_id: str, repaired_cause_ids: tuple[str, ...]
) -> bool:
    """Hidden simulator outcome oracle; this never executes a machine repair."""

    scenario = _SCENARIOS.get(scenario_id)
    if scenario is None:
        raise ValueError("unknown simulated scenario")
    required = set(_FAMILIES[scenario.family].causes[scenario.cause][0])
    return bool(required - set(repaired_cause_ids))


def _digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _split_keys(scenario_id: str, family_id: str) -> tuple[SimSplitKey, ...]:
    raw: tuple[tuple[GroupKind, str], ...] = (
        ("case", scenario_id),
        ("machine", f"synthetic-{family_id}-machine"),
        ("application", f"synthetic-{family_id}-application"),
        ("application_version", f"synthetic-{family_id}-application:1"),
        ("fault_family", family_id),
    )
    return tuple(SimSplitKey(kind=kind, value_sha256=_digest((kind, value))) for kind, value in raw)


def _probe_result(
    family: _Family, cause_key: str, probe_id: str, *, battery_high: bool, missing_probe: str | None
) -> str | None:
    """One fresh, read-only simulated measurement; None means unavailable."""

    if probe_id == missing_probe:
        return None
    if probe_id == _BATTERY.probe_id:
        return "high" if battery_high else "normal"
    return family.causes[cause_key][1][probe_id]


def _compatible_cause_sets(family: _Family, probe_id: str, observed: str) -> set[tuple[str, ...]]:
    """Cross nuisance states with every cause to avoid shortcut correlations."""

    compatible: set[tuple[str, ...]] = set()
    for cause_key, (root_causes, _) in family.causes.items():
        for battery_high in (False, True):
            for missing_probe in (None, probe_id):
                result = _probe_result(
                    family,
                    cause_key,
                    probe_id,
                    battery_high=battery_high,
                    missing_probe=missing_probe,
                )
                if result == observed:
                    compatible.add(root_causes)
    return compatible


def _full_signature(
    family: _Family,
    cause_key: str,
    *,
    battery_high: bool,
    missing_probe: str | None,
) -> tuple[str | None, ...]:
    return tuple(
        _probe_result(
            family,
            cause_key,
            candidate.probe_id,
            battery_high=battery_high,
            missing_probe=missing_probe,
        )
        for candidate in family.candidates
    )


def _full_signature_compatible_causes(
    family: _Family, scenario: _Scenario
) -> tuple[tuple[str, ...], ...]:
    """Evaluator-only exact-cause identifiability under every registered toy probe."""

    observed = _full_signature(
        family,
        scenario.cause,
        battery_high=scenario.battery_high,
        missing_probe=scenario.missing_probe,
    )
    compatible: set[tuple[str, ...]] = set()
    missing_choices = (None, *(candidate.probe_id for candidate in family.candidates))
    for cause_key, (root_causes, _) in family.causes.items():
        for battery_high in (False, True):
            for missing_probe in missing_choices:
                if (
                    _full_signature(
                        family,
                        cause_key,
                        battery_high=battery_high,
                        missing_probe=missing_probe,
                    )
                    == observed
                ):
                    compatible.add(root_causes)
    return tuple(sorted(compatible))


def generate_simulated_episode(
    scenario_id: str,
    *,
    split: str = "fixture",
    executed_probe_ids: tuple[str, ...] = (),
) -> SimulatedEpisode:
    """Build deterministic labels from independently reset alternative probes.

    Utility means only that an observed result eliminates at least one *toy*
    causal world. It is not a Windows diagnosis or a justified training label.
    """

    scenario = _SCENARIOS.get(scenario_id)
    if scenario is None:
        raise ValueError("unknown simulated scenario")
    family = _FAMILIES[scenario.family]
    candidate_ids = {candidate.probe_id for candidate in family.candidates}
    if len(executed_probe_ids) != len(set(executed_probe_ids)):
        raise ValueError("duplicate simulated probe selection")
    if not set(executed_probe_ids) <= candidate_ids:
        raise ValueError("unregistered simulated probe selection")
    selected = set(executed_probe_ids)
    all_causes = {item[0] for item in family.causes.values()}
    adjudications: list[SimAdjudication] = []
    for candidate in family.candidates:
        probe_id = candidate.probe_id
        if probe_id not in selected:
            adjudications.append(
                SimAdjudication(
                    probe_id=probe_id, status="unrun", observation=None, utility="unknown"
                )
            )
            continue
        # No previous probe result is carried into this fresh simulated run.
        observed = _probe_result(
            family,
            scenario.cause,
            probe_id,
            battery_high=scenario.battery_high,
            missing_probe=scenario.missing_probe,
        )
        if observed is None:
            adjudications.append(
                SimAdjudication(
                    probe_id=probe_id, status="unavailable", observation=None, utility="unknown"
                )
            )
            continue
        remaining = _compatible_cause_sets(family, probe_id, observed)
        if not remaining or family.causes[scenario.cause][0] not in remaining:
            raise ValueError("simulator oracle contradicts probe result")
        adjudications.append(
            SimAdjudication(
                probe_id=probe_id,
                status="observed",
                observation=observed,
                utility="useful" if len(remaining) < len(all_causes) else "negative",
                compatible_causes_before=len(all_causes),
                compatible_causes_after=len(remaining),
            )
        )
    causes = family.causes[scenario.cause][0]
    compatible = _full_signature_compatible_causes(family, scenario)
    if causes not in compatible:
        raise ValueError("simulator oracle is incompatible with full probe signature")
    return SimulatedEpisode(
        scenario_id=scenario_id,
        split=split,
        split_keys=_split_keys(scenario_id, scenario.family),
        model_input=SimModelInput(
            symptom=family.symptom,
            baseline_facts=family.baseline,
            candidates=family.candidates,
        ),
        oracle=SimOracle(
            symptom_reproduced=bool(causes),
            root_causes=causes,
            exact_repairs_required=causes,
            compatible_root_cause_sets=compatible,
            exact_diagnosis_abstain_required=len(compatible) > 1,
        ),
        adjudications=tuple(adjudications),
    )


def validate_simulated_splits(episodes: tuple[SimulatedEpisode, ...]) -> None:
    """Reject shared grouped keys across splits, even for toy data."""

    owners: dict[tuple[GroupKind, str], str] = {}
    for episode in episodes:
        verify_simulated_episode(episode)
        if len({item.kind for item in episode.split_keys}) != 5:
            raise ValueError("simulated split keys are incomplete")
        for item in episode.split_keys:
            key = (item.kind, item.value_sha256)
            prior = owners.setdefault(key, episode.split)
            if prior != episode.split:
                raise ValueError(f"{item.kind} group crosses simulated splits")


def verify_simulated_episode(episode: SimulatedEpisode) -> None:
    """Rebuild toy output exactly; no caller-supplied utility can override it."""

    try:
        SimulatedEpisode.model_validate(episode.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("simulated replay envelope is invalid") from error
    executed = tuple(item.probe_id for item in episode.adjudications if item.status != "unrun")
    replay = generate_simulated_episode(
        episode.scenario_id, split=episode.split, executed_probe_ids=executed
    )
    if replay != episode:
        raise ValueError("simulated episode differs from deterministic replay")
