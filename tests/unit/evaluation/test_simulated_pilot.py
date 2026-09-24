"""A controlled simulator can test labeling contracts, not Windows diagnosis quality."""

from __future__ import annotations

import json

import pytest

from systemsense.evaluation.simulated_pilot import (
    generate_simulated_episode,
    scenario_ids,
    simulated_symptom_after_hypothetical_repair,
    validate_simulated_splits,
    verify_simulated_episode,
)


def test_catalog_covers_distinct_fault_and_control_conditions() -> None:
    assert {
        "wifi_healthy",
        "wifi_dns",
        "wifi_irrelevant_abnormality",
        "wifi_missing_measurement",
        "wifi_competing_causes",
        "pdf_slow_storage",
        "game_thermal_limit",
    } <= set(scenario_ids())


@pytest.mark.parametrize("scenario_id", scenario_ids())
def test_every_scenario_replays_with_explicit_unrun_unknowns(scenario_id: str) -> None:
    episode = generate_simulated_episode(scenario_id)

    verify_simulated_episode(episode)
    assert all(
        item.status == "unrun" and item.utility == "unknown" for item in episode.adjudications
    )
    assert len(episode.adjudications) == len(episode.model_input.candidates)


def test_predecision_input_excludes_oracle_future_results_and_recipe() -> None:
    episode = generate_simulated_episode("wifi_dns", executed_probe_ids=("wifi.gateway",))
    visible = json.loads(episode.model_input.model_dump_json())

    assert visible["symptom"] == "Wi-Fi connection is unreliable"
    assert "oracle" not in visible
    assert "scenario_id" not in visible
    assert "utility" not in visible
    assert "observations" not in visible
    assert "compatible_root_cause_sets" not in visible
    assert "exact_diagnosis_abstain_required" not in visible
    assert "utility_scope" not in visible
    assert "dns_misconfiguration" not in json.dumps(visible)
    assert episode.oracle.root_causes == ("dns_misconfiguration",)
    assert episode.training_admissible is False
    assert episode.diagnostic_performance_admissible is False
    assert episode.model_input == generate_simulated_episode("wifi_healthy").model_input
    assert (
        episode.model_input == generate_simulated_episode("wifi_irrelevant_abnormality").model_input
    )
    assert episode.model_input == generate_simulated_episode("wifi_missing_measurement").model_input


def test_controlled_alternative_outcomes_distinguish_useful_from_irrelevant() -> None:
    episode = generate_simulated_episode(
        "wifi_irrelevant_abnormality",
        executed_probe_ids=("wifi.gateway", "system.battery_wear"),
    )
    labels = {item.probe_id: item for item in episode.adjudications}

    assert labels["wifi.gateway"].utility == "useful"
    assert labels["wifi.gateway"].observation == "reachable"
    assert labels["system.battery_wear"].observation == "high"
    assert labels["system.battery_wear"].utility == "negative"
    assert labels["wifi.radio"].utility == "unknown"
    assert labels["wifi.radio"].observation is None


def test_missing_measurement_is_unknown_not_negative() -> None:
    episode = generate_simulated_episode(
        "wifi_missing_measurement", executed_probe_ids=("wifi.gateway", "wifi.dns")
    )
    labels = {item.probe_id: item for item in episode.adjudications}

    assert labels["wifi.dns"].status == "unavailable"
    assert labels["wifi.dns"].utility == "unknown"
    assert labels["wifi.gateway"].utility == "useful"


def test_competing_cause_oracle_does_not_collapse_to_one_fault() -> None:
    episode = generate_simulated_episode(
        "wifi_competing_causes", executed_probe_ids=("wifi.radio", "wifi.dns")
    )

    assert episode.oracle.root_causes == ("dns_misconfiguration", "radio_disabled")
    assert {item.probe_id for item in episode.adjudications if item.utility == "useful"} == {
        "wifi.radio",
        "wifi.dns",
    }
    assert episode.adjudications[0].compatible_causes_after == 2
    assert episode.oracle.exact_diagnosis_abstain_required is True
    assert episode.oracle.compatible_root_cause_sets == (
        ("dns_misconfiguration", "radio_disabled"),
        ("radio_disabled",),
    )
    assert episode.utility_scope == "independent_single_probe_from_frozen_baseline"
    # Both are useful *from baseline*. After radio=disabled, dns=failed does
    # not distinguish the dual-cause world from the radio-only world.
    assert episode.adjudications[2].utility == "useful"
    assert episode.adjudications[2].compatible_causes_after == 4
    assert (
        simulated_symptom_after_hypothetical_repair("wifi_competing_causes", ("radio_disabled",))
        is True
    )
    assert (
        simulated_symptom_after_hypothetical_repair(
            "wifi_competing_causes", ("radio_disabled", "dns_misconfiguration")
        )
        is False
    )


def test_healthy_oracle_and_irrelevant_repair_do_not_invent_a_fix() -> None:
    assert simulated_symptom_after_hypothetical_repair("wifi_healthy", ()) is False
    assert simulated_symptom_after_hypothetical_repair("wifi_dns", ("battery_wear",)) is True


def test_healthy_control_has_no_fault_oracle() -> None:
    episode = generate_simulated_episode(
        "wifi_healthy", executed_probe_ids=("wifi.radio", "wifi.gateway")
    )

    assert episode.oracle.root_causes == ()
    assert episode.oracle.exact_diagnosis_abstain_required is False
    assert episode.oracle.compatible_root_cause_sets == ((),)
    assert all(item.status == "observed" for item in episode.adjudications[:2])


def test_radio_only_and_missing_measurement_expose_oracle_ambiguity() -> None:
    radio = generate_simulated_episode("wifi_radio")
    missing = generate_simulated_episode("wifi_missing_measurement")

    assert radio.oracle.exact_diagnosis_abstain_required is True
    assert radio.oracle.compatible_root_cause_sets == (
        ("dns_misconfiguration", "radio_disabled"),
        ("radio_disabled",),
    )
    assert missing.oracle.exact_diagnosis_abstain_required is True
    assert missing.oracle.compatible_root_cause_sets == ((), ("dns_misconfiguration",))
    assert generate_simulated_episode("wifi_dns").oracle.exact_diagnosis_abstain_required is False


def test_resettable_alternatives_are_order_independent() -> None:
    first = generate_simulated_episode(
        "wifi_dns", executed_probe_ids=("wifi.gateway", "wifi.radio")
    )
    second = generate_simulated_episode(
        "wifi_dns", executed_probe_ids=("wifi.radio", "wifi.gateway")
    )

    by_probe_first = {item.probe_id: item for item in first.adjudications}
    by_probe_second = {item.probe_id: item for item in second.adjudications}
    assert by_probe_first == by_probe_second
    assert first.model_input == second.model_input


def test_split_validation_rejects_shared_fault_family_across_splits() -> None:
    healthy = generate_simulated_episode("wifi_healthy", split="train")
    fault = generate_simulated_episode("wifi_dns", split="test")
    with pytest.raises(ValueError, match="group crosses"):
        validate_simulated_splits((healthy, fault))


def test_split_validation_allows_distinct_families() -> None:
    wifi = generate_simulated_episode("wifi_dns", split="train")
    pdf = generate_simulated_episode("pdf_slow_storage", split="test")
    game = generate_simulated_episode("game_thermal_limit", split="validation")

    validate_simulated_splits((wifi, pdf, game))
    assert all(len(item.split_keys) == 5 for item in (wifi, pdf, game))


def test_unknown_or_duplicate_probe_selection_is_rejected() -> None:
    with pytest.raises(ValueError, match="unregistered"):
        generate_simulated_episode("wifi_dns", executed_probe_ids=("unknown.probe",))
    with pytest.raises(ValueError, match="duplicate"):
        generate_simulated_episode("wifi_dns", executed_probe_ids=("wifi.radio", "wifi.radio"))


def test_replay_verifier_rejects_mutated_utility_and_model_input() -> None:
    episode = generate_simulated_episode("wifi_dns", executed_probe_ids=("wifi.gateway",))
    verify_simulated_episode(episode)
    first = episode.adjudications[1].model_copy(update={"utility": "negative"})
    forged_label = episode.model_copy(
        update={"adjudications": (episode.adjudications[0], first, *episode.adjudications[2:])}
    )
    with pytest.raises(ValueError, match="replay"):
        verify_simulated_episode(forged_label)
    forged_input = episode.model_copy(
        update={"model_input": episode.model_input.model_copy(update={"symptom": "fault leaked"})}
    )
    with pytest.raises(ValueError, match="replay"):
        verify_simulated_episode(forged_input)
