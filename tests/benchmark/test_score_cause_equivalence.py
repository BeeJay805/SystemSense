"""Cause-level scoring keeps nuisance recipe differences out of the verdict."""

from __future__ import annotations

from typing import Any

from benchmarks.score_cause_equivalence import score_case_cause_equivalence


def _run(
    case_id: str, observations: dict[str, str], *, failed: str | None = None
) -> dict[str, Any]:
    executions: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for index, (probe_id, value) in enumerate(observations.items()):
        execution_id = f"exec_{index}"
        executions.append({"execution_id": execution_id, "probe_id": probe_id, "status": "ok"})
        evidence.append(
            {
                "execution_id": execution_id,
                "statement_kind": "observed_fact",
                "facts": [
                    {"name": "measurement_status", "value": "observed"},
                    {"name": "observation", "value": value},
                ],
            }
        )
    if failed is not None:
        executions.append({"execution_id": "exec_failed", "probe_id": failed, "status": "failed"})
    return {"case_id": case_id, "executions": executions, "evidence": evidence}


def test_same_cause_nuisance_variants_are_not_causal_ambiguity() -> None:
    network = score_case_cause_equivalence(
        _run(
            "toy-network-003",
            {
                "browser.proxy_settings": "disabled",
                "browser.route_attempt": "dns_failure",
                "browser.direct_control": "dns_failure",
                "browser.external_control": "http_204",
            },
            failed="system.battery_wear",
        )
    )
    application = score_case_cause_equivalence(
        _run(
            "toy-application-003",
            {
                "application.external_control": "normal",
                "application.storage_latency": "normal",
                "application.renderer_mode": "software",
                "application.task_timing": "slow",
            },
        )
    )
    assert network["compatible_world_ids"] == ["toy-network-003", "toy-network-005"]
    assert network["compatible_cause_labels"] == [["dns_configuration"]]
    assert network["single_known_cause_label"] is True
    assert network["unknown_probe_ids"] == ["system.battery_wear"]
    assert application["compatible_world_ids"] == ["toy-application-003", "toy-application-005"]
    assert application["compatible_cause_labels"] == [["software_rendering"]]
    assert application["single_known_cause_label"] is True

    battery_variant = score_case_cause_equivalence(
        _run(
            "toy-network-005",
            {
                "browser.proxy_settings": "disabled",
                "browser.route_attempt": "dns_failure",
                "browser.direct_control": "dns_failure",
                "browser.external_control": "http_204",
                "system.battery_wear": "high",
            },
        )
    )
    assert battery_variant["compatible_world_ids"] == ["toy-network-005"]
    assert "system.battery_wear" not in battery_variant["cause_reducing_probe_ids"]


def test_failed_or_unrecognized_observation_stays_unknown() -> None:
    failed = score_case_cause_equivalence(
        _run(
            "toy-network-003",
            {"browser.proxy_settings": "disabled"},
            failed="browser.route_attempt",
        )
    )
    assert "browser.route_attempt" in failed["unknown_probe_ids"]
    assert failed["single_known_cause_label"] is False

    inconsistent = score_case_cause_equivalence(
        _run("toy-network-003", {"browser.route_attempt": "never_declared"})
    )
    assert inconsistent["status"] == "inconsistent_observation"
    assert inconsistent["single_known_cause_label"] is False

    unobserved = score_case_cause_equivalence(_run("toy-network-006", {}))
    assert unobserved["unknown_world_compatible"] is True
    assert unobserved["single_known_cause_label"] is False
