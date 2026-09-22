from systemsense.application.bootstrap import default_planner
from systemsense.orchestration.planner import CasePlanningRequest
from systemsense.packs.runtime import default_probe_runner
from systemsense.worker import REGISTERED_PROBE_IDS


def test_default_planner_selects_only_registered_runtime_probes() -> None:
    runner = default_probe_runner()
    plan = default_planner().plan(
        CasePlanningRequest(
            symptom="application audio device network update cuda python",
            target_traits=frozenset({"application", "device"}),
            fresh_probe_ids=frozenset(),
            budget_ms=60_000,
            max_probes=32,
        )
    )

    assert set(plan.probe_ids) <= runner.probe_ids
    assert runner.isolated_probe_ids <= REGISTERED_PROBE_IDS
    assert runner.isolated_probe_ids == runner.probe_ids


def test_default_planner_uses_network_target_when_human_symptom_omits_port_term() -> None:
    plan = default_planner().plan(
        CasePlanningRequest(
            symptom="Local app exits with a Windows socket address-in-use error.",
            target_traits=frozenset({"application", "network"}),
            fresh_probe_ids=frozenset(),
            budget_ms=30_000,
            max_probes=16,
        )
    )

    assert "application.snapshot" in plan.probe_ids
    assert "network.snapshot" in plan.probe_ids
    assert "network.listeners" in plan.probe_ids


def test_default_runtime_registers_broad_read_only_windows_probe_families() -> None:
    runner = default_probe_runner()

    assert {
        "gpu.telemetry.sample",
        "storage.snapshot",
        "network.listeners",
        "network.configuration",
        "pressure.sample",
        "power.snapshot",
        "security.snapshot",
        "incident.events",
    } <= runner.probe_ids
    assert runner.probe_ids == runner.isolated_probe_ids
    application = runner.manifest("application.snapshot")
    assert application is not None
    assert application.limits.max_records >= 512


def test_broad_probe_catalog_costs_cover_observed_cold_worker_latency() -> None:
    plan = default_planner().plan(
        CasePlanningRequest(
            symptom=(
                "application storage drive dns route proxy battery power security firewall "
                "hardware freeze event cpu slow port bind gpu thermal throttle"
            ),
            target_traits=frozenset(
                {
                    "application",
                    "storage",
                    "network",
                    "power",
                    "security",
                    "incident",
                    "performance",
                    "gpu",
                }
            ),
            fresh_probe_ids=frozenset(),
            budget_ms=120_000,
            max_probes=32,
        )
    )
    costs = {probe.probe_id: probe.cost_ms for probe in plan.probes}

    assert costs["application.snapshot"] >= 7000
    assert costs["storage.snapshot"] >= 1200
    assert costs["network.configuration"] >= 1200
    assert costs["power.snapshot"] >= 2000
    assert costs["security.snapshot"] >= 1000
    assert costs["incident.events"] >= 1000
    assert costs["network.listeners"] >= 1000
    assert costs["pressure.sample"] >= 8000
    assert costs["gpu.telemetry.sample"] >= 2000
