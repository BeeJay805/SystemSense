from systemsense.mcp_server import default_planner
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
    assert runner.isolated_probe_ids == {
        "devices.snapshot",
        "servicing.snapshot",
        "local_ai.snapshot",
    }


def test_default_planner_infers_network_probe_from_socket_error_without_target_traits() -> None:
    plan = default_planner().plan(
        CasePlanningRequest(
            symptom=(
                "My local development app stopped starting after I resumed the PC. "
                "It prints a Windows socket address-in-use error and exits."
            ),
            target_traits=frozenset(),
            fresh_probe_ids=frozenset(),
            budget_ms=5000,
            max_probes=16,
        )
    )

    assert "application.snapshot" in plan.probe_ids
    assert "network.snapshot" in plan.probe_ids
