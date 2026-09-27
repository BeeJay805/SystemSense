"""Registered control observations remain available when a local route stalls."""

from pathlib import Path

from benchmarks.sequential_investigator_episodes import run_episode_suite


def test_registered_browser_controls_remain_in_the_investigation(tmp_path: Path) -> None:
    report = run_episode_suite(
        tmp_path / "episodes", case_ids=("toy-network-002", "toy-network-007")
    )

    for run in report["runs"]:
        assert run["runtime_complete"] is True
        executed = {item["probe_id"] for item in run["executions"]}
        assert "browser.route_attempt" in executed
        assert "browser.proxy_settings" in executed
        assert "browser.direct_control" in executed
        assert "browser.external_control" in executed
        assert "system.battery_wear" not in executed
