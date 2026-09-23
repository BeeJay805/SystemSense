import pytest

from systemsense.application.investigator import (
    _baseline_probe_ids,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.parametrize(
    ("symptom", "expected"),
    [
        ("I cannot connect to Wi-Fi", ("network.connectivity", "core.system")),
        ("Proxy is blocking the browser", ("network.connectivity", "core.system")),
        ("My game is at 12 FPS", ("gpu.telemetry.sample", "core.system")),
        ("This PDF is slow", ("core.resources", "core.system")),
        ("My audio driver failed", ("devices.snapshot", "core.system")),
        ("The disk is failing", ("storage.snapshot", "core.system")),
        ("Something is wrong", ("core.system",)),
    ],
)
def test_seed_does_not_broad_scan_unrelated_families(
    symptom: str, expected: tuple[str, ...]
) -> None:
    available = frozenset(
        {
            "core.system",
            "core.resources",
            "application.snapshot",
            "devices.snapshot",
            "network.configuration",
            "network.connectivity",
            "storage.snapshot",
            "gpu.telemetry.sample",
        }
    )
    assert _baseline_probe_ids(symptom, available) == expected


def test_seed_uses_existing_network_probe_when_targeted_probe_is_unavailable() -> None:
    assert _baseline_probe_ids(
        "Wi-Fi will not connect", frozenset({"core.system", "network.configuration"})
    ) == ("network.configuration", "core.system")
