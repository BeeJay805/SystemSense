"""A real loopback fault with a separately checked target application."""

import os
import socket
from pathlib import Path
from typing import Any

import pytest

import benchmarks.owned_port_journey as journey
from benchmarks.owned_port_journey import matching_owned_listener, run_owned_port_journey


def test_binding_requires_exact_endpoint_and_stable_owner() -> None:
    created = "2026-09-22T12:00:00+00:00"
    listener = {
        "protocol": "tcp4",
        "local_address": "127.0.0.1",
        "local_port": 43199,
        "pid": 1234,
        "process_name": "python.exe",
        "process_creation_time": created,
        "owner_status": "available",
    }
    assert matching_owned_listener([listener], 43199, 1234, "python.exe", created)
    assert not matching_owned_listener([listener], 43200, 1234, "python.exe", created)
    assert not matching_owned_listener([listener], 43199, 1235, "python.exe", created)
    assert not matching_owned_listener(
        [listener], 43199, 1234, "python.exe", "2026-09-22T12:00:01+00:00"
    )
    assert not matching_owned_listener(
        [dict(listener, owner_status="denied")], 43199, 1234, "python.exe", created
    )
    assert not matching_owned_listener(
        [listener, dict(listener, pid=99)], 43199, 1234, "python.exe", created
    )


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("SYSTEMSENSE_OWNED_PORT_REHEARSAL") != "1",
    reason="set SYSTEMSENSE_OWNED_PORT_REHEARSAL=1 on Windows for the owned host rehearsal",
)
def test_owned_port_journey(tmp_path: Path) -> None:
    result = run_owned_port_journey(tmp_path / "case.db")
    assert result["classification"] == "controlled_host_rehearsal"
    assert result["diagnostic_accuracy_claim"] is False
    assert result["consumer_repair_claim"] is False
    assert result["before"]["bind_failed_address_in_use"] is True
    assert result["investigation"]["listener_probe_observed"] is True
    assert result["investigation"]["outcome"] != "supported_explanation"
    assert result["investigation"]["assessment"]["disposition"] == "supported_observed_finding"
    assert result["investigation"]["assessment"]["root_cause_proven"] is False
    assert result["action"]["bound_to_owned_blocker"] is True
    assert result["after"]["target_bind_succeeded"] is True
    assert result["after"]["target_http_verified"] is True


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("SYSTEMSENSE_OWNED_PORT_REHEARSAL") != "1",
    reason="set SYSTEMSENSE_OWNED_PORT_REHEARSAL=1 on Windows for the owned host rehearsal",
)
def test_unmatched_evidence_blocks_action_and_cleans_owned_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_evidence(
        _listeners: list[dict[str, Any]],
        _port: int,
        _pid: int,
        _name: str,
        _created: str,
    ) -> bool:
        return False

    monkeypatch.setattr(journey, "matching_owned_listener", reject_evidence)
    result = run_owned_port_journey(tmp_path / "case.db")
    assert result["status"] == "failed"
    assert result["failure_stage"] == "investigate_read_only"
    assert result["action"]["bound_to_owned_blocker"] is False
    port = int(result["endpoint"].rsplit(":", 1)[1])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
        target.bind(("127.0.0.1", port))
