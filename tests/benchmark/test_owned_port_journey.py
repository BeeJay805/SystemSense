"""A real loopback fault with a separately checked target application."""

import json
import os
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
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


def test_failed_observer_cannot_count_as_target_recovery() -> None:
    raw = {
        "address": "127.0.0.1",
        "port": 43199,
        "protocol": "tcp4",
        "pid": 1234,
        "bind_started_at": "2026-09-22T12:00:01+00:00",
        "bind_completed_at": "2026-09-22T12:00:02+00:00",
        "finished_at": "2026-09-22T12:00:03+00:00",
        "bind_succeeded": True,
        "served_http": True,
        "errno": None,
        "winerror": None,
        "socket_error": None,
    }
    valid = {
        "pid": 1234,
        "configuration_digest": journey.target_configuration_digest(43199),
        "started_at": "2026-09-22T12:00:00+00:00",
        "finished_at": "2026-09-22T12:00:04+00:00",
        "completed": True,
        "exit_code": 0,
        "bind_succeeded": True,
        "served_http": True,
        "http_response_verified": True,
        "raw_stdout": json.dumps(raw, separators=(",", ":")),
        "raw_result": raw,
        "observer_error": None,
    }
    assert journey.target_recovered(valid)
    for missing in (
        "completed",
        "exit_code",
        "bind_succeeded",
        "served_http",
        "http_response_verified",
    ):
        failed = dict(valid)
        failed[missing] = False if isinstance(failed[missing], bool) else 1
        assert not journey.target_recovered(failed)
    assert not journey.target_recovered({**valid, "observer_error": "TimeoutExpired"})
    assert not journey.target_recovered({**valid, "raw_result": None})
    assert not journey.target_recovered({**valid, "pid": 9999})
    assert not journey.target_recovered({**valid, "configuration_digest": "0" * 64})
    assert not journey.target_recovered({**valid, "raw_stdout": "{}"})
    assert not journey.target_recovered({**valid, "started_at": "2026-09-22T12:00:00"})
    assert not journey.target_recovered({**valid, "finished_at": "2026-09-22T12:00:01+00:00"})
    assert not journey.target_recovered({**valid, "raw_result": {**raw, "served_http": False}})


def test_after_observer_must_start_after_before_finishes() -> None:
    before = {"started_at": "2026-09-22T12:00:00+00:00", "finished_at": "2026-09-22T12:00:04+00:00"}
    after = {"started_at": "2026-09-22T12:00:05+00:00", "finished_at": "2026-09-22T12:00:08+00:00"}
    assert journey.measurements_ordered(before, after)
    assert not journey.measurements_ordered(before, {**after, "started_at": before["finished_at"]})
    assert not journey.measurements_ordered(before, {**after, "started_at": "2026-09-22T12:00:05"})


@pytest.mark.skipif(os.name != "nt", reason="Windows-only observer process flags")
def test_observer_cleanup_race_invalidates_measurement_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = 43199
    child_pid = 12345
    now = datetime.now(UTC)
    raw = {
        "address": "127.0.0.1",
        "port": port,
        "protocol": "tcp4",
        "pid": child_pid,
        "bind_started_at": now.isoformat(),
        "bind_completed_at": (now + timedelta(milliseconds=1)).isoformat(),
        "finished_at": (now + timedelta(milliseconds=2)).isoformat(),
        "bind_succeeded": True,
        "served_http": True,
    }

    class FakeObserver:
        pid = child_pid
        returncode = 0
        killed = False

        def poll(self) -> None:
            return None

        def communicate(self, timeout: float) -> tuple[bytes, bytes]:
            return json.dumps(raw).encode(), b""

        def terminate(self) -> None:
            raise OSError("injected exit race")

        def kill(self) -> None:
            self.killed = True

    observer = FakeObserver()

    def fake_popen(*_args: Any, **_kwargs: Any) -> FakeObserver:
        return observer

    def fake_owned_endpoint(_pid: int, _port: int) -> bool:
        return True

    def fake_http_read(_port: int) -> bytes:
        return b"HTTP/1.1 200 OK\r\n\r\nTARGET_OK"

    monkeypatch.setattr(journey.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(journey, "_owned_endpoint", fake_owned_endpoint)
    monkeypatch.setattr(journey, "_http_read", fake_http_read)
    measurement = journey.__dict__["_run_target_observer"](port)
    assert measurement["completed"] is False
    assert "injected exit race" in measurement["observer_error"]
    assert not journey.target_recovered(measurement)
    assert measurement["finished_at"] is not None
    assert observer.killed


@pytest.mark.skipif(os.name != "nt", reason="Windows-only observer process flags")
def test_observer_kill_and_communicate_failures_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeObserver:
        pid = 12345
        returncode: int | None = None

        def poll(self) -> None:
            return None

        def communicate(self, timeout: float) -> tuple[bytes, bytes]:
            raise subprocess.TimeoutExpired("fake observer", timeout)

        def terminate(self) -> None:
            return None

        def kill(self) -> None:
            raise OSError("injected kill failure")

    observer = FakeObserver()

    def fake_popen(*_args: Any, **_kwargs: Any) -> FakeObserver:
        return observer

    def fake_owned_endpoint(_pid: int, _port: int) -> bool:
        return True

    def fake_http_read(_port: int) -> bytes:
        return b""

    monkeypatch.setattr(journey.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(journey, "_owned_endpoint", fake_owned_endpoint)
    monkeypatch.setattr(journey, "_http_read", fake_http_read)
    measurement = journey.__dict__["_run_target_observer"](43199)
    assert measurement["completed"] is False
    assert "injected kill failure" in measurement["observer_error"]
    assert "final communicate" in measurement["observer_error"]
    assert "observer process exit not confirmed" in measurement["observer_error"]
    assert measurement["finished_at"] is not None


@pytest.mark.skipif(os.name != "nt", reason="Windows-only owned process flags")
def test_blocker_cleanup_error_preserves_primary_failure_and_attempts_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeBlocker:
        pid = 12345
        returncode: int | None = None
        killed = False

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            raise OSError("injected terminate failure")

        def wait(self, timeout: float) -> int:
            if not self.killed:
                raise subprocess.TimeoutExpired("fake blocker", timeout)
            self.returncode = -9
            return -9

        def kill(self) -> None:
            self.killed = True

    blocker = FakeBlocker()

    def primary_failure(_pid: int, _port: int) -> bool:
        raise RuntimeError("injected primary failure")

    monkeypatch.setattr(journey, "_choose_port", lambda: 43199)

    def fake_popen(*_args: Any, **_kwargs: Any) -> FakeBlocker:
        return blocker

    monkeypatch.setattr(journey.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(journey, "_owned_endpoint", primary_failure)
    result = run_owned_port_journey(tmp_path / "case.db")
    assert result["status"] == "uncertain"
    assert result["failure_stage"] == "start_owned_blocker"
    assert result["failure_reason"] == "RuntimeError: injected primary failure"
    assert "injected terminate failure" in str(result["cleanup_errors"])
    assert blocker.killed
    assert result["ended_at"]


def test_existing_report_blocks_run_before_host_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "report.json"
    report.write_text("keep", encoding="utf-8")

    def unexpected_run(_database: Path, *, budget_ms: int) -> dict[str, Any]:
        pytest.fail("existing report must be rejected before running host work")

    monkeypatch.setattr(journey, "run_owned_port_journey", unexpected_run)
    monkeypatch.setattr(
        sys,
        "argv",
        ["owned_port_journey", "--database", str(tmp_path / "case.db"), "--output", str(report)],
    )
    with pytest.raises(FileExistsError):
        journey.main()
    assert report.read_text(encoding="utf-8") == "keep"


def test_report_is_reserved_and_fsynced_before_host_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "report.json"
    original_fsync = os.fsync
    fsync_count = 0

    def record_fsync(fd: int) -> None:
        nonlocal fsync_count
        fsync_count += 1
        original_fsync(fd)

    def fake_run(_database: Path, *, budget_ms: int) -> dict[str, Any]:
        assert json.loads(report.read_text(encoding="utf-8"))["status"] == "in_progress"
        assert fsync_count == 1
        return {"schema_version": 2, "status": "controlled_target_recovered_only"}

    monkeypatch.setattr(journey.os, "fsync", record_fsync)
    monkeypatch.setattr(journey, "run_owned_port_journey", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        ["owned_port_journey", "--database", str(tmp_path / "case.db"), "--output", str(report)],
    )
    assert journey.main() == 0
    assert fsync_count == 2
    assert (
        json.loads(report.read_text(encoding="utf-8"))["status"]
        == "controlled_target_recovered_only"
    )


def test_unexpected_host_run_error_preserves_uncertain_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "report.json"

    def failed_run(_database: Path, *, budget_ms: int) -> dict[str, Any]:
        assert json.loads(report.read_text(encoding="utf-8"))["status"] == "in_progress"
        raise RuntimeError("injected host failure")

    monkeypatch.setattr(journey, "run_owned_port_journey", failed_run)
    monkeypatch.setattr(
        sys,
        "argv",
        ["owned_port_journey", "--database", str(tmp_path / "case.db"), "--output", str(report)],
    )
    assert journey.main() == 1
    saved = json.loads(report.read_text(encoding="utf-8"))
    assert saved["status"] == "uncertain"
    assert saved["diagnostic_accuracy_claim"] is False
    assert saved["consumer_repair_claim"] is False
    assert saved["failure_stage"] == "host_run_exception"


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("SYSTEMSENSE_OWNED_PORT_REHEARSAL") != "1",
    reason="set SYSTEMSENSE_OWNED_PORT_REHEARSAL=1 on Windows for the owned host rehearsal",
)
def test_owned_port_journey(tmp_path: Path) -> None:
    result = run_owned_port_journey(tmp_path / "case.db")
    assert result["schema_version"] == 2
    assert result["classification"] == "controlled_host_rehearsal"
    assert result["diagnostic_accuracy_claim"] is False
    assert result["consumer_repair_claim"] is False
    assert result["before"]["bind_failed_address_in_use"] is True
    assert result["before"]["observer"]["completed"] is True
    assert result["before"]["observer"]["raw_stdout"]
    assert result["before"]["observer"]["started_at"]
    assert result["before"]["observer"]["finished_at"]
    assert result["investigation"]["listener_probe_observed"] is True
    assert result["investigation"]["outcome"] != "supported_explanation"
    assert result["investigation"]["assessment"]["disposition"] == "supported_observed_finding"
    assert result["investigation"]["assessment"]["root_cause_proven"] is False
    assert result["action"]["bound_to_owned_blocker"] is True
    assert result["after"]["target_bind_succeeded"] is True
    assert result["after"]["target_http_verified"] is True
    assert result["after"]["observer"]["completed"] is True
    assert result["after"]["observer"]["raw_stdout"]
    assert result["after"]["observer"]["pid"] != result["before"]["observer"]["pid"]
    assert (
        result["after"]["observer"]["configuration_digest"]
        == result["before"]["observer"]["configuration_digest"]
    )


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
