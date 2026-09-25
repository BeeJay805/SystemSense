"""Managed deep admission never launches a real server or loads a GPU."""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from systemsense.domain.time import utc_now
from systemsense.inference.host_lease import LeaseBudget, capture_worker_identity
from systemsense.inference.host_telemetry import HostTelemetryReading
from systemsense.inference.managed_ollama import ManagedOllamaAdmission, ManagedOllamaPolicy
from systemsense.inference.owned_ollama import (
    OwnedOllamaCloseResult,
    OwnedOllamaConfig,
    OwnedOllamaError,
)
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger

GIB = 1024**3
GPU = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


class FakeProcess:
    pid = os.getpid()


class FakeJob:
    def __init__(self) -> None:
        self.assigned = False
        self.empty = False
        self.open = True

    def is_assigned_worker(self, worker: Any) -> bool:
        return self.assigned and self.open and worker.pid == FakeProcess.pid

    def wait_until_empty(self, _timeout: float) -> bool:
        if not self.open:
            raise RuntimeError("closed")
        return self.empty


class FakeService:
    def __init__(
        self,
        admit: Callable[[Any, Any], bool],
        finalize: Callable[[bool, Any | None, Any | None], bool],
        *,
        exit_verified: bool = True,
    ) -> None:
        self.admit = admit
        self.finalize = finalize
        self.job = FakeJob()
        self.process = FakeProcess()
        self.ready = False
        self.exit_verified = exit_verified
        self.events: list[str] = []
        self.closed: OwnedOllamaCloseResult | None = None

    def start(self) -> None:
        self.events.append("assigned")
        self.job.assigned = True
        if not self.admit(self.process, self.job):
            self.close()
            return
        self.events.append("resumed")
        self.ready = True

    def owns_ready_endpoint(self) -> bool:
        return self.ready and self.job.assigned and self.job.open

    def close(self) -> OwnedOllamaCloseResult:
        if self.closed is not None:
            return self.closed
        self.events.append("terminate")
        self.ready = False
        self.job.empty = self.exit_verified
        finalized = self.finalize(self.exit_verified, self.job, self.process)
        self.job.open = False
        self.closed = OwnedOllamaCloseResult(self.exit_verified, finalized, True)
        return self.closed


def _config(tmp_path: Path) -> OwnedOllamaConfig:
    binary = tmp_path / "ollama.exe"
    binary.write_bytes(b"fake")
    models = tmp_path / "models"
    models.mkdir()
    return OwnedOllamaConfig(
        executable=binary,
        executable_sha256=hashlib.sha256(b"fake").hexdigest(),
        models_dir=models,
        endpoint="http://127.0.0.1:12434/api/chat",
        model="qwen3.8:27b",
        model_digest="a" * 64,
        startup_timeout_seconds=0.1,
    )


def _policy() -> ManagedOllamaPolicy:
    return ManagedOllamaPolicy(
        gpu_device_index=0,
        gpu_uuid=GPU,
        peak_ram_bytes=4 * GIB,
        peak_vram_bytes=10 * GIB,
        ram_reserve_bytes=2 * GIB,
        vram_reserve_bytes=2 * GIB,
        max_telemetry_age_ms=2000,
        renew_interval_seconds=0.01,
    )


def _sample(*, vram: int = 20 * GIB, uuid: str = GPU, stale: bool = False) -> HostTelemetryReading:
    now = utc_now()
    start = now - timedelta(seconds=4 if stale else 0.1)
    return HostTelemetryReading(
        source_window_started_at=start,
        source_window_ended_at=start + timedelta(milliseconds=10),
        gpu_uuid=uuid,
        gpu_device_index=0,
        available_ram_bytes=20 * GIB,
        free_vram_bytes=vram,
    )


def _build(
    tmp_path: Path,
    *,
    sample: Callable[[int], HostTelemetryReading] | None = None,
    exit_verified: bool = True,
) -> tuple[ManagedOllamaAdmission, FakeService, TreeHostInferenceLeaseLedger]:
    ledger = TreeHostInferenceLeaseLedger(
        tmp_path / "host.sqlite3",
        LeaseBudget(1, 16 * GIB, 16 * GIB, 0),
        lease_ttl_seconds=10,
    )
    holder: list[FakeService] = []

    def make_service(
        _config: OwnedOllamaConfig,
        admit: Callable[[Any, Any], bool],
        finalize: Callable[[bool, Any | None, Any | None], bool],
    ) -> FakeService:
        service = FakeService(admit, finalize, exit_verified=exit_verified)
        holder.append(service)
        return service

    controller = ManagedOllamaAdmission(
        _config(tmp_path),
        _policy(),
        ledger,
        telemetry_reader=sample or (lambda _index: _sample()),
        identity_reader=capture_worker_identity,
        service_factory=make_service,
    )
    return controller, holder[0], ledger


def test_acquire_before_resume_renew_during_idle_and_release_after_empty(tmp_path: Path) -> None:
    controller, service, ledger = _build(tmp_path)
    status = controller.start()
    assert status.phase == "ready"
    assert status.lease_id is not None
    assert service.events == ["assigned", "resumed"]
    assert controller.call_admission()
    assert ledger.renew(status.lease_id)
    closed = controller.close()
    assert closed.phase == "closed"
    assert not ledger.renew(status.lease_id)
    assert controller.close() == closed


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("owned Ollama server exited during startup", "startup_server_exited"),
        ("endpoint already has a listener", "startup_endpoint_occupied"),
        ("owned Ollama startup timed out", "startup_timeout"),
        ("pinned local model digest is unavailable", "startup_model_digest_unavailable"),
        (r"private path C:\\Users\\secret\\token", "startup_unclassified"),
    ],
)
def test_owned_startup_failure_keeps_only_safe_reason(
    tmp_path: Path, failure: str, expected: str
) -> None:
    controller, service, _ledger = _build(tmp_path)

    def fail_start() -> None:
        # The real owned service closes its Job before re-raising startup failure.
        service.close()
        raise OwnedOllamaError(failure, tree_exit_verified=True)

    service.start = fail_start  # type: ignore[method-assign]
    status = controller.start()
    assert status.phase == "closed"
    assert status.reason == expected
    assert failure not in repr(status)


def test_unloaded_model_rechecks_cold_vram_headroom_before_each_call(tmp_path: Path) -> None:
    free_vram = 20 * GIB

    def telemetry(_index: int) -> HostTelemetryReading:
        return _sample(vram=free_vram)

    controller, _service, _ledger = _build(tmp_path, sample=telemetry)
    assert controller.start().phase == "ready"
    # This owned client requests keep_alive=0: the server can be alive while
    # the model is unloaded, so the next call must budget a fresh model load.
    free_vram = 5 * GIB
    assert not controller.call_admission()
    assert controller.status.reason == "vram_headroom"
    controller.close()


def test_stale_or_insufficient_telemetry_denies_before_resume(tmp_path: Path) -> None:
    def stale(_index: int) -> HostTelemetryReading:
        return _sample(stale=True)

    def headroom(_index: int) -> HostTelemetryReading:
        return _sample(vram=11 * GIB)

    def wrong_gpu(_index: int) -> HostTelemetryReading:
        return _sample(uuid="GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

    for name, sample in (("stale", stale), ("headroom", headroom), ("gpu", wrong_gpu)):
        candidate = tmp_path / name
        candidate.mkdir()
        controller, service, _ = _build(candidate, sample=sample)
        status = controller.start()
        assert status.phase != "ready"
        assert "resumed" not in service.events
        assert not controller.call_admission()


def test_unverified_tree_exit_keeps_lease_capacity(tmp_path: Path) -> None:
    controller, service, ledger = _build(tmp_path, exit_verified=False)
    status = controller.start()
    assert status.lease_id is not None
    closed = controller.close()
    assert closed.phase == "quarantined"
    assert not controller.call_admission()
    assert ledger.renew(status.lease_id)
    assert not service.job.open


def test_second_telemetry_failure_releases_verified_pre_resume_lease(tmp_path: Path) -> None:
    calls = 0

    def changed_sample(_index: int) -> HostTelemetryReading:
        nonlocal calls
        calls += 1
        return _sample(vram=20 * GIB if calls == 1 else 11 * GIB)

    controller, service, ledger = _build(tmp_path, sample=changed_sample)
    acquired: list[str] = []
    original_acquire = ledger.try_acquire

    def record_acquire(*args: Any, **kwargs: Any) -> Any:
        decision = original_acquire(*args, **kwargs)
        if decision.lease_id is not None:
            acquired.append(decision.lease_id)
        return decision

    ledger.try_acquire = record_acquire  # type: ignore[method-assign]
    status = controller.start()
    assert calls == 2
    assert acquired and not ledger.renew(acquired[0])
    assert status.phase == "closed" and status.reason == "vram_headroom"
    assert "resumed" not in service.events


def test_lost_lease_refuses_next_call_and_retires(tmp_path: Path) -> None:
    controller, _service, ledger = _build(tmp_path)
    status = controller.start()
    assert status.lease_id is not None
    ledger.renew = lambda _lease_id: False  # type: ignore[method-assign]
    assert not controller.call_admission()
    assert controller.status.phase in ("closing", "quarantined", "closed")
    controller.close()


def test_lost_endpoint_ownership_refuses_model_call(tmp_path: Path) -> None:
    controller, service, _ledger = _build(tmp_path)
    assert controller.start().phase == "ready"
    service.owns_ready_endpoint = lambda: False  # type: ignore[method-assign]
    assert not controller.call_admission()
    controller.close()
    assert controller.status.reason == "service_custody_unverifiable"


def test_watchdog_renews_idle_lease_and_explicit_close_race_is_idempotent(tmp_path: Path) -> None:
    controller, service, ledger = _build(tmp_path)
    status = controller.start()
    assert status.phase == "ready"
    renewed = threading.Event()
    original_renew = ledger.renew

    def observe_renew(lease_id: str) -> bool:
        renewed.set()
        return original_renew(lease_id)

    ledger.renew = observe_renew  # type: ignore[method-assign]
    assert renewed.wait(0.5)
    closer = threading.Thread(target=controller.close)
    closer.start()
    controller.close()
    closer.join(timeout=1)
    assert not closer.is_alive()
    assert controller.status.phase == "closed"
    assert service.events.count("terminate") == 1
