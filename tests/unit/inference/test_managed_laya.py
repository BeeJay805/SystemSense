"""Managed CUDA Laya ownership and admission are deterministic under fake telemetry."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic, sleep

import pytest

from systemsense.inference import host_lease
from systemsense.inference.host_lease import (
    HostInferenceLeaseLedger,
    LeaseBudget,
    LeaseReleaseDecision,
    WorkerIdentity,
)
from systemsense.inference.host_telemetry import HostTelemetryReading
from systemsense.inference.managed_laya import ManagedLayaAdmission, ManagedLayaPolicy
from systemsense.inference.tree_host_lease import TreeCustody, TreeHostInferenceLeaseLedger

GIB = 1024**3
GPU_UUID = "GPU-12345678-1234-1234-1234-123456789abc"
NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


class FakeRuntime:
    def __init__(self, worker_states: dict[int, host_lease.WorkerState]) -> None:
        self.worker_states = worker_states
        self.worker_pid: int | None = None
        self.close_calls = 0
        self.fail_close = False

    def close(self) -> None:
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError("termination unverified")
        if self.worker_pid is not None:
            self.worker_states[self.worker_pid] = "exited"


def reading(
    *, free_gib: float = 12, ram_gib: float = 16, uuid: str = GPU_UUID, age_ms: int = 0
) -> HostTelemetryReading:
    instant = NOW - timedelta(milliseconds=age_ms)
    return HostTelemetryReading(
        source_window_started_at=instant,
        source_window_ended_at=instant,
        gpu_uuid=uuid,
        gpu_device_index=0,
        available_ram_bytes=int(ram_gib * GIB),
        free_vram_bytes=int(free_gib * GIB),
    )


def test_freshness_covers_whole_source_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale_ram = HostTelemetryReading(
        source_window_started_at=NOW - timedelta(milliseconds=1900),
        source_window_ended_at=NOW,
        gpu_uuid=GPU_UUID,
        gpu_device_index=0,
        available_ram_bytes=16 * GIB,
        free_vram_bytes=12 * GIB,
    )
    controller, runtime, _ledger = make_controller(
        tmp_path, monkeypatch, readings=[stale_ram], max_telemetry_age_ms=100
    )
    runtime.worker_pid = 1234
    assert not controller.startup_admission(1234, 100.0)
    assert controller.status.reason == "telemetry_stale"
    controller.close()


def test_failed_shutdown_without_lease_remains_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, _ledger = make_controller(tmp_path, monkeypatch)
    runtime.worker_pid = 1234
    runtime.fail_close = True
    assert not controller.startup_admission(1234, 999.0)
    assert controller.close().phase != "closed"
    runtime.fail_close = False
    assert controller.close().phase == "closed"


def make_controller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    readings: list[HostTelemetryReading] | None = None,
    db: Path | None = None,
    worker_states: dict[int, host_lease.WorkerState] | None = None,
    worker_state_reader: Callable[[host_lease.WorkerIdentity], host_lease.WorkerState]
    | None = None,
    lease_clock: Callable[[], float] | None = None,
    telemetry_reader: Callable[[int], HostTelemetryReading] | None = None,
    max_telemetry_age_ms: int = 2000,
) -> tuple[ManagedLayaAdmission, FakeRuntime, HostInferenceLeaseLedger]:
    states: dict[int, host_lease.WorkerState] = (
        worker_states if worker_states is not None else {1234: "alive"}
    )

    def observe(worker: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return states[worker.pid]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    ledger = HostInferenceLeaseLedger(
        db or tmp_path / "lease.sqlite3",
        LeaseBudget(1, 4 * GIB, 3 * GIB, gpu_device_index=0),
        lease_ttl_seconds=30,
        clock=lease_clock or monotonic,
    )
    samples = iter(readings if readings is not None else [reading()] * 10)
    policy = ManagedLayaPolicy(
        gpu_device_index=0,
        gpu_uuid=GPU_UUID,
        peak_ram_bytes=2 * GIB,
        peak_vram_bytes=int(2.5 * GIB),
        ram_reserve_bytes=4 * GIB,
        target_vram_reserve_bytes=6 * GIB,
        max_telemetry_age_ms=max_telemetry_age_ms,
        renew_interval_seconds=0.05,
    )
    controller = ManagedLayaAdmission(
        policy,
        ledger,
        telemetry_reader=telemetry_reader or (lambda gpu_device_index: next(samples)),
        identity_reader=lambda pid: host_lease.WorkerIdentity(pid, 100.0),
        worker_state_reader=worker_state_reader or observe,
        clock=lambda: NOW,
    )
    runtime = FakeRuntime(states)
    controller.attach_runtime(runtime)
    return controller, runtime, ledger


def test_startup_acquires_exact_worker_lease_before_load_and_release_follows_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch)
    runtime.worker_pid = 1234

    assert controller.startup_admission(1234, 100.0)
    status = controller.status
    assert status.phase == "leased" and status.worker_pid == 1234 and status.lease_id
    assert controller.call_admission(1234, 100.0)
    assert not ledger.release(status.lease_id)

    final = controller.close()
    assert final.phase == "closed"
    assert runtime.close_calls == 1
    assert not ledger.renew(status.lease_id)


def test_tree_lease_stays_reserved_after_root_exit_until_job_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Worker:
        pid = 1234

    class Job:
        empty = False
        closed = False

        def is_assigned_worker(self, worker: object) -> bool:
            return worker is process and not self.closed

        def wait_until_empty(self, timeout_seconds: float) -> bool:
            assert timeout_seconds >= 0
            if self.closed:
                raise RuntimeError("closed")
            return self.empty

    class Runtime:
        def __init__(self, custody: TreeCustody) -> None:
            self.tree_custody = custody
            self.released = False

        def close(self) -> None:
            job.empty = True

        def release_tree_custody(self) -> None:
            assert job.empty
            job.closed = True
            self.released = True

    process, job = Worker(), Job()
    worker = WorkerIdentity(1234, 100.0)
    custody = TreeCustody.create(job, process, worker)
    ledger = TreeHostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3", LeaseBudget(1, 4 * GIB, 3 * GIB, gpu_device_index=0)
    )

    def alive(_worker: WorkerIdentity) -> str:
        return "alive"

    monkeypatch.setattr("systemsense.inference.tree_host_lease._observe_worker", alive)
    controller = ManagedLayaAdmission(
        ManagedLayaPolicy(gpu_device_index=0, gpu_uuid=GPU_UUID),
        ledger,
        telemetry_reader=lambda _: reading(),
        identity_reader=lambda _: worker,
        worker_state_reader=lambda _: "exited",
        clock=lambda: NOW,
    )
    runtime = Runtime(custody)
    controller.attach_runtime(runtime)
    assert controller.startup_admission(1234, 100.0)
    lease_id = controller.status.lease_id
    assert lease_id
    assert not ledger.release(lease_id, custody=custody)
    assert controller.status.phase == "leased"
    assert controller.close().phase == "closed"
    assert runtime.released


def test_unreadable_job_accounting_quarantines_tree_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Worker:
        pid = 1234

    class Job:
        unreadable = False

        def is_assigned_worker(self, worker: object) -> bool:
            assert worker is process
            return True

        def wait_until_empty(self, timeout_seconds: float) -> bool:
            assert timeout_seconds >= 0
            if self.unreadable:
                raise OSError("job query failed")
            return False

    class Runtime:
        def __init__(self, custody: TreeCustody) -> None:
            self.tree_custody = custody

        def close(self) -> None:
            job.unreadable = True
            raise RuntimeError("job drain unverified")

    process, job = Worker(), Job()
    worker = WorkerIdentity(1234, 100.0)
    custody = TreeCustody.create(job, process, worker)
    ledger = TreeHostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3", LeaseBudget(1, 4 * GIB, 3 * GIB, gpu_device_index=0)
    )

    def alive(_worker: WorkerIdentity) -> str:
        return "alive"

    monkeypatch.setattr("systemsense.inference.tree_host_lease._observe_worker", alive)
    controller = ManagedLayaAdmission(
        ManagedLayaPolicy(gpu_device_index=0, gpu_uuid=GPU_UUID),
        ledger,
        telemetry_reader=lambda _: reading(),
        identity_reader=lambda _: worker,
        clock=lambda: NOW,
    )
    controller.attach_runtime(Runtime(custody))
    assert controller.startup_admission(1234, 100.0)
    lease_id = controller.status.lease_id
    assert lease_id
    assert controller.close().phase == "quarantined"
    assert controller.status.lease_id == lease_id
    assert not ledger.release(lease_id, custody=custody)


def test_policy_is_readable_for_factory_cross_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, _, _ = make_controller(tmp_path, monkeypatch)
    assert controller.policy.gpu_device_index == 0
    assert controller.policy.gpu_uuid == GPU_UUID


def test_two_contenders_cannot_overbook_and_queued_request_is_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    states: dict[int, host_lease.WorkerState] = {1234: "alive", 5678: "alive"}
    db = tmp_path / "lease.sqlite3"
    first, first_runtime, _ = make_controller(tmp_path, monkeypatch, db=db, worker_states=states)
    second, second_runtime, ledger = make_controller(
        tmp_path, monkeypatch, db=db, worker_states=states
    )
    first_runtime.worker_pid = 1234
    second_runtime.worker_pid = 5678

    assert first.startup_admission(1234, 100.0)
    assert not second.startup_admission(5678, 100.0)
    assert second.status.reason.startswith("lease_")
    assert not ledger.cancel_pending(second.status.request_id or "")
    assert first.close().phase == "closed"
    assert second.close().phase == "closed"


@pytest.mark.parametrize(
    ("sample", "reason"),
    [
        (reading(age_ms=3000), "telemetry_stale"),
        (reading(free_gib=8), "vram_headroom"),
        (reading(ram_gib=5), "ram_headroom"),
        (reading(uuid="GPU-abcdefab-1234-1234-1234-123456789abc"), "gpu_mismatch"),
    ],
)
def test_startup_denies_untrusted_or_insufficient_telemetry_without_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sample: HostTelemetryReading,
    reason: str,
) -> None:
    controller, runtime, _ = make_controller(tmp_path, monkeypatch, readings=[sample])
    runtime.worker_pid = 1234

    assert not controller.startup_admission(1234, 100.0)
    assert controller.status.reason == reason
    assert controller.status.lease_id is None
    assert controller.close().phase == "closed"


def test_wrong_creation_identity_denied_before_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, _ = make_controller(tmp_path, monkeypatch)
    runtime.worker_pid = 1234
    assert not controller.startup_admission(1234, 99.0)
    assert controller.status.reason == "worker_identity_mismatch"
    assert controller.close().phase == "closed"


def test_failed_close_retains_lease_until_exact_worker_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    states: dict[int, host_lease.WorkerState] = {1234: "alive"}
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch, worker_states=states)
    runtime.worker_pid = 1234
    runtime.fail_close = True
    assert controller.startup_admission(1234, 100.0)
    lease_id = controller.status.lease_id
    assert lease_id

    assert controller.close().phase == "closing"
    assert ledger.renew(lease_id)
    states[1234] = "exited"
    deadline = monotonic() + 1
    while controller.status.phase != "closed" and monotonic() < deadline:
        sleep(0.01)
    assert controller.status.phase == "closed"
    assert controller.status.lease_id is None


def test_call_denial_never_closes_reentrantly_under_runtime_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, _ = make_controller(
        tmp_path, monkeypatch, readings=[reading(), reading(), reading(free_gib=4)]
    )
    runtime.worker_pid = 1234
    assert controller.startup_admission(1234, 100.0)
    runtime_lock = Lock()
    original_close = runtime.close

    def locked_close() -> None:
        with runtime_lock:
            original_close()

    runtime.close = locked_close  # type: ignore[method-assign]
    with runtime_lock:
        assert not controller.call_admission(1234, 100.0)
        assert controller.status.reason == "vram_headroom"
    assert controller.close().phase == "closed"


def test_unknown_worker_state_at_call_denies_instead_of_throwing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fault = [True]
    states: dict[int, host_lease.WorkerState] = {1234: "alive"}

    def unreadable(_: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        if fault[0]:
            raise RuntimeError("process table unavailable")
        return states[1234]

    controller, runtime, _ = make_controller(
        tmp_path, monkeypatch, worker_states=states, worker_state_reader=unreadable
    )
    runtime.worker_pid = 1234
    assert controller.startup_admission(1234, 100.0)
    assert not controller.call_admission(1234, 100.0)
    assert controller.status.reason == "worker_identity_unverifiable"
    fault[0] = False
    assert controller.close().phase == "closed"


def test_close_during_delayed_startup_leaves_no_orphan_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch)
    runtime.worker_pid = 1234
    entered, proceed = Event(), Event()
    acquire = ledger.try_acquire

    def slow_acquire(*args: object, **kwargs: object) -> host_lease.LeaseDecision:
        entered.set()
        assert proceed.wait(1)
        return acquire(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ledger, "try_acquire", slow_acquire)
    admission: list[bool] = []
    thread = Thread(target=lambda: admission.append(controller.startup_admission(1234, 100.0)))
    thread.start()
    assert entered.wait(1)
    close_result: list[str] = []
    closing = Thread(target=lambda: close_result.append(controller.close().phase))
    closing.start()
    proceed.set()
    thread.join(timeout=1)
    closing.join(timeout=1)

    assert not thread.is_alive() and not closing.is_alive()
    assert close_result == ["closed"]
    assert controller.status.lease_id is None
    if admission == [True]:
        assert runtime.close_calls >= 1


def test_idle_watchdog_renews_and_retires_on_headroom_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two cold checks, one healthy idle check, then the target needs its VRAM.
    samples = [reading(), reading(), reading(), reading(free_gib=4)]
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch, readings=samples)
    runtime.worker_pid = 1234
    renew_count = [0]
    original_renew = ledger.renew

    def renew(lease_id: str) -> bool:
        renew_count[0] += 1
        return original_renew(lease_id)

    monkeypatch.setattr(ledger, "renew", renew)
    assert controller.startup_admission(1234, 100.0)
    deadline = monotonic() + 1
    while controller.status.phase != "closed" and monotonic() < deadline:
        sleep(0.01)
    assert controller.status.phase == "closed"
    assert renew_count[0] >= 2
    assert runtime.close_calls >= 1


def test_lease_renewal_failure_requests_owned_close_without_freeing_live_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    states: dict[int, host_lease.WorkerState] = {1234: "alive"}
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch, worker_states=states)
    runtime.worker_pid = 1234
    runtime.fail_close = True
    assert controller.startup_admission(1234, 100.0)
    lease_id = controller.status.lease_id
    assert lease_id

    def deny_renewal(_lease_id: str) -> bool:
        return False

    monkeypatch.setattr(ledger, "renew", deny_renewal)
    deadline = monotonic() + 1
    while controller.status.reason != "lease_renewal_failed" and monotonic() < deadline:
        sleep(0.01)
    assert controller.status.phase == "closing"
    assert controller.status.lease_id == lease_id
    assert runtime.close_calls >= 1
    states[1234] = "exited"
    deadline = monotonic() + 1

    def exited_and_released() -> bool:
        return controller.status.phase == "closed"

    while not exited_and_released() and monotonic() < deadline:
        sleep(0.01)
    assert exited_and_released()


def test_failed_close_keeps_renewing_until_worker_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    states: dict[int, host_lease.WorkerState] = {1234: "alive"}
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch, worker_states=states)
    runtime.worker_pid = 1234
    runtime.fail_close = True
    assert controller.startup_admission(1234, 100.0)
    renew_count = [0]
    original_renew = ledger.renew

    def renew(lease_id: str) -> bool:
        renew_count[0] += 1
        return original_renew(lease_id)

    monkeypatch.setattr(ledger, "renew", renew)
    assert controller.close().phase == "closing"
    deadline = monotonic() + 0.25
    while renew_count[0] < 2 and monotonic() < deadline:
        sleep(0.01)
    assert renew_count[0] >= 2
    states[1234] = "exited"
    deadline = monotonic() + 1
    while controller.status.phase != "closed" and monotonic() < deadline:
        sleep(0.01)
    assert controller.status.phase == "closed"


def test_ledger_renewal_exception_does_not_escape_rank_callback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch)
    runtime.worker_pid = 1234
    assert controller.startup_admission(1234, 100.0)

    def broken_renew(_lease_id: str) -> bool:
        raise OSError("store unavailable")

    monkeypatch.setattr(ledger, "renew", broken_renew)
    assert not controller.call_admission(1234, 100.0)
    assert controller.status.reason == "lease_renewal_failed"
    assert controller.close().phase == "closed"


def test_ledger_renewal_exception_in_watchdog_retires_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch)
    runtime.worker_pid = 1234
    assert controller.startup_admission(1234, 100.0)

    def broken_renew(_lease_id: str) -> bool:
        raise OSError("store unavailable")

    monkeypatch.setattr(ledger, "renew", broken_renew)
    deadline = monotonic() + 1
    while runtime.close_calls == 0 and monotonic() < deadline:
        sleep(0.01)
    assert runtime.close_calls >= 1
    while controller.status.phase != "closed" and monotonic() < deadline:
        sleep(0.01)
    assert controller.status.phase == "closed"


def test_prior_verified_expiry_reclaim_is_not_reported_as_unreleased(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tick = [1000.0]
    states: dict[int, host_lease.WorkerState] = {1234: "alive"}
    controller, runtime, ledger = make_controller(
        tmp_path,
        monkeypatch,
        worker_states=states,
        lease_clock=lambda: tick[0],
    )
    runtime.worker_pid = 1234
    assert controller.startup_admission(1234, 100.0)
    lease_id = controller.status.lease_id
    assert lease_id
    states[1234] = "exited"
    tick[0] += 31
    # Any other operation can auto-reclaim the expired, verified-exited row.
    ledger.try_acquire("other", host_lease.LeaseDemand(1, 1))
    assert controller.close().phase == "closed"
    assert controller.status.lease_id is None


def test_reconciliation_store_outage_is_reported_and_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, ledger = make_controller(tmp_path, monkeypatch)
    runtime.worker_pid = 1234
    assert controller.startup_admission(1234, 100.0)
    original = ledger.reconcile_release
    unavailable = [True]

    def reconcile(lease_id: str, worker: WorkerIdentity) -> LeaseReleaseDecision:
        return (
            LeaseReleaseDecision("store_unavailable")
            if unavailable[0]
            else original(lease_id, worker)
        )

    monkeypatch.setattr(ledger, "reconcile_release", reconcile)
    assert controller.close().phase == "quarantined"
    assert controller.status.lease_id is not None
    unavailable[0] = False
    deadline = monotonic() + 1
    while controller.status.phase != "closed" and monotonic() < deadline:
        sleep(0.01)
    assert controller.status.phase == "closed"


def test_delayed_watchdog_sample_cannot_reopen_closed_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, proceed = Event(), Event()
    calls = [0]

    def telemetry(_index: int) -> HostTelemetryReading:
        calls[0] += 1
        if calls[0] > 2:
            entered.set()
            assert proceed.wait(1)
            return reading(free_gib=4)
        return reading()

    controller, runtime, _ = make_controller(tmp_path, monkeypatch, telemetry_reader=telemetry)
    runtime.worker_pid = 1234
    assert controller.startup_admission(1234, 100.0)
    assert entered.wait(1)
    assert controller.close().phase == "closed"
    proceed.set()
    sleep(0.1)
    assert controller.status.phase == "closed"
    assert controller.status.lease_id is None
