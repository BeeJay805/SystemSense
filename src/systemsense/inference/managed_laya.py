"""Opt-in, host-wide admission for one pinned CUDA Laya worker.

This is a resource-safety coordinator, not a sandbox. It owns only the Laya
worker supplied by its caller. It never controls an Ollama server or another
application. A lease begins before the worker receives its model-load token and
is held until its owned Job tree is verified empty in tree-custody mode.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

import psutil

from systemsense.domain.time import utc_now
from systemsense.inference.host_lease import (
    HostInferenceLeaseLedger,
    LeaseDemand,
    WorkerIdentity,
    WorkerState,
    capture_worker_identity,
)
from systemsense.inference.host_telemetry import HostTelemetryReading, read_host_telemetry
from systemsense.inference.tree_host_lease import TreeCustody, TreeHostInferenceLeaseLedger

GIB = 1024**3
Phase = Literal["unattached", "ready", "leased", "closing", "quarantined", "closed"]


class ManagedRuntime(Protocol):
    """The existing Laya runtime's verified-exit close contract."""

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ManagedLayaPolicy:
    gpu_device_index: int
    gpu_uuid: str
    peak_ram_bytes: int = 2 * GIB
    peak_vram_bytes: int = int(2.5 * GIB)
    ram_reserve_bytes: int = 4 * GIB
    target_vram_reserve_bytes: int = 6 * GIB
    max_telemetry_age_ms: int = 2000
    renew_interval_seconds: float = 1.0

    def __post_init__(self) -> None:
        if not 0 <= self.gpu_device_index <= 15 or not self.gpu_uuid.startswith("GPU-"):
            raise ValueError("managed CUDA admission requires a pinned GPU")
        if any(
            not 0 < value <= 512 * GIB
            for value in (
                self.peak_ram_bytes,
                self.peak_vram_bytes,
                self.ram_reserve_bytes,
                self.target_vram_reserve_bytes,
            )
        ):
            raise ValueError("managed CUDA peaks and reserves must be positive and bounded")
        if not 100 <= self.max_telemetry_age_ms <= 2000:
            raise ValueError("telemetry freshness bound must be at most two seconds")
        if not 0.01 <= self.renew_interval_seconds <= 30:
            raise ValueError("lease renewal must be finite and bounded")


@dataclass(frozen=True, slots=True)
class ManagedLayaStatus:
    phase: Phase
    reason: str
    worker_pid: int | None
    lease_id: str | None
    request_id: str | None


def _read_telemetry(index: int) -> HostTelemetryReading:
    return read_host_telemetry(gpu_device_index=index)


def _worker_state(worker: WorkerIdentity) -> WorkerState:
    # The lease ledger uses the same PID+creation-time check. Keep this
    # separate so a failed release cannot be mistaken for verified exit.
    try:
        created_at = psutil.Process(worker.pid).create_time()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "exited"
    except (psutil.Error, OSError):
        return "unknown"
    return "alive" if created_at == worker.started_at else "exited"


class ManagedLayaAdmission:
    """One-worker admission callbacks plus a renewing idle watchdog.

    Construct before runtime startup, attach that runtime once, then pass
    ``startup_admission`` and ``call_admission`` to it. A denied callback never
    calls runtime.close synchronously: rank owns the runtime lock at that point.
    Failure marks the worker for asynchronous retirement and preserves or
    quarantines its lease until verified exit.
    """

    def __init__(
        self,
        policy: ManagedLayaPolicy,
        ledger: HostInferenceLeaseLedger | TreeHostInferenceLeaseLedger,
        *,
        telemetry_reader: Callable[[int], HostTelemetryReading] = _read_telemetry,
        identity_reader: Callable[[int], WorkerIdentity] = capture_worker_identity,
        worker_state_reader: Callable[[WorkerIdentity], WorkerState] = _worker_state,
        clock: Callable[[], datetime] = utc_now,
        call_telemetry_reuse_ms: int = 0,
    ) -> None:
        if policy.renew_interval_seconds * 3 >= ledger.lease_ttl_seconds:
            raise ValueError("lease TTL must exceed three renewal intervals")
        if type(call_telemetry_reuse_ms) is not int or not 0 <= call_telemetry_reuse_ms <= min(
            200, policy.max_telemetry_age_ms
        ):
            raise ValueError("call telemetry reuse must be a bounded freshness interval")
        self._policy = policy
        self._ledger = ledger
        self._tree_mode = isinstance(ledger, TreeHostInferenceLeaseLedger)
        self._custody: TreeCustody | None = None
        self._telemetry_reader = telemetry_reader
        self._identity_reader = identity_reader
        self._worker_state_reader = worker_state_reader
        self._clock = clock
        self._call_telemetry_reuse_ms = call_telemetry_reuse_ms
        self._last_call_telemetry: HostTelemetryReading | None = None
        self._runtime: ManagedRuntime | None = None
        self._phase: Phase = "unattached"
        self._reason = "not_attached"
        self._worker: WorkerIdentity | None = None
        self._lease_id: str | None = None
        self._request_id: str | None = None
        self._lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._wake = threading.Event()
        self._watchdog: threading.Thread | None = None
        self._closer: threading.Thread | None = None

    @property
    def policy(self) -> ManagedLayaPolicy:
        return self._policy

    @property
    def status(self) -> ManagedLayaStatus:
        with self._lock:
            return ManagedLayaStatus(
                self._phase,
                self._reason,
                self._worker.pid if self._worker else None,
                self._lease_id,
                self._request_id,
            )

    def attach_runtime(self, runtime: ManagedRuntime) -> None:
        with self._lock:
            if self._phase != "unattached":
                raise ValueError("managed Laya runtime can be attached only once")
            self._runtime = runtime
            self._phase = "ready"
            self._reason = "ready"

    def startup_admission(self, pid: int, created_at: float) -> bool:
        """Called while the new worker waits for its model-load token."""

        with self._lock:
            if self._phase != "ready" or self._runtime is None:
                return False
            try:
                worker = self._identity_reader(pid)
            except Exception:
                return self._deny("worker_identity_unavailable")
            if worker.pid != pid or worker.started_at != created_at:
                return self._deny("worker_identity_mismatch")
            custody: TreeCustody | None = None
            if self._tree_mode:
                candidate = getattr(self._runtime, "tree_custody", None)
                if not isinstance(candidate, TreeCustody) or candidate.root != worker:
                    return self._deny("tree_custody_unavailable")
                if not candidate.is_open():
                    return self._deny("tree_custody_unverifiable")
                custody = candidate
            reason = self._telemetry_denial(cold=True)
            if reason:
                return self._deny(reason)
            request_id = uuid.uuid4().hex
            self._request_id = request_id
            demand = LeaseDemand(
                1,
                self._policy.peak_ram_bytes,
                self._policy.peak_vram_bytes,
                self._policy.gpu_device_index,
            )
            try:
                if self._tree_mode:
                    assert isinstance(self._ledger, TreeHostInferenceLeaseLedger)
                    decision = self._ledger.try_acquire(request_id, demand, custody=custody)
                else:
                    assert isinstance(self._ledger, HostInferenceLeaseLedger)
                    decision = self._ledger.try_acquire(request_id, demand, worker_identity=worker)
            except Exception:
                return self._deny("lease_store_unavailable")
            if decision.status != "acquired" or decision.lease_id is None:
                if decision.status == "queued":
                    if not self._tree_mode:
                        assert isinstance(self._ledger, HostInferenceLeaseLedger)
                        self._ledger.cancel_pending(request_id)
                return self._deny(f"lease_{decision.reason}")
            self._worker = worker
            self._custody = custody
            self._lease_id = decision.lease_id
            self._phase = "leased"
            self._reason = "admitted"
            self._watchdog = threading.Thread(target=self._maintain, daemon=True)
            self._watchdog.start()
            # The pre-lease sample cannot authorize a delayed model load.
            reason = self._telemetry_denial(cold=True)
            if reason:
                return self._deny(reason)
            return True

    def call_admission(self, pid: int, created_at: float) -> bool:
        """Fail closed immediately before each rank; never close reentrantly."""

        with self._lock:
            if self._phase != "leased" or self._worker is None or self._lease_id is None:
                return False
            if self._worker.pid != pid or self._worker.started_at != created_at:
                return self._deny("worker_identity_mismatch")
            if self._tree_mode and (self._custody is None or not self._custody.is_open()):
                return self._deny("tree_custody_unverifiable")
            try:
                worker_state = self._worker_state_reader(self._worker)
            except Exception:
                worker_state = "unknown"
            if worker_state != "alive":
                return self._deny("worker_identity_unverifiable")
            if not self._renew(self._lease_id):
                return self._deny("lease_renewal_failed")
            reason = self._telemetry_denial(cold=False, allow_recent_call_sample=True)
            return self._deny(reason) if reason else True

    def close(self) -> ManagedLayaStatus:
        """Request owned shutdown and report whether exit and release completed."""

        with self._lock:
            if self._phase == "closed":
                return self.status
            self._phase = "closing"
            self._reason = "close_requested"
            self._wake.set()
        self._perform_close()
        return self.status

    def _deny(self, reason: str) -> bool:
        self._phase = "closing"
        self._reason = reason
        self._last_call_telemetry = None
        self._wake.set()
        return False

    def _telemetry_denial(
        self, *, cold: bool, allow_recent_call_sample: bool = False
    ) -> str | None:
        try:
            sample = self._last_call_telemetry if allow_recent_call_sample else None
            now = self._clock()
            if sample is not None:
                cached_age_ms = (now - sample.source_window_started_at).total_seconds() * 1000
                if cached_age_ms < 0:
                    return "telemetry_stale"
                if cached_age_ms > self._call_telemetry_reuse_ms:
                    sample = None
            if sample is None:
                sample = self._telemetry_reader(self._policy.gpu_device_index)
                now = self._clock()
            # RAM is sampled at the beginning; GPU sampling may occur anywhere
            # inside the source window. Age the oldest possible measurement.
            age_ms = (now - sample.source_window_started_at).total_seconds() * 1000
        except Exception:
            return "telemetry_unavailable"
        if not 0 <= age_ms <= self._policy.max_telemetry_age_ms:
            return "telemetry_stale"
        if (
            sample.gpu_device_index != self._policy.gpu_device_index
            or sample.gpu_uuid != self._policy.gpu_uuid
        ):
            return "gpu_mismatch"
        required_ram = self._policy.ram_reserve_bytes + (self._policy.peak_ram_bytes if cold else 0)
        required_vram = self._policy.target_vram_reserve_bytes + (
            self._policy.peak_vram_bytes if cold else 0
        )
        if sample.available_ram_bytes < required_ram:
            return "ram_headroom"
        if sample.free_vram_bytes < required_vram:
            return "vram_headroom"
        if allow_recent_call_sample:
            # The call still checks exact worker identity, lease renewal, and
            # limits. Reuse only an already-valid reading with an extra full
            # model-peak margin, and never extend its original source age.
            self._last_call_telemetry = (
                sample
                if self._call_telemetry_reuse_ms
                and sample.available_ram_bytes >= required_ram + self._policy.peak_ram_bytes
                and sample.free_vram_bytes >= required_vram + self._policy.peak_vram_bytes
                else None
            )
        return None

    def _maintain(self) -> None:
        """Renew even during idle and retire on lost lease or target headroom."""

        while True:
            self._wake.wait(timeout=self._policy.renew_interval_seconds)
            self._wake.clear()
            with self._lock:
                if self._phase == "closed":
                    return
                worker, lease_id, phase = self._worker, self._lease_id, self._phase
            if worker is None or lease_id is None:
                return
            if self._reconcile_exit(worker, lease_id):
                return
            if phase in ("leased", "closing"):
                if not self._renew(lease_id) and phase == "leased":
                    with self._lock:
                        self._deny_if_current(worker, lease_id, "lease_renewal_failed")
                elif phase == "leased":
                    reason = self._telemetry_denial(cold=False)
                    if reason:
                        with self._lock:
                            self._deny_if_current(worker, lease_id, reason)
            with self._lock:
                if self._phase == "closing":
                    self._schedule_close()

    def _schedule_close(self) -> None:
        if self._closer is None or not self._closer.is_alive():
            self._closer = threading.Thread(target=self._perform_close, daemon=True)
            self._closer.start()

    def _deny_if_current(self, worker: WorkerIdentity, lease_id: str, reason: str) -> None:
        if self._phase == "leased" and self._worker == worker and self._lease_id == lease_id:
            self._deny(reason)

    def _renew(self, lease_id: str) -> bool:
        try:
            return self._ledger.renew(lease_id)
        except Exception:
            return False

    def _perform_close(self) -> None:
        with self._close_lock:
            runtime = self._runtime
            exit_verified = runtime is None
            if runtime is not None:
                try:
                    runtime.close()
                    exit_verified = True
                except Exception:
                    # An unverified exit keeps the lease (or its quarantine).
                    pass
            with self._lock:
                worker, lease_id = self._worker, self._lease_id
            if worker is not None and lease_id is not None:
                self._reconcile_exit(worker, lease_id)
            else:
                with self._lock:
                    if exit_verified:
                        if self._tree_mode and runtime is not None:
                            release_custody = getattr(runtime, "release_tree_custody", None)
                            try:
                                if not callable(release_custody):
                                    raise RuntimeError("Job release unavailable")
                                release_custody()
                            except Exception:
                                self._phase = "quarantined"
                                self._reason = "tree_custody_release_unverified_no_lease"
                                return
                        self._phase = "closed"
                        prior_reason = self._reason
                        self._reason = (
                            "worker_exit_verified_no_lease"
                            if prior_reason == "close_requested"
                            else f"{prior_reason};worker_exit_verified_no_lease"
                        )
                        self._wake.set()
                    else:
                        self._phase = "quarantined"
                        self._reason = "worker_exit_unverified_no_lease"

    def _reconcile_exit(self, worker: WorkerIdentity, lease_id: str) -> bool:
        if self._tree_mode:
            custody = self._custody
            if custody is None or not custody.is_open():
                with self._lock:
                    if self._worker == worker and self._lease_id == lease_id:
                        self._phase = "quarantined"
                        self._reason = "tree_custody_unverifiable"
                return False
            if not custody.is_empty():
                return False
            try:
                assert isinstance(self._ledger, TreeHostInferenceLeaseLedger)
                released = self._ledger.release(lease_id, custody=custody)
            except Exception:
                released = False
            with self._lock:
                if self._worker != worker or self._lease_id != lease_id:
                    return False
                if not released:
                    self._phase = "quarantined"
                    self._reason = "tree_lease_release_unconfirmed"
                    return False
                runtime = self._runtime
                self._lease_id = None
                self._custody = None
            release_custody = getattr(runtime, "release_tree_custody", None)
            try:
                if not callable(release_custody):
                    raise RuntimeError("Job release unavailable")
                release_custody()
            except Exception:
                with self._lock:
                    self._phase = "quarantined"
                    self._reason = "tree_custody_handle_close_unverified;lease_released"
                return False
            with self._lock:
                self._phase = "closed"
                self._reason = "job_tree_empty_lease_released"
                self._wake.set()
            return True
        try:
            exited = self._worker_state_reader(worker) == "exited"
        except Exception:
            exited = False
        if not exited:
            return False
        try:
            assert isinstance(self._ledger, HostInferenceLeaseLedger)
            release = self._ledger.reconcile_release(lease_id, worker)
            released = release.status in (
                "released_now",
                "verified_exited_prior_reclaim",
            )
        except Exception:
            released = False
        with self._lock:
            if self._worker != worker or self._lease_id != lease_id:
                return False
            if released:
                self._lease_id = None
                self._phase = "closed"
                prior_reason = self._reason
                self._reason = (
                    "worker_exited_lease_released"
                    if prior_reason in ("admitted", "close_requested")
                    else f"{prior_reason};worker_exited_lease_released"
                )
            else:
                self._phase = "quarantined"
                self._reason = "worker_exited_lease_release_unconfirmed"
            if released:
                self._wake.set()
        return released
