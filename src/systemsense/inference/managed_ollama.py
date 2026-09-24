"""Lifetime admission for one owned, loopback-only deep reasoning service.

Construction is inert. The caller must keep the controller alive for the whole
service lifetime and invoke call_admission immediately before each model call.
An uncertain Job exit leaves the v4 lease occupied for quarantine.
"""

from __future__ import annotations

import math
import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol

from systemsense.domain.time import utc_now
from systemsense.inference.host_lease import LeaseDemand, WorkerIdentity, capture_worker_identity
from systemsense.inference.host_telemetry import HostTelemetryReading, read_host_telemetry
from systemsense.inference.owned_ollama import OwnedOllamaConfig, OwnedOllamaService
from systemsense.inference.tree_host_lease import TreeCustody, TreeHostInferenceLeaseLedger

GIB = 1024**3
_GPU_UUID = re.compile(
    r"GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
Phase = Literal[
    "configured", "starting_unloaded", "leased", "ready", "closing", "closed", "quarantined"
]


@dataclass(frozen=True, slots=True)
class ManagedOllamaPolicy:
    """Explicit peak including residency and call workspace, plus free headroom.

    These are qualification inputs, not measurements made by this controller.
    No Laya reserve floor is inherited or relaxed here.
    """

    gpu_device_index: int
    gpu_uuid: str
    peak_ram_bytes: int
    peak_vram_bytes: int
    ram_reserve_bytes: int
    vram_reserve_bytes: int
    max_telemetry_age_ms: int = 2000
    renew_interval_seconds: float = 1.0

    def __post_init__(self) -> None:
        if not 0 <= self.gpu_device_index <= 15 or not _GPU_UUID.fullmatch(self.gpu_uuid):
            raise ValueError("managed deep admission requires a pinned GPU UUID and index")
        if any(
            isinstance(value, bool) or not 0 < value <= 512 * GIB
            for value in (
                self.peak_ram_bytes,
                self.peak_vram_bytes,
                self.ram_reserve_bytes,
                self.vram_reserve_bytes,
            )
        ):
            raise ValueError("deep peaks and reserves must be explicit positive bounded bytes")
        if not 100 <= self.max_telemetry_age_ms <= 2000:
            raise ValueError("telemetry age must be between 100 and 2000 ms")
        if not math.isfinite(self.renew_interval_seconds) or not (
            0.01 <= self.renew_interval_seconds <= 30
        ):
            raise ValueError("lease renewal interval must be finite and bounded")


@dataclass(frozen=True, slots=True)
class ManagedOllamaStatus:
    phase: Phase
    reason: str
    worker_pid: int | None
    lease_id: str | None
    model_digest: str


class _Service(Protocol):
    @property
    def ready(self) -> bool: ...

    def start(self) -> None: ...

    def owns_ready_endpoint(self) -> bool: ...

    def close(self) -> Any: ...


def _read_telemetry(index: int) -> HostTelemetryReading:
    return read_host_telemetry(gpu_device_index=index)


def _new_service(
    config: OwnedOllamaConfig,
    admit: Callable[[Any, Any], bool],
    finalize: Callable[[bool, Any | None, Any | None], bool],
) -> _Service:
    return OwnedOllamaService(config, admit=admit, finalize_admission=finalize)


class ManagedOllamaAdmission:
    """One-shot admission and cleanup owner; no service work occurs in init."""

    def __init__(
        self,
        config: OwnedOllamaConfig,
        policy: ManagedOllamaPolicy,
        ledger: TreeHostInferenceLeaseLedger,
        *,
        telemetry_reader: Callable[[int], HostTelemetryReading] = _read_telemetry,
        identity_reader: Callable[[int], WorkerIdentity] = capture_worker_identity,
        service_factory: Callable[
            [
                OwnedOllamaConfig,
                Callable[[Any, Any], bool],
                Callable[[bool, Any | None, Any | None], bool],
            ],
            _Service,
        ] = _new_service,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if policy.renew_interval_seconds * 3 >= ledger.lease_ttl_seconds:
            raise ValueError("lease TTL must exceed three renewal intervals")
        if (
            config.startup_timeout_seconds + policy.renew_interval_seconds * 3
            >= ledger.lease_ttl_seconds
        ):
            raise ValueError("lease TTL must cover bounded service startup and renewal")
        self._config = config
        self._policy = policy
        self._ledger = ledger
        self._telemetry_reader = telemetry_reader
        self._identity_reader = identity_reader
        self._clock = clock
        self._state_lock = threading.RLock()
        self._operation_lock = threading.RLock()
        self._wake = threading.Event()
        self._watchdog: threading.Thread | None = None
        self._phase: Phase = "configured"
        self._reason = "not_started"
        self._worker: WorkerIdentity | None = None
        self._custody: TreeCustody | None = None
        self._lease_id: str | None = None
        self._service = service_factory(config, self._admit, self._finalize)

    @property
    def status(self) -> ManagedOllamaStatus:
        with self._state_lock:
            return ManagedOllamaStatus(
                self._phase,
                self._reason,
                self._worker.pid if self._worker is not None else None,
                self._lease_id,
                self._config.model_digest,
            )

    def start(self) -> ManagedOllamaStatus:
        with self._operation_lock:
            with self._state_lock:
                if self._phase != "configured":
                    return self.status
                self._phase = "starting_unloaded"
                self._reason = "starting"
            try:
                self._service.start()
            except Exception as error:
                with self._state_lock:
                    if self._reason == "starting":
                        self._reason = f"startup_{type(error).__name__}"
                self.close()
                return self.status
            admitted = self.status.phase == "leased"
            if admitted and self._service.owns_ready_endpoint():
                with self._state_lock:
                    if self.status.phase == "leased":
                        self._phase = "ready"
                        self._reason = "ready"
                        return self.status
            with self._state_lock:
                if self._reason == "starting":
                    self._reason = "service_readiness_unverified"
            self.close()
            return self.status

    def call_admission(self) -> bool:
        """The managed client must call this immediately before every model load/call."""
        with self._state_lock:
            worker, custody, lease_id = self._worker, self._custody, self._lease_id
            if self._phase != "ready" or worker is None or custody is None or lease_id is None:
                return False
            try:
                if (
                    not self._service.owns_ready_endpoint()
                    or not custody.is_open()
                    or custody.is_empty()
                    or self._identity_reader(worker.pid) != worker
                ):
                    return self._deny("service_custody_unverifiable")
                if not self._ledger.renew(lease_id):
                    return self._deny("lease_renewal_failed")
            except Exception:
                return self._deny("service_custody_unverifiable")
            reason = self._telemetry_denial(cold=False)
            return self._deny(reason) if reason else True

    def close(self) -> ManagedOllamaStatus:
        with self._operation_lock:
            with self._state_lock:
                if self._phase in ("closed", "quarantined"):
                    return self.status
                self._phase = "closing"
                if self._reason in ("not_started", "ready", "starting", "admitted"):
                    self._reason = "close_requested"
                self._wake.set()
            try:
                result = self._service.close()
                if not result.admission_finalized:
                    with self._state_lock:
                        self._phase = "quarantined"
                        self._reason = "admission_finalization_unverified"
            except Exception:
                with self._state_lock:
                    self._phase = "quarantined"
                    self._reason = "service_close_unverified"
            return self.status

    def _admit(self, process: Any, job: Any) -> bool:
        with self._state_lock:
            if self._phase != "starting_unloaded":
                return False
            try:
                worker = self._identity_reader(process.pid)
                if worker.pid != process.pid:
                    return self._deny("worker_identity_mismatch")
                custody = TreeCustody.create(job, process, worker)
            except Exception:
                return self._deny("tree_custody_unverifiable")
            reason = self._telemetry_denial(cold=True)
            if reason:
                return self._deny(reason)
            request_id = uuid.uuid4().hex
            demand = LeaseDemand(
                1,
                self._policy.peak_ram_bytes,
                self._policy.peak_vram_bytes,
                self._policy.gpu_device_index,
            )
            try:
                decision = self._ledger.try_acquire(request_id, demand, custody=custody)
            except Exception:
                return self._deny("lease_store_unavailable")
            if decision.status != "acquired" or decision.lease_id is None:
                return self._deny(f"lease_{decision.reason}")
            self._worker = worker
            self._custody = custody
            self._lease_id = decision.lease_id
            self._phase = "leased"
            self._reason = "admitted"
            reason = self._telemetry_denial(cold=True)
            if reason:
                return self._deny(reason)
            self._watchdog = threading.Thread(
                target=self._maintain, name="managed-ollama-lease", daemon=True
            )
            self._watchdog.start()
            return True

    def _finalize(self, verified: bool, _job: Any | None, _process: Any | None) -> bool:
        """OwnedOllamaService calls this while its Job handle remains open."""
        with self._state_lock:
            lease_id, custody = self._lease_id, self._custody
            if not verified:
                self._phase = "quarantined"
                self._reason = "owned_tree_exit_unverified"
                self._wake.set()
                return True  # v4 retains the lease, then quarantines it on expiry.
            if lease_id is not None:
                if custody is None:
                    self._phase = "quarantined"
                    self._reason = "tree_custody_unavailable"
                    return False
                try:
                    released = self._ledger.release(lease_id, custody=custody)
                except Exception:
                    released = False
                if not released:
                    self._phase = "quarantined"
                    self._reason = "tree_lease_release_unconfirmed"
                    return False
                self._lease_id = None
                self._custody = None
            self._phase = "closed"
            if self._reason in ("starting", "admitted", "ready", "close_requested"):
                self._reason = "owned_tree_exited"
            self._wake.set()
            return True

    def _deny(self, reason: str) -> bool:
        self._phase = "closing"
        self._reason = reason
        self._wake.set()
        return False

    def _telemetry_denial(self, *, cold: bool) -> str | None:
        try:
            sample = self._telemetry_reader(self._policy.gpu_device_index)
            now = self._clock()
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
        required_vram = self._policy.vram_reserve_bytes + (
            self._policy.peak_vram_bytes if cold else 0
        )
        if sample.available_ram_bytes < required_ram:
            return "ram_headroom"
        if sample.free_vram_bytes < required_vram:
            return "vram_headroom"
        return None

    def _maintain(self) -> None:
        while True:
            self._wake.wait(timeout=self._policy.renew_interval_seconds)
            with self._state_lock:
                self._wake.clear()
                lease_id, worker, custody, phase = (
                    self._lease_id,
                    self._worker,
                    self._custody,
                    self._phase,
                )
                if phase in ("closed", "quarantined"):
                    return
                if phase in ("leased", "ready") and lease_id is not None:
                    try:
                        healthy = (
                            worker is not None
                            and custody is not None
                            and custody.is_open()
                            and not custody.is_empty()
                            and self._identity_reader(worker.pid) == worker
                            and self._ledger.renew(lease_id)
                        )
                    except Exception:
                        healthy = False
                    if not healthy:
                        self._deny("lease_or_tree_lost")
                    elif phase == "ready":
                        reason = self._telemetry_denial(cold=False)
                        if reason:
                            self._deny(reason)
                should_close = self._phase == "closing"
            if should_close:
                self.close()
                return
