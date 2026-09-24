"""In-process, fail-closed host resource admission for replaceable local brains.

This policy accepts trusted, fresh host telemetry and conservative per-model peak
footprints. It reserves capacity atomically inside one process. It never starts,
stops, unloads, or evicts any model or unrelated process. A later host-wide
lease and measured footprint validation are required before production use.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime

GIB = 1024**3
_MAX_MEMORY = 512 * GIB
BrainRole = Literal["fast", "deep"]
AdmissionMode = Literal[
    "dual_local", "fast_local_only", "deep_local_only", "deterministic_fallback"
]


class LocalBrainFootprint(FrozenModel):
    """Incremental *peak* load and per-investigation memory, not artifact size."""

    role: BrainRole
    model_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9_.:-]+$")
    device: Literal["cpu", "cuda"]
    gpu_device_index: int | None = Field(default=None, ge=0, le=15)
    resident: bool
    cold_ram_bytes: int = Field(ge=0, le=_MAX_MEMORY)
    cold_vram_bytes: int = Field(ge=0, le=_MAX_MEMORY)
    session_ram_bytes: int = Field(gt=0, le=_MAX_MEMORY)
    session_vram_bytes: int = Field(ge=0, le=_MAX_MEMORY)
    footprint_origin: Literal["measured", "conservative_config"]

    @model_validator(mode="after")
    def validate_placement(self) -> LocalBrainFootprint:
        if not self.resident and self.cold_ram_bytes == 0:
            raise ValueError("cold model requires a positive RAM peak estimate")
        if self.device == "cpu" and (
            self.gpu_device_index is not None or self.cold_vram_bytes or self.session_vram_bytes
        ):
            raise ValueError("CPU placement cannot reserve VRAM")
        if self.device == "cuda" and (
            self.gpu_device_index is None
            or (self.resident and self.session_vram_bytes == 0)
            or (not self.resident and self.cold_vram_bytes == 0)
        ):
            raise ValueError("CUDA placement requires a device and positive VRAM peaks")
        return self

    @property
    def incremental_ram_bytes(self) -> int:
        return self.session_ram_bytes + (0 if self.resident else self.cold_ram_bytes)

    @property
    def incremental_vram_bytes(self) -> int:
        return self.session_vram_bytes + (0 if self.resident else self.cold_vram_bytes)


class HostResourceSnapshot(FrozenModel):
    """Trusted single-host telemetry; free memory already reflects other workloads."""

    observed_at: UtcDateTime
    available_ram_bytes: int = Field(ge=0, le=_MAX_MEMORY)
    free_vram_bytes: int | None = Field(default=None, ge=0, le=_MAX_MEMORY)
    gpu_device_index: int | None = Field(default=None, ge=0, le=15)
    active_sessions: int = Field(ge=0, le=1024)
    active_fast_calls: int = Field(ge=0, le=1024)
    active_deep_calls: int = Field(ge=0, le=1024)


class HostAdmissionPolicy(FrozenModel):
    ram_reserve_bytes: int = Field(default=4 * GIB, ge=GIB, le=64 * GIB)
    vram_reserve_bytes: int = Field(default=2 * GIB, ge=GIB, le=32 * GIB)
    max_sessions: int = Field(default=1, ge=1, le=16)
    max_fast_calls: int = Field(default=1, ge=1, le=16)
    max_deep_calls: int = Field(default=1, ge=1, le=16)
    max_snapshot_age_ms: int = Field(default=2000, ge=100, le=10_000)
    allow_degradation: bool = True
    prefer_deep_when_constrained: bool = True


@dataclass(frozen=True, slots=True)
class HostAdmissionOutcome:
    mode: AdmissionMode
    admitted_roles: tuple[BrainRole, ...]
    required_ram_bytes: int
    required_vram_bytes: int
    reservation_id: str | None
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Reservation:
    roles: tuple[BrainRole, ...]
    ram_bytes: int
    vram_bytes: int


class HostResourceAdmission:
    """Atomic reservations for one coordinator process, with explicit release."""

    def __init__(self, policy: HostAdmissionPolicy) -> None:
        self._policy = policy
        self._lock = threading.Lock()
        self._reservations: dict[str, _Reservation] = {}

    @property
    def active_reservations(self) -> int:
        with self._lock:
            return len(self._reservations)

    def release(self, reservation_id: str) -> None:
        with self._lock:
            if self._reservations.pop(reservation_id, None) is None:
                raise ValueError("host resource reservation does not exist")

    def try_admit(
        self,
        snapshot: HostResourceSnapshot,
        *,
        fast: LocalBrainFootprint | None,
        deep: LocalBrainFootprint | None,
        now: datetime,
    ) -> HostAdmissionOutcome:
        """Choose the fullest safe local mode, or visible deterministic fallback.

        Callers must hold the returned reservation until the session is closed.
        Do not reuse this in-memory ledger across processes as a global lease.
        """

        if fast is not None and fast.role != "fast":
            raise ValueError("fast slot requires a fast-brain footprint")
        if deep is not None and deep.role != "deep":
            raise ValueError("deep slot requires a deep-brain footprint")
        if now.utcoffset() is None:
            return self._fallback(("resource_clock_invalid",))
        age_ms = (now - snapshot.observed_at).total_seconds() * 1000
        if not 0 <= age_ms <= self._policy.max_snapshot_age_ms:
            return self._fallback(("resource_snapshot_stale_or_future",))
        with self._lock:
            reservations = tuple(self._reservations.values())
            if snapshot.active_sessions + len(reservations) >= self._policy.max_sessions:
                return self._fallback(("session_cap",))
            available_ram = (
                snapshot.available_ram_bytes
                - self._policy.ram_reserve_bytes
                - sum(item.ram_bytes for item in reservations)
            )
            available_vram = (
                None
                if snapshot.free_vram_bytes is None
                else snapshot.free_vram_bytes
                - self._policy.vram_reserve_bytes
                - sum(item.vram_bytes for item in reservations)
            )
            active_fast = snapshot.active_fast_calls + sum(
                "fast" in item.roles for item in reservations
            )
            active_deep = snapshot.active_deep_calls + sum(
                "deep" in item.roles for item in reservations
            )

            def failed(label: str, brains: tuple[LocalBrainFootprint, ...]) -> tuple[str, ...]:
                reasons: list[str] = []
                ram = sum(item.incremental_ram_bytes for item in brains)
                vram = sum(item.incremental_vram_bytes for item in brains)
                if (
                    "fast" in (item.role for item in brains)
                    and active_fast >= self._policy.max_fast_calls
                ):
                    reasons.append("fast_concurrency_cap")
                if (
                    "deep" in (item.role for item in brains)
                    and active_deep >= self._policy.max_deep_calls
                ):
                    reasons.append("deep_concurrency_cap")
                if ram > available_ram:
                    reasons.append(f"{label}_ram_headroom")
                if vram:
                    if any(
                        item.device == "cuda" and item.gpu_device_index != snapshot.gpu_device_index
                        for item in brains
                    ):
                        reasons.append(f"{label}_gpu_device_mismatch")
                    elif available_vram is None:
                        reasons.append(f"{label}_vram_unknown")
                    elif vram > available_vram:
                        reasons.append(f"{label}_vram_headroom")
                return tuple(reasons)

            def reserve(
                mode: AdmissionMode,
                brains: tuple[LocalBrainFootprint, ...],
                reasons: tuple[str, ...],
            ) -> HostAdmissionOutcome:
                ram = sum(item.incremental_ram_bytes for item in brains)
                vram = sum(item.incremental_vram_bytes for item in brains)
                reservation_id = uuid.uuid4().hex
                roles = cast("tuple[BrainRole, ...]", tuple(item.role for item in brains))
                self._reservations[reservation_id] = _Reservation(roles, ram, vram)
                return HostAdmissionOutcome(mode, roles, ram, vram, reservation_id, reasons)

            if fast is not None and deep is not None:
                dual_failed = failed("dual", (fast, deep))
                if not dual_failed:
                    return reserve("dual_local", (fast, deep), ())
                if not self._policy.allow_degradation:
                    return self._fallback(
                        tuple(
                            dict.fromkeys(
                                (*dual_failed, *failed("fast", (fast,)), *failed("deep", (deep,)))
                            )
                        )
                    )
                options: tuple[tuple[str, LocalBrainFootprint], ...] = (
                    (("deep", deep), ("fast", fast))
                    if self._policy.prefer_deep_when_constrained
                    else (("fast", fast), ("deep", deep))
                )
                failures = list(dual_failed)
                for label, brain in options:
                    single_failed = failed(label, (brain,))
                    if not single_failed:
                        mode: AdmissionMode = (
                            "deep_local_only" if label == "deep" else "fast_local_only"
                        )
                        return reserve(mode, (brain,), tuple(dict.fromkeys(failures)))
                    failures.extend(single_failed)
                return self._fallback(tuple(dict.fromkeys(failures)))
            if fast is not None:
                fast_failed = failed("fast", (fast,))
                return (
                    self._fallback(fast_failed)
                    if fast_failed
                    else reserve("fast_local_only", (fast,), ())
                )
            if deep is not None:
                deep_failed = failed("deep", (deep,))
                return (
                    self._fallback(deep_failed)
                    if deep_failed
                    else reserve("deep_local_only", (deep,), ())
                )
            return self._fallback(("no_local_brain_configured",))

    @staticmethod
    def _fallback(reasons: tuple[str, ...]) -> HostAdmissionOutcome:
        return HostAdmissionOutcome("deterministic_fallback", (), 0, 0, None, reasons)
