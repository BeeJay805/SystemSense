"""Display adapter and GPU driver observations."""

import importlib
import shutil
from collections.abc import Iterable
from typing import Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class GpuObservation(FrozenModel):
    name: str = Field(min_length=1, max_length=1024)
    vendor: str | None = Field(default=None, max_length=255)
    driver_version: str | None = Field(default=None, max_length=255)
    adapter_ram_bytes: int | None = Field(default=None, ge=0)
    vendor_utility_available: bool


def collect_gpus(
    observations: tuple[GpuObservation, ...],
    *,
    max_records: int = 8,
) -> tuple[GpuObservation, ...]:
    if not 1 <= max_records <= 32:
        raise ValueError("max_records must be between 1 and 32")
    return observations[:max_records]


class _WmiService(Protocol):
    def ExecQuery(self, query: str) -> Iterable[object]: ...


class _WmiClient(Protocol):
    def GetObject(self, path: str) -> _WmiService: ...


class _WmiGpu(Protocol):
    Name: str | None
    AdapterCompatibility: str | None
    DriverVersion: str | None
    AdapterRAM: int | None


class WmiGpuBackend:
    def gpus(self, *, max_records: int = 32) -> tuple[GpuObservation, ...]:
        client = cast("_WmiClient", importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT Name,AdapterCompatibility,DriverVersion,AdapterRAM FROM Win32_VideoController"
        )
        observations: list[GpuObservation] = []
        for raw_row in rows:
            row = cast("_WmiGpu", raw_row)
            if not row.Name:
                continue
            vendor = None if row.AdapterCompatibility is None else str(row.AdapterCompatibility)
            observations.append(
                GpuObservation(
                    name=str(row.Name),
                    vendor=vendor,
                    driver_version=(None if row.DriverVersion is None else str(row.DriverVersion)),
                    adapter_ram_bytes=(
                        None if row.AdapterRAM is None else max(0, int(row.AdapterRAM))
                    ),
                    vendor_utility_available=_vendor_utility_available(vendor),
                )
            )
            if len(observations) == max_records:
                break
        return tuple(observations)


def _vendor_utility_available(vendor: str | None) -> bool:
    normalized = (vendor or "").casefold()
    if "nvidia" in normalized:
        return shutil.which("nvidia-smi.exe") is not None
    if "amd" in normalized or "advanced micro" in normalized:
        return shutil.which("amd-smi.exe") is not None
    return False
