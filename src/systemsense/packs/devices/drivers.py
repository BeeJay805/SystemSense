"""Signed PnP driver identity observations."""

import importlib
from collections.abc import Iterable
from typing import Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class DriverObservation(FrozenModel):
    device_id: str = Field(min_length=1, max_length=4096)
    name: str = Field(min_length=1, max_length=1024)
    version: str | None = Field(default=None, max_length=255)
    provider: str | None = Field(default=None, max_length=255)
    driver_date: str | None = Field(default=None, max_length=255)
    inf_name: str | None = Field(default=None, max_length=255)


def collect_drivers(
    observations: tuple[DriverObservation, ...],
    *,
    max_records: int = 256,
) -> tuple[DriverObservation, ...]:
    if not 1 <= max_records <= 1024:
        raise ValueError("max_records must be between 1 and 1024")
    return observations[:max_records]


class _WmiService(Protocol):
    def ExecQuery(self, query: str) -> Iterable[object]: ...


class _WmiClient(Protocol):
    def GetObject(self, path: str) -> _WmiService: ...


class _WmiDriver(Protocol):
    DeviceID: str | None
    DeviceName: str | None
    DriverVersion: str | None
    DriverProviderName: str | None
    DriverDate: str | None
    InfName: str | None


class WmiDriverBackend:
    def drivers(self, *, max_records: int = 1024) -> tuple[DriverObservation, ...]:
        client = cast("_WmiClient", importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT DeviceID,DeviceName,DriverVersion,DriverProviderName,"
            "DriverDate,InfName FROM Win32_PnPSignedDriver"
        )
        observations: list[DriverObservation] = []
        for raw_row in rows:
            row = cast("_WmiDriver", raw_row)
            if not row.DeviceID:
                continue
            observations.append(
                DriverObservation(
                    device_id=str(row.DeviceID),
                    name=str(row.DeviceName or row.DeviceID),
                    version=None if row.DriverVersion is None else str(row.DriverVersion),
                    provider=(
                        None if row.DriverProviderName is None else str(row.DriverProviderName)
                    ),
                    driver_date=None if row.DriverDate is None else str(row.DriverDate),
                    inf_name=None if row.InfName is None else str(row.InfName),
                )
            )
            if len(observations) == max_records:
                break
        return tuple(observations)
