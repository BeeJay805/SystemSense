"""Bounded Plug and Play device observations."""

import importlib
from collections.abc import Iterable
from typing import Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class DeviceObservation(FrozenModel):
    instance_id: str = Field(min_length=1, max_length=4096)
    name: str = Field(min_length=1, max_length=1024)
    pnp_class: str | None = Field(default=None, max_length=255)
    status: str | None = Field(default=None, max_length=255)
    problem_code: int | None = Field(default=None, ge=0)
    present: bool


def collect_devices(
    observations: tuple[DeviceObservation, ...],
    *,
    max_records: int = 256,
) -> tuple[DeviceObservation, ...]:
    if not 1 <= max_records <= 1024:
        raise ValueError("max_records must be between 1 and 1024")
    return observations[:max_records]


class _WmiService(Protocol):
    def ExecQuery(self, query: str) -> Iterable[object]: ...


class _WmiClient(Protocol):
    def GetObject(self, path: str) -> _WmiService: ...


class _WmiDevice(Protocol):
    DeviceID: str | None
    Name: str | None
    PNPClass: str | None
    Status: str | None
    ConfigManagerErrorCode: int | None


class WmiDeviceBackend:
    def devices(self, *, max_records: int = 1024) -> tuple[DeviceObservation, ...]:
        client = cast("_WmiClient", importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT DeviceID,Name,PNPClass,Status,ConfigManagerErrorCode FROM Win32_PnPEntity"
        )
        observations: list[DeviceObservation] = []
        for raw_row in rows:
            row = cast("_WmiDevice", raw_row)
            if not row.DeviceID:
                continue
            observations.append(
                DeviceObservation(
                    instance_id=str(row.DeviceID),
                    name=str(row.Name or row.DeviceID),
                    pnp_class=None if row.PNPClass is None else str(row.PNPClass),
                    status=None if row.Status is None else str(row.Status),
                    problem_code=(
                        None
                        if row.ConfigManagerErrorCode is None
                        else int(row.ConfigManagerErrorCode)
                    ),
                    present=True,
                )
            )
            if len(observations) == max_records:
                break
        return tuple(observations)
