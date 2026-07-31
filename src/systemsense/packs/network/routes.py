"""Bounded IPv4 route table observations."""

import importlib
import ipaddress
from collections.abc import Iterable
from typing import Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class RouteObservation(FrozenModel):
    destination: str = Field(min_length=1, max_length=255)
    prefix_length: int = Field(ge=0, le=128)
    next_hop: str = Field(min_length=1, max_length=255)
    interface_index: int = Field(ge=0)
    metric: int = Field(ge=0)


def collect_routes(
    observations: tuple[RouteObservation, ...],
    *,
    max_records: int = 256,
) -> tuple[RouteObservation, ...]:
    if not 1 <= max_records <= 1024:
        raise ValueError("max_records must be between 1 and 1024")
    return observations[:max_records]


class _WmiService(Protocol):
    def ExecQuery(self, query: str) -> Iterable[object]: ...


class _WmiClient(Protocol):
    def GetObject(self, path: str) -> _WmiService: ...


class _WmiRoute(Protocol):
    Destination: str | None
    Mask: str | None
    NextHop: str | None
    InterfaceIndex: int | None
    Metric1: int | None


class WmiRouteBackend:
    def routes(self, *, max_records: int = 1024) -> tuple[RouteObservation, ...]:
        client = cast("_WmiClient", importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT Destination,Mask,NextHop,InterfaceIndex,Metric1 FROM Win32_IP4RouteTable"
        )
        observations: list[RouteObservation] = []
        for raw_row in rows:
            row = cast("_WmiRoute", raw_row)
            if not row.Destination or not row.NextHop:
                continue
            observations.append(
                RouteObservation(
                    destination=str(row.Destination),
                    prefix_length=_prefix_length(row.Mask),
                    next_hop=str(row.NextHop),
                    interface_index=int(row.InterfaceIndex or 0),
                    metric=max(0, int(row.Metric1 or 0)),
                )
            )
            if len(observations) == max_records:
                break
        return tuple(observations)


def _prefix_length(mask: str | None) -> int:
    if not mask:
        return 0
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError):
        return 0
