"""Bounded IPv4 route table observations."""

import ctypes
import importlib
import ipaddress
import os
import sys
from collections.abc import Callable, Iterable
from typing import Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class RouteObservation(FrozenModel):
    destination: str = Field(min_length=1, max_length=255)
    prefix_length: int = Field(ge=0, le=128)
    next_hop: str = Field(min_length=1, max_length=255)
    interface_index: int = Field(ge=0)
    metric: int = Field(ge=0)


class _MibIpForwardRow(ctypes.Structure):
    """Microsoft's 14-DWORD MIB_IPFORWARDROW (Iphlpapi.h)."""

    _fields_ = [
        (name, ctypes.c_uint32)
        for name in (
            "dwForwardDest",
            "dwForwardMask",
            "dwForwardPolicy",
            "dwForwardNextHop",
            "dwForwardIfIndex",
            "dwForwardType",
            "dwForwardProto",
            "dwForwardAge",
            "dwForwardNextHopAS",
            "dwForwardMetric1",
            "dwForwardMetric2",
            "dwForwardMetric3",
            "dwForwardMetric4",
            "dwForwardMetric5",
        )
    ]


def _load_get_best_route() -> object:
    if os.name != "nt":
        raise NotImplementedError("GetBestRoute requires Windows")
    try:
        function = ctypes.WinDLL("iphlpapi", use_last_error=True).GetBestRoute
    except AttributeError as error:
        raise NotImplementedError("GetBestRoute export is unavailable") from error
    function.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(_MibIpForwardRow),
    ]
    function.restype = ctypes.c_uint32
    return function


class WindowsBestRouteBackend:
    """Read the system-selected IPv4 route without transmitting traffic."""

    def route_to(self, destination: str) -> RouteObservation:
        address = ipaddress.IPv4Address(destination)
        result = _MibIpForwardRow()
        query = cast(Callable[[int, int, object], int], _load_get_best_route())
        # A zero source asks Windows for the host-wide best route. Supplying the
        # Wi-Fi interface here would incorrectly hide a VPN/Ethernet selection.
        status = query(int.from_bytes(address.packed, sys.byteorder), 0, ctypes.byref(result))
        if status:
            raise OSError(status, "GetBestRoute failed")
        route_address = ipaddress.IPv4Address(result.dwForwardDest.to_bytes(4, sys.byteorder))
        mask = ipaddress.IPv4Address(result.dwForwardMask.to_bytes(4, sys.byteorder))
        next_hop = ipaddress.IPv4Address(result.dwForwardNextHop.to_bytes(4, sys.byteorder))
        network = ipaddress.IPv4Network(f"{route_address}/{mask}", strict=False)
        if result.dwForwardIfIndex == 0 or address not in network:
            raise ValueError("GetBestRoute returned an invalid destination or interface")
        return RouteObservation(
            destination=str(network.network_address),
            prefix_length=network.prefixlen,
            next_hop=str(next_hop),
            interface_index=result.dwForwardIfIndex,
            metric=result.dwForwardMetric1,
        )


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
    def __init__(self) -> None:
        self.omitted_route_count = 0

    def routes(self, *, max_records: int = 1024) -> tuple[RouteObservation, ...]:
        self.omitted_route_count = 0
        client = cast("_WmiClient", importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT Destination,Mask,NextHop,InterfaceIndex,Metric1 FROM Win32_IP4RouteTable"
        )
        observations: list[RouteObservation] = []
        for row_number, raw_row in enumerate(rows):
            if row_number >= max_records:
                self.omitted_route_count += 1
                break
            row = cast("_WmiRoute", raw_row)
            if not row.Destination or not row.NextHop:
                self.omitted_route_count += 1
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
        return tuple(observations)


def _prefix_length(mask: str | None) -> int:
    if not mask:
        return 0
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError):
        return 0
