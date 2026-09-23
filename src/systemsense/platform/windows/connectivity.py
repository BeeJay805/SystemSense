"""Bounded, passive Windows connectivity facts for staged fault isolation.

Only fixed local WLAN, WMI, registry, and Event Log sources are queried. No
network request, scan, route change, command, or caller-supplied query occurs.
"""

from __future__ import annotations

import ctypes
import importlib
import ipaddress
import os
import socket
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any, Literal, Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import EvidenceFact, FrozenModel
from systemsense.domain.ids import JsonValue, stable_source_id
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.packs.network.routes import RouteObservation
from systemsense.platform.windows.deep_collectors import ComponentStatus
from systemsense.platform.windows.eventlog import parse_event_xml

_WLAN_CHANNEL = "Microsoft-Windows-WLAN-AutoConfig/Operational"
_WLAN_EVENT_LIMIT = 64
_WLAN_FAILURE_LIMIT = 16
_WLAN_FAILURE_WINDOW = timedelta(hours=1)
_WLAN_MAX_NAME_LENGTH = 256


class WifiInterface(FrozenModel):
    interface_guid: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=256)
    association_state: str = Field(min_length=1, max_length=64)
    current_ssid: str | None = Field(default=None, max_length=128)
    signal_quality_percent: int | None = Field(default=None, ge=0, le=100)
    authentication_algorithm: int | None = Field(default=None, ge=0)
    security_enabled: bool | None = None
    one_x_enabled: bool | None = None
    details_status: ComponentStatus = ComponentStatus.AVAILABLE


class AdapterNetwork(FrozenModel):
    interface_index: int = Field(ge=0)
    description: str = Field(min_length=1, max_length=256)
    interface_guid: str | None = Field(default=None, max_length=64)
    ip_addresses: tuple[str, ...] = ()
    ip_addresses_complete: bool = True
    default_gateways: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()
    dns_servers_complete: bool = True
    dhcp_enabled: bool | None = None
    dhcp_server: str | None = Field(default=None, max_length=64)


class ProxySettings(FrozenModel):
    manual_enabled: bool | None = None
    manual_server: str | None = Field(default=None, max_length=1024)
    auto_configured: bool | None = None
    server_redacted: bool = False


class WlanFailure(FrozenModel):
    source_id: str = Field(pattern=r"^src_[0-9a-f]{64}$")
    observed_at: UtcDateTime
    event_id: int = Field(ge=0)
    interface_guid: str | None = Field(default=None, max_length=64)
    reason_code: int | None = Field(default=None, ge=0)


class WifiPath(FrozenModel):
    """Exact local joins between a WLAN interface and passive stage observations."""

    interface_guid: str = Field(min_length=1, max_length=64)
    association_state: str = Field(min_length=1, max_length=64)
    adapter_status: Literal["matched", "unmatched", "ambiguous", "incomplete", "unknown"]
    interface_index: int | None = Field(default=None, ge=0)
    address_status: Literal["present", "absent", "incomplete", "unknown"]
    ipv4_default_route_status: Literal["present", "absent", "incomplete", "unknown"]
    failure_status: Literal["recorded", "none_recorded", "incomplete", "unknown"]
    failure_count: int = Field(ge=0, le=_WLAN_FAILURE_LIMIT)


class ConnectivitySnapshot(FrozenModel):
    source_id: str = Field(pattern=r"^src_[0-9a-f]{64}$")
    captured_at: UtcDateTime
    wifi_observed_at: UtcDateTime
    wifi_status: ComponentStatus
    wifi_interfaces: tuple[WifiInterface, ...]
    wifi_paths: tuple[WifiPath, ...] = Field(default=(), max_length=16)
    omitted_wifi_path_count: int = Field(default=0, ge=0)
    wifi_interface_count: int | None = Field(default=None, ge=0)
    omitted_wifi_count: int = Field(ge=0)
    addresses_observed_at: UtcDateTime
    addresses_status: ComponentStatus
    adapters: tuple[AdapterNetwork, ...]
    adapter_count: int | None = Field(default=None, ge=0)
    omitted_adapter_count: int = Field(ge=0)
    routes_observed_at: UtcDateTime
    routes_status: ComponentStatus
    default_routes: tuple[RouteObservation, ...]
    route_count: int | None = Field(default=None, ge=0)
    omitted_route_count: int = Field(ge=0)
    proxy_observed_at: UtcDateTime
    proxy_status: ComponentStatus
    proxy: ProxySettings | None
    wlan_events_observed_at: UtcDateTime
    wlan_events_status: ComponentStatus
    recent_failures: tuple[WlanFailure, ...]
    failure_count: int | None = Field(default=None, ge=0)
    omitted_failure_count: int = Field(ge=0)
    status: ComponentStatus
    limitations: tuple[str, ...] = ()
    scope_notes: tuple[str, ...] = (
        "IP, gateway, DNS, and proxy settings are observed configuration, not reachability tests.",
        "WinINET proxy state does not establish WinHTTP or application-specific proxy state.",
        "The WLAN connection API does not expose a past authentication failure reason; "
        "only recent recorded WLAN failures can supply one.",
        "Only the latest 64 WLAN AutoConfig events are scanned; older failures may be missed, "
        "and a reason code is present only when the event records one.",
        "Wi-Fi path rows join local observations by exact interface GUID and route index; "
        "IPv4 default route status describes only the bounded local route-table view, "
        "not target-specific routing, reachability, or a cause.",
    )


def _canonical_guid(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return "{" + str(uuid.UUID(value.strip().strip("{}"))) + "}"
    except ValueError:
        return None


def correlate_wifi_paths(
    *,
    wifi_interfaces: tuple[WifiInterface, ...],
    wifi_status: ComponentStatus,
    adapters: tuple[AdapterNetwork, ...],
    addresses_status: ComponentStatus,
    omitted_adapter_count: int,
    default_routes: tuple[RouteObservation, ...],
    routes_status: ComponentStatus,
    omitted_route_count: int,
    recent_failures: tuple[WlanFailure, ...],
    wlan_events_status: ComponentStatus,
    omitted_failure_count: int,
) -> tuple[WifiPath, ...]:
    """Correlate fixed local sources; never infer an unmatched interface's route."""

    paths: list[WifiPath] = []
    for wifi in wifi_interfaces[:16]:
        guid = _canonical_guid(wifi.interface_guid)
        matches = tuple(
            adapter
            for adapter in adapters
            if guid is not None and _canonical_guid(adapter.interface_guid) == guid
        )
        if guid is None or wifi_status not in {ComponentStatus.AVAILABLE, ComponentStatus.PARTIAL}:
            adapter_status = "unknown"
        elif (
            len(matches) > 1
            or sum(_canonical_guid(item.interface_guid) == guid for item in wifi_interfaces) > 1
        ):
            adapter_status = "ambiguous"
        elif addresses_status not in {ComponentStatus.AVAILABLE, ComponentStatus.PARTIAL}:
            adapter_status = "unknown"
        elif omitted_adapter_count or any(
            _canonical_guid(item.interface_guid) is None for item in adapters
        ):
            adapter_status = "incomplete"
        elif len(matches) == 1:
            adapter_status = "matched"
        elif addresses_status is ComponentStatus.PARTIAL:
            adapter_status = "incomplete"
        else:
            # The fixed WMI view includes only IP-enabled adapters.
            adapter_status = "unmatched"
        adapter = next(iter(matches), None) if adapter_status == "matched" else None
        index = adapter.interface_index if adapter is not None else None
        if adapter is None:
            address_status = "unknown"
            route_status = "unknown"
        else:
            address_status = (
                "present"
                if adapter.ip_addresses
                else "absent"
                if adapter.ip_addresses_complete
                else "incomplete"
            )
            index_unique = (
                omitted_adapter_count == 0
                and sum(item.interface_index == index for item in adapters) == 1
            )
            if not index_unique or routes_status not in {
                ComponentStatus.AVAILABLE,
                ComponentStatus.PARTIAL,
            }:
                route_status = "unknown"
            elif any(route.interface_index == index for route in default_routes):
                route_status = "present"
            elif routes_status is ComponentStatus.PARTIAL or omitted_route_count:
                route_status = "incomplete"
            else:
                route_status = "absent"
        failures = tuple(
            failure
            for failure in recent_failures
            if guid is not None and _canonical_guid(failure.interface_guid) == guid
        )
        if failures:
            failure_status = "recorded"
        elif wlan_events_status not in {ComponentStatus.AVAILABLE, ComponentStatus.PARTIAL}:
            failure_status = "unknown"
        elif (
            wlan_events_status is ComponentStatus.PARTIAL
            or omitted_failure_count
            or any(_canonical_guid(item.interface_guid) is None for item in recent_failures)
        ):
            failure_status = "incomplete"
        else:
            failure_status = "none_recorded"
        paths.append(
            WifiPath(
                interface_guid=wifi.interface_guid,
                association_state=wifi.association_state,
                adapter_status=adapter_status,
                interface_index=index,
                address_status=address_status,
                ipv4_default_route_status=route_status,
                failure_status=failure_status,
                failure_count=len(failures),
            )
        )
    return tuple(paths)


def connectivity_preview(snapshot: ConnectivitySnapshot) -> dict[str, JsonValue]:
    """Keep every stage/time visible within one inference fact's 4 KiB budget.

    The full redacted snapshot is retained as a separate fact. Counts include
    locally omitted rows and rows withheld only from this preview, so an empty
    preview list can never be mistaken for a complete negative observation.
    """

    wifi_order = {"connected": 0, "authenticating": 1, "associating": 2}
    relevant_wifi = tuple(
        sorted(
            snapshot.wifi_interfaces,
            key=lambda item: (wifi_order.get(item.association_state, 3), item.interface_guid),
        )
    )
    paths_by_guid = {item.interface_guid: item for item in snapshot.wifi_paths}
    relevant_paths = tuple(
        paths_by_guid[item.interface_guid]
        for item in relevant_wifi
        if item.interface_guid in paths_by_guid
    )
    relevant_routes = tuple(
        sorted(
            snapshot.default_routes,
            key=lambda item: (item.metric, item.interface_index, item.next_hop),
        )
    )
    route_rank: dict[int, int] = {}
    for rank, route in enumerate(relevant_routes):
        route_rank.setdefault(route.interface_index, rank)
    relevant_adapters = tuple(
        sorted(
            snapshot.adapters,
            key=lambda item: (
                route_rank.get(item.interface_index, len(relevant_routes)),
                item.interface_index,
            ),
        )
    )
    limits = ((2, 2, 2, 2), (1, 1, 1, 1), (0, 0, 0, 0))
    for wifi_limit, adapter_limit, route_limit, failure_limit in limits:
        wifi = relevant_wifi[:wifi_limit]
        adapters = relevant_adapters[:adapter_limit]
        routes = relevant_routes[:route_limit]
        failures = snapshot.recent_failures[-failure_limit:] if failure_limit else ()
        proxy = snapshot.proxy
        if proxy is not None and proxy.manual_server is not None:
            proxy = proxy.model_copy(update={"manual_server": None, "server_redacted": True})
        preview = snapshot.model_copy(
            update={
                "wifi_interfaces": wifi,
                "wifi_paths": relevant_paths[:wifi_limit],
                "omitted_wifi_path_count": snapshot.omitted_wifi_path_count
                + len(snapshot.wifi_paths)
                - len(relevant_paths[:wifi_limit]),
                "wifi_interface_count": len(snapshot.wifi_interfaces),
                "omitted_wifi_count": snapshot.omitted_wifi_count
                + len(snapshot.wifi_interfaces)
                - len(wifi),
                "adapters": adapters,
                "adapter_count": len(snapshot.adapters),
                "omitted_adapter_count": snapshot.omitted_adapter_count
                + len(snapshot.adapters)
                - len(adapters),
                "default_routes": routes,
                "route_count": len(snapshot.default_routes),
                "omitted_route_count": snapshot.omitted_route_count
                + len(snapshot.default_routes)
                - len(routes),
                "proxy": proxy,
                "recent_failures": failures,
                "failure_count": len(snapshot.recent_failures),
                "omitted_failure_count": snapshot.omitted_failure_count
                + len(snapshot.recent_failures)
                - len(failures),
                "limitations": (
                    *snapshot.limitations[:4],
                    "This is a bounded preview; complete redacted connectivity facts remain local.",
                    *(
                        ("Additional source limitations omitted from the preview.",)
                        if len(snapshot.limitations) > 4
                        else ()
                    ),
                ),
            }
        )
        value = preview.model_dump(mode="json")
        fact_bytes = (
            EvidenceFact(name="connectivity", value=value).model_dump_json().encode("utf-8")
        )
        if len(fact_bytes) <= 4096:
            return cast(dict[str, JsonValue], value)
    raise ValueError("connectivity stage metadata exceeds the bounded preview budget")


class ConnectivityProvider(Protocol):
    def wifi_interfaces(self) -> tuple[WifiInterface, ...]: ...

    def adapter_networks(self) -> tuple[AdapterNetwork, ...]: ...

    def default_routes(self) -> tuple[RouteObservation, ...]: ...

    def proxy_settings(self) -> ProxySettings: ...

    def recent_wlan_failures(self) -> tuple[WlanFailure, ...]: ...


def collect_connectivity_snapshot(
    provider: ConnectivityProvider | None = None,
    *,
    clock: Callable[[], UtcDateTime] = utc_now,
) -> ConnectivitySnapshot:
    """Read four fixed local sources, retaining independent failure and time state."""
    backend = provider or WindowsConnectivityProvider()
    limitations: list[str] = []

    def read[T](label: str, operation: Callable[[], T]) -> tuple[T | None, ComponentStatus]:
        try:
            return operation(), ComponentStatus.AVAILABLE
        except (
            PermissionError,
            OSError,
            ValueError,
            RuntimeError,
            NotImplementedError,
            ImportError,
        ) as error:
            status = (
                ComponentStatus.PERMISSION_DENIED
                if isinstance(error, PermissionError)
                else ComponentStatus.UNSUPPORTED
                if isinstance(error, (NotImplementedError, ImportError, FileNotFoundError))
                else ComponentStatus.FAILED
            )
            limitations.append(f"{label} unavailable: {type(error).__name__}")
            return None, status

    wifi_raw, wifi_status = read("WLAN state", backend.wifi_interfaces)
    wifi_observed_at = clock()
    wifi = wifi_raw or ()
    omitted_wifi = max(0, len(wifi) - 16)
    wifi = wifi[:16]
    if omitted_wifi or any(item.details_status is not ComponentStatus.AVAILABLE for item in wifi):
        wifi_status = ComponentStatus.PARTIAL if wifi_raw is not None else wifi_status
        limitations.append("WLAN details are unavailable or capped")

    adapters_raw, addresses_status = read("adapter IP/DNS", backend.adapter_networks)
    addresses_observed_at = clock()
    adapters = adapters_raw or ()
    backend_omitted_adapters = (
        backend.omitted_adapter_rows if isinstance(backend, WindowsConnectivityProvider) else 0
    )
    omitted_adapters = max(0, len(adapters) - 32) + backend_omitted_adapters
    adapters = adapters[:32]
    invalid_adapter_guid = any(
        _canonical_guid(adapter.interface_guid) is None for adapter in adapters
    )
    if (
        omitted_adapters
        or any(
            not (adapter.ip_addresses_complete and adapter.dns_servers_complete)
            for adapter in adapters
        )
        or invalid_adapter_guid
    ):
        addresses_status = ComponentStatus.PARTIAL
        if omitted_adapters:
            limitations.append(
                f"omitted at least {omitted_adapters} invalid or capped adapter rows"
            )
        if any(
            not (adapter.ip_addresses_complete and adapter.dns_servers_complete)
            for adapter in adapters
        ):
            limitations.append("At least one adapter IP or DNS list is missing, invalid, or capped")
        if invalid_adapter_guid:
            limitations.append(
                "At least one IP adapter has no valid interface GUID for WLAN matching"
            )

    routes_raw, routes_status = read("IPv4 default routes", backend.default_routes)
    routes_observed_at = clock()
    routes = tuple(
        route
        for route in routes_raw or ()
        if route.destination == "0.0.0.0" and route.prefix_length == 0
    )
    backend_omitted_routes = (
        backend.omitted_route_rows if isinstance(backend, WindowsConnectivityProvider) else 0
    )
    omitted_routes = max(0, len(routes) - 8) + backend_omitted_routes
    routes = routes[:8]
    if omitted_routes:
        routes_status = ComponentStatus.PARTIAL
        limitations.append(
            f"omitted at least {omitted_routes} invalid or capped IPv4 default routes"
        )

    proxy, proxy_status = read("WinINET proxy", backend.proxy_settings)
    proxy_observed_at = clock()
    if proxy is not None and proxy.server_redacted:
        proxy_status = ComponentStatus.PARTIAL
        limitations.append("WinINET proxy server omitted because it may contain credentials")

    failures_raw, wlan_events_status = read("WLAN event history", backend.recent_wlan_failures)
    wlan_events_observed_at = clock()
    failures = tuple(
        item
        for item in failures_raw or ()
        if wlan_events_observed_at - _WLAN_FAILURE_WINDOW
        <= item.observed_at
        <= wlan_events_observed_at
    )
    omitted_failures = max(0, len(failures) - _WLAN_FAILURE_LIMIT)
    failures = failures[-_WLAN_FAILURE_LIMIT:]
    if omitted_failures:
        wlan_events_status = ComponentStatus.PARTIAL
        limitations.append(f"omitted {omitted_failures} recent WLAN failure records beyond the cap")

    captured_at = clock()
    statuses = (wifi_status, addresses_status, routes_status, proxy_status, wlan_events_status)
    overall = (
        ComponentStatus.AVAILABLE
        if all(status is ComponentStatus.AVAILABLE for status in statuses)
        else ComponentStatus.PARTIAL
    )
    return ConnectivitySnapshot(
        source_id=stable_source_id(
            "windows.connectivity.snapshot", {"computer": socket.gethostname().casefold()}
        ),
        captured_at=captured_at,
        wifi_observed_at=wifi_observed_at,
        wifi_status=wifi_status,
        wifi_interfaces=wifi,
        wifi_paths=correlate_wifi_paths(
            wifi_interfaces=wifi,
            wifi_status=wifi_status,
            adapters=adapters,
            addresses_status=addresses_status,
            omitted_adapter_count=omitted_adapters,
            default_routes=routes,
            routes_status=routes_status,
            omitted_route_count=omitted_routes,
            recent_failures=failures,
            wlan_events_status=wlan_events_status,
            omitted_failure_count=omitted_failures,
        ),
        omitted_wifi_path_count=omitted_wifi,
        omitted_wifi_count=omitted_wifi,
        addresses_observed_at=addresses_observed_at,
        addresses_status=addresses_status,
        adapters=adapters,
        omitted_adapter_count=omitted_adapters,
        routes_observed_at=routes_observed_at,
        routes_status=routes_status,
        default_routes=routes,
        omitted_route_count=omitted_routes,
        proxy_observed_at=proxy_observed_at,
        proxy_status=proxy_status,
        proxy=proxy,
        wlan_events_observed_at=wlan_events_observed_at,
        wlan_events_status=wlan_events_status,
        recent_failures=failures,
        omitted_failure_count=omitted_failures,
        status=overall,
        limitations=tuple(limitations),
    )


class WindowsConnectivityProvider:
    """Fixed local Windows APIs, with no caller-controlled selectors."""

    def __init__(self) -> None:
        self.omitted_adapter_rows = 0
        self.omitted_route_rows = 0

    def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
        return _native_wifi_interfaces()

    def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
        self.omitted_adapter_rows = 0
        client = cast(Any, importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT InterfaceIndex,SettingID,Description,IPAddress,DefaultIPGateway,"
            "DNSServerSearchOrder,DHCPEnabled,DHCPServer "
            "FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"
        )
        adapters: list[AdapterNetwork] = []
        for row_number, row in enumerate(rows):
            if row_number >= 64:
                self.omitted_adapter_rows += 1
                break
            index = getattr(row, "InterfaceIndex", None)
            if not isinstance(index, int) or index < 0:
                self.omitted_adapter_rows += 1
                continue
            ip_addresses, ip_complete = _addresses_with_completeness(
                getattr(row, "IPAddress", None), 16
            )
            dns_servers, dns_complete = _addresses_with_completeness(
                getattr(row, "DNSServerSearchOrder", None), 16
            )
            adapters.append(
                AdapterNetwork(
                    interface_index=index,
                    description=str(getattr(row, "Description", "Network adapter"))[:256],
                    interface_guid=_canonical_guid(getattr(row, "SettingID", None)),
                    ip_addresses=ip_addresses,
                    ip_addresses_complete=ip_complete,
                    default_gateways=_addresses(getattr(row, "DefaultIPGateway", None), 8),
                    dns_servers=dns_servers,
                    dns_servers_complete=dns_complete,
                    dhcp_enabled=(
                        None if getattr(row, "DHCPEnabled", None) is None else bool(row.DHCPEnabled)
                    ),
                    dhcp_server=_address(getattr(row, "DHCPServer", None)),
                )
            )
        return tuple(adapters)

    def default_routes(self) -> tuple[RouteObservation, ...]:
        self.omitted_route_rows = 0
        client = cast(Any, importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT Destination,Mask,NextHop,InterfaceIndex,Metric1 "
            "FROM Win32_IP4RouteTable WHERE Destination='0.0.0.0'"
        )
        routes: list[RouteObservation] = []
        for row_number, row in enumerate(rows):
            if row_number >= 32:
                self.omitted_route_rows += 1
                break
            index = getattr(row, "InterfaceIndex", None)
            metric = getattr(row, "Metric1", None)
            next_hop = _address(getattr(row, "NextHop", None))
            if (
                getattr(row, "Mask", None) != "0.0.0.0"
                or not isinstance(index, int)
                or index < 0
                or not isinstance(metric, int)
                or metric < 0
                or next_hop is None
                or ipaddress.ip_address(next_hop).version != 4
            ):
                self.omitted_route_rows += 1
                continue
            routes.append(
                RouteObservation(
                    destination="0.0.0.0",
                    prefix_length=0,
                    next_hop=next_hop,
                    interface_index=index,
                    metric=metric,
                )
            )
        return tuple(routes)

    def proxy_settings(self) -> ProxySettings:
        registry = cast(Any, importlib.import_module("winreg"))
        with registry.OpenKey(
            registry.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            registry.KEY_READ,
        ) as key:

            def value(name: str) -> object | None:
                try:
                    return registry.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    return None

            enabled = value("ProxyEnable")
            server = value("ProxyServer")
            auto_config_url = value("AutoConfigURL")
        server_text = str(server) if server else None
        server_redacted = bool(server_text and ("@" in server_text or len(server_text) > 1024))
        return ProxySettings(
            manual_enabled=None if enabled is None else bool(enabled),
            manual_server=None if server_redacted else server_text,
            auto_configured=bool(auto_config_url),
            server_redacted=server_redacted,
        )

    def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
        module = cast(Any, importlib.import_module("win32evtlog"))
        flags = module.EvtQueryChannelPath | module.EvtQueryReverseDirection
        result_set = module.EvtQuery(_WLAN_CHANNEL, flags, "*")
        events: list[Any] = []
        try:
            events = list(module.EvtNext(result_set, _WLAN_EVENT_LIMIT))
            failures: list[WlanFailure] = []
            for handle in events:
                event = parse_event_xml(module.EvtRender(handle, module.EvtRenderEventXml))
                if event.channel != _WLAN_CHANNEL or event.event_id not in {8002, 11006}:
                    continue
                values = {key.casefold(): value for key, value in event.event_data.items()}
                code = _reason_code(values.get("reasoncode") or values.get("reason-code"))
                guid = values.get("interfaceguid") or values.get("interface-guid")
                failures.append(
                    WlanFailure(
                        source_id=event.source_id,
                        observed_at=event.observed_at,
                        event_id=event.event_id,
                        interface_guid=guid[:64] if guid else None,
                        reason_code=code,
                    )
                )
            return tuple(reversed(failures))
        finally:
            for handle in events:
                handle.Close()
            result_set.Close()


def _address(value: object) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _addresses(value: object, limit: int) -> tuple[str, ...]:
    return _addresses_with_completeness(value, limit)[0]


def _addresses_with_completeness(value: object, limit: int) -> tuple[tuple[str, ...], bool]:
    if value is None:
        return (), False
    values: tuple[object, ...] = (
        tuple(cast(list[object] | tuple[object, ...], value))
        if isinstance(value, (list, tuple))
        else (value,)
    )
    parsed = tuple(item for raw in values[:limit] if (item := _address(raw)) is not None)
    return parsed, len(values) <= limit and len(parsed) == len(values)


def _reason_code(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        code = int(value.strip(), 0)
        return code if code >= 0 else None
    except ValueError:
        return None


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _WlanInterfaceInfo(ctypes.Structure):
    _fields_ = [
        ("guid", _Guid),
        ("description", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
        ("state", ctypes.c_uint32),
    ]


class _WlanInterfaceListHeader(ctypes.Structure):
    _fields_ = [("count", ctypes.c_uint32), ("index", ctypes.c_uint32)]


class _Dot11Ssid(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("bytes", ctypes.c_ubyte * 32)]


class _AssociationAttributes(ctypes.Structure):
    _fields_ = [
        ("ssid", _Dot11Ssid),
        ("bss_type", ctypes.c_uint32),
        ("bssid", ctypes.c_ubyte * 6),
        ("phy_type", ctypes.c_uint32),
        ("phy_index", ctypes.c_uint32),
        ("signal_quality", ctypes.c_uint32),
        ("rx_rate", ctypes.c_uint32),
        ("tx_rate", ctypes.c_uint32),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("enabled", ctypes.c_int32),
        ("one_x_enabled", ctypes.c_int32),
        ("authentication_algorithm", ctypes.c_uint32),
        ("cipher_algorithm", ctypes.c_uint32),
    ]


class _ConnectionAttributes(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32),
        ("mode", ctypes.c_uint32),
        ("profile_name", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
        ("association", _AssociationAttributes),
        ("security", _SecurityAttributes),
    ]


_WLAN_STATES = {
    0: "not_ready",
    1: "connected",
    2: "ad_hoc_network_formed",
    3: "disconnecting",
    4: "disconnected",
    5: "associating",
    6: "discovering",
    7: "authenticating",
}


def _native_wifi_interfaces() -> tuple[WifiInterface, ...]:
    if os.name != "nt":
        raise NotImplementedError("WLAN API requires Windows")
    wlan = ctypes.WinDLL("wlanapi.dll")
    wlan.WlanOpenHandle.argtypes = [
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    wlan.WlanOpenHandle.restype = ctypes.c_uint32
    wlan.WlanEnumInterfaces.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    wlan.WlanEnumInterfaces.restype = ctypes.c_uint32
    wlan.WlanQueryInterface.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_Guid),
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    wlan.WlanQueryInterface.restype = ctypes.c_uint32
    wlan.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    wlan.WlanCloseHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    negotiated = ctypes.c_uint32()
    client = ctypes.c_void_p()
    code = wlan.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(client))
    if code:
        if code == 5:
            raise PermissionError(code, "WLAN API access denied")
        if code in {50, 1058, 1062}:
            raise NotImplementedError("WLAN service is unavailable")
        raise OSError(code, "WLAN API open failed")
    interfaces_ptr = ctypes.c_void_p()
    try:
        code = wlan.WlanEnumInterfaces(client, None, ctypes.byref(interfaces_ptr))
        if code:
            if code == 5:
                raise PermissionError(code, "WLAN interface enumeration denied")
            if code in {50, 1058, 1062}:
                raise NotImplementedError("WLAN service is unavailable")
            raise OSError(code, "WLAN interface enumeration failed")
        if not interfaces_ptr.value:
            raise RuntimeError("WLAN API returned no interface-list buffer")
        header = ctypes.cast(interfaces_ptr, ctypes.POINTER(_WlanInterfaceListHeader)).contents
        if header.count > 64:
            raise RuntimeError("WLAN API interface count exceeded the supported bound")
        address = interfaces_ptr.value + ctypes.sizeof(_WlanInterfaceListHeader)
        rows = (_WlanInterfaceInfo * header.count).from_address(address)
        observed: list[WifiInterface] = []
        for row in rows:
            state = _WLAN_STATES.get(row.state, "unknown")
            guid = "{" + str(uuid.UUID(bytes_le=bytes(row.guid))) + "}"
            current_ssid: str | None = None
            signal_quality_percent: int | None = None
            authentication_algorithm: int | None = None
            security_enabled: bool | None = None
            one_x_enabled: bool | None = None
            details_status = ComponentStatus.AVAILABLE
            if row.state == 1:
                size = ctypes.c_uint32()
                pointer = ctypes.c_void_p()
                value_type = ctypes.c_uint32()
                code = wlan.WlanQueryInterface(
                    client,
                    ctypes.byref(row.guid),
                    7,  # wlan_intf_opcode_current_connection
                    None,
                    ctypes.byref(size),
                    ctypes.byref(pointer),
                    ctypes.byref(value_type),
                )
                try:
                    if (
                        not code
                        and pointer.value
                        and size.value >= ctypes.sizeof(_ConnectionAttributes)
                    ):
                        connected = ctypes.cast(
                            pointer, ctypes.POINTER(_ConnectionAttributes)
                        ).contents
                        ssid = connected.association.ssid
                        if ssid.length <= 32:
                            current_ssid = bytes(ssid.bytes[: ssid.length]).decode(
                                "utf-8", errors="replace"
                            )[:128]
                        signal_quality_percent = min(100, connected.association.signal_quality)
                        authentication_algorithm = connected.security.authentication_algorithm
                        security_enabled = bool(connected.security.enabled)
                        one_x_enabled = bool(connected.security.one_x_enabled)
                    else:
                        details_status = (
                            ComponentStatus.PERMISSION_DENIED
                            if code == 5
                            else ComponentStatus.UNSUPPORTED
                            if code in {50, 5023}
                            else ComponentStatus.FAILED
                        )
                finally:
                    if pointer.value:
                        wlan.WlanFreeMemory(pointer)
            observed.append(
                WifiInterface(
                    interface_guid=guid,
                    description=row.description[:256] or "Wireless adapter",
                    association_state=state,
                    details_status=details_status,
                    current_ssid=current_ssid,
                    signal_quality_percent=signal_quality_percent,
                    authentication_algorithm=authentication_algorithm,
                    security_enabled=security_enabled,
                    one_x_enabled=one_x_enabled,
                )
            )
        return tuple(observed)
    finally:
        if interfaces_ptr.value:
            wlan.WlanFreeMemory(interfaces_ptr)
        wlan.WlanCloseHandle(client, None)
