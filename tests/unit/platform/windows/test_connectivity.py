from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def test_connectivity_snapshot_keeps_staged_network_facts_and_source_times() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return (
                WifiInterface(
                    interface_guid="{00000000-0000-0000-0000-000000000001}",
                    description="Wi-Fi adapter",
                    association_state="connected",
                    current_ssid="Office",
                    signal_quality_percent=81,
                    authentication_algorithm=7,
                    security_enabled=True,
                    one_x_enabled=False,
                ),
            )

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return (
                AdapterNetwork(
                    interface_index=3,
                    description="Wi-Fi adapter",
                    ip_addresses=("192.0.2.9",),
                    default_gateways=("192.0.2.1",),
                    dns_servers=("192.0.2.53",),
                    dhcp_enabled=True,
                    dhcp_server="192.0.2.1",
                ),
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return (
                RouteObservation(
                    destination="0.0.0.0",
                    prefix_length=0,
                    next_hop="192.0.2.1",
                    interface_index=3,
                    metric=4,
                ),
            )

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(
                manual_enabled=True,
                manual_server="proxy.example:8080",
                auto_configured=False,
            )

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return (
                WlanFailure(
                    source_id="src_" + "a" * 64,
                    observed_at=NOW,
                    event_id=8002,
                    interface_guid="{00000000-0000-0000-0000-000000000001}",
                    reason_code=163851,
                ),
            )

    observed = iter((NOW,) * 7)
    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: next(observed))

    assert snapshot.wifi_observed_at == NOW
    assert snapshot.addresses_observed_at == NOW
    assert snapshot.proxy_observed_at == NOW
    assert snapshot.wlan_events_observed_at == NOW
    assert snapshot.wifi_interfaces[0].current_ssid == "Office"
    assert snapshot.adapters[0].default_gateways == ("192.0.2.1",)
    assert snapshot.adapters[0].dns_servers == ("192.0.2.53",)
    assert snapshot.default_routes[0].interface_index == 3
    assert snapshot.routes_observed_at == NOW
    assert snapshot.proxy is not None
    assert snapshot.proxy.manual_enabled is True
    assert snapshot.proxy.manual_server == "proxy.example:8080"
    assert snapshot.recent_failures[0].observed_at == NOW
    assert snapshot.recent_failures[0].reason_code == 163851
    assert snapshot.status.value == "available"


def test_connectivity_snapshot_preserves_unavailable_component_without_guessing() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            raise PermissionError("private location detail")

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return ()

        def default_routes(self) -> tuple[RouteObservation, ...]:
            raise OSError("route table unavailable")

        def proxy_settings(self) -> ProxySettings:
            raise OSError("registry unavailable")

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert snapshot.wifi_status.value == "permission_denied"
    assert snapshot.wifi_interfaces == ()
    assert snapshot.proxy_status.value == "failed"
    assert snapshot.proxy is None
    assert snapshot.addresses_status.value == "available"
    assert snapshot.adapters == ()
    assert snapshot.default_routes == ()
    assert snapshot.routes_status.value == "failed"
    assert snapshot.wlan_events_status.value == "available"
    assert snapshot.status.value == "partial"
    assert all("private location detail" not in note for note in snapshot.limitations)


def test_connectivity_snapshot_caps_backend_rows_and_marks_partial() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return tuple(
                AdapterNetwork(interface_index=index, description=f"Adapter {index}")
                for index in range(65)
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert len(snapshot.adapters) == 32
    assert snapshot.omitted_adapter_count == 33
    assert snapshot.addresses_status.value == "partial"
    assert snapshot.status.value == "partial"


def test_connectivity_snapshot_source_identity_survives_new_collection_time() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return ()

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False, auto_configured=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    first = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)
    second = collect_connectivity_snapshot(Provider(), clock=lambda: NOW + timedelta(minutes=1))

    assert first.source_id == second.source_id
    assert first.captured_at != second.captured_at


def test_connectivity_snapshot_marks_missing_wlan_capability_unsupported() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            raise NotImplementedError("WLAN service is not installed")

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return ()

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False, auto_configured=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert snapshot.wifi_status.value == "unsupported"
    assert snapshot.wifi_interfaces == ()
    assert snapshot.status.value == "partial"


def test_wlan_event_reader_extracts_only_fixed_failure_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.platform.windows import connectivity

    class Handle:
        def __init__(self, event_id: int) -> None:
            self.event_id = event_id
            self.closed = False

        def Close(self) -> None:
            self.closed = True

    handles = [Handle(8002), Handle(8001)]
    result_set = Handle(0)

    def query(channel: str, flags: int, expression: str) -> Handle:
        assert channel == "Microsoft-Windows-WLAN-AutoConfig/Operational"
        assert flags == 3
        assert expression == "*"
        return result_set

    def next_events(result: Handle, limit: int) -> list[Handle]:
        assert result is result_set
        assert limit == 64
        return handles

    def render(event: Handle, _flags: int) -> str:
        return (
            "<Event><System><Provider Name='Microsoft-Windows-WLAN-AutoConfig'/>"
            f"<EventID>{event.event_id}</EventID><Level>2</Level>"
            f"<EventRecordID>{event.event_id}</EventRecordID>"
            "<TimeCreated SystemTime='2026-09-22T12:00:00Z'/>"
            "<Channel>Microsoft-Windows-WLAN-AutoConfig/Operational</Channel>"
            "<Computer>fixture</Computer></System><EventData>"
            "<Data Name='ReasonCode'>163851</Data>"
            "<Data Name='InterfaceGuid'>{00000000-0000-0000-0000-000000000001}</Data>"
            "</EventData></Event>"
        )

    module = SimpleNamespace(
        EvtQueryChannelPath=1,
        EvtQueryReverseDirection=2,
        EvtRenderEventXml=3,
        EvtQuery=query,
        EvtNext=next_events,
        EvtRender=render,
    )
    imported = connectivity.importlib.import_module

    def fake_import(name: str) -> object:
        return module if name == "win32evtlog" else imported(name)

    monkeypatch.setattr(
        connectivity.importlib,
        "import_module",
        fake_import,
    )

    failures = connectivity.WindowsConnectivityProvider().recent_wlan_failures()

    assert len(failures) == 1
    assert failures[0].event_id == 8002
    assert failures[0].reason_code == 163851
    assert failures[0].observed_at == NOW
    assert all(handle.closed for handle in handles)
    assert result_set.closed


def test_wmi_adapter_invalid_identity_is_reported_without_losing_valid_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows import connectivity
    from systemsense.platform.windows.connectivity import (
        ProxySettings,
        WifiInterface,
        WlanFailure,
    )

    class Service:
        def ExecQuery(self, query: str) -> list[SimpleNamespace]:
            assert "Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE" in query
            return [
                SimpleNamespace(InterfaceIndex=None),
                SimpleNamespace(
                    InterfaceIndex=0,
                    Description="Valid zero",
                    IPAddress=("192.0.2.4",),
                    DefaultIPGateway=("192.0.2.1",),
                    DNSServerSearchOrder=("192.0.2.53",),
                    DHCPEnabled=False,
                    DHCPServer=None,
                ),
            ]

    class Provider(connectivity.WindowsConnectivityProvider):
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False, auto_configured=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    imported = connectivity.importlib.import_module

    def get_object(_path: str) -> Service:
        return Service()

    client = SimpleNamespace(GetObject=get_object)

    def fake_import(name: str) -> object:
        return client if name == "win32com.client" else imported(name)

    monkeypatch.setattr(connectivity.importlib, "import_module", fake_import)

    snapshot = connectivity.collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert [item.interface_index for item in snapshot.adapters] == [0]
    assert snapshot.addresses_status.value == "partial"
    assert snapshot.omitted_adapter_count == 1


def test_default_route_reader_rejects_unknown_interface_without_minting_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.platform.windows import connectivity

    class Service:
        def ExecQuery(self, query: str) -> list[SimpleNamespace]:
            assert "WHERE Destination='0.0.0.0'" in query
            return [
                SimpleNamespace(
                    Destination="0.0.0.0",
                    Mask="0.0.0.0",
                    NextHop="192.0.2.1",
                    InterfaceIndex=None,
                    Metric1=2,
                ),
                SimpleNamespace(
                    Destination="0.0.0.0",
                    Mask="0.0.0.0",
                    NextHop="192.0.2.2",
                    InterfaceIndex=0,
                    Metric1=4,
                ),
            ]

    imported = connectivity.importlib.import_module

    def get_object(_path: str) -> Service:
        return Service()

    client = SimpleNamespace(GetObject=get_object)

    def fake_import(name: str) -> object:
        return client if name == "win32com.client" else imported(name)

    monkeypatch.setattr(connectivity.importlib, "import_module", fake_import)
    provider = connectivity.WindowsConnectivityProvider()

    routes = provider.default_routes()

    assert [route.interface_index for route in routes] == [0]
    assert provider.omitted_route_rows == 1


def test_wininet_proxy_reader_does_not_store_embedded_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.platform.windows import connectivity

    class Key:
        def __enter__(self) -> Key:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def query_value(_key: Key, name: str) -> tuple[object, int]:
        values: dict[str, object] = {
            "ProxyEnable": 1,
            "ProxyServer": "http=user:secret@proxy.example:8080",
        }
        if name not in values:
            raise FileNotFoundError(name)
        return values[name], 1

    def open_key(*_args: object) -> Key:
        return Key()

    registry = SimpleNamespace(
        HKEY_CURRENT_USER=1,
        KEY_READ=1,
        OpenKey=open_key,
        QueryValueEx=query_value,
    )
    imported = connectivity.importlib.import_module

    def fake_import(name: str) -> object:
        return registry if name == "winreg" else imported(name)

    monkeypatch.setattr(connectivity.importlib, "import_module", fake_import)

    proxy = connectivity.WindowsConnectivityProvider().proxy_settings()

    assert proxy.manual_enabled is True
    assert proxy.manual_server is None
    assert proxy.server_redacted is True
