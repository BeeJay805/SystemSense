from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def test_connectivity_preview_preserves_all_stage_statuses_under_fact_budget() -> None:
    from systemsense.domain.evidence import EvidenceFact
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ConnectivitySnapshot,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        connectivity_preview,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    wifi = WifiInterface(
        interface_guid="{00000000-0000-0000-0000-000000000001}",
        description="W" * 256,
        association_state="disconnected",
        current_ssid="S" * 128,
    )
    adapter = AdapterNetwork(
        interface_index=3,
        description="A" * 256,
        ip_addresses=("192.0.2.1",) * 16,
        default_gateways=("192.0.2.2",) * 8,
        dns_servers=("192.0.2.53",) * 16,
    )
    failure = WlanFailure(
        source_id="src_" + "a" * 64,
        observed_at=NOW,
        event_id=8002,
        reason_code=42,
    )
    snapshot = ConnectivitySnapshot(
        source_id="src_" + "b" * 64,
        captured_at=NOW,
        wifi_observed_at=NOW,
        wifi_status=ComponentStatus.AVAILABLE,
        wifi_interfaces=(wifi,) * 16,
        omitted_wifi_count=4,
        addresses_observed_at=NOW,
        addresses_status=ComponentStatus.AVAILABLE,
        adapters=(adapter,) * 32,
        omitted_adapter_count=2,
        routes_observed_at=NOW,
        routes_status=ComponentStatus.UNSUPPORTED,
        default_routes=(),
        omitted_route_count=0,
        proxy_observed_at=NOW,
        proxy_status=ComponentStatus.AVAILABLE,
        proxy=ProxySettings(manual_enabled=True, manual_server="P" * 1024),
        wlan_events_observed_at=NOW,
        wlan_events_status=ComponentStatus.PARTIAL,
        recent_failures=(failure,) * 16,
        omitted_failure_count=3,
        status=ComponentStatus.PARTIAL,
    )

    preview = connectivity_preview(snapshot)
    parsed = ConnectivitySnapshot.model_validate(preview)
    assert snapshot.dns_route_schema_version is None
    encoded = EvidenceFact(name="connectivity", value=preview).model_dump_json().encode("utf-8")
    assert len(encoded) <= 4096
    assert parsed.wifi_status is ComponentStatus.AVAILABLE
    assert parsed.routes_status is ComponentStatus.UNSUPPORTED
    assert parsed.proxy_status is ComponentStatus.AVAILABLE
    assert parsed.wlan_events_status is ComponentStatus.PARTIAL
    assert parsed.wifi_interface_count == 16
    assert parsed.omitted_wifi_count >= 4
    assert parsed.adapter_count == 32
    assert parsed.omitted_adapter_count >= 2
    assert parsed.failure_count == 16
    assert parsed.omitted_failure_count >= 3
    assert parsed.proxy is not None and parsed.proxy.manual_enabled is True
    assert parsed.wifi_interfaces[0].association_state == "disconnected"
    assert parsed.recent_failures[0].reason_code == 42


def test_connectivity_preview_prioritizes_connected_wifi_and_active_route_adapter() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ConnectivitySnapshot,
        WifiInterface,
        connectivity_preview,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    wifi = tuple(
        WifiInterface(
            interface_guid=f"{{00000000-0000-0000-0000-00000000000{index}}}",
            description=f"Wi-Fi {index}",
            association_state=state,
        )
        for index, state in enumerate(("disconnected", "authenticating", "connected"), start=1)
    )
    adapters = tuple(
        AdapterNetwork(interface_index=index, description=f"Adapter {index}") for index in (2, 3, 4)
    )
    routes = tuple(
        RouteObservation(
            destination="0.0.0.0",
            prefix_length=0,
            next_hop=f"192.0.2.{index}",
            interface_index=index,
            metric=metric,
        )
        for index, metric in ((2, 70), (3, 30), (4, 5))
    )
    snapshot = ConnectivitySnapshot(
        source_id="src_" + "b" * 64,
        captured_at=NOW,
        wifi_observed_at=NOW,
        wifi_status=ComponentStatus.AVAILABLE,
        wifi_interfaces=wifi,
        omitted_wifi_count=0,
        addresses_observed_at=NOW,
        addresses_status=ComponentStatus.AVAILABLE,
        adapters=adapters,
        omitted_adapter_count=0,
        routes_observed_at=NOW,
        routes_status=ComponentStatus.AVAILABLE,
        default_routes=routes,
        omitted_route_count=0,
        proxy_observed_at=NOW,
        proxy_status=ComponentStatus.UNSUPPORTED,
        proxy=None,
        wlan_events_observed_at=NOW,
        wlan_events_status=ComponentStatus.UNSUPPORTED,
        recent_failures=(),
        omitted_failure_count=0,
        status=ComponentStatus.PARTIAL,
    )

    preview = ConnectivitySnapshot.model_validate(connectivity_preview(snapshot))

    assert preview.wifi_interfaces[0].association_state == "connected"
    assert preview.default_routes[0].metric == 5
    assert preview.adapters[0].interface_index == 4
    assert preview.omitted_wifi_count == 3 - len(preview.wifi_interfaces)
    assert preview.omitted_adapter_count == 3 - len(preview.adapters)
    assert preview.omitted_route_count == 3 - len(preview.default_routes)
    assert snapshot.wifi_interfaces == wifi
    assert snapshot.adapters == adapters
    assert snapshot.default_routes == routes


def test_connectivity_preview_respects_utf8_byte_budget() -> None:
    from systemsense.domain.evidence import EvidenceFact
    from systemsense.platform.windows.connectivity import (
        ConnectivitySnapshot,
        WifiInterface,
        connectivity_preview,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    snapshot = ConnectivitySnapshot(
        source_id="src_" + "b" * 64,
        captured_at=NOW,
        wifi_observed_at=NOW,
        wifi_status=ComponentStatus.AVAILABLE,
        wifi_interfaces=tuple(
            WifiInterface(
                interface_guid=f"{{wifi-{index}}}",
                description="界" * 256,
                association_state="disconnected",
                current_ssid="界" * 128,
            )
            for index in range(16)
        ),
        omitted_wifi_count=0,
        addresses_observed_at=NOW,
        addresses_status=ComponentStatus.AVAILABLE,
        adapters=(),
        omitted_adapter_count=0,
        routes_observed_at=NOW,
        routes_status=ComponentStatus.AVAILABLE,
        default_routes=(),
        omitted_route_count=0,
        proxy_observed_at=NOW,
        proxy_status=ComponentStatus.AVAILABLE,
        proxy=None,
        wlan_events_observed_at=NOW,
        wlan_events_status=ComponentStatus.AVAILABLE,
        recent_failures=(),
        omitted_failure_count=0,
        status=ComponentStatus.AVAILABLE,
    )

    preview = connectivity_preview(snapshot)
    encoded = EvidenceFact(name="connectivity", value=preview).model_dump_json().encode("utf-8")
    assert len(encoded) <= 4096
    assert ConnectivitySnapshot.model_validate(preview).omitted_wifi_count > 0


def test_address_cap_and_invalid_values_record_incomplete_lists() -> None:
    from systemsense.platform.windows.connectivity import (
        _addresses_with_completeness,  # pyright: ignore[reportPrivateUsage]
    )

    assert _addresses_with_completeness(["not-an-ip", "192.0.2.9"], 16) == (("192.0.2.9",), False)
    assert _addresses_with_completeness(["not-an-ip"] * 16 + ["192.0.2.9"], 16) == ((), False)
    assert _addresses_with_completeness(None, 16) == ((), False)


def test_wifi_path_joins_only_exact_interface_and_route() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        WifiInterface,
        WlanFailure,
        correlate_wifi_paths,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    wifi_guid = "{00000000-0000-0000-0000-000000000001}"
    ethernet_guid = "{00000000-0000-0000-0000-000000000002}"
    paths = correlate_wifi_paths(
        wifi_interfaces=(
            WifiInterface(
                interface_guid=wifi_guid, description="Wi-Fi", association_state="connected"
            ),
        ),
        wifi_status=ComponentStatus.AVAILABLE,
        adapters=(
            AdapterNetwork(
                interface_guid=wifi_guid,
                interface_index=3,
                description="Wi-Fi",
                ip_addresses=("192.0.2.2",),
            ),
            AdapterNetwork(
                interface_guid=ethernet_guid,
                interface_index=4,
                description="Ethernet",
                ip_addresses=("198.51.100.2",),
            ),
        ),
        addresses_status=ComponentStatus.AVAILABLE,
        omitted_adapter_count=0,
        default_routes=(
            RouteObservation(
                destination="0.0.0.0",
                prefix_length=0,
                next_hop="198.51.100.1",
                interface_index=4,
                metric=1,
            ),
        ),
        routes_status=ComponentStatus.AVAILABLE,
        omitted_route_count=0,
        recent_failures=(
            WlanFailure(
                source_id="src_" + "a" * 64,
                observed_at=NOW,
                event_id=8002,
                interface_guid=ethernet_guid,
                reason_code=42,
            ),
        ),
        wlan_events_status=ComponentStatus.AVAILABLE,
        omitted_failure_count=0,
    )

    assert len(paths) == 1
    assert paths[0].adapter_status == "matched"
    assert paths[0].interface_index == 3
    assert paths[0].address_status == "present"
    assert paths[0].ipv4_default_route_status == "absent"
    assert paths[0].failure_status == "none_recorded"


def test_wifi_path_fails_closed_for_missing_ambiguous_or_incomplete_join() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        WifiInterface,
        WifiPath,
        correlate_wifi_paths,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    guid = "{00000000-0000-0000-0000-000000000001}"
    wifi = (
        WifiInterface(interface_guid=guid, description="Wi-Fi", association_state="disconnected"),
    )

    def paths(
        adapters: tuple[AdapterNetwork, ...], addresses_status: ComponentStatus, omitted: int
    ) -> tuple[WifiPath, ...]:
        return correlate_wifi_paths(
            wifi_interfaces=wifi,
            wifi_status=ComponentStatus.AVAILABLE,
            adapters=adapters,
            addresses_status=addresses_status,
            omitted_adapter_count=omitted,
            default_routes=(
                RouteObservation(
                    destination="0.0.0.0",
                    prefix_length=0,
                    next_hop="192.0.2.1",
                    interface_index=9,
                    metric=1,
                ),
            ),
            routes_status=ComponentStatus.AVAILABLE,
            omitted_route_count=0,
            recent_failures=(),
            wlan_events_status=ComponentStatus.PERMISSION_DENIED,
            omitted_failure_count=0,
        )

    missing = paths((), ComponentStatus.AVAILABLE, 0)
    omitted = paths((), ComponentStatus.PARTIAL, 1)
    malformed = paths(
        (AdapterNetwork(interface_guid=None, interface_index=3, description="Unknown"),),
        ComponentStatus.AVAILABLE,
        0,
    )
    hidden_duplicate = paths(
        (
            AdapterNetwork(
                interface_guid=guid,
                interface_index=3,
                description="Visible Wi-Fi",
                ip_addresses=("192.0.2.2",),
            ),
        ),
        ComponentStatus.PARTIAL,
        1,
    )
    ambiguous = paths(
        (
            AdapterNetwork(interface_guid=guid, interface_index=3, description="A"),
            AdapterNetwork(interface_guid=guid, interface_index=4, description="B"),
        ),
        ComponentStatus.AVAILABLE,
        0,
    )
    assert (missing[0].adapter_status, missing[0].ipv4_default_route_status) == (
        "unmatched",
        "unknown",
    )
    assert omitted[0].adapter_status == "incomplete"
    assert malformed[0].adapter_status == "incomplete"
    assert hidden_duplicate[0].adapter_status == "incomplete"
    assert hidden_duplicate[0].address_status == "unknown"
    assert hidden_duplicate[0].ipv4_default_route_status == "unknown"
    assert ambiguous[0].adapter_status == "ambiguous"
    assert all(item.failure_status == "unknown" for item in (missing[0], omitted[0], ambiguous[0]))


def test_wifi_path_carries_same_interface_failure_without_calling_it_causal() -> None:
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        WifiInterface,
        WlanFailure,
        correlate_wifi_paths,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    guid = "{00000000-0000-0000-0000-000000000001}"
    path = correlate_wifi_paths(
        wifi_interfaces=(
            WifiInterface(interface_guid=guid, description="Wi-Fi", association_state="connected"),
        ),
        wifi_status=ComponentStatus.AVAILABLE,
        adapters=(
            AdapterNetwork(
                interface_guid=guid,
                interface_index=3,
                description="Wi-Fi",
                ip_addresses=(),
                ip_addresses_complete=False,
            ),
        ),
        addresses_status=ComponentStatus.PARTIAL,
        omitted_adapter_count=0,
        default_routes=(),
        routes_status=ComponentStatus.PARTIAL,
        omitted_route_count=1,
        recent_failures=(
            WlanFailure(
                source_id="src_" + "a" * 64,
                observed_at=NOW,
                event_id=8002,
                interface_guid=guid.upper(),
                reason_code=42,
            ),
        ),
        wlan_events_status=ComponentStatus.AVAILABLE,
        omitted_failure_count=0,
    )[0]
    assert path.address_status == "incomplete"
    assert path.ipv4_default_route_status == "incomplete"
    assert path.failure_status == "recorded"
    assert path.failure_count == 1


def test_wifi_path_does_not_assign_route_when_interface_index_is_ambiguous() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        WifiInterface,
        correlate_wifi_paths,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    guid = "{00000000-0000-0000-0000-000000000001}"
    path = correlate_wifi_paths(
        wifi_interfaces=(
            WifiInterface(interface_guid=guid, description="Wi-Fi", association_state="connected"),
        ),
        wifi_status=ComponentStatus.AVAILABLE,
        adapters=(
            AdapterNetwork(interface_guid=guid, interface_index=3, description="Wi-Fi"),
            AdapterNetwork(
                interface_guid="{00000000-0000-0000-0000-000000000002}",
                interface_index=3,
                description="Other",
            ),
        ),
        addresses_status=ComponentStatus.AVAILABLE,
        omitted_adapter_count=0,
        default_routes=(
            RouteObservation(
                destination="0.0.0.0",
                prefix_length=0,
                next_hop="192.0.2.1",
                interface_index=3,
                metric=1,
            ),
        ),
        routes_status=ComponentStatus.AVAILABLE,
        omitted_route_count=0,
        recent_failures=(),
        wlan_events_status=ComponentStatus.AVAILABLE,
        omitted_failure_count=0,
    )[0]
    assert path.adapter_status == "matched"
    assert path.ipv4_default_route_status == "unknown"


def test_connectivity_snapshot_keeps_staged_network_facts_and_source_times() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ConnectivitySnapshot,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
        connectivity_preview,
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
                    interface_guid="{00000000-0000-0000-0000-000000000001}",
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

        def best_ipv4_route(self, destination: str) -> RouteObservation:
            assert destination == "192.0.2.53"
            return RouteObservation(
                destination="0.0.0.0",
                prefix_length=0,
                next_hop="192.0.2.1",
                interface_index=3,
                metric=4,
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

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

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
    assert snapshot.wifi_paths[0].adapter_status == "matched"
    assert snapshot.wifi_paths[0].address_status == "present"
    assert snapshot.wifi_paths[0].ipv4_default_route_status == "present"
    assert snapshot.wifi_paths[0].failure_status == "recorded"
    preview = ConnectivitySnapshot.model_validate(connectivity_preview(snapshot))
    assert preview.wifi_paths[0].ipv4_default_route_status == "present"
    assert snapshot.status.value == "available"


def test_dns_route_uses_only_observed_dns_and_preserves_system_selected_interface() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
        connectivity_preview,
    )

    class Provider:
        def __init__(self) -> None:
            self.queried: list[str] = []

        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return (
                AdapterNetwork(
                    interface_index=3,
                    description="Wi-Fi",
                    dns_servers=("192.0.2.53", "not-an-ip"),
                ),
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return (
                RouteObservation(
                    destination="0.0.0.0",
                    prefix_length=0,
                    next_hop="192.0.2.1",
                    interface_index=3,
                    metric=10,
                ),
            )

        def best_ipv4_route(self, destination: str) -> RouteObservation:
            self.queried.append(destination)
            return RouteObservation(
                destination="192.0.2.0",
                prefix_length=24,
                next_hop="198.51.100.1",
                interface_index=7,
                metric=20,
            )

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    provider = Provider()
    snapshot = collect_connectivity_snapshot(provider, clock=lambda: NOW)

    assert snapshot.dns_route_schema_version == 1
    assert provider.queried == ["192.0.2.53"]
    assert len(snapshot.dns_routes) == 1
    observed = snapshot.dns_routes[0]
    assert observed.destination_ip == "192.0.2.53"
    assert observed.configured_on_interface_indices == (3,)
    assert observed.selected_route is not None
    assert observed.selected_route.interface_index == 7
    assert observed.selected_route.next_hop == "198.51.100.1"
    assert observed.selected_route.prefix_length == 24
    assert observed.observed_at == NOW
    assert "reachability" in " ".join(snapshot.scope_notes).casefold()
    preview = connectivity_preview(snapshot)
    assert preview["dns_routes"] == [observed.model_dump(mode="json")]


def test_dns_route_retains_all_interfaces_that_configured_same_server() -> None:
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
            return (
                AdapterNetwork(interface_index=3, description="Wi-Fi", dns_servers=("192.0.2.53",)),
                AdapterNetwork(interface_index=7, description="VPN", dns_servers=("192.0.2.53",)),
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def best_ipv4_route(self, destination: str) -> RouteObservation:
            assert destination == "192.0.2.53"
            return RouteObservation(
                destination="0.0.0.0",
                prefix_length=0,
                next_hop="198.51.100.1",
                interface_index=7,
                metric=20,
            )

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert len(snapshot.dns_routes) == 1
    assert snapshot.dns_routes[0].configured_on_interface_indices == (3, 7)


def test_dns_route_contract_rejects_unrelated_route_and_invalid_status_pair() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import DnsRouteObservation
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    with pytest.raises(ValueError):
        DnsRouteObservation(
            destination_ip="192.0.2.53",
            configured_on_interface_indices=(3,),
            query_started_at=NOW,
            observed_at=NOW,
            status=ComponentStatus.AVAILABLE,
            selected_route=RouteObservation(
                destination="198.51.100.0",
                prefix_length=24,
                next_hop="198.51.100.1",
                interface_index=7,
                metric=20,
            ),
        )
    with pytest.raises(ValueError):
        DnsRouteObservation(
            destination_ip="192.0.2.53",
            configured_on_interface_indices=(3,),
            query_started_at=NOW,
            observed_at=NOW,
            status=ComponentStatus.PERMISSION_DENIED,
            selected_route=RouteObservation(
                destination="0.0.0.0",
                prefix_length=0,
                next_hop="192.0.2.1",
                interface_index=3,
                metric=20,
            ),
        )


def test_dns_route_contract_rejects_zero_selected_interface() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import DnsRouteObservation
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    with pytest.raises(ValueError):
        DnsRouteObservation(
            destination_ip="192.0.2.53",
            configured_on_interface_indices=(3,),
            query_started_at=NOW,
            observed_at=NOW,
            status=ComponentStatus.AVAILABLE,
            selected_route=RouteObservation(
                destination="0.0.0.0",
                prefix_length=0,
                next_hop="192.0.2.1",
                interface_index=0,
                metric=20,
            ),
        )


def test_connectivity_snapshot_rejects_route_observed_after_capture() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import ConnectivitySnapshot, DnsRouteObservation
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    route = DnsRouteObservation(
        destination_ip="192.0.2.53",
        configured_on_interface_indices=(3,),
        query_started_at=NOW,
        observed_at=NOW + timedelta(seconds=1),
        status=ComponentStatus.AVAILABLE,
        selected_route=RouteObservation(
            destination="0.0.0.0",
            prefix_length=0,
            next_hop="192.0.2.1",
            interface_index=3,
            metric=20,
        ),
    )
    with pytest.raises(ValueError):
        ConnectivitySnapshot.model_validate(
            {
                "source_id": "src_" + "a" * 64,
                "captured_at": NOW.isoformat(),
                "wifi_observed_at": NOW.isoformat(),
                "wifi_status": "available",
                "wifi_interfaces": [],
                "omitted_wifi_count": 0,
                "addresses_observed_at": NOW.isoformat(),
                "addresses_status": "available",
                "adapters": [],
                "omitted_adapter_count": 0,
                "routes_observed_at": NOW.isoformat(),
                "routes_status": "available",
                "default_routes": [],
                "omitted_route_count": 0,
                "dns_route_status": "available",
                "dns_routes": [route.model_dump(mode="json")],
                "proxy_observed_at": NOW.isoformat(),
                "proxy_status": "available",
                "proxy": None,
                "wlan_events_observed_at": NOW.isoformat(),
                "wlan_events_status": "available",
                "recent_failures": [],
                "omitted_failure_count": 0,
                "status": "available",
            }
        )


def test_connectivity_preview_counts_dns_routes_omitted_for_byte_budget() -> None:
    from systemsense.domain.evidence import EvidenceFact
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        ConnectivitySnapshot,
        DnsRouteObservation,
        connectivity_preview,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    route = RouteObservation(
        destination="0.0.0.0",
        prefix_length=0,
        next_hop="192.0.2.1",
        interface_index=3,
        metric=20,
    )
    selected = tuple(
        DnsRouteObservation(
            destination_ip=destination,
            configured_on_interface_indices=(3,),
            query_started_at=NOW,
            observed_at=NOW,
            status=ComponentStatus.AVAILABLE,
            selected_route=route,
        )
        for destination in ("192.0.2.53", "198.51.100.53")
    )
    snapshot = ConnectivitySnapshot(
        source_id="src_" + "a" * 64,
        captured_at=NOW,
        wifi_observed_at=NOW,
        wifi_status=ComponentStatus.AVAILABLE,
        wifi_interfaces=(),
        omitted_wifi_count=0,
        addresses_observed_at=NOW,
        addresses_status=ComponentStatus.AVAILABLE,
        adapters=(),
        omitted_adapter_count=0,
        routes_observed_at=NOW,
        routes_status=ComponentStatus.AVAILABLE,
        default_routes=(),
        omitted_route_count=0,
        dns_route_status=ComponentStatus.AVAILABLE,
        dns_routes=selected,
        proxy_observed_at=NOW,
        proxy_status=ComponentStatus.AVAILABLE,
        proxy=None,
        wlan_events_observed_at=NOW,
        wlan_events_status=ComponentStatus.AVAILABLE,
        recent_failures=(),
        omitted_failure_count=0,
        status=ComponentStatus.AVAILABLE,
        scope_notes=("S" * 2750,),
    )

    preview = connectivity_preview(snapshot)
    parsed = ConnectivitySnapshot.model_validate(preview)

    assert len(EvidenceFact(name="connectivity", value=preview).model_dump_json().encode()) <= 4096
    assert parsed.omitted_dns_route_count > 0
    assert parsed.dns_route_status is ComponentStatus.PARTIAL
    assert len(parsed.dns_routes) + parsed.omitted_dns_route_count == 2


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


def test_dns_route_distinguishes_adapter_denial_from_no_configured_dns() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    class Provider:
        denied = False

        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            if self.denied:
                raise PermissionError("sensitive adapter detail")
            return (AdapterNetwork(interface_index=3, description="Wi-Fi", dns_servers=()),)

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    provider = Provider()
    no_dns = collect_connectivity_snapshot(provider, clock=lambda: NOW)
    provider.denied = True
    denied = collect_connectivity_snapshot(provider, clock=lambda: NOW)

    assert no_dns.dns_route_status is None
    assert any("no configured ipv4 dns" in text.casefold() for text in no_dns.limitations)
    assert denied.dns_route_status is ComponentStatus.PERMISSION_DENIED
    assert denied.dns_routes == ()
    assert all("sensitive adapter detail" not in text for text in denied.limitations)


def test_dns_route_native_denial_has_explicit_permission_coverage() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return (
                AdapterNetwork(interface_index=3, description="Wi-Fi", dns_servers=("192.0.2.53",)),
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def best_ipv4_route(self, _destination: str) -> RouteObservation:
            raise PermissionError("private OS text must not escape")

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert snapshot.dns_route_status is ComponentStatus.PERMISSION_DENIED
    assert snapshot.dns_routes[0].status is ComponentStatus.PERMISSION_DENIED
    assert snapshot.dns_routes[0].selected_route is None
    assert all("private OS text" not in note for note in snapshot.limitations)


def test_dns_route_rejects_provider_route_outside_dns_destination_without_losing_snapshot() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return (
                AdapterNetwork(interface_index=3, description="Wi-Fi", dns_servers=("192.0.2.53",)),
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def best_ipv4_route(self, _destination: str) -> RouteObservation:
            return RouteObservation(
                destination="198.51.100.0",
                prefix_length=24,
                next_hop="198.51.100.1",
                interface_index=7,
                metric=20,
            )

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert snapshot.dns_route_status is ComponentStatus.FAILED
    assert snapshot.dns_routes[0].selected_route is None
    assert snapshot.dns_routes[0].status is ComponentStatus.FAILED


def test_connectivity_snapshot_caps_backend_rows_and_marks_partial() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return tuple(
                AdapterNetwork(
                    interface_index=index,
                    description=f"Adapter {index}",
                    dns_servers=("192.0.2.53",) if index == 0 else (),
                )
                for index in range(65)
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def best_ipv4_route(self, _destination: str) -> RouteObservation:
            return RouteObservation(
                destination="192.0.2.0",
                prefix_length=24,
                next_hop="192.0.2.1",
                interface_index=3,
                metric=20,
            )

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert len(snapshot.adapters) == 32
    assert snapshot.omitted_adapter_count == 33
    assert snapshot.addresses_status.value == "partial"
    assert snapshot.dns_routes[0].status.value == "available"
    assert snapshot.dns_route_status is ComponentStatus.PARTIAL
    assert snapshot.status.value == "partial"


def test_successful_dns_route_query_keeps_partial_source_coverage() -> None:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ProxySettings,
        WifiInterface,
        WlanFailure,
        collect_connectivity_snapshot,
    )
    from systemsense.platform.windows.deep_collectors import ComponentStatus

    class Provider:
        def wifi_interfaces(self) -> tuple[WifiInterface, ...]:
            return ()

        def adapter_networks(self) -> tuple[AdapterNetwork, ...]:
            return (
                AdapterNetwork(
                    interface_index=3,
                    description="Wi-Fi",
                    dns_servers=("192.0.2.53",),
                    dns_servers_complete=False,
                ),
            )

        def default_routes(self) -> tuple[RouteObservation, ...]:
            return ()

        def best_ipv4_route(self, _destination: str) -> RouteObservation:
            return RouteObservation(
                destination="192.0.2.0",
                prefix_length=24,
                next_hop="192.0.2.1",
                interface_index=3,
                metric=20,
            )

        def proxy_settings(self) -> ProxySettings:
            return ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[WlanFailure, ...]:
            return ()

    snapshot = collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert snapshot.addresses_status is ComponentStatus.PARTIAL
    assert snapshot.dns_routes[0].status is ComponentStatus.AVAILABLE
    assert snapshot.dns_route_status is ComponentStatus.PARTIAL


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
            assert "SettingID" in query
            return [
                SimpleNamespace(InterfaceIndex=None),
                SimpleNamespace(
                    InterfaceIndex=0,
                    SettingID="00000000-0000-0000-0000-000000000001",
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
    assert snapshot.adapters[0].interface_guid == "{00000000-0000-0000-0000-000000000001}"
    assert snapshot.addresses_status.value == "partial"
    assert snapshot.omitted_adapter_count == 1


def test_wmi_adapter_malformed_setting_id_marks_identity_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.platform.windows import connectivity

    class Service:
        def ExecQuery(self, query: str) -> list[SimpleNamespace]:
            assert "SettingID" in query
            return [
                SimpleNamespace(
                    InterfaceIndex=3,
                    SettingID="not-a-guid",
                    Description="Wi-Fi adapter",
                    IPAddress=("192.0.2.4",),
                    DefaultIPGateway=("192.0.2.1",),
                    DNSServerSearchOrder=("192.0.2.53",),
                    DHCPEnabled=True,
                    DHCPServer="192.0.2.1",
                )
            ]

    class Provider(connectivity.WindowsConnectivityProvider):
        def wifi_interfaces(self) -> tuple[connectivity.WifiInterface, ...]:
            return (
                connectivity.WifiInterface(
                    interface_guid="{00000000-0000-0000-0000-000000000001}",
                    description="Wi-Fi adapter",
                    association_state="connected",
                ),
            )

        def default_routes(self) -> tuple[connectivity.RouteObservation, ...]:
            return ()

        def proxy_settings(self) -> connectivity.ProxySettings:
            return connectivity.ProxySettings(manual_enabled=False)

        def recent_wlan_failures(self) -> tuple[connectivity.WlanFailure, ...]:
            return ()

    imported = connectivity.importlib.import_module

    def get_object(_path: str) -> Service:
        return Service()

    client = SimpleNamespace(GetObject=get_object)

    def fake_import(name: str) -> object:
        return client if name == "win32com.client" else imported(name)

    monkeypatch.setattr(
        connectivity.importlib,
        "import_module",
        fake_import,
    )
    snapshot = connectivity.collect_connectivity_snapshot(Provider(), clock=lambda: NOW)

    assert snapshot.adapters[0].ip_addresses == ("192.0.2.4",)
    assert snapshot.adapters[0].interface_guid is None
    assert snapshot.addresses_status is connectivity.ComponentStatus.PARTIAL
    assert snapshot.wifi_paths[0].adapter_status == "incomplete"
    assert snapshot.wifi_paths[0].address_status == "unknown"


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
