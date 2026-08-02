from systemsense.packs.network.adapters import AdapterObservation, collect_adapters
from systemsense.packs.network.connections import (
    ConnectionObservation,
    collect_connections,
)
from systemsense.packs.network.dns import DnsProxyObservation, collect_dns_proxy
from systemsense.packs.network.routes import RouteObservation, collect_routes
from systemsense.packs.runtime import summarize_network_snapshot


def test_adapter_state_and_addresses_are_preserved() -> None:
    adapter = AdapterObservation(
        name="Ethernet",
        is_up=True,
        speed_mbps=1000,
        mtu=1500,
        addresses=("192.0.2.10", "fe80::1"),
    )

    assert collect_adapters((adapter,), max_records=16)[0].addresses == (
        "192.0.2.10",
        "fe80::1",
    )


def test_routes_and_dns_proxy_are_structured_without_active_resolution() -> None:
    route = RouteObservation(
        destination="0.0.0.0",
        prefix_length=0,
        next_hop="192.0.2.1",
        interface_index=7,
        metric=25,
    )
    configuration = DnsProxyObservation(
        dns_servers=("192.0.2.53",),
        proxy_enabled=True,
        proxy_server="http://proxy.example:8080",
    )

    assert collect_routes((route,), max_records=32)[0].next_hop == "192.0.2.1"
    collected = collect_dns_proxy((configuration,))
    assert collected.dns_servers == ("192.0.2.53",)
    assert collected.proxy_enabled


def test_connections_keep_only_listening_and_connected_endpoints() -> None:
    connections = (
        ConnectionObservation(
            local_address="0.0.0.0",
            local_port=8000,
            remote_address=None,
            remote_port=None,
            status="LISTEN",
            pid=10,
        ),
        ConnectionObservation(
            local_address="192.0.2.10",
            local_port=51000,
            remote_address="198.51.100.20",
            remote_port=443,
            status="ESTABLISHED",
            pid=11,
        ),
        ConnectionObservation(
            local_address="192.0.2.10",
            local_port=51001,
            remote_address="198.51.100.20",
            remote_port=443,
            status="TIME_WAIT",
            pid=None,
        ),
    )

    result = collect_connections(connections, max_records=64)

    assert [connection.status for connection in result] == ["LISTEN", "ESTABLISHED"]


def test_connections_prioritize_listeners_before_bounded_established_entries() -> None:
    established = tuple(
        ConnectionObservation(
            local_address="192.0.2.10",
            local_port=50_000 + index,
            remote_address="198.51.100.20",
            remote_port=443,
            status="ESTABLISHED",
            pid=11,
        )
        for index in range(10)
    )
    listener = ConnectionObservation(
        local_address="127.0.0.1",
        local_port=8000,
        remote_address=None,
        remote_port=None,
        status="LISTEN",
        pid=12,
    )

    result = collect_connections((*established, listener), max_records=3)

    assert result[0] == listener
    assert len(result) == 3


def test_runtime_summary_surfaces_actionable_listener_details() -> None:
    listener = ConnectionObservation(
        local_address="127.0.0.1",
        local_port=8000,
        remote_address=None,
        remote_port=None,
        status="LISTEN",
        pid=12,
        process_name="python.exe",
        process_executable=r"C:\Tools\Python\python.exe",
        process_command_line=(r"C:\Tools\Python\python.exe -m http.server 8000 --bind 127.0.0.1"),
        parent_pid=4,
    )
    summary = summarize_network_snapshot(0, (listener,))

    assert "127.0.0.1:8000 pid=12" in summary
    assert "process=python.exe" in summary
    assert "command=C:\\Tools\\Python\\python.exe -m http.server 8000" in summary
    assert "parent_pid=4" in summary
    assert len(summary) <= 1000
