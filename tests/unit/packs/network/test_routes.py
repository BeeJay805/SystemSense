from __future__ import annotations

import ctypes
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest


def test_get_best_route_uses_host_wide_source_zero_and_network_byte_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.packs.network import routes

    assert ctypes.sizeof(routes._MibIpForwardRow) == 56  # pyright: ignore[reportPrivateUsage]
    assert routes._MibIpForwardRow.dwForwardIfIndex.offset == 16  # pyright: ignore[reportPrivateUsage]
    calls: list[tuple[int, int]] = []

    def fake_get_best_route(destination: int, source: int, result: object) -> int:
        calls.append((destination, source))
        row = ctypes.cast(
            cast(Any, result),
            ctypes.POINTER(routes._MibIpForwardRow),  # pyright: ignore[reportPrivateUsage]
        ).contents
        row.dwForwardDest = int.from_bytes(bytes((192, 0, 2, 0)), sys.byteorder)
        row.dwForwardMask = int.from_bytes(bytes((255, 255, 255, 0)), sys.byteorder)
        row.dwForwardNextHop = int.from_bytes(bytes((198, 51, 100, 1)), sys.byteorder)
        row.dwForwardIfIndex = 7
        row.dwForwardMetric1 = 29
        return 0

    monkeypatch.setattr(routes, "_load_get_best_route", lambda: fake_get_best_route, raising=False)

    chosen = routes.WindowsBestRouteBackend().route_to("192.0.2.53")

    assert calls == [(int.from_bytes(bytes((192, 0, 2, 53)), sys.byteorder), 0)]
    assert chosen.destination == "192.0.2.0"
    assert chosen.prefix_length == 24
    assert chosen.next_hop == "198.51.100.1"
    assert chosen.interface_index == 7
    assert chosen.metric == 29


def test_wmi_route_backend_reports_rows_beyond_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    from systemsense.packs.network import routes

    rows = [
        SimpleNamespace(
            Destination="0.0.0.0",
            Mask="0.0.0.0",
            NextHop=f"192.0.2.{index}",
            InterfaceIndex=index,
            Metric1=index,
        )
        for index in range(1, 4)
    ]

    class Service:
        def ExecQuery(self, _query: str) -> list[SimpleNamespace]:
            return rows

    class Client:
        def GetObject(self, _path: str) -> Service:
            return Service()

    def load_client(_name: str) -> Client:
        return Client()

    monkeypatch.setattr(routes.importlib, "import_module", load_client)

    backend = routes.WmiRouteBackend()
    captured = backend.routes(max_records=2)

    assert len(captured) == 2
    assert backend.omitted_route_count >= 1


def test_missing_native_get_best_route_export_is_explicitly_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.packs.network import routes

    def load_dll(_name: str, *, use_last_error: bool) -> SimpleNamespace:
        assert use_last_error
        return SimpleNamespace()

    monkeypatch.setattr(routes.ctypes, "WinDLL", load_dll)

    with pytest.raises(NotImplementedError):
        routes.WindowsBestRouteBackend().route_to("192.0.2.53")
