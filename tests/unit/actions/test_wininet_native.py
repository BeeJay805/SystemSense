"""The native proxy adapter is tested with a bridge that cannot touch Windows."""

import ctypes
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from systemsense.actions import wininet_native
from systemsense.actions.wininet_native import NativeWinInetProxyBackend, WinInetSnapshot

SID = "S-1-5-21-1000-2000-3000-1001"
NOW = datetime(2026, 9, 22, tzinfo=UTC)
DIRECT = 1
PROXY = 2
PAC = 4
AUTO = 8


class FakeWinInet:
    def __init__(self, flags: int = DIRECT | PROXY | PAC | AUTO) -> None:
        self.flags = flags
        self.server = "bad.example:8080"
        self.writes: list[int] = []
        self.notifications = 0

    def query(self) -> WinInetSnapshot:
        return WinInetSnapshot(self.flags, self.server)

    def set_flags(self, flags: int) -> None:
        self.flags = flags
        self.writes.append(flags)

    def notify(self) -> None:
        self.notifications += 1


def _backend(
    bridge: FakeWinInet, *, sid: list[str] | None = None, allowed: bool = True
) -> NativeWinInetProxyBackend:
    current_sid = sid or [SID]
    return NativeWinInetProxyBackend(
        bridge=bridge,
        identity=lambda: current_sid[0],
        policy_guard=lambda: allowed,
        clock=lambda: NOW,
    )


def test_disable_preserves_pac_autodetect_and_server_then_restores_original_flags() -> None:
    bridge = FakeWinInet()
    backend = _backend(bridge)
    before = backend.read()
    assert before.user_sid == SID and before.enabled and before.server == bridge.server
    backend.set_enabled(False)
    assert bridge.writes == [DIRECT | PAC | AUTO]
    assert bridge.notifications == 1
    assert not backend.read().enabled
    backend.set_enabled(True)
    assert bridge.writes == [DIRECT | PAC | AUTO, DIRECT | PROXY | PAC | AUTO]
    assert bridge.notifications == 2


def test_policy_denial_blocks_read_and_write() -> None:
    bridge = FakeWinInet()
    backend = _backend(bridge, allowed=False)
    with pytest.raises(RuntimeError, match="policy"):
        backend.read()
    with pytest.raises(RuntimeError, match="policy"):
        backend.set_enabled(False)
    assert bridge.writes == []


def test_identity_switch_or_changed_flags_blocks_write() -> None:
    bridge = FakeWinInet()
    sid = [SID]
    backend = _backend(bridge, sid=sid)
    backend.read()
    sid[0] = "S-1-5-21-9000-9000-9000-1001"
    with pytest.raises(RuntimeError, match="identity"):
        backend.set_enabled(False)
    sid[0] = SID
    bridge.flags = DIRECT | PROXY
    with pytest.raises(RuntimeError, match="changed"):
        backend.set_enabled(False)
    assert bridge.writes == []


def test_unknown_flags_and_missing_snapshot_fail_closed() -> None:
    bridge = FakeWinInet(flags=DIRECT | PROXY | 0x100)
    backend = _backend(bridge)
    with pytest.raises(RuntimeError, match="unsupported"):
        backend.read()
    with pytest.raises(RuntimeError, match="snapshot"):
        backend.set_enabled(False)
    assert bridge.writes == []


def test_changed_post_disable_state_blocks_restore() -> None:
    bridge = FakeWinInet()
    backend = _backend(bridge)
    backend.read()
    backend.set_enabled(False)
    backend.read()
    bridge.server = "someone-else.example:8080"
    with pytest.raises(RuntimeError, match="changed"):
        backend.set_enabled(True)
    assert bridge.writes == [DIRECT | PAC | AUTO]


def test_ctypes_bridge_uses_fixed_options_and_frees_query_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []
    allocations: list[ctypes.Array[ctypes.c_wchar]] = []

    class FakeFunction:
        def __init__(self, action: Any) -> None:
            self.action = action
            self.argtypes: Any = None
            self.restype: Any = None

        def __call__(self, *args: Any) -> Any:
            return self.action(*args)

    def query(handle: Any, option: int, buffer: Any, size: Any) -> int:
        assert handle is None and option == 75
        data = ctypes.cast(
            buffer,
            ctypes.POINTER(wininet_native._OptionList),  # pyright: ignore[reportPrivateUsage]
        ).contents
        assert data.pszConnection is None and data.dwOptionCount == 1
        requested = data.pOptions[0].dwOption
        calls.append(("query", requested))
        if requested == 10:
            data.pOptions[0].Value.dwValue = DIRECT | PROXY | AUTO
        elif requested == 2:
            allocation = ctypes.create_unicode_buffer("bad.example:8080")
            allocations.append(allocation)
            data.pOptions[0].Value.pszValue = ctypes.addressof(allocation)
        else:
            pytest.fail("unexpected query option")
        return 1

    def set_option(handle: Any, option: int, buffer: Any, length: int) -> int:
        assert handle is None
        if option == 75:
            data = ctypes.cast(
                buffer,
                ctypes.POINTER(wininet_native._OptionList),  # pyright: ignore[reportPrivateUsage]
            ).contents
            assert data.dwOptionCount == 1 and data.pOptions[0].dwOption == 1
            calls.append(("set_flags", data.pOptions[0].Value.dwValue))
        else:
            assert buffer is None and length == 0
            calls.append(("notify", option))
        return 1

    def global_free(address: int) -> None:
        calls.append(("free", address))

    wininet = SimpleNamespace(
        InternetQueryOptionW=FakeFunction(query), InternetSetOptionW=FakeFunction(set_option)
    )
    kernel = SimpleNamespace(GlobalFree=FakeFunction(global_free))

    def fake_dll(name: str, **kwargs: object) -> SimpleNamespace:
        return wininet if name == "wininet.dll" else kernel

    monkeypatch.setattr(wininet_native.ctypes, "WinDLL", fake_dll)
    monkeypatch.setattr(wininet_native.sys, "platform", "win32")
    bridge = wininet_native.NativeWinInetBridge()
    assert bridge.query() == WinInetSnapshot(DIRECT | PROXY | AUTO, "bad.example:8080")
    bridge.set_flags(DIRECT | AUTO)
    bridge.notify()
    assert [(kind, value) for kind, value in calls if kind != "free"] == [
        ("query", 10),
        ("query", 2),
        ("set_flags", DIRECT | AUTO),
        ("notify", 39),
        ("notify", 37),
    ]
    assert len([entry for entry in calls if entry[0] == "free"]) == 1
