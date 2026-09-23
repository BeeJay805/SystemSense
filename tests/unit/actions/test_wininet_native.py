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


@pytest.mark.parametrize("state", range(10))
def test_only_active_wts_session_is_admitted(monkeypatch: pytest.MonkeyPatch, state: int) -> None:
    """Connected-but-not-active, disconnected, and unknown states all deny."""
    monkeypatch.setattr(wininet_native.sys, "platform", "win32")

    class FakeFunction:
        argtypes: Any = None
        restype: Any = None

        def __call__(
            self, _server: Any, session: int, info_class: int, output: Any, size: Any
        ) -> int:
            assert session == 7 and info_class == 8
            value = ctypes.pointer(ctypes.c_int(state))
            # Keep the pointee live until WTSFreeMemory is called.
            allocations.append(value)
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(
                value, ctypes.c_void_p
            )
            ctypes.cast(size, ctypes.POINTER(ctypes.c_ulong))[0] = ctypes.sizeof(ctypes.c_int)
            return 1

    allocations: list[Any] = []
    free_calls: list[int] = []

    class Free:
        argtypes: Any = None
        restype: Any = None

        def __call__(self, address: int) -> None:
            free_calls.append(address)

    wts = SimpleNamespace(WTSQuerySessionInformationW=FakeFunction(), WTSFreeMemory=Free())

    def fake_dll(_name: str, **_kw: object) -> SimpleNamespace:
        return wts

    monkeypatch.setattr(wininet_native.ctypes, "WinDLL", fake_dll)
    if state == 0:
        wininet_native._require_active_session(7)  # pyright: ignore[reportPrivateUsage]
    else:
        with pytest.raises(RuntimeError, match="active"):
            wininet_native._require_active_session(7)  # pyright: ignore[reportPrivateUsage]
    assert len(free_calls) == 1


@pytest.mark.parametrize("query_ok,length", [(False, 4), (True, 2)])
def test_wts_query_failure_or_malformed_response_fails_closed_and_frees_buffer(
    monkeypatch: pytest.MonkeyPatch, query_ok: bool, length: int
) -> None:
    allocation = ctypes.pointer(ctypes.c_int(0))
    released: list[int] = []

    class Query:
        argtypes: Any = None
        restype: Any = None

        def __call__(self, _server: Any, _session: int, _class: int, output: Any, size: Any) -> int:
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(
                allocation, ctypes.c_void_p
            )
            ctypes.cast(size, ctypes.POINTER(ctypes.c_ulong))[0] = length
            return int(query_ok)

    class Free:
        argtypes: Any = None
        restype: Any = None

        def __call__(self, address: Any) -> None:
            released.append(address.value)

    dll = SimpleNamespace(WTSQuerySessionInformationW=Query(), WTSFreeMemory=Free())

    def fake_dll(_name: str, **_kw: object) -> SimpleNamespace:
        return dll

    monkeypatch.setattr(wininet_native.ctypes, "WinDLL", fake_dll)
    with pytest.raises(RuntimeError, match=r"cannot establish|invalid"):
        wininet_native._require_active_session(7)  # pyright: ignore[reportPrivateUsage]
    assert released == [ctypes.addressof(allocation.contents)]


@pytest.mark.parametrize("token_session,token_type", [(8, 1), (7, 2)])
def test_process_token_must_be_primary_and_match_active_session(
    monkeypatch: pytest.MonkeyPatch, token_session: int, token_type: int
) -> None:
    monkeypatch.setattr(wininet_native.sys, "platform", "win32")
    active_calls: list[int] = []
    monkeypatch.setattr(wininet_native, "_require_active_session", active_calls.append)
    monkeypatch.setattr(wininet_native, "_require_no_thread_impersonation", lambda: None)

    class ProcessSession:
        argtypes: Any = None
        restype: Any = None

        def __call__(self, _pid: int, output: Any) -> int:
            ctypes.cast(output, ctypes.POINTER(ctypes.c_ulong))[0] = 7
            return 1

    kernel = SimpleNamespace(ProcessIdToSessionId=ProcessSession())

    def fake_dll(_name: str, **_kw: object) -> SimpleNamespace:
        return kernel

    monkeypatch.setattr(wininet_native.ctypes, "WinDLL", fake_dll)

    class Token:
        closed = False

        def Close(self) -> None:
            self.closed = True

    token = Token()

    def open_token(_process: object, _access: int) -> Token:
        return token

    def token_info(_token: Token, which: int) -> int:
        return {12: token_session, 8: token_type}[which]

    security = SimpleNamespace(
        TokenSessionId=12,
        TokenType=8,
        TokenPrimary=1,
        TokenUser=1,
        OpenProcessToken=open_token,
        GetTokenInformation=token_info,
    )
    modules = {
        "win32security": security,
        "win32api": SimpleNamespace(GetCurrentProcess=lambda: 9),
        "win32con": SimpleNamespace(TOKEN_QUERY=8),
    }
    monkeypatch.setattr(wininet_native.importlib, "import_module", modules.__getitem__)
    with pytest.raises(RuntimeError, match="token"):
        wininet_native._interactive_current_sid()  # pyright: ignore[reportPrivateUsage]
    assert active_calls == [7]
    assert token.closed


@pytest.mark.parametrize("opened,error", [(1, 0), (0, 5), (0, 1008)])
def test_thread_impersonation_or_indeterminate_token_blocks_identity(
    monkeypatch: pytest.MonkeyPatch, opened: int, error: int
) -> None:
    monkeypatch.setattr(wininet_native.sys, "platform", "win32")
    closed: list[int] = []

    class OpenThreadToken:
        argtypes: Any = None
        restype: Any = None

        def __call__(self, thread: Any, access: int, as_self: int, output: Any) -> int:
            assert thread == 123 and access == 8 and as_self == 1
            if opened:
                ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(456)
            return opened

    class CloseHandle:
        argtypes: Any = None
        restype: Any = None

        def __call__(self, handle: Any) -> int:
            closed.append(handle.value)
            return 1

    def fake_dll(name: str, **_kw: object) -> SimpleNamespace:
        if name == "advapi32.dll":
            return SimpleNamespace(OpenThreadToken=OpenThreadToken())
        return SimpleNamespace(GetCurrentThread=lambda: 123, CloseHandle=CloseHandle())

    monkeypatch.setattr(wininet_native.ctypes, "WinDLL", fake_dll)
    monkeypatch.setattr(wininet_native.ctypes, "get_last_error", lambda: error)
    if error == 1008:
        wininet_native._require_no_thread_impersonation()  # pyright: ignore[reportPrivateUsage]
    else:
        with pytest.raises(RuntimeError, match=r"impersonat|token"):
            wininet_native._require_no_thread_impersonation()  # pyright: ignore[reportPrivateUsage]
    assert closed == ([456] if opened else [])


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
