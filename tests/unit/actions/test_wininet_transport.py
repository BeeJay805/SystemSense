"""WinINet lab transport tests use only local process fakes, never a network."""

import ctypes
import multiprocessing
import time
from ctypes import wintypes
from typing import Any

import pytest

from systemsense.actions import wininet_transport
from systemsense.actions.wininet_native import WinInetSnapshot
from systemsense.actions.wininet_oracle import LabCheckDescriptor, LabWinInetResponse
from systemsense.actions.wininet_transport import (
    ProcessIsolatedDirectWinInetTransport,
    ProcessIsolatedWinInetTransport,
    _run_isolated,  # pyright: ignore[reportPrivateUsage]
)

SID = "S-1-5-21-1000-2000-3000-1001"


def _descriptor(*, timeout_ms: int = 3000) -> LabCheckDescriptor:
    return LabCheckDescriptor(
        "lab.owned_https", "probe.example.org", "/health/204", SID, timeout_ms
    )


def _successful_worker(descriptor: LabCheckDescriptor) -> LabWinInetResponse:
    return LabWinInetResponse(204, 0, False, descriptor.host, SID, 1, None)


def _hung_worker(_descriptor: LabCheckDescriptor) -> LabWinInetResponse:
    time.sleep(5)
    raise AssertionError("worker was not killed")


def _secret_error_worker(_descriptor: LabCheckDescriptor) -> LabWinInetResponse:
    raise RuntimeError("user:password@example.org/private")


def _forged_worker(descriptor: LabCheckDescriptor) -> LabWinInetResponse:
    return LabWinInetResponse(204, 0, False, "different.example.org", SID, 1, None)


def _sensitive_response_worker(descriptor: LabCheckDescriptor) -> LabWinInetResponse:
    return LabWinInetResponse(None, 0, False, descriptor.host, SID, 1, "password:secret")


def test_transport_needs_exact_registered_descriptor_and_endpoint_admission() -> None:
    descriptor = _descriptor()
    seen: list[LabCheckDescriptor] = []
    transport = ProcessIsolatedWinInetTransport(
        descriptor=descriptor,
        endpoint_admission=lambda value: seen.append(value) or False,
        current_user_sid=lambda: SID,
    )
    with pytest.raises(RuntimeError, match="endpoint not admitted"):
        transport.check(descriptor)
    with pytest.raises(ValueError, match="registered"):
        transport.check(_descriptor(timeout_ms=2000))
    assert seen == [descriptor]


def test_transport_requires_current_user_before_endpoint_admission() -> None:
    transport = ProcessIsolatedWinInetTransport(
        descriptor=_descriptor(),
        endpoint_admission=lambda _value: pytest.fail("admission should not run"),
        current_user_sid=lambda: "S-1-5-21-9-9-9-9",
    )
    with pytest.raises(RuntimeError, match="identity"):
        transport.check(_descriptor())


def test_direct_control_has_same_descriptor_and_admission_boundary() -> None:
    descriptor = _descriptor()
    transport = ProcessIsolatedDirectWinInetTransport(
        descriptor=descriptor,
        endpoint_admission=lambda _value: False,
        current_user_sid=lambda: SID,
    )
    with pytest.raises(RuntimeError, match="endpoint not admitted"):
        transport.check(descriptor)
    with pytest.raises(ValueError, match="registered"):
        transport.check(_descriptor(timeout_ms=2000))


def test_isolation_returns_only_bounded_metadata() -> None:
    result = _run_isolated(_descriptor(), _successful_worker)
    assert result.status == 204
    assert result.error is None
    assert result.final_host == "probe.example.org"
    assert result.executing_user_sid == SID


def test_isolation_kills_hung_worker_at_deadline() -> None:
    original = {child.pid for child in multiprocessing.active_children()}
    started = time.monotonic()
    result = _run_isolated(_descriptor(timeout_ms=500), _hung_worker)
    assert result.error == "deadline_exceeded"
    assert time.monotonic() - started < 3
    assert {child.pid for child in multiprocessing.active_children()} == original


def test_worker_exception_does_not_leak_sensitive_string() -> None:
    result = _run_isolated(_descriptor(), _secret_error_worker)
    assert result.error == "worker_error"
    assert "password" not in repr(result)


def test_forged_child_result_is_rejected() -> None:
    result = _run_isolated(_descriptor(), _forged_worker)
    assert result.error == "invalid_worker_result"
    assert result.status is None


def test_worker_metadata_cannot_send_arbitrary_error_text() -> None:
    result = _run_isolated(_descriptor(), _sensitive_response_worker)
    assert result.error == "worker_error"
    assert "secret" not in repr(result)


class FakeCall:
    def __init__(self, name: str, owner: "FakeNative") -> None:
        self.name = name
        self.owner = owner
        self.argtypes: list[object] = []
        self.restype: object = None

    def __call__(self, *args: Any) -> int:
        self.owner.calls.append((self.name, args))
        if self.name == "InternetOpenW":
            return 11
        if self.name == "InternetConnectW":
            return 22
        if self.name == "HttpOpenRequestW":
            return 33
        if self.name == "InternetSetOptionW":
            return 1
        if self.name == "HttpSendRequestW":
            return 0 if self.owner.fail_send else 1
        if self.name == "HttpQueryInfoW":
            ctypes.cast(args[2], ctypes.POINTER(wintypes.DWORD)).contents.value = self.owner.status
            return 1
        if self.name == "InternetReadFile":
            ctypes.cast(args[3], ctypes.POINTER(wintypes.DWORD)).contents.value = 0
            return 1
        if self.name == "InternetCloseHandle":
            self.owner.closed.append(args[0])
            return 0 if self.owner.fail_close else 1
        raise AssertionError(self.name)


class FakeNative:
    def __init__(
        self, *, fail_send: bool = False, status: int = 204, fail_close: bool = False
    ) -> None:
        self.fail_send = fail_send
        self.status = status
        self.fail_close = fail_close
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.closed: list[int] = []
        for name in (
            "InternetOpenW",
            "InternetConnectW",
            "HttpOpenRequestW",
            "InternetSetOptionW",
            "HttpSendRequestW",
            "HttpQueryInfoW",
            "InternetReadFile",
            "InternetCloseHandle",
        ):
            setattr(self, name, FakeCall(name, self))


def _no_dns(_host: str) -> None:
    return


def _supported_preconfig_state() -> None:
    return


def _install_fake_native(monkeypatch: pytest.MonkeyPatch, fake: FakeNative) -> None:
    def fake_library(_name: str, *, use_last_error: bool) -> FakeNative:
        return fake

    monkeypatch.setattr(wininet_transport.sys, "platform", "win32")
    monkeypatch.setattr(wininet_transport, "_interactive_current_sid", lambda: SID)
    monkeypatch.setattr(wininet_transport, "_supported_preconfig_state", _supported_preconfig_state)
    monkeypatch.setattr(wininet_transport, "_public_dns_only", _no_dns)
    monkeypatch.setattr(wininet_transport.ctypes, "WinDLL", fake_library)


def test_native_request_uses_fixed_https_flags_and_closes_all_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeNative()
    _install_fake_native(monkeypatch, fake)
    result = wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert result.status == 204 and result.body_bytes == 0 and result.error is None
    assert fake.closed == [33, 22, 11]
    names = [name for name, _args in fake.calls]
    assert names.count("HttpSendRequestW") == names.count("InternetReadFile") == 1
    open_args = next(args for name, args in fake.calls if name == "InternetOpenW")
    assert open_args[1] == 0 and open_args[2:4] == (None, None)
    connect_args = next(args for name, args in fake.calls if name == "InternetConnectW")
    assert connect_args[1:3] == ("probe.example.org", 443)
    request_args = next(args for name, args in fake.calls if name == "HttpOpenRequestW")
    assert request_args[1:3] == ("GET", "/health/204")
    assert any(
        name == "InternetSetOptionW" and args[0:2] == (33, 104) for name, args in fake.calls
    )  # suppress origin credentials and client certificate
    assert request_args[6] & 0x00200000  # no automatic redirect
    assert request_args[6] & 0x00040000  # no automatic authentication
    assert request_args[6] & 0x00080000  # no cookies
    assert request_args[6] & 0x00800000  # HTTPS
    assert request_args[6] & 0x00002000 == 0  # no certificate-date bypass
    assert request_args[6] & 0x00001000 == 0  # no certificate-name bypass


def test_preconfig_retries_after_proxy_disable_with_retained_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeNative()
    state_guard = wininet_transport._supported_preconfig_state  # pyright: ignore[reportPrivateUsage]
    _install_fake_native(monkeypatch, fake)

    class FakeBridge:
        def query(self) -> WinInetSnapshot:
            return WinInetSnapshot(0x01, "proxy.example.org:8080")

        def query_bypass(self) -> str:
            return ""

    monkeypatch.setattr(wininet_transport, "NativeWinInetBridge", FakeBridge)
    monkeypatch.setattr(wininet_transport, "_supported_preconfig_state", state_guard)
    result = wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert result.status == 204 and result.error is None
    assert [name for name, _args in fake.calls].count("HttpSendRequestW") == 1
    open_args = next(args for name, args in fake.calls if name == "InternetOpenW")
    assert open_args[1] == 0  # still PRECONFIG, not the DIRECT control


@pytest.mark.parametrize(
    ("flags", "server", "bypass"),
    [
        (0x01, "", ""),
        (0x01, "http=proxy.example.org:8080", ""),
        (0x01, "proxy.example.org:8080", "*.example.org"),
        (0x05, "proxy.example.org:8080", ""),
    ],
)
def test_disabled_preconfig_rejects_unsupported_state_before_request(
    monkeypatch: pytest.MonkeyPatch, flags: int, server: str, bypass: str
) -> None:
    fake = FakeNative()
    state_guard = wininet_transport._supported_preconfig_state  # pyright: ignore[reportPrivateUsage]
    _install_fake_native(monkeypatch, fake)

    class FakeBridge:
        def query(self) -> WinInetSnapshot:
            return WinInetSnapshot(flags, server)

        def query_bypass(self) -> str:
            return bypass

    monkeypatch.setattr(wininet_transport, "NativeWinInetBridge", FakeBridge)
    monkeypatch.setattr(wininet_transport, "_supported_preconfig_state", state_guard)
    with pytest.raises(RuntimeError, match=r"proxy|bypass"):
        wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert fake.calls == []


def test_disabled_preconfig_rejects_reenabled_proxy_during_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeNative()
    state_guard = wininet_transport._supported_preconfig_state  # pyright: ignore[reportPrivateUsage]
    _install_fake_native(monkeypatch, fake)
    snapshots = iter(
        (
            WinInetSnapshot(0x01, "proxy.example.org:8080"),
            WinInetSnapshot(0x03, "proxy.example.org:8080"),
        )
    )

    class FakeBridge:
        def query(self) -> WinInetSnapshot:
            return next(snapshots)

        def query_bypass(self) -> str:
            return ""

    monkeypatch.setattr(wininet_transport, "NativeWinInetBridge", FakeBridge)
    monkeypatch.setattr(wininet_transport, "_supported_preconfig_state", state_guard)
    with pytest.raises(RuntimeError, match="proxy setting changed"):
        wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert [name for name, _args in fake.calls].count("HttpSendRequestW") == 1
    assert fake.closed == [33, 22, 11]


def test_direct_control_uses_documented_proxy_bypassing_access_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeNative()
    _install_fake_native(monkeypatch, fake)

    def unexpected_proxy_guard() -> None:
        raise AssertionError("DIRECT should not inspect or use proxy settings")

    monkeypatch.setattr(wininet_transport, "_supported_preconfig_state", unexpected_proxy_guard)
    result = wininet_transport._native_direct_probe(  # pyright: ignore[reportPrivateUsage]
        _descriptor()
    )
    assert result.status == 204 and result.error is None
    open_args = next(args for name, args in fake.calls if name == "InternetOpenW")
    assert open_args[1] == 1  # INTERNET_OPEN_TYPE_DIRECT, not PRECONFIG=0
    assert open_args[2:4] == (None, None)
    assert fake.closed == [33, 22, 11]


def test_native_send_failure_closes_handles_and_never_reports_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeNative(fail_send=True)
    _install_fake_native(monkeypatch, fake)
    result = wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert result.status is None and result.error is not None
    assert fake.closed == [33, 22, 11]


def test_native_redirect_is_reported_but_never_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeNative(status=302)
    _install_fake_native(monkeypatch, fake)
    result = wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert result.status == 302 and result.redirected
    assert [name for name, _args in fake.calls].count("HttpSendRequestW") == 1
    assert fake.closed == [33, 22, 11]


def test_native_handle_close_failure_is_not_success(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeNative(fail_close=True)
    _install_fake_native(monkeypatch, fake)
    result = wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert result.status is None and result.error == "worker_error"
    assert fake.closed == [33, 22, 11]


def test_preconfig_rejects_proxy_setting_change_during_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeNative()
    _install_fake_native(monkeypatch, fake)
    snapshots = iter(((3, "proxy-a:8080", ""), (3, "proxy-b:8080", "")))
    monkeypatch.setattr(wininet_transport, "_supported_preconfig_state", lambda: next(snapshots))
    with pytest.raises(RuntimeError, match="proxy setting changed"):
        wininet_transport._native_probe(_descriptor())  # pyright: ignore[reportPrivateUsage]
    assert fake.closed == [33, 22, 11]


def test_dns_preflight_rejects_any_nonpublic_address(monkeypatch: pytest.MonkeyPatch) -> None:
    def mixed_addresses(
        _host: str, _port: int, *, type: int
    ) -> list[tuple[None, None, None, None, tuple[str, int]]]:
        return [
            (None, None, None, None, ("8.8.8.8", 443)),
            (None, None, None, None, ("127.0.0.1", 443)),
        ]

    monkeypatch.setattr(
        wininet_transport.socket,
        "getaddrinfo",
        mixed_addresses,
    )
    with pytest.raises(RuntimeError, match="non-public"):
        wininet_transport._public_dns_only("probe.example.org")  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("flags,server", [(0x05, ""), (0x09, ""), (0x02, "host:8080")])
def test_native_guard_rejects_auto_proxy_and_unsupported_flags(
    monkeypatch: pytest.MonkeyPatch, flags: int, server: str
) -> None:
    class FakeBridge:
        def query(self) -> WinInetSnapshot:
            return WinInetSnapshot(flags, server)

        def query_bypass(self) -> str:
            return ""

    monkeypatch.setattr(wininet_transport, "NativeWinInetBridge", FakeBridge)
    with pytest.raises(RuntimeError, match="automatic or unknown"):
        wininet_transport._supported_preconfig_state()  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("flags", "server", "bypass"),
    [
        (0x01, "", ""),
        (0x03, "", ""),
        (0x03, "http=proxy.example.org:8080", ""),
        (0x03, "proxy.example.org:8080", "*.example.org"),
        (0x03, "https=proxy-a.example.org:8080 https=proxy-b.example.org:8080", ""),
        (0x03, "https=proxy.example.org:8080 garbage", ""),
        (0x03, "https=", ""),
    ],
)
def test_preconfig_requires_unambiguous_https_proxy_without_bypass(
    monkeypatch: pytest.MonkeyPatch, flags: int, server: str, bypass: str
) -> None:
    class FakeBridge:
        def query(self) -> WinInetSnapshot:
            return WinInetSnapshot(flags, server)

        def query_bypass(self) -> str:
            return bypass

    monkeypatch.setattr(wininet_transport, "NativeWinInetBridge", FakeBridge)
    with pytest.raises(RuntimeError, match=r"proxy|bypass"):
        wininet_transport._supported_preconfig_state()  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "server", ["proxy.example.org:8080", "http=other.example.org:8080 https=proxy.example.org:8080"]
)
def test_preconfig_accepts_explicit_manual_https_proxy(
    monkeypatch: pytest.MonkeyPatch, server: str
) -> None:
    class FakeBridge:
        def query(self) -> WinInetSnapshot:
            return WinInetSnapshot(0x03, server)

        def query_bypass(self) -> str:
            return ""

    monkeypatch.setattr(wininet_transport, "NativeWinInetBridge", FakeBridge)
    assert wininet_transport._supported_preconfig_state() == (0x03, server, "")  # pyright: ignore[reportPrivateUsage]
