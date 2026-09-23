"""The rig-owned proxy sink never relays a request or invents guest evidence."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

import pytest

from benchmarks.vm_lab_custody import CaptureKind, verify_capture

NONCE = "a" * 32
HOST = f"{NONCE}.owned.example.org"
VM_UUID = UUID("11111111-2222-3333-4444-555555555555")
DENIAL = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def _registration():
    from benchmarks.owned_proxy_sink import ProxySinkRegistration

    return ProxySinkRegistration(
        episode_id="proxy-001",
        controller_id="oracle-controller",
        trial_nonce=NONCE,
        expected_host=HOST,
        vm_uuid=VM_UUID,
        generation_id="generation-clean-001",
        guest_boot_id="boot-001",
    )


def test_owned_sink_records_real_connect_then_denies_without_tunneling(tmp_path: Path) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    with OwnedProxySink(tmp_path, _registration(), timeout_seconds=1.0) as sink:
        assert sink.address[0] == "127.0.0.1"
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(sink.serve_once)
            with socket.create_connection(sink.address, timeout=1.0) as client:
                client.sendall(f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode())
                assert client.recv(256) == DENIAL
                assert client.recv(1) == b""
            outcome = pending.result(timeout=2.0)
        assert outcome.classification == "host_proxy_denial_only"
        assert outcome.connect.receipt.kind is CaptureKind.PROXY_CONNECT
        assert outcome.denial_receipt.kind is CaptureKind.PROXY_DENIAL
        assert verify_capture(tmp_path, outcome.connect.receipt)
        assert verify_capture(tmp_path, outcome.denial_receipt)
        with pytest.raises(RuntimeError, match="once"):
            sink.serve_once()


def test_owned_sink_rejects_wrong_target_without_denial_or_custody(tmp_path: Path) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    with OwnedProxySink(tmp_path, _registration(), timeout_seconds=1.0) as sink:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(sink.serve_once)
            with socket.create_connection(sink.address, timeout=1.0) as client:
                client.sendall(
                    b"CONNECT wrong.example.org:443 HTTP/1.1\r\nHost: wrong.example.org:443\r\n\r\n"
                )
                assert client.recv(1) == b""
            with pytest.raises(ValueError, match="target mismatch"):
                pending.result(timeout=2.0)
    assert not (tmp_path / "proxy-001" / "oracle" / f"connect-{NONCE}.bin").exists()
    assert not (tmp_path / "proxy-001" / "oracle" / f"denial-{NONCE}.bin").exists()


def test_owned_sink_times_out_without_a_client_and_closes_listener(tmp_path: Path) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    with OwnedProxySink(tmp_path, _registration(), timeout_seconds=0.02) as sink:
        address = sink.address
        with pytest.raises(TimeoutError, match="accept deadline"):
            sink.serve_once()
    with pytest.raises(OSError):
        socket.create_connection(address, timeout=0.1)
    assert not (tmp_path / "proxy-001").exists()


def test_owned_sink_refuses_public_or_unspecified_bind(tmp_path: Path) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    for host in ("0.0.0.0", "8.8.8.8", "192.168.1.5"):
        with pytest.raises(ValueError, match="loopback"):
            OwnedProxySink(tmp_path, _registration(), bind_host=host)


def test_owned_sink_rejects_unbounded_timeouts(tmp_path: Path) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    for timeout in (31.0, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="timeout"):
            OwnedProxySink(tmp_path, _registration(), timeout_seconds=timeout)


def test_context_exit_cancels_accepted_partial_connect(tmp_path: Path) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    sink = OwnedProxySink(tmp_path, _registration(), timeout_seconds=2.0)
    with ThreadPoolExecutor(max_workers=1) as pool:
        sink.__enter__()
        try:
            pending = pool.submit(sink.serve_once)
            with socket.create_connection(sink.address, timeout=1.0) as client:
                client.sendall(f"CONNECT {HOST}:443 HTTP/1.1\r\n".encode())
                deadline = time.monotonic() + 1.0
                # Synchronize at the real accept boundary before cancelling it.
                while sink._active_socket is None and time.monotonic() < deadline:  # pyright: ignore[reportPrivateUsage]
                    time.sleep(0.001)
                assert sink._active_socket is not None  # pyright: ignore[reportPrivateUsage]
                sink.__exit__(None, None, None)
                with pytest.raises((OSError, ValueError, RuntimeError)):
                    pending.result(timeout=1.0)
        finally:
            sink.__exit__(None, None, None)
    assert not (tmp_path / "proxy-001").exists()


def test_replayed_nonce_cannot_overwrite_custody_or_send_denial(tmp_path: Path) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    def try_connect() -> bytes:
        with OwnedProxySink(tmp_path, _registration()) as sink:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(sink.serve_once)
                with socket.create_connection(sink.address, timeout=1.0) as client:
                    client.sendall(
                        f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode()
                    )
                    response = client.recv(256)
                pending.result(timeout=2.0)
        return response

    assert try_connect() == DENIAL
    with pytest.raises(FileExistsError):
        try_connect()


@pytest.mark.parametrize(
    "payload",
    [
        b"CONNECT wrong.example.org:443 HTTP/1.1\nHost: wrong.example.org:443\n\n",
        b"x" * 2049,
        b"CONNECT incomplete.example.org:443 HTTP/1.1\r\n",
        b"",
    ],
)
def test_malformed_or_closed_request_never_produces_denial(tmp_path: Path, payload: bytes) -> None:
    from benchmarks.owned_proxy_sink import OwnedProxySink

    with OwnedProxySink(tmp_path, _registration()) as sink:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(sink.serve_once)
            with socket.create_connection(sink.address, timeout=1.0) as client:
                if payload:
                    client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                assert client.recv(1) == b""
            with pytest.raises(ValueError):
                pending.result(timeout=2.0)
    assert not (tmp_path / "proxy-001" / "oracle" / f"denial-{NONCE}.bin").exists()
