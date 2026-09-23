"""Offline route-witness tests; only ephemeral loopback sockets are opened."""

from __future__ import annotations

import socket
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from benchmarks.vm_lab_custody import CaptureKind, capture_bytes, verify_capture
from benchmarks.wininet_route_witness import (
    GuestSocketObservation,
    OriginObservation,
    ProxyConnectCapture,
    RouteExpectation,
    bind_proxy_connect,
    read_proxy_connect,
    record_proxy_connect,
)

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
NONCE = "a" * 32
HOST = f"{NONCE}.owned.example.org"
VM_ID = "vm_" + "b" * 32
VM_UUID = UUID("11111111-2222-3333-4444-555555555555")
SID = "S-1-5-21-1-2-3-4"


def _record(
    tmp_path: Path, payload: bytes, *, guest_boot_id: str = "boot-001"
) -> ProxyConnectCapture:
    ticks = iter((NOW, NOW + timedelta(seconds=1), NOW + timedelta(seconds=2)))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket() as client:
            client.connect(listener.getsockname())
            with listener.accept()[0] as accepted:
                client.sendall(payload)
                return record_proxy_connect(
                    accepted,
                    root=tmp_path,
                    episode_id="proxy-001",
                    capture_id=f"connect-{NONCE}",
                    controller_id="oracle-controller",
                    expected_host=HOST,
                    trial_nonce=NONCE,
                    vm_uuid=VM_UUID,
                    generation_id="generation-clean-001",
                    guest_boot_id=guest_boot_id,
                    clock=lambda: next(ticks),
                    timeout_seconds=0.2,
                )


def test_records_real_connect_bytes_in_separate_write_once_custody(tmp_path: Path) -> None:
    raw = f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode()
    capture = _record(tmp_path, raw)

    assert capture.receipt.kind is CaptureKind.PROXY_CONNECT
    assert capture.receipt.role == "oracle"
    assert capture.target_host == HOST
    assert capture.observed_at == NOW
    assert capture.receipt.source_observed_at == NOW
    assert capture.receipt.collected_at == NOW + timedelta(seconds=1)
    assert capture.manifest_receipt.kind is CaptureKind.PROXY_CONNECT_MANIFEST
    assert capture.manifest_receipt.collected_at == NOW + timedelta(seconds=2)
    assert verify_capture(tmp_path, capture.manifest_receipt)
    assert capture.peer_address[0] == "127.0.0.1"
    assert verify_capture(tmp_path, capture.receipt)
    assert (tmp_path / "proxy-001" / "oracle" / f"connect-{NONCE}.bin").read_bytes() == raw
    with pytest.raises(FileExistsError):
        _record(tmp_path, raw)
    assert read_proxy_connect(tmp_path, capture.receipt) == raw


def test_rejects_oversized_boot_identity_before_custody(tmp_path: Path) -> None:
    raw = f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode()
    with pytest.raises(ValueError, match="registration"):
        _record(tmp_path, raw, guest_boot_id="b" * 3000)
    assert not (tmp_path / "proxy-001" / "oracle").exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"CONNECT other.example.org:443 HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\n",
        b"CONNECT a.example.org:80 HTTP/1.1\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.0\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\nHost: x\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\n\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\n",
        f"CONNECT {HOST}:443 HTTP/1.1\r\n\r\n".encode(),
        f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n".encode()
        + b"User-Agent: token-secret\r\n\r\n",
        f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n".encode()
        + b"Proxy-Authorization: Basic abc\r\n\r\n",
        b"x" * 2049,
        f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\nextra".encode(),
    ],
)
def test_rejects_wrong_or_malformed_or_truncated_connect(tmp_path: Path, raw: bytes) -> None:
    with pytest.raises(ValueError):
        _record(tmp_path, raw)
    assert not (tmp_path / "proxy-001" / "oracle" / f"connect-{NONCE}.bin").exists()


def test_capture_read_times_out_without_complete_header(tmp_path: Path) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket() as client:
            client.connect(listener.getsockname())
            with listener.accept()[0] as accepted:
                client.sendall(f"CONNECT {HOST}:443 HTTP/1.1\r\n".encode())
                with pytest.raises(ValueError, match=r"deadline|incomplete"):
                    record_proxy_connect(
                        accepted,
                        root=tmp_path,
                        episode_id="proxy-001",
                        capture_id=f"connect-{NONCE}",
                        controller_id="oracle-controller",
                        expected_host=HOST,
                        trial_nonce=NONCE,
                        vm_uuid=VM_UUID,
                        generation_id="generation-clean-001",
                        guest_boot_id="boot-001",
                        clock=lambda: NOW,
                        timeout_seconds=0.01,
                    )


def test_binds_proxy_connect_to_trial_worker_and_verified_origin(tmp_path: Path) -> None:
    capture = _record(tmp_path, f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode())
    origin = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id=f"origin-{NONCE}",
        kind=CaptureKind.ORIGIN_EVENT,
        controller_id="oracle-controller",
        source_observed_at=NOW + timedelta(milliseconds=100),
        collected_at=NOW + timedelta(seconds=1),
        data=f"{HOST}\t204\t{NONCE}\n".encode(),
    )
    expected = RouteExpectation(
        episode_id="proxy-001",
        trial_nonce=NONCE,
        vm_id=VM_ID,
        vm_uuid=VM_UUID,
        generation_id="generation-clean-001",
        guest_boot_id="boot-001",
        expected_user_sid=SID,
        expected_host=HOST,
        expected_worker_pid=4242,
        expected_worker_created_at=NOW - timedelta(seconds=1),
        expected_proxy_address=capture.local_address,
        expected_route="preconfig",
    )
    socket_observation = GuestSocketObservation(
        episode_id="proxy-001",
        trial_nonce=NONCE,
        vm_id=VM_ID,
        vm_uuid=VM_UUID,
        generation_id="generation-clean-001",
        guest_boot_id="boot-001",
        user_sid=SID,
        worker_pid=4242,
        worker_created_at=NOW - timedelta(seconds=1),
        local_address=capture.peer_address,
        remote_address=capture.local_address,
        observed_at=NOW,
    )
    origin_observation = OriginObservation(
        receipt=origin,
    )

    binding = bind_proxy_connect(
        tmp_path, capture, expected, socket_observation, origin_observation
    )
    assert binding.classification == "host_route_binding_only"
    assert binding.proxy_capture_digest == capture.receipt.sha256
    assert binding.origin_capture_digest == origin.sha256
    earlier_socket = replace(socket_observation, observed_at=NOW - timedelta(milliseconds=100))
    assert (
        bind_proxy_connect(tmp_path, capture, expected, earlier_socket, origin_observation)
        == binding
    )
    relabeled_capture = replace(
        capture,
        vm_uuid=UUID(int=8),
        generation_id="generation-replayed",
        guest_boot_id="boot-replayed",
        peer_address=("127.0.0.1", 8),
        local_address=("127.0.0.1", 9),
    )
    relabeled_expected = replace(
        expected,
        vm_uuid=relabeled_capture.vm_uuid,
        generation_id=relabeled_capture.generation_id,
        guest_boot_id=relabeled_capture.guest_boot_id,
        expected_proxy_address=relabeled_capture.local_address,
    )
    relabeled_socket = replace(
        socket_observation,
        vm_uuid=relabeled_capture.vm_uuid,
        generation_id=relabeled_capture.generation_id,
        guest_boot_id=relabeled_capture.guest_boot_id,
        local_address=relabeled_capture.peer_address,
        remote_address=relabeled_capture.local_address,
    )
    with pytest.raises(ValueError, match="manifest"):
        bind_proxy_connect(
            tmp_path,
            relabeled_capture,
            relabeled_expected,
            relabeled_socket,
            origin_observation,
        )

    changes = (
        (replace(expected, trial_nonce="c" * 32), socket_observation, origin_observation),
        (
            replace(expected, generation_id="generation-other"),
            socket_observation,
            origin_observation,
        ),
        (replace(expected, vm_uuid=UUID(int=8)), socket_observation, origin_observation),
        (replace(expected, expected_worker_pid=4243), socket_observation, origin_observation),
        (
            replace(expected, expected_user_sid="S-1-5-21-9-8-7-6"),
            socket_observation,
            origin_observation,
        ),
        (expected, replace(socket_observation, local_address=("127.0.0.1", 9)), origin_observation),
        (replace(expected, expected_route="direct"), socket_observation, origin_observation),
        (
            replace(expected, expected_proxy_address=("127.0.0.1", 9)),
            socket_observation,
            origin_observation,
        ),
        (
            expected,
            replace(socket_observation, observed_at=NOW - timedelta(seconds=3)),
            origin_observation,
        ),
        (expected, socket_observation, OriginObservation(receipt=replace(origin, sha256="0" * 64))),
    )
    for changed_expected, changed_socket, changed_origin in changes:
        with pytest.raises(ValueError):
            bind_proxy_connect(tmp_path, capture, changed_expected, changed_socket, changed_origin)
    with pytest.raises(ValueError):
        bind_proxy_connect(
            tmp_path,
            replace(capture, generation_id="generation-replayed"),
            expected,
            socket_observation,
            origin_observation,
        )


@pytest.mark.parametrize(
    "payload",
    [f"{HOST}\t503\t{NONCE}\n", f"{HOST}\t204\t{'b' * 32}\n"],
)
def test_origin_receipt_bytes_must_show_exact_host_nonce_and_204(
    tmp_path: Path, payload: str
) -> None:
    capture = _record(tmp_path, f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode())
    expected = RouteExpectation(
        episode_id="proxy-001",
        trial_nonce=NONCE,
        vm_id=VM_ID,
        vm_uuid=VM_UUID,
        generation_id="generation-clean-001",
        guest_boot_id="boot-001",
        expected_user_sid=SID,
        expected_host=HOST,
        expected_worker_pid=4242,
        expected_worker_created_at=NOW - timedelta(seconds=1),
        expected_proxy_address=capture.local_address,
        expected_route="preconfig",
    )
    socket_observation = GuestSocketObservation(
        episode_id="proxy-001",
        trial_nonce=NONCE,
        vm_id=VM_ID,
        vm_uuid=VM_UUID,
        generation_id="generation-clean-001",
        guest_boot_id="boot-001",
        user_sid=SID,
        worker_pid=4242,
        worker_created_at=NOW - timedelta(seconds=1),
        local_address=capture.peer_address,
        remote_address=capture.local_address,
        observed_at=NOW,
    )
    origin = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id=f"origin-{NONCE}",
        kind=CaptureKind.ORIGIN_EVENT,
        controller_id="oracle-controller",
        source_observed_at=NOW,
        collected_at=NOW + timedelta(seconds=1),
        data=payload.encode(),
    )
    with pytest.raises(ValueError, match="origin"):
        bind_proxy_connect(
            tmp_path, capture, expected, socket_observation, OriginObservation(origin)
        )
