"""Host-side CONNECT custody and trial binding for a future isolated WinINet lab.

The recorder reads an accepted socket supplied by a rig controller. A successful
binding proves local consistency of captured bytes and supplied host/guest
metadata; it cannot authenticate the VM, telemetry issuer, origin, or worker.
It emits no repair RouteProof and does not enable a native proxy write.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast
from uuid import UUID

from benchmarks.vm_lab_custody import CaptureKind, CaptureReceipt, capture_bytes, verify_capture

_MAX_CONNECT_BYTES = 2048
_MAX_MANIFEST_BYTES = 2048
_MAX_ORIGIN_BYTES = 512
_NONCE = re.compile(r"[0-9a-f]{32}")
_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_HEADER = re.compile(rb"(?:Host|Proxy-Connection|Connection|User-Agent): [\x21-\x7e]{1,256}")
_GENERATION = re.compile(r"generation-[a-z0-9-]{3,80}")
_BOOT = re.compile(r"[a-z0-9][a-z0-9-]{0,79}")
type SocketAddress = tuple[str, int]


@dataclass(frozen=True, slots=True)
class ProxyConnectCapture:
    receipt: CaptureReceipt
    manifest_receipt: CaptureReceipt
    target_host: str
    trial_nonce: str
    vm_uuid: UUID
    generation_id: str
    guest_boot_id: str
    peer_address: SocketAddress
    local_address: SocketAddress
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class RouteExpectation:
    episode_id: str
    trial_nonce: str
    vm_id: str
    vm_uuid: UUID
    generation_id: str
    guest_boot_id: str
    expected_user_sid: str
    expected_host: str
    expected_worker_pid: int
    expected_worker_created_at: datetime
    expected_proxy_address: SocketAddress
    expected_route: Literal["preconfig", "direct"]


@dataclass(frozen=True, slots=True)
class GuestSocketObservation:
    episode_id: str
    trial_nonce: str
    vm_id: str
    vm_uuid: UUID
    generation_id: str
    guest_boot_id: str
    user_sid: str
    worker_pid: int
    worker_created_at: datetime
    local_address: SocketAddress
    remote_address: SocketAddress
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class OriginObservation:
    receipt: CaptureReceipt


@dataclass(frozen=True, slots=True)
class HostRouteBinding:
    classification: Literal["host_route_binding_only"]
    episode_id: str
    trial_nonce: str
    vm_uuid: UUID
    generation_id: str
    proxy_capture_digest: str
    origin_capture_digest: str


def _utc(value: datetime) -> bool:
    return value.utcoffset() == UTC.utcoffset(value)


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _manifest_bytes(
    *,
    receipt: CaptureReceipt,
    target_host: str,
    trial_nonce: str,
    vm_uuid: UUID,
    generation_id: str,
    guest_boot_id: str,
    peer_address: SocketAddress,
    local_address: SocketAddress,
    observed_at: datetime,
) -> bytes:
    """Seal the recorder's registration and accepted-socket metadata with raw identity."""

    payload = {
        "schema_version": 1,
        "episode_id": receipt.episode_id,
        "connect_capture_id": receipt.capture_id,
        "connect_sha256": receipt.sha256,
        "target_host": target_host,
        "trial_nonce": trial_nonce,
        "vm_uuid": str(vm_uuid),
        "generation_id": generation_id,
        "guest_boot_id": guest_boot_id,
        "peer_address": peer_address,
        "local_address": local_address,
        "observed_at": observed_at.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_connect(raw: bytes, expected_host: str) -> str:
    if not 0 < len(raw) <= _MAX_CONNECT_BYTES or not raw.endswith(b"\r\n\r\n"):
        raise ValueError("incomplete or oversized CONNECT header")
    if b"\n" in raw.replace(b"\r\n", b""):
        raise ValueError("malformed CONNECT line endings")
    lines = raw[:-4].split(b"\r\n")
    expected_target = f"CONNECT {expected_host}:443 HTTP/1.1".encode("ascii")
    if not lines or lines[0] != expected_target:
        raise ValueError("CONNECT target mismatch")
    seen: set[bytes] = set()
    for line in lines[1:]:
        if _HEADER.fullmatch(line) is None:
            raise ValueError("unsupported or sensitive CONNECT header")
        name, value = line.split(b": ", 1)
        lower = name.lower()
        if lower in seen:
            raise ValueError("duplicate CONNECT header")
        seen.add(lower)
        if lower == b"host" and value != f"{expected_host}:443".encode("ascii"):
            raise ValueError("CONNECT Host header mismatch")
        if lower == b"user-agent" and value != b"SystemSense-LabOracle":
            raise ValueError("unexpected CONNECT User-Agent")
        if lower in (b"connection", b"proxy-connection") and value.lower() not in (
            b"keep-alive",
            b"close",
        ):
            raise ValueError("unexpected CONNECT connection header")
    if b"host" not in seen:
        raise ValueError("CONNECT Host header missing")
    return expected_host


def record_proxy_connect(
    accepted: socket.socket,
    *,
    root: Path,
    episode_id: str,
    capture_id: str,
    controller_id: str,
    expected_host: str,
    trial_nonce: str,
    vm_uuid: UUID,
    generation_id: str,
    guest_boot_id: str,
    timeout_seconds: float = 1.0,
    clock: Callable[[], datetime] = _now_utc,
) -> ProxyConnectCapture:
    """Read one actual accepted CONNECT header and seal the exact bytes once."""

    if (
        _NONCE.fullmatch(trial_nonce) is None
        or _HOST.fullmatch(expected_host) is None
        or not expected_host.startswith(f"{trial_nonce}.")
        or capture_id != f"connect-{trial_nonce}"
        or _GENERATION.fullmatch(generation_id) is None
        or _BOOT.fullmatch(guest_boot_id) is None
        or timeout_seconds <= 0
    ):
        raise ValueError("invalid trial-bound CONNECT registration")
    peer = cast(tuple[str, int], accepted.getpeername())
    local = cast(tuple[str, int], accepted.getsockname())
    peer_address: SocketAddress = (peer[0], peer[1])
    local_address: SocketAddress = (local[0], local[1])
    previous_timeout = accepted.gettimeout()
    deadline = time.monotonic() + timeout_seconds
    raw = bytearray()
    try:
        while not raw.endswith(b"\r\n\r\n"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("CONNECT read deadline exceeded")
            accepted.settimeout(remaining)
            try:
                part = accepted.recv(_MAX_CONNECT_BYTES + 1 - len(raw))
            except TimeoutError as exc:
                raise ValueError("CONNECT read deadline exceeded") from exc
            if not part:
                raise ValueError("incomplete CONNECT header")
            raw.extend(part)
            if len(raw) > _MAX_CONNECT_BYTES:
                raise ValueError("oversized CONNECT header")
            if b"\r\n\r\n" in raw and not raw.endswith(b"\r\n\r\n"):
                raise ValueError("unexpected bytes after CONNECT header")
    finally:
        accepted.settimeout(previous_timeout)
    _parse_connect(bytes(raw), expected_host)
    observed_at = clock()
    if not _utc(observed_at):
        raise ValueError("CONNECT observation time must be UTC")
    collected_at = clock()
    if not _utc(collected_at) or collected_at < observed_at:
        raise ValueError("CONNECT collection time must follow observation in UTC")
    receipt = capture_bytes(
        root,
        episode_id=episode_id,
        capture_id=capture_id,
        kind=CaptureKind.PROXY_CONNECT,
        controller_id=controller_id,
        source_observed_at=observed_at,
        collected_at=collected_at,
        data=bytes(raw),
    )
    manifest = _manifest_bytes(
        receipt=receipt,
        target_host=expected_host,
        trial_nonce=trial_nonce,
        vm_uuid=vm_uuid,
        generation_id=generation_id,
        guest_boot_id=guest_boot_id,
        peer_address=peer_address,
        local_address=local_address,
        observed_at=observed_at,
    )
    if len(manifest) > _MAX_MANIFEST_BYTES:
        raise ValueError("CONNECT custody manifest exceeded limit")
    manifest_collected_at = clock()
    if not _utc(manifest_collected_at) or manifest_collected_at < collected_at:
        raise ValueError("CONNECT manifest collection time must follow raw capture")
    manifest_receipt = capture_bytes(
        root,
        episode_id=episode_id,
        capture_id=f"connect-manifest-{trial_nonce}",
        kind=CaptureKind.PROXY_CONNECT_MANIFEST,
        controller_id=controller_id,
        source_observed_at=observed_at,
        collected_at=manifest_collected_at,
        data=manifest,
    )
    return ProxyConnectCapture(
        receipt=receipt,
        manifest_receipt=manifest_receipt,
        target_host=expected_host,
        trial_nonce=trial_nonce,
        vm_uuid=vm_uuid,
        generation_id=generation_id,
        guest_boot_id=guest_boot_id,
        peer_address=peer_address,
        local_address=local_address,
        observed_at=observed_at,
    )


def _read_capture(root: Path, receipt: CaptureReceipt, limit: int) -> bytes:
    if not verify_capture(root, receipt) or receipt.byte_count > limit:
        raise ValueError("capture receipt failed readback")
    path = root / receipt.episode_id / receipt.role / f"{receipt.capture_id}.bin"
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) != receipt.byte_count or hashlib.sha256(data).hexdigest() != receipt.sha256:
        raise ValueError("capture changed during readback")
    return data


def read_proxy_connect(root: Path, receipt: CaptureReceipt) -> bytes:
    if receipt.kind is not CaptureKind.PROXY_CONNECT or receipt.role != "oracle":
        raise ValueError("not a proxy CONNECT capture")
    return _read_capture(root, receipt, _MAX_CONNECT_BYTES)


def bind_proxy_connect(
    root: Path,
    capture: ProxyConnectCapture,
    expected: RouteExpectation,
    guest_socket: GuestSocketObservation,
    origin: OriginObservation,
) -> HostRouteBinding:
    """Join captured wire bytes to supplied rig records, without issuer authentication."""

    receipt = capture.receipt
    manifest_receipt = capture.manifest_receipt
    if (
        manifest_receipt.kind is not CaptureKind.PROXY_CONNECT_MANIFEST
        or manifest_receipt.role != "oracle"
        or manifest_receipt.episode_id != receipt.episode_id
        or manifest_receipt.capture_id != f"connect-manifest-{capture.trial_nonce}"
        or manifest_receipt.controller_id != receipt.controller_id
        or manifest_receipt.source_observed_at != receipt.source_observed_at
        or manifest_receipt.collected_at < receipt.collected_at
    ):
        raise ValueError("CONNECT custody manifest receipt mismatch")
    stored_manifest = _read_capture(root, manifest_receipt, _MAX_MANIFEST_BYTES)
    expected_manifest = _manifest_bytes(
        receipt=receipt,
        target_host=capture.target_host,
        trial_nonce=capture.trial_nonce,
        vm_uuid=capture.vm_uuid,
        generation_id=capture.generation_id,
        guest_boot_id=capture.guest_boot_id,
        peer_address=capture.peer_address,
        local_address=capture.local_address,
        observed_at=capture.observed_at,
    )
    if stored_manifest != expected_manifest:
        raise ValueError("CONNECT custody manifest content mismatch")
    if (
        expected.expected_route != "preconfig"
        or _NONCE.fullmatch(expected.trial_nonce) is None
        or _HOST.fullmatch(expected.expected_host) is None
        or not expected.expected_host.startswith(f"{expected.trial_nonce}.")
        or expected.expected_host != capture.target_host
        or expected.trial_nonce != capture.trial_nonce
        or expected.vm_uuid != capture.vm_uuid
        or expected.generation_id != capture.generation_id
        or expected.guest_boot_id != capture.guest_boot_id
        or expected.expected_proxy_address != capture.local_address
        or expected.episode_id != receipt.episode_id
        or receipt.capture_id != f"connect-{expected.trial_nonce}"
        or receipt.kind is not CaptureKind.PROXY_CONNECT
        or receipt.role != "oracle"
        or receipt.source_observed_at != capture.observed_at
        or not _utc(capture.observed_at)
        or guest_socket.episode_id != expected.episode_id
        or guest_socket.trial_nonce != expected.trial_nonce
        or guest_socket.vm_id != expected.vm_id
        or guest_socket.vm_uuid != expected.vm_uuid
        or guest_socket.generation_id != expected.generation_id
        or guest_socket.guest_boot_id != expected.guest_boot_id
        or guest_socket.user_sid != expected.expected_user_sid
        or guest_socket.worker_pid != expected.expected_worker_pid
        or guest_socket.worker_created_at != expected.expected_worker_created_at
        or guest_socket.local_address != capture.peer_address
        or guest_socket.remote_address != capture.local_address
        or not _utc(guest_socket.observed_at)
        or not _utc(expected.expected_worker_created_at)
        or guest_socket.worker_created_at > guest_socket.observed_at
        or not guest_socket.observed_at
        <= capture.observed_at
        <= guest_socket.observed_at + timedelta(seconds=2)
    ):
        raise ValueError("proxy CONNECT trial or worker binding mismatch")
    raw = read_proxy_connect(root, receipt)
    _parse_connect(raw, expected.expected_host)
    origin_receipt = origin.receipt
    if (
        origin_receipt.kind is not CaptureKind.ORIGIN_EVENT
        or origin_receipt.role != "oracle"
        or origin_receipt.episode_id != expected.episode_id
        or origin_receipt.capture_id != f"origin-{expected.trial_nonce}"
        or origin_receipt.controller_id != receipt.controller_id
        or origin_receipt.capture_id == receipt.capture_id
        or origin_receipt.source_observed_at < receipt.source_observed_at
    ):
        raise ValueError("origin capture binding mismatch")
    origin_bytes = _read_capture(root, origin_receipt, _MAX_ORIGIN_BYTES)
    if origin_bytes != f"{expected.expected_host}\t204\t{expected.trial_nonce}\n".encode():
        raise ValueError("origin capture does not show trial 204")
    return HostRouteBinding(
        classification="host_route_binding_only",
        episode_id=expected.episode_id,
        trial_nonce=expected.trial_nonce,
        vm_uuid=expected.vm_uuid,
        generation_id=expected.generation_id,
        proxy_capture_digest=receipt.sha256,
        origin_capture_digest=origin_receipt.sha256,
    )
