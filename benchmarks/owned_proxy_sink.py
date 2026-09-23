"""One-shot, deny-only, loopback proxy producer for a future isolated lab.

This owns the socket that receives a CONNECT request. Its receipts prove only
host-side bytes and response submission. They cannot authenticate a guest,
external HTTPS origin, affected application, or successful repair.
"""

from __future__ import annotations

import math
import re
import socket
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self
from uuid import UUID

from benchmarks.vm_lab_custody import CaptureKind, CaptureReceipt, capture_bytes
from benchmarks.wininet_route_witness import ProxyConnectCapture, record_proxy_connect

_DENIAL = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_NONCE = re.compile(r"[0-9a-f]{32}")
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_CONTROLLER_ID = re.compile(r"[a-z][a-z0-9_.-]{2,79}")
_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_GENERATION = re.compile(r"generation-[a-z0-9-]{3,80}")
_BOOT = re.compile(r"[a-z0-9][a-z0-9-]{0,79}")


@dataclass(frozen=True, slots=True)
class ProxySinkRegistration:
    episode_id: str
    controller_id: str
    trial_nonce: str
    expected_host: str
    vm_uuid: UUID
    generation_id: str
    guest_boot_id: str

    def __post_init__(self) -> None:
        if (
            _ID.fullmatch(self.episode_id) is None
            or _CONTROLLER_ID.fullmatch(self.controller_id) is None
            or _NONCE.fullmatch(self.trial_nonce) is None
            or _HOST.fullmatch(self.expected_host) is None
            or not self.expected_host.startswith(f"{self.trial_nonce}.")
            or _GENERATION.fullmatch(self.generation_id) is None
            or _BOOT.fullmatch(self.guest_boot_id) is None
        ):
            raise ValueError("invalid proxy sink registration")


@dataclass(frozen=True, slots=True)
class HostProxyDenial:
    classification: Literal["host_proxy_denial_only"]
    connect: ProxyConnectCapture
    denial_receipt: CaptureReceipt


class OwnedProxySink:
    """Accept exactly one localhost CONNECT, record it, and refuse the tunnel."""

    def __init__(
        self,
        root: Path,
        registration: ProxySinkRegistration,
        *,
        bind_host: str = "127.0.0.1",
        timeout_seconds: float = 1.0,
    ) -> None:
        if bind_host != "127.0.0.1":
            raise ValueError("proxy sink must bind IPv4 loopback only")
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30:
            raise ValueError("proxy sink timeout must be between 0 and 30 seconds")
        self._root = root
        self._registration = registration
        self._timeout_seconds = timeout_seconds
        self._listener: socket.socket | None = None
        self._active_socket: socket.socket | None = None
        self._used = False
        self._closed = False
        self._lock = threading.Lock()

    def __enter__(self) -> Self:
        with self._lock:
            if self._listener is not None or self._used or self._closed:
                raise RuntimeError("proxy sink can be entered only once")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(self._timeout_seconds)
            except BaseException:
                listener.close()
                raise
            self._listener = listener
        return self

    def __exit__(self, *_exc: object) -> None:
        with self._lock:
            self._closed = True
            if self._listener is not None:
                self._listener.close()
                self._listener = None
            if self._active_socket is not None:
                try:
                    self._active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self._active_socket.close()
                self._active_socket = None
            self._used = True

    @property
    def address(self) -> tuple[str, int]:
        listener = self._listener
        if listener is None:
            raise RuntimeError("proxy sink is not listening")
        address = listener.getsockname()
        return (str(address[0]), int(address[1]))

    def serve_once(self) -> HostProxyDenial:
        with self._lock:
            listener = self._listener
            if self._used:
                raise RuntimeError("proxy sink may serve only once")
            if listener is None:
                raise RuntimeError("proxy sink is not listening")
            self._used = True
        deadline = time.monotonic() + self._timeout_seconds
        try:
            listener.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                accepted, peer = listener.accept()
            except TimeoutError as exc:
                raise TimeoutError("proxy accept deadline exceeded") from exc
        finally:
            listener.close()
            with self._lock:
                self._listener = None
        with self._lock:
            if self._closed:
                accepted.close()
                raise RuntimeError("proxy sink was cancelled")
            self._active_socket = accepted
        with accepted:
            try:
                if peer[0] != "127.0.0.1":
                    raise ValueError("proxy peer is not loopback")
                registration = self._registration
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("proxy CONNECT deadline exceeded")
                connect = record_proxy_connect(
                    accepted,
                    root=self._root,
                    episode_id=registration.episode_id,
                    capture_id=f"connect-{registration.trial_nonce}",
                    controller_id=registration.controller_id,
                    expected_host=registration.expected_host,
                    trial_nonce=registration.trial_nonce,
                    vm_uuid=registration.vm_uuid,
                    generation_id=registration.generation_id,
                    guest_boot_id=registration.guest_boot_id,
                    timeout_seconds=remaining,
                )
                with self._lock:
                    if self._closed:
                        raise RuntimeError("proxy sink was cancelled")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("proxy denial deadline exceeded")
                    accepted.settimeout(remaining)
                    accepted.sendall(_DENIAL)
                    sent_at = datetime.now(UTC)
                    denial_receipt = capture_bytes(
                        self._root,
                        episode_id=registration.episode_id,
                        capture_id=f"denial-{registration.trial_nonce}",
                        kind=CaptureKind.PROXY_DENIAL,
                        controller_id=registration.controller_id,
                        source_observed_at=sent_at,
                        data=_DENIAL,
                    )
            finally:
                with self._lock:
                    if self._active_socket is accepted:
                        self._active_socket = None
        return HostProxyDenial(
            classification="host_proxy_denial_only",
            connect=connect,
            denial_receipt=denial_receipt,
        )
