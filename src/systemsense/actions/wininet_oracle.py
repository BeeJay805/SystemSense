"""Fixed-destination WinINet connectivity oracle contract for controlled labs.

No native network transport or application route is supplied here. A trusted
composition root must register an owned external HTTPS endpoint and separately
qualify an isolated WinINet transport before this oracle can be used. That
transport must also establish that the destination is genuinely external,
not merely a public-looking DNS name resolving to a local address. The
investigation/model layer can select only the registered check ID, never a URL.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from systemsense.actions.wininet_proxy import ConnectivityObservation
from systemsense.domain.ids import EvidenceId
from systemsense.domain.time import ensure_utc, utc_now

_CHECK_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_DNS_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_SID = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+")
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".invalid", ".test", ".example")


@dataclass(frozen=True, slots=True)
class LabCheckDescriptor:
    """One trusted, immutable HTTPS probe; no free-form URL is accepted.

    The host must be owned by the lab operator. Ownership is an external
    admission gate, not a property this syntax validator can prove.
    """

    check_id: str
    host: str
    path: str
    expected_user_sid: str
    timeout_ms: int

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            pass
        else:
            raise ValueError("lab endpoint must not be an IP literal")
        if _CHECK_ID.fullmatch(self.check_id) is None:
            raise ValueError("invalid lab check ID")
        if (
            _DNS_NAME.fullmatch(self.host) is None
            or self.host != self.host.lower()
            or self.host.endswith(_LOCAL_SUFFIXES)
            or self.host.rsplit(".", 1)[-1].isdigit()
        ):
            raise ValueError("lab endpoint must be an external DNS name")
        if (
            not self.path.startswith("/")
            or self.path.startswith("//")
            or len(self.path) > 128
            or re.fullmatch(r"/[a-zA-Z0-9/_-]*", self.path) is None
        ):
            raise ValueError("lab endpoint must have a fixed canonical path")
        if _SID.fullmatch(self.expected_user_sid) is None:
            raise ValueError("lab check must bind to one current-user SID")
        if not 100 <= self.timeout_ms <= 5000:
            raise ValueError("lab check timeout must be bounded")


@dataclass(frozen=True, slots=True)
class LabWinInetResponse:
    """Metadata only; a transport must never return response content.

    The separately qualified transport must use current-user WinINet
    PRECONFIG, HTTPS with normal certificate validation, no redirects,
    cookies, automatic auth, cache, UI, or caller-controlled destinations.
    It must enforce a hard deadline in an isolated process and read at most
    one response byte. This module does not claim those conditions are met.
    """

    status: int | None
    body_bytes: int
    redirected: bool
    final_host: str
    executing_user_sid: str
    elapsed_ms: int
    error: str | None


class LabWinInetTransport(Protocol):
    def check(self, descriptor: LabCheckDescriptor) -> LabWinInetResponse: ...


@dataclass(frozen=True, slots=True)
class LabConnectivityEvidence:
    evidence_id: EvidenceId
    check_id: str
    path: str
    destination_host_sha256: str
    user_sid_sha256: str
    started_at: datetime
    observed_at: datetime
    passed: bool
    result_code: str
    status: int | None
    elapsed_ms: int


class LabEvidenceSink(Protocol):
    def save(self, record: LabConnectivityEvidence) -> None: ...


class LabWinInetOracle:
    """Evidence-backed verdict for exactly one registered lab check."""

    def __init__(
        self,
        *,
        descriptor: LabCheckDescriptor,
        transport: LabWinInetTransport,
        direct_transport: LabWinInetTransport | None = None,
        current_user_sid: Callable[[], str],
        evidence: LabEvidenceSink,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._descriptor = descriptor
        self._transport = transport
        self._direct_transport = direct_transport
        self._current_user_sid = current_user_sid
        self._evidence = evidence
        self._clock = clock
        self._monotonic = monotonic

    def supports(self, check_id: str) -> bool:
        return check_id == self._descriptor.check_id

    def check(self, check_id: str) -> ConnectivityObservation:
        return self._check_route(check_id, self._transport, "wininet_current_user")

    def check_direct_control(self, check_id: str) -> ConnectivityObservation:
        """Independent proxy-bypass control against the exact same endpoint.

        The direct transport is unimplemented in this repository; absent an
        explicitly qualified adapter, the control is unavailable, not false.
        """
        if self._direct_transport is None:
            raise RuntimeError("direct control unavailable")
        return self._check_route(check_id, self._direct_transport, "wininet_direct_control")

    def _check_route(
        self, check_id: str, transport: LabWinInetTransport, path: str
    ) -> ConnectivityObservation:
        if not self.supports(check_id):
            raise ValueError("unregistered WinINet lab check")
        descriptor = self._descriptor
        if self._current_user_sid() != descriptor.expected_user_sid:
            raise RuntimeError("current-user identity does not match lab check")
        started_at = ensure_utc(self._clock())
        started_mono = self._monotonic()
        response: LabWinInetResponse | None = None
        try:
            response = transport.check(descriptor)
        except Exception:
            # Never persist an exception string: it could contain credentials,
            # a URL, or another response from the environment.
            pass
        elapsed_ms = round((self._monotonic() - started_mono) * 1000)
        observed_at = ensure_utc(self._clock())
        if self._current_user_sid() != descriptor.expected_user_sid:
            raise RuntimeError("current-user identity changed during lab check")
        if observed_at < started_at or elapsed_ms < 0:
            raise RuntimeError("lab check clock moved backwards")
        passed = (
            response is not None
            and response.error is None
            and response.status == 204
            and response.body_bytes == 0
            and not response.redirected
            and response.final_host == descriptor.host
            and response.executing_user_sid == descriptor.expected_user_sid
            and 0 <= response.elapsed_ms <= descriptor.timeout_ms
            and elapsed_ms <= descriptor.timeout_ms
        )
        if response is None:
            code = "transport_error"
        elif elapsed_ms > descriptor.timeout_ms or response.elapsed_ms > descriptor.timeout_ms:
            code = "timeout"
        elif passed:
            code = "expected_204"
        else:
            code = "unexpected_response"
        evidence_id = EvidenceId.new()
        self._evidence.save(
            LabConnectivityEvidence(
                evidence_id=evidence_id,
                check_id=check_id,
                path=path,
                destination_host_sha256=hashlib.sha256(descriptor.host.encode()).hexdigest(),
                user_sid_sha256=hashlib.sha256(descriptor.expected_user_sid.encode()).hexdigest(),
                started_at=started_at,
                observed_at=observed_at,
                passed=passed,
                result_code=code,
                status=response.status if response is not None else None,
                elapsed_ms=elapsed_ms,
            )
        )
        return ConnectivityObservation(
            check_id=check_id,
            passed=passed,
            observed_at=observed_at,
            evidence_id=evidence_id,
            path=path,
            destination_scope="external",
        )
