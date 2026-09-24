"""Offline custody check for a future WinINet affected-application oracle.

All records are supplied by a host controller. This module authenticates neither
guest telemetry nor origin events, and grants no repair or scoring authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from benchmarks.lab_episodes import LabModel
from benchmarks.vm_lab_custody import CaptureKind, CaptureReceipt, verify_capture
from benchmarks.wininet_route_witness import (
    HostRouteBinding,
    _parse_connect,  # pyright: ignore[reportPrivateUsage]
)

_NONCE = re.compile(r"^[0-9a-f]{32}$")
_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_HASH = r"^[0-9a-f]{64}$"
_PHASES = ("clean", "injected", "direct_control", "after_arm", "after_restore")
type Phase = Literal["clean", "injected", "direct_control", "after_arm", "after_restore"]
type Route = Literal["affected_preconfig", "rig_direct"]
type Result = Literal[
    "http_204", "proxy_failure", "dns_error", "tls_error", "timeout", "other_error"
]


class AffectedTaskExpectation(LabModel):
    """Sealed trial identity; its source is not authenticated by this binder."""

    schema_version: Literal[1] = 1
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    trial_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    vm_uuid: UUID
    generation_id: str = Field(pattern=r"^generation-[a-z0-9-]{3,80}$")
    guest_boot_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,79}$")
    user_sid: str = Field(pattern=r"^S-1-5-21-(?:[0-9]+-){3}[0-9]+$")
    application_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    application_sha256: str = Field(pattern=_HASH)
    application_pid: int = Field(gt=0)
    application_created_at: datetime
    origin_host: str = Field(max_length=253)
    endpoint_sha256: str = Field(pattern=_HASH)
    oracle_controller_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,79}$")

    @model_validator(mode="after")
    def valid_origin_and_time(self) -> Self:
        if (
            not self.origin_host.startswith(f"{self.trial_nonce}.")
            or _HOST.fullmatch(self.origin_host) is None
            or _NONCE.fullmatch(self.trial_nonce) is None
            or self.application_created_at.utcoffset() != UTC.utcoffset(self.application_created_at)
        ):
            raise ValueError("invalid trial origin or application time")
        return self


class AffectedTaskObservation(LabModel):
    """One claimed request outcome, stored as a write-once oracle capture."""

    schema_version: Literal[1]
    episode_id: str
    trial_nonce: str
    vm_uuid: UUID
    generation_id: str
    guest_boot_id: str
    user_sid: str
    application_id: str
    application_sha256: str
    application_pid: int
    application_created_at: datetime
    origin_host: str
    endpoint_sha256: str
    request_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    phase: Phase
    route: Route
    result: Result
    http_status: int | None = Field(default=None, ge=100, le=599)
    observed_at: datetime
    elapsed_ms: int = Field(ge=0, le=120_000)

    @model_validator(mode="after")
    def valid_time(self) -> Self:
        if (
            self.observed_at.utcoffset() != UTC.utcoffset(self.observed_at)
            or self.application_created_at.utcoffset() != UTC.utcoffset(self.application_created_at)
            or self.application_created_at > self.observed_at
        ):
            raise ValueError("invalid affected-task observation time")
        return self


@dataclass(frozen=True, slots=True)
class HostAffectedTaskBinding:
    schema_version: Literal[1]
    classification: Literal["host_affected_task_only"]
    episode_id: str
    trial_nonce: str
    vm_uuid: UUID
    generation_id: str
    capture_digests: tuple[str, ...]
    complete: Literal[True]
    diagnostic_accuracy_claim: Literal[False]
    repair_verified: Literal[False]


def bind_affected_task(
    root: Path,
    expected: AffectedTaskExpectation,
    receipts: tuple[CaptureReceipt, ...],
    *,
    route_binding: HostRouteBinding,
    proxy_receipt: CaptureReceipt,
    route_origin_receipt: CaptureReceipt,
    origin_receipts: tuple[CaptureReceipt, ...],
) -> HostAffectedTaskBinding:
    """Require full task, proxy and same-origin controls; return host-only custody."""

    if len(receipts) != len(_PHASES) or len(origin_receipts) != 4:
        raise ValueError("affected-task phase or origin control missing")
    if route_binding.classification != "host_route_binding_only" or (
        route_binding.episode_id,
        route_binding.trial_nonce,
        route_binding.vm_uuid,
        route_binding.generation_id,
    ) != (
        expected.episode_id,
        expected.trial_nonce,
        expected.vm_uuid,
        expected.generation_id,
    ):
        raise ValueError("proxy route trial mismatch")
    if (
        not verify_capture(root, proxy_receipt)
        or proxy_receipt.kind is not CaptureKind.PROXY_CONNECT
        or proxy_receipt.capture_id != f"connect-{expected.trial_nonce}"
        or proxy_receipt.sha256 != route_binding.proxy_capture_digest
        or proxy_receipt.episode_id != expected.episode_id
        or proxy_receipt.controller_id != expected.oracle_controller_id
    ):
        raise ValueError("proxy CONNECT custody missing or mismatched")
    _parse_connect(_read(root, proxy_receipt, 2048), expected.origin_host)
    if (
        not verify_capture(root, route_origin_receipt)
        or route_origin_receipt.kind is not CaptureKind.ORIGIN_EVENT
        or route_origin_receipt.capture_id != f"origin-{expected.trial_nonce}"
        or route_origin_receipt.episode_id != expected.episode_id
        or route_origin_receipt.controller_id != expected.oracle_controller_id
        or route_origin_receipt.sha256 != route_binding.origin_capture_digest
        or _read(root, route_origin_receipt, 512)
        != f"{expected.origin_host}\t204\t{expected.trial_nonce}\n".encode()
    ):
        raise ValueError("route origin control missing or mismatched")
    observations: list[AffectedTaskObservation] = []
    for phase, receipt in zip(_PHASES, receipts, strict=True):
        if (
            receipt.kind is not CaptureKind.AFFECTED_TASK
            or receipt.role != "oracle"
            or receipt.capture_id != f"task-{phase.replace('_', '-')}-{expected.trial_nonce}"
            or receipt.episode_id != expected.episode_id
            or receipt.controller_id != expected.oracle_controller_id
            or not verify_capture(root, receipt)
        ):
            raise ValueError("affected-task capture custody invalid")
        data = _read(root, receipt, 4096)
        observation = AffectedTaskObservation.model_validate_json(data)
        if (
            observation.phase != phase
            or observation.episode_id != expected.episode_id
            or observation.trial_nonce != expected.trial_nonce
            or observation.vm_uuid != expected.vm_uuid
            or observation.generation_id != expected.generation_id
            or observation.guest_boot_id != expected.guest_boot_id
            or observation.user_sid != expected.user_sid
            or observation.origin_host != expected.origin_host
            or observation.endpoint_sha256 != expected.endpoint_sha256
            or observation.observed_at != receipt.source_observed_at
            or receipt.collected_at - receipt.source_observed_at > timedelta(minutes=2)
        ):
            raise ValueError("affected-task identity or phase mismatch")
        if phase != "direct_control" and (
            observation.route != "affected_preconfig"
            or observation.application_id != expected.application_id
            or observation.application_sha256 != expected.application_sha256
            or observation.application_pid != expected.application_pid
            or observation.application_created_at != expected.application_created_at
        ):
            raise ValueError("affected-application process identity mismatch")
        if phase == "direct_control" and observation.route != "rig_direct":
            raise ValueError("DIRECT control route missing")
        observations.append(observation)
    if len({item.request_id for item in observations}) != len(observations):
        raise ValueError("affected-task request replay")
    if any(a.observed_at >= b.observed_at for a, b in pairwise(observations)):
        raise ValueError("affected-task observation order invalid")
    if not (
        observations[0].observed_at
        < proxy_receipt.source_observed_at
        <= observations[1].observed_at
        < route_origin_receipt.source_observed_at
        <= observations[2].observed_at
    ):
        raise ValueError("proxy and DIRECT control time order invalid")
    if tuple(item.result for item in observations) != (
        "http_204",
        "proxy_failure",
        "http_204",
        "http_204",
        "http_204",
    ):
        raise ValueError("affected-task result or direct control ambiguous")
    if tuple(item.http_status for item in observations) != (204, 502, 204, 204, 204):
        raise ValueError("affected-task HTTP outcome ambiguous")
    for phase, task, origin in zip(
        ("clean", "direct_control", "after_arm", "after_restore"),
        (observations[0], observations[2], observations[3], observations[4]),
        origin_receipts,
        strict=True,
    ):
        if (
            origin.kind is not CaptureKind.ORIGIN_EVENT
            or origin.role != "oracle"
            or origin.capture_id != f"task-origin-{phase.replace('_', '-')}-{expected.trial_nonce}"
            or origin.episode_id != expected.episode_id
            or origin.controller_id != expected.oracle_controller_id
            or origin.source_observed_at != task.observed_at
            or not verify_capture(root, origin)
            or _read(root, origin, 512)
            != f"{expected.origin_host}\t204\t{expected.trial_nonce}\t{task.request_id}\n".encode()
        ):
            raise ValueError("same-origin 204 control missing or mismatched")
    if (
        len(
            {
                r.capture_id
                for r in (*receipts, proxy_receipt, route_origin_receipt, *origin_receipts)
            }
        )
        != 11
    ):
        raise ValueError("capture receipt replay")
    return HostAffectedTaskBinding(
        schema_version=1,
        classification="host_affected_task_only",
        episode_id=expected.episode_id,
        trial_nonce=expected.trial_nonce,
        vm_uuid=expected.vm_uuid,
        generation_id=expected.generation_id,
        capture_digests=tuple(
            r.sha256 for r in (*receipts, proxy_receipt, route_origin_receipt, *origin_receipts)
        ),
        complete=True,
        diagnostic_accuracy_claim=False,
        repair_verified=False,
    )


def _read(root: Path, receipt: CaptureReceipt, limit: int) -> bytes:
    if receipt.byte_count > limit or not verify_capture(root, receipt):
        raise ValueError("bounded capture readback failed")
    path = root / receipt.episode_id / receipt.role / f"{receipt.capture_id}.bin"
    data = path.read_bytes()
    if len(data) != receipt.byte_count or hashlib.sha256(data).hexdigest() != receipt.sha256:
        raise ValueError("capture changed during readback")
    return data
