"""Host-side, write-once custody for raw VM episode captures.

This records bytes supplied by a trusted rig process. Hashes detect later file
changes; they do not authenticate the sensor, controller, clock, or VM state.
The arm must receive only its own explicitly selected inputs, never this root.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from itertools import pairwise
from pathlib import Path
from typing import Literal

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_CONTROLLER_ID = re.compile(r"^[a-z][a-z0-9_.-]{2,79}$")
_MAX_CAPTURE_BYTES = 8 * 1024 * 1024


class CustodyError(ValueError):
    """A capture cannot be safely admitted to host-side custody."""


class CaptureKind(StrEnum):
    PREFLIGHT = "preflight"
    RESET_READBACK = "reset_readback"
    INJECTION_READBACK = "injection_readback"
    CLEAN_ORACLE = "clean_oracle"
    INJECTED_ORACLE = "injected_oracle"
    AFTER_ARM_ORACLE = "after_arm_oracle"
    AFTER_RESTORE_ORACLE = "after_restore_oracle"
    PROXY_CONNECT = "proxy_connect"
    PROXY_CONNECT_MANIFEST = "proxy_connect_manifest"
    ORIGIN_EVENT = "origin_event"
    ARM_TRACE = "arm_trace"
    RUNTIME_EPISODE_TRACE = "runtime_episode_trace"
    BLINDED_REVIEW = "blinded_review"


type CustodyRole = Literal["rig_sealed", "oracle", "arm", "reviewer"]

_ROLE: dict[CaptureKind, CustodyRole] = {
    CaptureKind.PREFLIGHT: "rig_sealed",
    CaptureKind.RESET_READBACK: "rig_sealed",
    CaptureKind.INJECTION_READBACK: "rig_sealed",
    CaptureKind.CLEAN_ORACLE: "oracle",
    CaptureKind.INJECTED_ORACLE: "oracle",
    CaptureKind.AFTER_ARM_ORACLE: "oracle",
    CaptureKind.AFTER_RESTORE_ORACLE: "oracle",
    CaptureKind.PROXY_CONNECT: "oracle",
    CaptureKind.PROXY_CONNECT_MANIFEST: "oracle",
    CaptureKind.ORIGIN_EVENT: "oracle",
    CaptureKind.ARM_TRACE: "arm",
    CaptureKind.RUNTIME_EPISODE_TRACE: "arm",
    CaptureKind.BLINDED_REVIEW: "reviewer",
}


@dataclass(frozen=True, slots=True)
class CaptureReceipt:
    schema_version: Literal[1]
    classification: Literal["host_capture_only"]
    episode_id: str
    capture_id: str
    kind: CaptureKind
    role: CustodyRole
    controller_id: str
    source_observed_at: datetime
    collected_at: datetime
    sha256: str
    byte_count: int

    def as_json(self) -> dict[str, str | int]:
        return {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "episode_id": self.episode_id,
            "capture_id": self.capture_id,
            "kind": self.kind.value,
            "role": self.role,
            "controller_id": self.controller_id,
            "source_observed_at": self.source_observed_at.isoformat(),
            "collected_at": self.collected_at.isoformat(),
            "sha256": self.sha256,
            "byte_count": self.byte_count,
        }


@dataclass(frozen=True, slots=True)
class TrialCustodyCheck:
    classification: Literal["host_capture_set_only"]
    complete: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReviewedCustodyCheck:
    classification: Literal["host_review_capture_set_only"]
    complete: bool
    reason_codes: tuple[str, ...]


_TRIAL_SEQUENCE = (
    CaptureKind.PREFLIGHT,
    CaptureKind.RESET_READBACK,
    CaptureKind.CLEAN_ORACLE,
    CaptureKind.INJECTION_READBACK,
    CaptureKind.INJECTED_ORACLE,
    CaptureKind.ARM_TRACE,
    CaptureKind.AFTER_ARM_ORACLE,
    CaptureKind.RESET_READBACK,
    CaptureKind.AFTER_RESTORE_ORACLE,
)


def check_trial_custody(
    root: Path, receipts: tuple[CaptureReceipt, ...] | list[CaptureReceipt]
) -> TrialCustodyCheck:
    """Check one trial's host captures, without certifying any real-world source."""

    reasons: set[str] = set()
    kinds = tuple(receipt.kind for receipt in receipts)
    for kind in set(_TRIAL_SEQUENCE):
        if kinds.count(kind) < _TRIAL_SEQUENCE.count(kind):
            reasons.add(f"missing_{kind.value}")
    if kinds != _TRIAL_SEQUENCE:
        reasons.add("capture_sequence_invalid")
    if len({receipt.capture_id for receipt in receipts}) != len(receipts):
        reasons.add("capture_id_reused")
    if len({receipt.episode_id for receipt in receipts}) != 1:
        reasons.add("episode_mismatch")
    if any(not verify_capture(root, receipt) for receipt in receipts):
        reasons.add("capture_invalid")
    controllers = {
        role: {receipt.controller_id for receipt in receipts if receipt.role == role}
        for role in ("rig_sealed", "oracle", "arm")
    }
    controller_ids: set[str] = set()
    for ids in controllers.values():
        controller_ids.update(ids)
    if any(len(ids) != 1 for ids in controllers.values()) or len(controller_ids) != 3:
        reasons.add("controller_ids_not_distinct")
    if any(left.collected_at > right.collected_at for left, right in pairwise(receipts)):
        reasons.add("collection_order_invalid")
    if any(
        left.source_observed_at > right.source_observed_at for left, right in pairwise(receipts)
    ):
        reasons.add("source_order_invalid")
    return TrialCustodyCheck(
        classification="host_capture_set_only",
        complete=not reasons,
        reason_codes=tuple(sorted(reasons)),
    )


def check_review_custody(
    root: Path,
    trial_receipts: tuple[CaptureReceipt, ...] | list[CaptureReceipt],
    reviewer_receipt: CaptureReceipt,
) -> ReviewedCustodyCheck:
    """Require a separate post-trial review capture before reviewer custody closes.

    This checks host files and controller-ID separation, not reviewer identity,
    actual blinding, or whether a conclusion was correct.
    """

    reasons: set[str] = set()
    if not check_trial_custody(root, trial_receipts).complete:
        reasons.add("trial_custody_invalid")
    if (
        reviewer_receipt.kind is not CaptureKind.BLINDED_REVIEW
        or reviewer_receipt.role != "reviewer"
    ):
        reasons.add("review_capture_kind_invalid")
    if not verify_capture(root, reviewer_receipt):
        reasons.add("review_capture_invalid")
    if not trial_receipts or any(
        receipt.episode_id != reviewer_receipt.episode_id for receipt in trial_receipts
    ):
        reasons.add("review_episode_mismatch")
    if reviewer_receipt.controller_id in {receipt.controller_id for receipt in trial_receipts}:
        reasons.add("reviewer_controller_not_distinct")
    if trial_receipts and (
        reviewer_receipt.collected_at < trial_receipts[-1].collected_at
        or reviewer_receipt.source_observed_at < trial_receipts[-1].collected_at
    ):
        reasons.add("review_precedes_trial_completion")
    return ReviewedCustodyCheck(
        classification="host_review_capture_set_only",
        complete=not reasons,
        reason_codes=tuple(sorted(reasons)),
    )


def capture_bytes(
    root: Path,
    *,
    episode_id: str,
    capture_id: str,
    kind: CaptureKind,
    controller_id: str,
    source_observed_at: datetime,
    data: bytes,
    collected_at: datetime | None = None,
) -> CaptureReceipt:
    """Store one bounded raw capture and its receipt with exclusive file creation."""

    _check_id(episode_id, "episode_id")
    _check_id(capture_id, "capture_id")
    if not _CONTROLLER_ID.fullmatch(controller_id):
        raise CustodyError("invalid controller_id")
    if not 0 < len(data) <= _MAX_CAPTURE_BYTES:
        raise CustodyError("capture must contain 1 to 8388608 bytes")
    collection_time = collected_at or datetime.now(UTC)
    _require_utc(source_observed_at, "source_observed_at")
    _require_utc(collection_time, "collected_at")
    if source_observed_at > collection_time:
        raise CustodyError("source observation is later than host collection")

    role = _ROLE[kind]
    receipt = CaptureReceipt(
        schema_version=1,
        classification="host_capture_only",
        episode_id=episode_id,
        capture_id=capture_id,
        kind=kind,
        role=role,
        controller_id=controller_id,
        source_observed_at=source_observed_at,
        collected_at=collection_time,
        sha256=hashlib.sha256(data).hexdigest(),
        byte_count=len(data),
    )
    folder = _capture_folder(root, episode_id, role)
    if any(path.is_symlink() for path in (root, root / episode_id, folder)):
        raise CustodyError("custody path must not be a symbolic link")
    folder.mkdir(parents=True, exist_ok=True)
    if any(path.is_symlink() for path in (root, root / episode_id, folder)):
        raise CustodyError("custody path must not be a symbolic link")
    payload_path = folder / f"{capture_id}.bin"
    receipt_path = folder / f"{capture_id}.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        raise FileExistsError(f"capture already exists: {capture_id}")
    # A failed receipt write leaves an orphan payload. Exclusive creation makes
    # retries fail closed; the controller must investigate rather than reuse it.
    with payload_path.open("xb") as payload_file:
        payload_file.write(data)
    with receipt_path.open("x", encoding="utf-8", newline="\n") as receipt_file:
        json.dump(receipt.as_json(), receipt_file, sort_keys=True, separators=(",", ":"))
        receipt_file.write("\n")
    return receipt


def verify_capture(root: Path, receipt: CaptureReceipt) -> bool:
    """Check persisted receipt and payload against a caller-held capture receipt."""

    try:
        _check_id(receipt.episode_id, "episode_id")
        _check_id(receipt.capture_id, "capture_id")
        if receipt.role != _ROLE[receipt.kind]:
            return False
        folder = _capture_folder(root, receipt.episode_id, receipt.role)
        if any(path.is_symlink() for path in (root, root / receipt.episode_id, folder)):
            return False
        payload_path = folder / f"{receipt.capture_id}.bin"
        receipt_path = folder / f"{receipt.capture_id}.json"
        if payload_path.is_symlink() or receipt_path.is_symlink():
            return False
        with receipt_path.open("r", encoding="utf-8") as receipt_file:
            receipt_text = receipt_file.read(16_385)
        if len(receipt_text) > 16_384:
            return False
        stored = json.loads(receipt_text)
        if not 0 < receipt.byte_count <= _MAX_CAPTURE_BYTES:
            return False
        with payload_path.open("rb") as payload_file:
            data = payload_file.read(_MAX_CAPTURE_BYTES + 1)
    except (CustodyError, KeyError, OSError, ValueError, TypeError):
        return False
    return (
        stored == receipt.as_json()
        and len(data) == receipt.byte_count
        and hashlib.sha256(data).hexdigest() == receipt.sha256
    )


def _capture_folder(root: Path, episode_id: str, role: CustodyRole) -> Path:
    return root / episode_id / role


def _check_id(value: str, name: str) -> None:
    if _ID.fullmatch(value) is None:
        raise CustodyError(f"invalid {name}")


def _require_utc(value: datetime, name: str) -> None:
    if value.utcoffset() is None or value.utcoffset() != UTC.utcoffset(value):
        raise CustodyError(f"{name} must be UTC")
