"""Bind raw host captures to submitted oracle readings, without authenticating their issuer.

The capture root belongs to the benchmark controller, never an investigator arm.
This adapter checks stored bytes and record consistency only. A separate trusted
rig and reviewer must authenticate the source before any performance claim.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from benchmarks.lab_episodes import ArmKind, LabModel, LabTrial, OracleReading
from benchmarks.vm_lab_contract import vm_record_digest
from benchmarks.vm_lab_custody import (
    CaptureKind,
    CaptureReceipt,
    check_review_custody,
)
from benchmarks.windows_scorecard import IndependentQualification, ReviewedArm

_MAX_TYPED_CAPTURE_BYTES = 64 * 1024
_MAX_CAPTURE_COLLECTION_LAG = timedelta(minutes=5)
_MAX_ORACLE_SAMPLE_SPAN = timedelta(minutes=2)
_PHASES: dict[CaptureKind, Literal["clean", "injected", "after_arm", "after_restore"]] = {
    CaptureKind.CLEAN_ORACLE: "clean",
    CaptureKind.INJECTED_ORACLE: "injected",
    CaptureKind.AFTER_ARM_ORACLE: "after_arm",
    CaptureKind.AFTER_RESTORE_ORACLE: "after_restore",
}


class EvidenceBindingError(ValueError):
    """Raw host custody and submitted episode records do not agree."""


class OracleCaptureV1(LabModel):
    schema_version: Literal[1]
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    arm_kind: ArmKind
    phase: Literal["clean", "injected", "after_arm", "after_restore"]
    readings: tuple[OracleReading, ...] = Field(min_length=2, max_length=10)

    @model_validator(mode="after")
    def ordered_utc_readings(self) -> Self:
        times = tuple(reading.observed_at for reading in self.readings)
        if any(stamp.utcoffset() != timedelta(0) for stamp in times):
            raise ValueError("oracle readings must have UTC timestamps")
        if times != tuple(sorted(times)):
            raise ValueError("oracle readings must be ordered")
        return self


class ArmTraceEnvelopeV1(LabModel):
    """Digest-only envelope; the referenced raw trace is not verified here."""

    schema_version: Literal[1]
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    arm_kind: ArmKind
    unverified_trace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReviewCaptureV1(LabModel):
    """Host-captured reviewer assertions, not proof of reviewer identity or blinding."""

    schema_version: Literal[1]
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    arm_kind: ArmKind
    reviewed_at: datetime
    reviewed_arm: ReviewedArm

    @model_validator(mode="after")
    def utc_review_time(self) -> Self:
        if self.reviewed_at.utcoffset() != timedelta(0):
            raise ValueError("review time must be UTC")
        return self


@dataclass(frozen=True, slots=True)
class HostEvidenceBinding:
    schema_version: Literal[1]
    classification: Literal["host_evidence_binding_only"]
    episode_id: str
    arm_kind: ArmKind
    oracle_record_digest: str
    trial_digest: str
    review_capture_digest: str
    trace_digest_verified: Literal[False]


def oracle_capture_digest(receipts: list[CaptureReceipt] | tuple[CaptureReceipt, ...]) -> str:
    """Canonical receipt-set identity, checked against raw readback during binding."""

    oracle = [receipt.as_json() for receipt in receipts if receipt.kind in _PHASES]
    encoded = json.dumps(oracle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def bind_trial_evidence(
    root: Path,
    receipts: list[CaptureReceipt] | tuple[CaptureReceipt, ...],
    reviewer_receipt: CaptureReceipt,
    trial: LabTrial,
    reviewed: ReviewedArm,
    qualification: IndependentQualification,
) -> HostEvidenceBinding:
    """Verify a full host capture set against one trial and one reviewed arm."""

    custody = check_review_custody(root, receipts, reviewer_receipt)
    if not custody.complete:
        raise EvidenceBindingError(f"capture custody invalid: {','.join(custody.reason_codes)}")
    for receipt in (*receipts, reviewer_receipt):
        lag = receipt.collected_at - receipt.source_observed_at
        if lag < timedelta(0):
            raise EvidenceBindingError("capture collection lag is negative")
        if lag > _MAX_CAPTURE_COLLECTION_LAG:
            raise EvidenceBindingError("stale capture")
    episode_id = reviewer_receipt.episode_id
    controllers = {receipt.role: receipt.controller_id for receipt in receipts}
    if (
        qualification.rig_controller_id != controllers["rig_sealed"]
        or qualification.oracle_controller_id != controllers["oracle"]
        or qualification.arm_executor_id != controllers["arm"]
        or qualification.reviewer_id != reviewer_receipt.controller_id
        or qualification.qualification_record_digest != reviewer_receipt.sha256
    ):
        raise EvidenceBindingError("qualification receipt or controller mismatch")
    if (
        reviewed.kind != trial.arm.kind
        or reviewed.warm_state != trial.arm.warm_state
        or reviewed.profile_digest != trial.arm.profile_digest
        or reviewed.vm_trial_digest != vm_record_digest(trial)
    ):
        raise EvidenceBindingError("reviewed arm does not bind the trial")
    digest = oracle_capture_digest(receipts)
    if reviewed.oracle_record_digest != digest:
        raise EvidenceBindingError("reviewed oracle digest does not bind captures")
    if (
        reviewed.oracle_before != tuple(reading.value for reading in trial.injected)
        or reviewed.oracle_after != tuple(reading.value for reading in trial.after_arm)
        or not trial.injected
        or not trial.after_arm
        or not reviewed.oracle_started_at
        <= trial.injected[0].observed_at
        <= trial.injected[-1].observed_at
        <= reviewed.oracle_before_finished_at
        or not reviewed.oracle_after_started_at
        <= trial.after_arm[0].observed_at
        <= trial.after_arm[-1].observed_at
        <= reviewed.oracle_finished_at
    ):
        raise EvidenceBindingError("reviewed oracle values or window mismatch")

    for receipt in receipts:
        if receipt.kind not in _PHASES and receipt.kind is not CaptureKind.ARM_TRACE:
            continue
        payload = _read_typed_capture(root, receipt)
        if receipt.kind is CaptureKind.ARM_TRACE:
            try:
                envelope = ArmTraceEnvelopeV1.model_validate_json(payload)
            except ValueError as error:
                raise EvidenceBindingError("arm trace envelope is invalid") from error
            if envelope.episode_id != episode_id or envelope.arm_kind != trial.arm.kind:
                raise EvidenceBindingError("arm trace identity mismatch")
            continue
        phase = _PHASES[receipt.kind]
        try:
            capture = OracleCaptureV1.model_validate_json(payload)
        except ValueError as error:
            raise EvidenceBindingError(f"{phase} oracle payload is invalid") from error
        if (
            capture.readings[-1].observed_at - capture.readings[0].observed_at
            > _MAX_ORACLE_SAMPLE_SPAN
        ):
            raise EvidenceBindingError(f"{phase} oracle sample span exceeded")
        if (
            capture.episode_id != episode_id
            or capture.arm_kind != trial.arm.kind
            or capture.phase != phase
            or capture.readings != getattr(trial, phase)
            or capture.readings[-1].observed_at != receipt.source_observed_at
        ):
            raise EvidenceBindingError(f"{phase} oracle capture mismatch")
    review_payload = _read_typed_capture(root, reviewer_receipt)
    try:
        captured_review = ReviewCaptureV1.model_validate_json(review_payload)
    except ValueError as error:
        raise EvidenceBindingError("review capture is invalid") from error
    if (
        captured_review.episode_id != episode_id
        or captured_review.arm_kind != trial.arm.kind
        or captured_review.reviewed_at != reviewer_receipt.source_observed_at
        or captured_review.reviewed_arm != reviewed
    ):
        raise EvidenceBindingError("reviewed arm mismatch with captured review")
    return HostEvidenceBinding(
        schema_version=1,
        classification="host_evidence_binding_only",
        episode_id=episode_id,
        arm_kind=trial.arm.kind,
        oracle_record_digest=digest,
        trial_digest=vm_record_digest(trial),
        review_capture_digest=reviewer_receipt.sha256,
        trace_digest_verified=False,
    )


def _read_typed_capture(root: Path, receipt: CaptureReceipt) -> bytes:
    episode_path = root / receipt.episode_id
    folder = episode_path / receipt.role
    path = folder / f"{receipt.capture_id}.bin"
    try:
        if any(item.is_symlink() for item in (root, episode_path, folder, path)):
            raise EvidenceBindingError("capture path is a symbolic link")
        with path.open("rb") as capture_file:
            payload = capture_file.read(_MAX_TYPED_CAPTURE_BYTES + 1)
    except OSError as error:
        raise EvidenceBindingError("capture readback failed") from error
    if (
        len(payload) > _MAX_TYPED_CAPTURE_BYTES
        or len(payload) != receipt.byte_count
        or hashlib.sha256(payload).hexdigest() != receipt.sha256
    ):
        raise EvidenceBindingError("capture readback digest or size mismatch")
    return payload
