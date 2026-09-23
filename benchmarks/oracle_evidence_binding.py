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

from benchmarks.lab_episodes import ArmKind, LabModel, LabTrial, NumericRule, OracleReading
from benchmarks.vm_lab_contract import vm_record_digest
from benchmarks.vm_lab_custody import (
    CaptureKind,
    CaptureReceipt,
    check_review_custody,
    verify_capture,
)
from benchmarks.windows_scorecard import (
    IndependentQualification,
    ReviewedArm,
    ReviewedWindowsEpisode,
)

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


class ArmReviewRecordV1(LabModel):
    arm_kind: ArmKind
    capture_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class EpisodeQualificationCaptureV1(LabModel):
    """One host-captured episode record listing the three arm review receipts."""

    schema_version: Literal[1]
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    qualified_at: datetime
    scenario_id: str = Field(min_length=3, max_length=120)
    fault_recipe_id: str = Field(min_length=3, max_length=120)
    sealed_cause_codes: tuple[str, ...] = Field(max_length=12)
    expected_symptom: bool
    oracle_rule: NumericRule
    common_budget_ms: int = Field(ge=100, le=600_000)
    arm_reviews: tuple[ArmReviewRecordV1, ...] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def valid_review_set(self) -> Self:
        if self.qualified_at.utcoffset() != timedelta(0):
            raise ValueError("qualification time must be UTC")
        if {item.arm_kind for item in self.arm_reviews} != set(ArmKind):
            raise ValueError("qualification requires distinct A/B/C review records")
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


@dataclass(frozen=True, slots=True)
class TrialCaptureSet:
    receipts: tuple[CaptureReceipt, ...]
    reviewer_receipt: CaptureReceipt
    trial: LabTrial


@dataclass(frozen=True, slots=True)
class HostEpisodeBinding:
    schema_version: Literal[1]
    classification: Literal["host_episode_binding_only"]
    episode_id: str
    qualification_record_digest: str
    arms: tuple[HostEvidenceBinding, ...]
    diagnostic_accuracy_claim: Literal[False]
    scorecard_bound: Literal[False]


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
        _check_collection_lag(receipt)
    episode_id = reviewer_receipt.episode_id
    controllers = {receipt.role: receipt.controller_id for receipt in receipts}
    if (
        qualification.rig_controller_id != controllers["rig_sealed"]
        or qualification.oracle_controller_id != controllers["oracle"]
        or qualification.arm_executor_id != controllers["arm"]
        or qualification.reviewer_id != reviewer_receipt.controller_id
    ):
        raise EvidenceBindingError("qualification controller mismatch")
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


def bind_episode_evidence(
    root: Path,
    episode: ReviewedWindowsEpisode,
    capture_sets: tuple[TrialCaptureSet, ...],
    qualification_receipt: CaptureReceipt | None,
) -> HostEpisodeBinding:
    """Bind three VM arm capture sets to one separate host qualification record.

    The result is still host consistency only. It does not invoke or upgrade the
    standalone scorecard, authenticate a reviewer, or prove that a VM ran.
    """

    try:
        episode = ReviewedWindowsEpisode.model_validate(episode.model_dump(mode="json"))
    except ValueError as error:
        raise EvidenceBindingError("reviewed episode is invalid") from error
    if episode.source != "independent_windows_vm":
        raise EvidenceBindingError("host VM capture binding requires a VM episode")
    if qualification_receipt is None:
        raise EvidenceBindingError("episode qualification capture is missing")
    if len(capture_sets) != 3 or {item.trial.arm.kind for item in capture_sets} != set(ArmKind):
        raise EvidenceBindingError("exactly one capture set per A/B/C arm is required")
    arms_by_kind = {arm.kind: arm for arm in episode.arms}
    if len(arms_by_kind) != 3 or set(arms_by_kind) != set(ArmKind):
        raise EvidenceBindingError("reviewed episode arm set is invalid")
    if (
        len({arm.access_digest for arm in episode.arms}) != 1
        or len({arm.warm_state for arm in episode.arms}) != 1
        or len({arm.reset_proof_digest for arm in episode.arms}) != 3
    ):
        raise EvidenceBindingError("reviewed arms are not matched")

    all_receipts = [qualification_receipt]
    for item in capture_sets:
        all_receipts.extend(item.receipts)
        all_receipts.append(item.reviewer_receipt)
    identities = {(r.episode_id, r.role, r.capture_id) for r in all_receipts}
    if len(identities) != len(all_receipts):
        raise EvidenceBindingError("capture receipt reused across arms")

    if (
        qualification_receipt.kind is not CaptureKind.BLINDED_REVIEW
        or qualification_receipt.role != "reviewer"
        or qualification_receipt.episode_id != episode.episode_id
        or qualification_receipt.controller_id != episode.qualification.reviewer_id
        or qualification_receipt.sha256 != episode.qualification.qualification_record_digest
        or not verify_capture(root, qualification_receipt)
    ):
        raise EvidenceBindingError("episode qualification receipt mismatch")
    _check_collection_lag(qualification_receipt)
    if qualification_receipt.source_observed_at < max(
        item.reviewer_receipt.collected_at for item in capture_sets
    ):
        raise EvidenceBindingError("episode qualification precedes arm reviews")
    try:
        qualified = EpisodeQualificationCaptureV1.model_validate_json(
            _read_typed_capture(root, qualification_receipt)
        )
    except ValueError as error:
        raise EvidenceBindingError("episode qualification capture is invalid") from error
    expected_reviews = {
        item.trial.arm.kind: (item.reviewer_receipt.capture_id, item.reviewer_receipt.sha256)
        for item in capture_sets
    }
    observed_reviews = {
        item.arm_kind: (item.capture_id, item.sha256) for item in qualified.arm_reviews
    }
    if (
        qualified.episode_id != episode.episode_id
        or qualified.qualified_at != qualification_receipt.source_observed_at
        or qualified.scenario_id != episode.scenario_id
        or qualified.fault_recipe_id != episode.fault_recipe_id
        or qualified.sealed_cause_codes != episode.sealed_cause_codes
        or qualified.expected_symptom != episode.expected_symptom
        or qualified.oracle_rule != episode.oracle_rule
        or qualified.common_budget_ms != episode.common_budget_ms
        or observed_reviews != expected_reviews
    ):
        raise EvidenceBindingError("episode qualification arm reviews mismatch")

    bindings: dict[ArmKind, HostEvidenceBinding] = {}
    for item in capture_sets:
        kind = item.trial.arm.kind
        binding = bind_trial_evidence(
            root,
            item.receipts,
            item.reviewer_receipt,
            item.trial,
            arms_by_kind[kind],
            episode.qualification,
        )
        if binding.episode_id != episode.episode_id:
            raise EvidenceBindingError("arm capture episode mismatch")
        bindings[kind] = binding
    return HostEpisodeBinding(
        schema_version=1,
        classification="host_episode_binding_only",
        episode_id=episode.episode_id,
        qualification_record_digest=qualification_receipt.sha256,
        arms=tuple(bindings[kind] for kind in ArmKind),
        diagnostic_accuracy_claim=False,
        scorecard_bound=False,
    )


def _check_collection_lag(receipt: CaptureReceipt) -> None:
    lag = receipt.collected_at - receipt.source_observed_at
    if lag < timedelta(0):
        raise EvidenceBindingError("capture collection lag is negative")
    if lag > _MAX_CAPTURE_COLLECTION_LAG:
        raise EvidenceBindingError("stale capture")


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
