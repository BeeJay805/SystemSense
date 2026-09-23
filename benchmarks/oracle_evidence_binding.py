"""Bind raw host captures to submitted oracle readings, without authenticating their issuer.

The capture root belongs to the benchmark controller, never an investigator arm.
This adapter checks stored bytes and record consistency only. A separate trusted
rig and reviewer must authenticate the source before any performance claim.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import Field, model_validator

from benchmarks.lab_episodes import (
    ArmKind,
    ArmResult,
    ArmSpec,
    LabModel,
    LabTrial,
    NumericRule,
    OracleReading,
    TrialStatus,
)
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
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.evaluation.models import EpisodeArtifact, MeasurementSource
from systemsense.orchestration.probes import ProbeRunStatus

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


class ArmResultCaptureV2(LabModel):
    """Stored arm result summary, not underlying probe or model event logs."""

    schema_version: Literal[2]
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    arm_kind: ArmKind
    arm: ArmSpec
    status: TrialStatus
    arm_elapsed_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    arm_result: ArmResult | None
    error_type: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def status_matches_arm_execution(self) -> Self:
        _validate_arm_execution(self.status, self.arm_elapsed_ms, self.arm_result, self.error_type)
        return self


def _validate_arm_execution(
    status: TrialStatus,
    elapsed_ms: float | None,
    result: ArmResult | None,
    error_type: str | None,
) -> None:
    if status is TrialStatus.VALID and (
        result is None or elapsed_ms is None or error_type is not None
    ):
        raise ValueError("valid trial requires an arm result, elapsed time, and no error")
    if status is TrialStatus.ARM_TIMEOUT and (
        elapsed_ms is None or error_type != "ArmBudgetExceeded"
    ):
        raise ValueError("arm timeout requires elapsed time and budget error")
    if status is TrialStatus.ARM_ERROR and (elapsed_ms is None or error_type is None):
        raise ValueError("arm error requires elapsed time and error type")
    if status in {
        TrialStatus.INVALID_BASELINE,
        TrialStatus.INVALID_INJECTION,
        TrialStatus.INJECTION_ERROR,
    } and (elapsed_ms is not None or result is not None):
        raise ValueError("pre-arm failure cannot contain an arm result or elapsed time")


class ProbeTraceEventV1(LabModel):
    kind: Literal["probe"]
    event_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,119}$")
    observed_at: datetime
    probe_id: str = Field(min_length=1, max_length=120)
    status: ProbeRunStatus


class ProviderTraceEventV1(LabModel):
    """One configured wrapper call and the provider whose response took effect, if any."""

    kind: Literal["provider"]
    event_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,119}$")
    observed_at: datetime
    role: Literal["decision", "reasoning"]
    attempted_provider_id: str = Field(min_length=1, max_length=80)
    effective_provider_id: str | None = Field(min_length=1, max_length=80)
    failed: bool = Field(strict=True)


class EvidenceTraceEventV1(LabModel):
    kind: Literal["evidence"]
    event_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,119}$")
    observed_at: datetime


class CoverageTraceEventV1(LabModel):
    kind: Literal["coverage"]
    event_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,119}$")
    observed_at: datetime


class TerminalTraceEventV1(LabModel):
    kind: Literal["terminal"]
    event_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,119}$")
    observed_at: datetime
    status: InvestigationStatus
    outcome: InvestigationOutcome


type CoordinatorTraceEventV1 = Annotated[
    ProbeTraceEventV1
    | ProviderTraceEventV1
    | EvidenceTraceEventV1
    | CoverageTraceEventV1
    | TerminalTraceEventV1,
    Field(discriminator="kind"),
]


class CoordinatorEventLogV1(LabModel):
    """Bounded event projections; capture bytes still need trusted external provenance."""

    schema_version: Literal[1]
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    events: tuple[CoordinatorTraceEventV1, ...] = Field(min_length=1, max_length=512)


class ArmResultCaptureV3(LabModel):
    """Schema-3 capture adds typed events; schema-2 summary captures stay readable."""

    schema_version: Literal[3]
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    arm_kind: ArmKind
    arm: ArmSpec
    status: TrialStatus
    arm_elapsed_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    arm_result: ArmResult | None
    error_type: str | None = Field(default=None, max_length=120)
    event_log: CoordinatorEventLogV1

    @model_validator(mode="after")
    def status_matches_arm_execution(self) -> Self:
        _validate_arm_execution(self.status, self.arm_elapsed_ms, self.arm_result, self.error_type)
        return self


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
    """Schema-2 binding with optional additive event-log consistency metadata."""

    schema_version: Literal[2]
    classification: Literal["host_evidence_binding_only"]
    episode_id: str
    arm_kind: ArmKind
    oracle_record_digest: str
    trial_digest: str
    review_capture_digest: str
    arm_result_capture_digest: str
    arm_result_capture_verified: bool
    trace_digest_verified: Literal[False]
    event_log_consistency_verified: bool = False
    event_log_digest: str | None = None


@dataclass(frozen=True, slots=True)
class TrialCaptureSet:
    receipts: tuple[CaptureReceipt, ...]
    reviewer_receipt: CaptureReceipt
    trial: LabTrial


@dataclass(frozen=True, slots=True)
class HostEpisodeBinding:
    schema_version: Literal[2]
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

    arm_result_capture_digest: str | None = None
    event_log_digest: str | None = None
    for receipt in receipts:
        if receipt.kind not in _PHASES and receipt.kind is not CaptureKind.ARM_TRACE:
            continue
        payload = _read_typed_capture(root, receipt)
        if receipt.kind is CaptureKind.ARM_TRACE:
            version: object = None
            try:
                raw_capture: object = json.loads(payload)
                if type(raw_capture) is not dict:
                    raise ValueError("arm result capture must be an object")
                data = cast(dict[str, object], raw_capture)
                version = data.get("schema_version")
                if type(version) is not int or version not in (2, 3):
                    raise ValueError("unsupported arm result capture version")
                capture = (
                    ArmResultCaptureV3.model_validate(data)
                    if version == 3
                    else ArmResultCaptureV2.model_validate(data)
                )
            except ValueError as error:
                label = "event log or arm result capture" if version == 3 else "arm result capture"
                raise EvidenceBindingError(f"{label} is invalid") from error
            if (
                capture.episode_id != episode_id
                or capture.arm_kind != trial.arm.kind
                or capture.arm != trial.arm
                or capture.status != trial.status
                or capture.arm_elapsed_ms != trial.arm_elapsed_ms
                or capture.arm_result != trial.arm_result
                or capture.error_type != trial.error_type
            ):
                raise EvidenceBindingError("arm result capture does not match trial")
            if isinstance(capture, ArmResultCaptureV3):
                episode = trial.arm_result.episode if trial.arm_result is not None else None
                if episode is None:
                    raise EvidenceBindingError("event log requires a measured coordinator episode")
                _verify_coordinator_events(capture.event_log, episode, trial, receipt)
                encoded = json.dumps(
                    capture.event_log.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                event_log_digest = hashlib.sha256(encoded).hexdigest()
            arm_result_capture_digest = receipt.sha256
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
    if arm_result_capture_digest is None:
        raise EvidenceBindingError("arm result capture is missing")
    return HostEvidenceBinding(
        schema_version=2,
        classification="host_evidence_binding_only",
        episode_id=episode_id,
        arm_kind=trial.arm.kind,
        oracle_record_digest=digest,
        trial_digest=vm_record_digest(trial),
        review_capture_digest=reviewer_receipt.sha256,
        arm_result_capture_digest=arm_result_capture_digest,
        arm_result_capture_verified=trial.arm_result is not None,
        trace_digest_verified=False,
        event_log_consistency_verified=event_log_digest is not None,
        event_log_digest=event_log_digest,
    )


def _verify_coordinator_events(
    event_log: CoordinatorEventLogV1,
    episode: EpisodeArtifact,
    trial: LabTrial,
    receipt: CaptureReceipt,
) -> None:
    events = event_log.events
    times = tuple(event.observed_at for event in events)
    if (
        event_log.case_id != str(episode.case_id)
        or episode.measurement_source is not MeasurementSource.LIVE
        or episode.synthetic
        or trial.arm_elapsed_ms is None
        or episode.elapsed_ms > trial.arm_elapsed_ms
        or not trial.injected
        or not trial.after_arm
        or not trial.injected[-1].observed_at
        <= episode.started_at
        <= episode.finished_at
        <= receipt.source_observed_at
        <= trial.after_arm[0].observed_at
        or any(stamp.utcoffset() != timedelta(0) for stamp in times)
        or times != tuple(sorted(times))
        or any(not episode.started_at <= stamp <= episode.finished_at for stamp in times)
        or len({event.event_id for event in events}) != len(events)
        or not isinstance(events[-1], TerminalTraceEventV1)
        or sum(isinstance(event, TerminalTraceEventV1) for event in events) != 1
    ):
        raise EvidenceBindingError("event log identity, order, or trial window is invalid")
    probes = [event for event in events if isinstance(event, ProbeTraceEventV1)]
    providers = [event for event in events if isinstance(event, ProviderTraceEventV1)]
    evidence = [event for event in events if isinstance(event, EvidenceTraceEventV1)]
    coverage = [event for event in events if isinstance(event, CoverageTraceEventV1)]
    terminal = events[-1]
    assert isinstance(terminal, TerminalTraceEventV1)
    statuses = Counter(event.status for event in probes)
    expected_statuses = {key: count for key, count in episode.probe_status_counts.items() if count}
    if (
        Counter(event.probe_id for event in probes) != Counter(episode.attempted_probe_ids)
        or dict(statuses) != expected_statuses
        or len(probes) != episode.probe_attempts.total
        or sum(event.status is not ProbeRunStatus.OK for event in probes)
        != episode.probe_attempts.failures
        or len(evidence) != episode.evidence_count
        or len(coverage) != episode.coverage_count
        or terminal.status != episode.terminal_status
        or terminal.outcome != episode.terminal_outcome
    ):
        raise EvidenceBindingError("event log does not match coordinator episode")
    for measurement in (episode.decision, episode.reasoning):
        actual = [event for event in providers if event.role == measurement.role]
        effective = next(
            (
                event.effective_provider_id
                for event in reversed(actual)
                if event.effective_provider_id
            ),
            None,
        )
        if (
            len(actual) != measurement.calls
            or sum(event.failed for event in actual) != measurement.failures
            or any(event.attempted_provider_id != measurement.provider_id for event in actual)
            or effective != measurement.effective_provider_id
        ):
            raise EvidenceBindingError("event log provider calls do not match coordinator episode")


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
        schema_version=2,
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
