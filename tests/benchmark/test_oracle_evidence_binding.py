"""Offline capture binding tests use invented bytes, not measured Windows episodes."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from benchmarks.lab_episodes import ArmKind, ArmSpec, LabTrial, OracleReading, TrialStatus
from benchmarks.oracle_evidence_binding import (
    EvidenceBindingError,
    bind_trial_evidence,
    oracle_capture_digest,
)
from benchmarks.vm_lab_contract import vm_record_digest
from benchmarks.vm_lab_custody import CaptureKind, CaptureReceipt, capture_bytes
from benchmarks.windows_scorecard import ArmOutcome, IndependentQualification, ReviewedArm

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)
EPISODE = "pdf-001"
ARM = ArmKind.KEYWORD_BASELINE
KINDS = (
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


def _bundle(
    tmp_path: Path,
    *,
    arm_kind: ArmKind = ARM,
    injected_capture_value: float | None = None,
    trace_leak: bool = False,
    collection_delay: timedelta = timedelta(0),
    review_collection_delay: timedelta = timedelta(0),
    wide_clean_span: bool = False,
    review_override: dict[str, object] | None = None,
    reviewed_at_override: datetime | None = None,
) -> tuple[list[CaptureReceipt], CaptureReceipt, LabTrial, ReviewedArm, IndependentQualification]:
    readings = {
        phase: tuple(
            OracleReading(
                value=value,
                observed_at=T0 + timedelta(seconds=position * 10 + sample),
                symptom_present=value > 100,
            )
            for sample, value in enumerate(values)
        )
        for position, (phase, values) in enumerate(
            (
                ("clean", (50.0, 51.0)),
                ("injected", (201.0, 202.0)),
                ("after_arm", (203.0, 204.0)),
                ("after_restore", (52.0, 53.0)),
            ),
            start=1,
        )
    }
    if wide_clean_span:
        readings["clean"] = (
            readings["clean"][0].model_copy(update={"observed_at": T0 - timedelta(minutes=3)}),
            readings["clean"][1],
        )
    trial = LabTrial(
        arm=ArmSpec(
            kind=arm_kind,
            warm_state="cold",
            profile_digest="a" * 64,
            decision_provider_id="keyword",
            reasoning_provider_id="deterministic",
        ),
        status=TrialStatus.VALID,
        clean=readings["clean"],
        injected=readings["injected"],
        after_arm=readings["after_arm"],
        after_restore=readings["after_restore"],
    )
    receipts: list[CaptureReceipt] = []
    oracle_kinds = {
        CaptureKind.CLEAN_ORACLE: "clean",
        CaptureKind.INJECTED_ORACLE: "injected",
        CaptureKind.AFTER_ARM_ORACLE: "after_arm",
        CaptureKind.AFTER_RESTORE_ORACLE: "after_restore",
    }
    rig_times = {0: 5, 1: 6, 3: 15, 7: 35}
    for index, kind in enumerate(KINDS):
        if kind in oracle_kinds:
            phase = oracle_kinds[kind]
            captured = [reading.model_dump(mode="json") for reading in readings[phase]]
            if phase == "injected" and injected_capture_value is not None:
                captured[0]["value"] = injected_capture_value
            payload = {
                "schema_version": 1,
                "episode_id": EPISODE,
                "arm_kind": arm_kind.value,
                "phase": phase,
                "readings": captured,
            }
            source_time = readings[phase][-1].observed_at
            controller = "oracle-controller"
        elif kind is CaptureKind.ARM_TRACE:
            payload: dict[str, object] = {
                "schema_version": 1,
                "episode_id": EPISODE,
                "arm_kind": arm_kind.value,
                "unverified_trace_sha256": "b" * 64,
            }
            if trace_leak:
                payload["sealed_oracle_values"] = [201.0, 202.0]
            source_time = T0 + timedelta(seconds=25)
            controller = "arm-controller"
        else:
            payload = {"rig_event": kind.value}
            source_time = T0 + timedelta(seconds=rig_times[index])
            controller = "rig-controller"
        receipts.append(
            capture_bytes(
                tmp_path,
                episode_id=EPISODE,
                capture_id=f"capture-{index}",
                kind=kind,
                controller_id=controller,
                source_observed_at=source_time,
                collected_at=T0 + timedelta(minutes=1, seconds=index) + collection_delay,
                data=json.dumps(payload, sort_keys=True).encode(),
            )
        )
    reviewed = ReviewedArm(
        kind=arm_kind,
        status=ArmOutcome.COMPLETED,
        warm_state="cold",
        access_digest="c" * 64,
        profile_digest=trial.arm.profile_digest,
        reset_proof_digest="d" * 64,
        vm_trial_digest=vm_record_digest(trial),
        wall_ms=40_000,
        claimed_cause_codes=(),
        cause_supported=False,
        claimed_fixed=False,
        repair_attempted=False,
        repair_appropriate=None,
        oracle_before=tuple(item.value for item in trial.injected),
        oracle_after=tuple(item.value for item in trial.after_arm),
        oracle_started_at=T0 + timedelta(seconds=19),
        oracle_before_finished_at=T0 + timedelta(seconds=22),
        oracle_after_started_at=T0 + timedelta(seconds=29),
        oracle_finished_at=T0 + timedelta(seconds=32),
        oracle_record_digest=oracle_capture_digest(receipts),
        recovery_reviewed=False,
    )
    reviewed_at = T0 + timedelta(minutes=2) + collection_delay
    reviewed_payload: dict[str, object] = reviewed.model_dump(mode="json")
    if review_override:
        reviewed_payload.update(review_override)
    review = capture_bytes(
        tmp_path,
        episode_id=EPISODE,
        capture_id="review",
        kind=CaptureKind.BLINDED_REVIEW,
        controller_id="reviewer-controller",
        source_observed_at=reviewed_at,
        collected_at=reviewed_at + review_collection_delay,
        data=json.dumps(
            {
                "schema_version": 1,
                "episode_id": EPISODE,
                "arm_kind": arm_kind.value,
                "reviewed_at": (reviewed_at_override or reviewed_at).isoformat(),
                "reviewed_arm": reviewed_payload,
            },
            sort_keys=True,
        ).encode(),
    )
    qualification = IndependentQualification(
        qualification_record_digest=review.sha256,
        rig_controller_id="rig-controller",
        oracle_controller_id="oracle-controller",
        reviewer_id="reviewer-controller",
        arm_executor_id="arm-controller",
    )
    return receipts, review, trial, reviewed, qualification


def test_binds_readback_to_trial_and_review_without_quality_claim(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    binding = bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)
    assert binding.schema_version == 1
    assert binding.classification == "host_evidence_binding_only"
    assert binding.episode_id == EPISODE
    assert binding.arm_kind is ARM
    assert binding.trace_digest_verified is False


def test_each_abc_arm_requires_its_own_consistent_capture_set(tmp_path: Path) -> None:
    digests: set[str] = set()
    for arm_kind in ArmKind:
        receipts, review, trial, reviewed, qualification = _bundle(
            tmp_path / arm_kind.value, arm_kind=arm_kind
        )
        binding = bind_trial_evidence(
            tmp_path / arm_kind.value, receipts, review, trial, reviewed, qualification
        )
        assert binding.arm_kind is arm_kind
        digests.add(binding.oracle_record_digest)
    assert len(digests) == 3


def test_rejects_tampered_or_missing_raw_capture(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    payload = tmp_path / EPISODE / "oracle" / "capture-4.bin"
    payload.write_bytes(b"tampered")
    with pytest.raises(EvidenceBindingError, match="custody"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)
    payload.unlink()
    with pytest.raises(EvidenceBindingError, match="custody"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


@pytest.mark.parametrize("change", ("role", "episode", "controller", "stale"))
def test_rejects_invalid_receipt_custody(tmp_path: Path, change: str) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    if change == "role":
        receipts[4] = replace(receipts[4], role="arm")
    elif change == "episode":
        receipts[4] = replace(receipts[4], episode_id="other-episode")
    elif change == "controller":
        receipts[4] = replace(receipts[4], controller_id="arm-controller")
    else:
        receipts[4] = replace(receipts[4], source_observed_at=T0 - timedelta(days=1))
    with pytest.raises(EvidenceBindingError):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


@pytest.mark.parametrize("change", ("value", "time", "digest", "trial_digest", "window"))
def test_rejects_mismatched_trial_or_review(tmp_path: Path, change: str) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    if change == "value":
        altered = trial.injected[0].model_copy(update={"value": 999.0})
        trial = trial.model_copy(update={"injected": (altered, *trial.injected[1:])})
    elif change == "time":
        altered = trial.after_arm[0].model_copy(update={"observed_at": T0})
        trial = trial.model_copy(update={"after_arm": (altered, *trial.after_arm[1:])})
    elif change == "digest":
        reviewed = reviewed.model_copy(update={"oracle_record_digest": "f" * 64})
    elif change == "trial_digest":
        reviewed = reviewed.model_copy(update={"vm_trial_digest": "f" * 64})
    else:
        reviewed = reviewed.model_copy(
            update={"oracle_after_started_at": T0 + timedelta(seconds=32)}
        )
    with pytest.raises(EvidenceBindingError):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_trace_payload_with_sealed_oracle_fields(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path, trace_leak=True)
    with pytest.raises(EvidenceBindingError, match="trace envelope"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_sealed_oracle_value_change_even_when_receipt_matches(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, injected_capture_value=999.0
    )
    with pytest.raises(EvidenceBindingError, match="injected oracle capture mismatch"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_stale_capture_with_intact_receipts(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, collection_delay=timedelta(minutes=10)
    )
    with pytest.raises(EvidenceBindingError, match="stale"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_stale_review_capture_with_intact_receipt(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, review_collection_delay=timedelta(minutes=10)
    )
    with pytest.raises(EvidenceBindingError, match="stale"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_negative_collection_lag_with_matching_receipt_files(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    forged: list[CaptureReceipt] = []
    for receipt in receipts:
        changed = replace(receipt, collected_at=receipt.source_observed_at - timedelta(seconds=1))
        receipt_path = tmp_path / EPISODE / receipt.role / f"{receipt.capture_id}.json"
        receipt_path.write_text(json.dumps(changed.as_json()), encoding="utf-8")
        forged.append(changed)
    reviewed = reviewed.model_copy(update={"oracle_record_digest": oracle_capture_digest(forged)})
    with pytest.raises(EvidenceBindingError, match="collection lag"):
        bind_trial_evidence(tmp_path, forged, review, trial, reviewed, qualification)


def test_rejects_wide_oracle_sample_span(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path, wide_clean_span=True)
    with pytest.raises(EvidenceBindingError, match="sample span"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


@pytest.mark.parametrize(
    "review_override",
    (
        {"cause_supported": True},
        {"supported_answer_at": (T0 + timedelta(seconds=26)).isoformat()},
    ),
)
def test_rejects_review_judgment_or_timestamp_mismatch_with_intact_capture(
    tmp_path: Path, review_override: dict[str, object]
) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, review_override=review_override
    )
    with pytest.raises(EvidenceBindingError, match="reviewed arm mismatch"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_review_observation_time_that_disagrees_with_receipt(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, reviewed_at_override=T0 + timedelta(minutes=3)
    )
    with pytest.raises(EvidenceBindingError, match="reviewed arm mismatch"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_tampered_review_bytes(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    (tmp_path / EPISODE / "reviewer" / "review.bin").write_bytes(b"tampered")
    with pytest.raises(EvidenceBindingError, match="custody"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_reused_or_unmatched_review_capture(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    with pytest.raises(EvidenceBindingError):
        bind_trial_evidence(
            tmp_path,
            receipts,
            review,
            trial,
            reviewed,
            qualification.model_copy(update={"qualification_record_digest": "e" * 64}),
        )
    with pytest.raises(EvidenceBindingError):
        bind_trial_evidence(tmp_path, receipts, receipts[-1], trial, reviewed, qualification)
