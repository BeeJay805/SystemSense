"""Offline capture binding tests use invented bytes, not measured Windows episodes."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from benchmarks.lab_episodes import (
    ArmKind,
    ArmResult,
    ArmSpec,
    LabTrial,
    NumericRule,
    OracleReading,
    TrialStatus,
)
from benchmarks.oracle_evidence_binding import (
    EvidenceBindingError,
    TrialCaptureSet,
    bind_episode_evidence,
    bind_trial_evidence,
    oracle_capture_digest,
)
from benchmarks.vm_lab_contract import vm_record_digest
from benchmarks.vm_lab_custody import CaptureKind, CaptureReceipt, capture_bytes
from benchmarks.windows_scorecard import (
    ArmOutcome,
    IndependentQualification,
    ReviewedArm,
    ReviewedWindowsEpisode,
)
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.domain.ids import CaseId
from systemsense.evaluation.models import (
    EpisodeArtifact,
    EvaluationMode,
    FailureCount,
    MeasurementSource,
    ProviderMeasurement,
)
from systemsense.orchestration.probes import ProbeRunStatus

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)
EPISODE = "pdf-001"
SCENARIO = "lab.vm.synthetic"
FAULT_RECIPE = "vm.synthetic.v1"
CAUSES = ("synthetic_contention",)
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
    missing_arm_result: bool = False,
    missing_arm_elapsed: bool = False,
    trial_status: TrialStatus = TrialStatus.VALID,
    trace_padding: int = 0,
    collection_delay: timedelta = timedelta(0),
    review_collection_delay: timedelta = timedelta(0),
    wide_clean_span: bool = False,
    review_override: dict[str, object] | None = None,
    reviewed_at_override: datetime | None = None,
    capture_prefix: str = "",
    arm_episode: EpisodeArtifact | None = None,
    trace_events: list[dict[str, object]] | None = None,
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
        status=trial_status,
        arm_elapsed_ms=(
            None
            if missing_arm_elapsed
            or trial_status in {TrialStatus.INVALID_BASELINE, TrialStatus.INVALID_INJECTION}
            else 1_000.0
        ),
        arm_result=(
            ArmResult(claimed_fixed=False, episode=arm_episode)
            if trial_status is TrialStatus.VALID and not missing_arm_result
            else None
        ),
        error_type=(
            "ArmBudgetExceeded"
            if trial_status is TrialStatus.ARM_TIMEOUT
            else "RuntimeError"
            if trial_status is TrialStatus.ARM_ERROR
            else None
        ),
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
                "schema_version": 3 if trace_events is not None else 2,
                "episode_id": EPISODE,
                "arm_kind": arm_kind.value,
                "arm": trial.arm.model_dump(mode="json"),
                "status": trial.status.value,
                "arm_elapsed_ms": trial.arm_elapsed_ms,
                "arm_result": (
                    trial.arm_result.model_dump(mode="json") if trial.arm_result else None
                ),
                "error_type": trial.error_type,
            }
            if trace_events is not None:
                payload["event_log"] = {
                    "schema_version": 1,
                    "case_id": str(arm_episode.case_id) if arm_episode else "case_" + "a" * 32,
                    "events": trace_events,
                }
            if trace_leak:
                payload["sealed_oracle_values"] = [201.0, 202.0]
            if trace_padding:
                payload["padding"] = "x" * trace_padding
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
                capture_id=f"{capture_prefix}capture-{index}",
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
        reset_proof_digest=f"{list(ArmKind).index(arm_kind) + 1:x}" * 64,
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
        capture_id=f"{capture_prefix}review",
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


def _coordinator_episode() -> EpisodeArtifact:
    return EpisodeArtifact(
        scenario_id=SCENARIO,
        measurement_source=MeasurementSource.LIVE,
        synthetic=False,
        mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
        case_id=CaseId(root="case_" + "a" * 32),
        objective="Diagnose the lab symptom",
        budget_ms=60_000,
        max_rounds=2,
        max_probes=2,
        started_at=T0 + timedelta(seconds=23),
        finished_at=T0 + timedelta(seconds=24),
        elapsed_ms=1_000,
        attempted_probe_ids=("network.snapshot",),
        skipped_probe_ids=(),
        probe_attempts=FailureCount(failures=0, total=1),
        probe_status_counts={ProbeRunStatus.OK: 1},
        evidence_count=1,
        coverage_count=0,
        decision=ProviderMeasurement(
            role="decision",
            provider_id="keyword",
            effective_provider_id="keyword",
            calls=1,
            failures=0,
        ),
        reasoning=ProviderMeasurement(
            role="reasoning",
            provider_id="deterministic",
            calls=0,
            failures=0,
        ),
        terminal_status=InvestigationStatus.COMPLETE,
        terminal_outcome=InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
    )


def _coordinator_events() -> list[dict[str, object]]:
    return [
        {
            "kind": "probe",
            "event_id": "exec-1",
            "observed_at": (T0 + timedelta(seconds=23, milliseconds=100)).isoformat(),
            "probe_id": "network.snapshot",
            "status": "ok",
        },
        {
            "kind": "evidence",
            "event_id": "ev-1",
            "observed_at": (T0 + timedelta(seconds=23, milliseconds=200)).isoformat(),
        },
        {
            "kind": "provider",
            "event_id": "call-1",
            "observed_at": (T0 + timedelta(seconds=23, milliseconds=300)).isoformat(),
            "role": "decision",
            "attempted_provider_id": "keyword",
            "effective_provider_id": "keyword",
            "failed": False,
        },
        {
            "kind": "terminal",
            "event_id": "end-1",
            "observed_at": (T0 + timedelta(seconds=24)).isoformat(),
            "status": "complete",
            "outcome": "insufficient_observability",
        },
    ]


def _episode_bundle(
    root: Path,
) -> tuple[ReviewedWindowsEpisode, tuple[TrialCaptureSet, ...], CaptureReceipt]:
    sets: list[TrialCaptureSet] = []
    arms: list[ReviewedArm] = []
    for arm_kind in ArmKind:
        receipts, review, trial, reviewed, _ = _bundle(
            root, arm_kind=arm_kind, capture_prefix=f"{arm_kind.value.replace('_', '-')}-"
        )
        sets.append(TrialCaptureSet(tuple(receipts), review, trial))
        arms.append(reviewed)
    qualification_time = T0 + timedelta(minutes=3)
    qualification_capture = capture_bytes(
        root,
        episode_id=EPISODE,
        capture_id="episode-qualification",
        kind=CaptureKind.BLINDED_REVIEW,
        controller_id="reviewer-controller",
        source_observed_at=qualification_time,
        collected_at=qualification_time,
        data=json.dumps(
            {
                "schema_version": 1,
                "episode_id": EPISODE,
                "qualified_at": qualification_time.isoformat(),
                "scenario_id": SCENARIO,
                "fault_recipe_id": FAULT_RECIPE,
                "sealed_cause_codes": CAUSES,
                "expected_symptom": True,
                "oracle_rule": {"gt": 100},
                "common_budget_ms": 60_000,
                "arm_reviews": [
                    {
                        "arm_kind": item.trial.arm.kind.value,
                        "capture_id": item.reviewer_receipt.capture_id,
                        "sha256": item.reviewer_receipt.sha256,
                    }
                    for item in sets
                ],
            },
            sort_keys=True,
        ).encode(),
    )
    episode = ReviewedWindowsEpisode(
        episode_id=EPISODE,
        source="independent_windows_vm",
        scenario_id=SCENARIO,
        fault_recipe_id=FAULT_RECIPE,
        sealed_cause_codes=CAUSES,
        expected_symptom=True,
        oracle_rule=NumericRule(gt=100),
        common_budget_ms=60_000,
        qualification=IndependentQualification(
            qualification_record_digest=qualification_capture.sha256,
            rig_controller_id="rig-controller",
            oracle_controller_id="oracle-controller",
            reviewer_id="reviewer-controller",
            arm_executor_id="arm-controller",
        ),
        vm_protocol=None,
        arms=tuple(arms),
    )
    return episode, tuple(sets), qualification_capture


def test_binds_readback_to_trial_and_review_without_quality_claim(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    binding = bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)
    assert binding.schema_version == 2
    assert binding.classification == "host_evidence_binding_only"
    assert binding.episode_id == EPISODE
    assert binding.arm_kind is ARM
    assert binding.trace_digest_verified is False
    assert binding.arm_result_capture_verified is True
    assert binding.arm_result_capture_digest == receipts[5].sha256
    assert binding.event_log_consistency_verified is False
    assert binding.event_log_digest is None


def test_binds_typed_coordinator_events_without_authenticity_claim(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, arm_episode=_coordinator_episode(), trace_events=_coordinator_events()
    )
    binding = bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)
    assert binding.event_log_consistency_verified is True
    assert binding.event_log_digest is not None
    assert binding.trace_digest_verified is False
    assert binding.classification == "host_evidence_binding_only"


def test_failed_configured_provider_with_effective_fallback_is_bound(tmp_path: Path) -> None:
    episode = _coordinator_episode()
    decision = episode.decision.model_copy(
        update={"provider_id": "laya", "effective_provider_id": "keyword", "failures": 1}
    )
    episode = episode.model_copy(update={"decision": decision})
    events = _coordinator_events()
    events[2]["attempted_provider_id"] = "laya"
    events[2]["effective_provider_id"] = "keyword"
    events[2]["failed"] = True
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, arm_episode=episode, trace_events=events
    )
    binding = bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)
    assert binding.event_log_consistency_verified is True
    assert binding.trace_digest_verified is False


def test_failed_fallback_misattributed_as_configured_call_is_rejected(tmp_path: Path) -> None:
    episode = _coordinator_episode()
    decision = episode.decision.model_copy(
        update={"provider_id": "laya", "effective_provider_id": "keyword", "failures": 1}
    )
    episode = episode.model_copy(update={"decision": decision})
    events = _coordinator_events()
    events[2]["attempted_provider_id"] = "keyword"
    events[2]["failed"] = True
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, arm_episode=episode, trace_events=events
    )
    with pytest.raises(EvidenceBindingError, match="event log provider"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_failed_configured_provider_without_fallback_has_no_effective_id(tmp_path: Path) -> None:
    episode = _coordinator_episode()
    decision = episode.decision.model_copy(
        update={"provider_id": "laya", "effective_provider_id": None, "failures": 1}
    )
    episode = episode.model_copy(update={"decision": decision})
    events = _coordinator_events()
    events[2]["attempted_provider_id"] = "laya"
    events[2]["effective_provider_id"] = None
    events[2]["failed"] = True
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, arm_episode=episode, trace_events=events
    )
    assert bind_trial_evidence(
        tmp_path, receipts, review, trial, reviewed, qualification
    ).event_log_consistency_verified


def test_coordinator_event_log_keeps_typed_capture_byte_limit(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path,
        arm_episode=_coordinator_episode(),
        trace_events=_coordinator_events(),
        trace_padding=70_000,
    )
    with pytest.raises(EvidenceBindingError, match="capture readback"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


@pytest.mark.parametrize(
    "change",
    (
        "missing_probe",
        "duplicate_id",
        "out_of_order",
        "outside_trial_window",
        "outside_episode_window",
        "wrong_provider",
        "wrong_effective_provider",
        "missing_effective_provider",
        "provider_failure",
        "wrong_terminal",
        "missing_terminal",
        "extra_evidence",
        "non_utc",
        "extra_secret_field",
        "summary_only",
    ),
)
def test_rejects_inconsistent_coordinator_event_log(tmp_path: Path, change: str) -> None:
    events = _coordinator_events()
    episode = _coordinator_episode()
    if change == "missing_probe":
        events.pop(0)
    elif change == "duplicate_id":
        events[1]["event_id"] = events[0]["event_id"]
    elif change == "out_of_order":
        events[1]["observed_at"] = (T0 + timedelta(seconds=23)).isoformat()
    elif change == "outside_trial_window":
        episode = episode.model_copy(update={"started_at": T0 + timedelta(seconds=20)})
    elif change == "outside_episode_window":
        events[0]["observed_at"] = (T0 + timedelta(seconds=22)).isoformat()
    elif change == "wrong_provider":
        events[2]["attempted_provider_id"] = "other-provider"
    elif change == "wrong_effective_provider":
        events[2]["effective_provider_id"] = "other-provider"
    elif change == "missing_effective_provider":
        events[2].pop("effective_provider_id")
    elif change == "provider_failure":
        events[2]["failed"] = True
    elif change == "wrong_terminal":
        events[3]["status"] = "failed"
    elif change == "missing_terminal":
        events.pop()
    elif change == "extra_evidence":
        events.insert(
            3,
            {
                "kind": "evidence",
                "event_id": "ev-2",
                "observed_at": (T0 + timedelta(seconds=23, milliseconds=400)).isoformat(),
            },
        )
    elif change == "non_utc":
        events[0]["observed_at"] = "2026-09-22T05:00:23.100-07:00"
    elif change == "extra_secret_field":
        events[0]["sealed_fault"] = "leak"
    elif change == "summary_only":
        episode = None
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path, arm_episode=episode, trace_events=events
    )
    with pytest.raises(EvidenceBindingError, match="event log"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


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


def test_episode_binds_three_distinct_reviews_to_one_qualification(tmp_path: Path) -> None:
    episode, sets, qualification_capture = _episode_bundle(tmp_path)
    binding = bind_episode_evidence(tmp_path, episode, sets, qualification_capture)
    assert binding.schema_version == 2
    assert binding.classification == "host_episode_binding_only"
    assert binding.episode_id == EPISODE
    assert binding.qualification_record_digest == episode.qualification.qualification_record_digest
    assert {arm.arm_kind for arm in binding.arms} == set(ArmKind)
    assert binding.diagnostic_accuracy_claim is False
    assert binding.scorecard_bound is False


def test_episode_rejects_arm_swap_and_missing_receipt(tmp_path: Path) -> None:
    episode, sets, qualification_capture = _episode_bundle(tmp_path)
    swapped = (
        replace(sets[0], reviewer_receipt=sets[1].reviewer_receipt),
        *sets[1:],
    )
    with pytest.raises(EvidenceBindingError):
        bind_episode_evidence(tmp_path, episode, swapped, qualification_capture)
    incomplete = (
        replace(sets[0], receipts=sets[0].receipts[:-1]),
        *sets[1:],
    )
    with pytest.raises(EvidenceBindingError):
        bind_episode_evidence(tmp_path, episode, incomplete, qualification_capture)


def test_episode_rejects_reused_cross_arm_receipt(tmp_path: Path) -> None:
    episode, sets, qualification_capture = _episode_bundle(tmp_path)
    reused = (
        sets[0],
        replace(sets[1], receipts=(sets[0].receipts[0], *sets[1].receipts[1:])),
        sets[2],
    )
    with pytest.raises(EvidenceBindingError, match="reused"):
        bind_episode_evidence(tmp_path, episode, reused, qualification_capture)


def test_episode_rejects_mismatched_trial_arm_or_qualification(tmp_path: Path) -> None:
    episode, sets, qualification_capture = _episode_bundle(tmp_path)
    mismatched_arm = episode.arms[0].model_copy(update={"vm_trial_digest": "f" * 64})
    with pytest.raises(EvidenceBindingError):
        bind_episode_evidence(
            tmp_path,
            episode.model_copy(update={"arms": (mismatched_arm, *episode.arms[1:])}),
            sets,
            qualification_capture,
        )
    with pytest.raises(EvidenceBindingError, match="qualification"):
        bind_episode_evidence(
            tmp_path,
            episode.model_copy(
                update={
                    "qualification": episode.qualification.model_copy(
                        update={"qualification_record_digest": "f" * 64}
                    )
                }
            ),
            sets,
            qualification_capture,
        )
    with pytest.raises(EvidenceBindingError, match="qualification"):
        bind_episode_evidence(tmp_path, episode, sets, None)


def test_episode_qualification_binds_sealed_fault_and_budget(tmp_path: Path) -> None:
    episode, sets, qualification_capture = _episode_bundle(tmp_path)
    with pytest.raises(EvidenceBindingError, match="qualification"):
        bind_episode_evidence(
            tmp_path,
            episode.model_copy(update={"sealed_cause_codes": ("different_fault",)}),
            sets,
            qualification_capture,
        )
    with pytest.raises(EvidenceBindingError, match="qualification"):
        bind_episode_evidence(
            tmp_path,
            episode.model_copy(update={"common_budget_ms": 30_000}),
            sets,
            qualification_capture,
        )


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
    with pytest.raises(EvidenceBindingError, match="arm result capture"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


@pytest.mark.parametrize("change", ("status", "arm_result"))
def test_rejects_arm_result_capture_that_disagrees_with_trial(tmp_path: Path, change: str) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    if change == "status":
        altered = trial.model_copy(
            update={"status": TrialStatus.ARM_ERROR, "error_type": "RuntimeError"}
        )
    else:
        assert trial.arm_result is not None
        altered = trial.model_copy(
            update={"arm_result": trial.arm_result.model_copy(update={"claimed_fixed": True})}
        )
    reviewed = reviewed.model_copy(update={"vm_trial_digest": vm_record_digest(altered)})
    with pytest.raises(EvidenceBindingError, match="arm result capture"):
        bind_trial_evidence(tmp_path, receipts, review, altered, reviewed, qualification)


def test_rejects_missing_arm_result_capture_bytes(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    (tmp_path / EPISODE / "arm" / "capture-5.bin").unlink()
    with pytest.raises(EvidenceBindingError, match="custody"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


@pytest.mark.parametrize("missing", ("result", "elapsed"))
def test_valid_trial_requires_arm_result_and_elapsed(tmp_path: Path, missing: str) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(
        tmp_path,
        missing_arm_result=missing == "result",
        missing_arm_elapsed=missing == "elapsed",
    )
    with pytest.raises(EvidenceBindingError, match="arm result capture"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


@pytest.mark.parametrize(
    "status",
    (TrialStatus.ARM_TIMEOUT, TrialStatus.ARM_ERROR, TrialStatus.INVALID_INJECTION),
)
def test_binds_structurally_valid_nonvalid_arm_statuses(
    tmp_path: Path, status: TrialStatus
) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path, trial_status=status)
    binding = bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)
    assert binding.arm_result_capture_digest == receipts[5].sha256
    assert binding.arm_result_capture_verified is False
    assert binding.trace_digest_verified is False


def test_rejects_arm_result_capture_above_typed_byte_limit(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path, trace_padding=70_000)
    with pytest.raises(EvidenceBindingError, match="capture readback"):
        bind_trial_evidence(tmp_path, receipts, review, trial, reviewed, qualification)


def test_rejects_tampered_arm_result_capture_bytes(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    (tmp_path / EPISODE / "arm" / "capture-5.bin").write_bytes(b"tampered")
    with pytest.raises(EvidenceBindingError, match="custody"):
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


def test_per_arm_binding_does_not_equate_episode_digest_with_review_digest(tmp_path: Path) -> None:
    receipts, review, trial, reviewed, qualification = _bundle(tmp_path)
    shared_qualification = qualification.model_copy(
        update={"qualification_record_digest": "e" * 64}
    )
    assert (
        bind_trial_evidence(
            tmp_path, receipts, review, trial, reviewed, shared_qualification
        ).review_capture_digest
        == review.sha256
    )
    with pytest.raises(EvidenceBindingError):
        bind_trial_evidence(tmp_path, receipts, receipts[-1], trial, reviewed, qualification)
