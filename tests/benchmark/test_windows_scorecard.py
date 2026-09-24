"""Scorecard math tests use invented records, never field-performance evidence."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from benchmarks.lab_episodes import ArmKind, LabResult, NumericRule, TrialStatus
from benchmarks.oracle_evidence_binding import HostEpisodeBinding, HostEvidenceBinding
from benchmarks.vm_lab_contract import (
    VmArmBinding,
    VmProtocolAdmission,
    VmProtocolBinding,
    VmRecipeId,
)
from benchmarks.windows_scorecard import (
    ArmOutcome,
    IndependentQualification,
    ReviewedArm,
    ReviewedWindowsEpisode,
    score_host_bound_episodes,
    score_reviewed_episodes,
)
from benchmarks.wininet_affected_task import HostAffectedTaskBinding

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)
HASH = "a" * 64
ARMS = (ArmKind.KEYWORD_BASELINE, ArmKind.DEEP_BRAIN_ONLY, ArmKind.DUAL_BRAIN)


def _arm(kind: ArmKind, episode_index: int) -> ReviewedArm:
    index = ARMS.index(kind)
    return ReviewedArm(
        kind=kind,
        status=ArmOutcome.COMPLETED,
        warm_state="cold",
        access_digest=HASH,
        profile_digest=f"{index + 7:x}" * 64,
        reset_proof_digest=hashlib.sha256(f"reset-{episode_index}-{index}".encode()).hexdigest(),
        vm_trial_digest=hashlib.sha256(f"trial-{episode_index}-{index}".encode()).hexdigest(),
        wall_ms=1000.0 + index * 100,
        claimed_cause_codes=("wininet_proxy_wrong_server",) if index else (),
        cause_supported=index != 0,
        claimed_fixed=index == 2,
        repair_attempted=index == 2,
        repair_appropriate=True if index == 2 else None,
        action_journal_digest="e" * 64 if index == 2 else None,
        oracle_before=(0.0, 0.0),
        oracle_after=(1.0, 1.0) if index == 2 else (0.0, 0.0),
        oracle_started_at=T0 + timedelta(minutes=index),
        oracle_before_finished_at=T0 + timedelta(minutes=index, milliseconds=100),
        first_useful_evidence_at=(
            T0 + timedelta(minutes=index, milliseconds=150) if index else None
        ),
        supported_answer_at=(T0 + timedelta(minutes=index, milliseconds=200) if index else None),
        action_attempted_at=T0 + timedelta(minutes=index, milliseconds=250) if index == 2 else None,
        oracle_after_started_at=T0 + timedelta(minutes=index, milliseconds=300),
        oracle_finished_at=T0 + timedelta(minutes=index, milliseconds=500),
        oracle_record_digest=f"{index + 4:x}" * 64,
        recovery_reviewed=index == 2,
    )


def _episode(index: int = 0) -> ReviewedWindowsEpisode:
    arms = tuple(_arm(kind, index) for kind in ARMS)
    protocol = VmProtocolAdmission(
        protocol_admitted=True,
        reason_codes=(),
        binding=VmProtocolBinding(
            manifest_digest=hashlib.sha256(f"manifest-{index}".encode()).hexdigest(),
            episode_id=f"windows-run-{index}",
            result_digest=hashlib.sha256(f"result-{index}".encode()).hexdigest(),
            recipe_digest=hashlib.sha256(f"recipe-{index}".encode()).hexdigest(),
            proof_digest=hashlib.sha256(f"proof-{index}".encode()).hexdigest(),
            scenario_id="lab.vm.wininet-proxy",
            fault_recipe_id=VmRecipeId.WRONG_WININET_PROXY_V1,
            sealed_cause_codes=("wininet_proxy_wrong_server",),
            expected_symptom=True,
            oracle_rule=NumericRule(lt=0.5),
            common_budget_ms=30_000,
            rig_controller_id="rig-controller",
            oracle_controller_id="oracle-controller",
            arm_executor_id="model-worker",
            arms=tuple(
                VmArmBinding(
                    kind=arm.kind,
                    trial_status=TrialStatus.VALID,
                    warm_state=arm.warm_state,
                    profile_digest=arm.profile_digest,
                    reset_proof_digest=arm.reset_proof_digest,
                    trial_digest=hashlib.sha256(
                        f"trial-{index}-{ARMS.index(arm.kind)}".encode()
                    ).hexdigest(),
                )
                for arm in arms
            ),
        ),
    )
    return ReviewedWindowsEpisode(
        episode_id=f"windows-run-{index}",
        source="independent_windows_vm",
        scenario_id="lab.vm.wininet-proxy",
        fault_recipe_id="vm.wrong_wininet_proxy.v1",
        sealed_cause_codes=("wininet_proxy_wrong_server",),
        expected_symptom=True,
        oracle_rule=NumericRule(lt=0.5),
        common_budget_ms=30_000,
        qualification=IndependentQualification(
            qualification_record_digest=hashlib.sha256(
                f"qualification-{index}".encode()
            ).hexdigest(),
            rig_controller_id="rig-controller",
            oracle_controller_id="oracle-controller",
            reviewer_id="human:reviewer",
            arm_executor_id="model-worker",
        ),
        vm_protocol=protocol,
        arms=arms,
    )


def _protocol_for(episode: ReviewedWindowsEpisode) -> VmProtocolAdmission:
    assert episode.vm_protocol is not None
    return episode.vm_protocol


def _host_binding(episode: ReviewedWindowsEpisode) -> HostEpisodeBinding:
    return HostEpisodeBinding(
        schema_version=2,
        classification="host_episode_binding_only",
        episode_id=episode.episode_id,
        qualification_record_digest=episode.qualification.qualification_record_digest,
        arms=tuple(
            HostEvidenceBinding(
                schema_version=2,
                classification="host_evidence_binding_only",
                episode_id=episode.episode_id,
                arm_kind=arm.kind,
                oracle_record_digest=arm.oracle_record_digest,
                trial_digest=arm.vm_trial_digest or "",
                review_capture_digest=hashlib.sha256(f"review-{arm.kind}".encode()).hexdigest(),
                arm_result_capture_digest=hashlib.sha256(f"result-{arm.kind}".encode()).hexdigest(),
                arm_result_capture_verified=True,
                trace_digest_verified=False,
            )
            for arm in episode.arms
        ),
        diagnostic_accuracy_claim=False,
        scorecard_bound=False,
    )


def test_host_bound_score_requires_matching_episode_binding() -> None:
    episode = _episode()
    binding = _host_binding(episode)
    score = score_host_bound_episodes(((episode, binding),))
    assert score.episode_count == 1

    with pytest.raises(ValueError, match="host evidence binding"):
        score_host_bound_episodes(((episode, replace(binding, episode_id="different")),))

    with pytest.raises(ValueError, match="host evidence binding"):
        score_host_bound_episodes(((episode, replace(binding, arms=binding.arms[:2])),))


def test_host_only_affected_task_binding_cannot_replace_episode_binding() -> None:
    episode = _episode()
    task = HostAffectedTaskBinding(
        schema_version=1,
        classification="host_affected_task_only",
        episode_id=episode.episode_id,
        trial_nonce="a" * 32,
        vm_uuid=UUID("11111111-2222-3333-4444-555555555555"),
        generation_id="generation-clean-001",
        capture_digests=("a" * 64,),
        complete=True,
        diagnostic_accuracy_claim=False,
        repair_verified=False,
    )
    with pytest.raises(ValueError, match="host evidence binding pair is invalid"):
        score_host_bound_episodes(((episode, task),))  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("oracle_record_digest", "f" * 64),
        ("trial_digest", "f" * 64),
        ("review_capture_digest", "not-a-digest"),
        ("arm_result_capture_digest", "not-a-digest"),
        ("classification", "wrong"),
        ("trace_digest_verified", True),
    ],
)
def test_host_bound_score_rejects_tampered_arm_binding(field: str, value: object) -> None:
    episode = _episode()
    binding = _host_binding(episode)
    arm = replace(binding.arms[0], **{field: value})
    with pytest.raises(ValueError, match="host evidence binding"):
        score_host_bound_episodes(((episode, replace(binding, arms=(arm, *binding.arms[1:]))),))


def test_host_bound_score_rejects_reused_binding_on_other_episode() -> None:
    first = _episode(0)
    second = _episode(1)
    with pytest.raises(ValueError, match="host evidence binding"):
        score_host_bound_episodes(((first, _host_binding(first)), (second, _host_binding(first))))


def test_matched_scorecard_reports_reviewed_rates_and_wall_time() -> None:
    score = score_reviewed_episodes(tuple(_episode(index) for index in range(5)))

    assert score.episode_count == 5
    assert score.evidence_class == "reviewed_input_only"
    by_kind = {arm.kind: arm for arm in score.arms}
    assert by_kind[ArmKind.KEYWORD_BASELINE].cause_accuracy.count == 0
    assert by_kind[ArmKind.DEEP_BRAIN_ONLY].cause_accuracy.count == 5
    assert by_kind[ArmKind.DUAL_BRAIN].verified_recovery.count == 5
    assert by_kind[ArmKind.DUAL_BRAIN].diagnosis_and_recovery.count == 5
    assert by_kind[ArmKind.DUAL_BRAIN].false_fix.count == 0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p50_ms == 1200.0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p95_ms == 1200.0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p50_ci95_ms is None
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p95_ci95_ms is None
    assert by_kind[ArmKind.KEYWORD_BASELINE].supported_answer_time.censored == 5
    assert by_kind[ArmKind.KEYWORD_BASELINE].supported_answer_time.p50_ms == 30_000
    assert by_kind[ArmKind.DUAL_BRAIN].first_useful_evidence_time.observed == 5
    assert by_kind[ArmKind.DUAL_BRAIN].supported_answer_time.p95_ms == 200
    assert by_kind[ArmKind.DUAL_BRAIN].verified_recovery_time.observed == 5
    assert by_kind[ArmKind.DUAL_BRAIN].verified_recovery_time.p95_ms == 500
    assert by_kind[ArmKind.KEYWORD_BASELINE].verified_recovery_time.censored == 5
    assert by_kind[ArmKind.KEYWORD_BASELINE].verified_recovery_time.p50_ms == 30_000
    assert by_kind[ArmKind.DUAL_BRAIN].cause_accuracy.ci95_low < 1
    assert len(score.paired_differences) == 3
    baseline_to_dual = score.paired_differences[1]
    assert baseline_to_dual.diagnosis_and_recovery_fraction == 1.0
    assert baseline_to_dual.joint_ci95 is not None
    assert baseline_to_dual.supported_answer_time_ms == -29_800
    assert baseline_to_dual.supported_answer_time_ci95_ms is None
    assert baseline_to_dual.both_recovered_pair_count == 0
    assert baseline_to_dual.verified_recovery_time_ms is None
    assert baseline_to_dual.verified_recovery_time_ci95_ms is None
    assert score.paired_differences[0].both_recovered_pair_count == 0


def test_early_supported_answer_survives_late_terminal_repair() -> None:
    episode = _episode()
    late_dual = episode.arms[2].model_copy(update={"wall_ms": 31_000.0})
    late = episode.model_copy(update={"arms": (*episode.arms[:2], late_dual)})
    score = score_reviewed_episodes((late,))
    dual = score.arms[2]
    assert dual.timed_out == 1
    assert dual.cause_accuracy.count == 1
    assert dual.supported_answer_time.p50_ms == 200
    assert dual.verified_recovery.count == 0
    assert dual.verified_recovery_time.censored == 1
    assert dual.wall_time.p50_ms == 31_000.0


def test_recovery_time_waits_for_independent_final_oracle_reading() -> None:
    episode = _episode()
    dual = episode.arms[2]
    delayed = dual.model_copy(
        update={
            "oracle_finished_at": dual.oracle_started_at + timedelta(milliseconds=900),
            "wall_ms": 1200.0,
        }
    )
    episode = episode.model_copy(update={"arms": (*episode.arms[:2], delayed)})

    score = score_reviewed_episodes((episode,)).arms[2]

    assert score.verified_recovery.count == 1
    assert score.verified_recovery_time.p50_ms == 900
    assert score.supported_answer_time.p50_ms == 200


def test_paired_recovery_speed_requires_both_arms_to_recover() -> None:
    episode = _episode()
    baseline = episode.arms[0]
    recovered_baseline = baseline.model_copy(
        update={
            "claimed_cause_codes": episode.sealed_cause_codes,
            "cause_supported": True,
            "claimed_fixed": True,
            "repair_attempted": True,
            "repair_appropriate": True,
            "action_journal_digest": "f" * 64,
            "oracle_after": (1.0, 1.0),
            "first_useful_evidence_at": baseline.oracle_started_at + timedelta(milliseconds=150),
            "supported_answer_at": baseline.oracle_started_at + timedelta(milliseconds=200),
            "action_attempted_at": baseline.oracle_started_at + timedelta(milliseconds=250),
            "oracle_finished_at": baseline.oracle_started_at + timedelta(milliseconds=800),
            "recovery_reviewed": True,
        }
    )
    episode = episode.model_copy(update={"arms": (recovered_baseline, *episode.arms[1:])})

    score = score_reviewed_episodes((episode,))
    comparison = score.paired_differences[1]

    assert comparison.both_recovered_pair_count == 1
    assert comparison.verified_recovery_time_ms == -300
    assert comparison.verified_recovery_time_ci95_ms is None


def test_repair_without_supported_diagnosis_does_not_satisfy_joint_promise() -> None:
    episode = _episode()
    dual = episode.arms[2].model_copy(
        update={
            "claimed_cause_codes": (),
            "cause_supported": False,
            "first_useful_evidence_at": None,
            "supported_answer_at": None,
        }
    )
    episode = episode.model_copy(update={"arms": (*episode.arms[:2], dual)})

    score = score_reviewed_episodes((episode,)).arms[2]

    assert score.verified_recovery.count == 1
    assert score.cause_accuracy.count == 0
    assert score.diagnosis_and_recovery.count == 0


def test_post_budget_answer_is_censored_even_if_later_reviewed_as_correct() -> None:
    episode = _episode()
    dual = episode.arms[2]
    delayed = dual.model_copy(
        update={
            "oracle_finished_at": dual.oracle_started_at + timedelta(seconds=31),
            "wall_ms": 31_000.0,
            "supported_answer_at": dual.oracle_started_at + timedelta(seconds=30, milliseconds=1),
            "action_attempted_at": dual.oracle_started_at + timedelta(seconds=30, milliseconds=100),
            "oracle_after_started_at": dual.oracle_started_at
            + timedelta(seconds=30, milliseconds=200),
        }
    )
    episode = episode.model_copy(update={"arms": (*episode.arms[:2], delayed)})
    dual_score = score_reviewed_episodes((episode,)).arms[2]
    assert dual_score.cause_accuracy.count == 0
    assert dual_score.supported_answer_time.censored == 1
    assert dual_score.supported_answer_time.p50_ms == 30_000


def test_oracle_window_longer_than_reported_wall_time_is_rejected() -> None:
    episode = _episode()
    too_long = episode.arms[0].model_copy(
        update={"oracle_finished_at": episode.arms[0].oracle_started_at + timedelta(seconds=20)}
    )
    episode = episode.model_copy(update={"arms": (too_long, *episode.arms[1:])})
    with pytest.raises(ValueError, match="wall time"):
        score_reviewed_episodes((episode,))


def test_post_action_oracle_cannot_start_before_the_action() -> None:
    episode = _episode()
    dual = episode.arms[2]
    wrong_order = dual.model_copy(
        update={
            "oracle_before_finished_at": dual.oracle_started_at + timedelta(milliseconds=100),
            "action_attempted_at": dual.oracle_started_at + timedelta(milliseconds=300),
            "oracle_after_started_at": dual.oracle_started_at + timedelta(milliseconds=200),
        }
    )
    episode = episode.model_copy(update={"arms": (*episode.arms[:2], wrong_order)})
    with pytest.raises(ValueError, match="order"):
        score_reviewed_episodes((episode,))


def test_failure_timeout_and_false_fix_remain_in_denominator() -> None:
    episode = _episode()
    baseline, deep, dual = episode.arms
    episode = episode.model_copy(
        update={
            "arms": (
                baseline,
                deep.model_copy(
                    update={
                        "status": ArmOutcome.TIMEOUT,
                        "claimed_cause_codes": (),
                        "cause_supported": False,
                        "supported_answer_at": None,
                        "wall_ms": 30_000.0,
                    }
                ),
                dual.model_copy(
                    update={
                        "claimed_fixed": True,
                        "recovery_reviewed": False,
                        "oracle_after": (0.0, 0.0),
                    }
                ),
            )
        }
    )
    score = score_reviewed_episodes((episode,))
    by_kind = {arm.kind: arm for arm in score.arms}
    assert by_kind[ArmKind.DEEP_BRAIN_ONLY].n == 1
    assert by_kind[ArmKind.DEEP_BRAIN_ONLY].timed_out == 1
    assert by_kind[ArmKind.DEEP_BRAIN_ONLY].cause_accuracy.count == 0
    assert by_kind[ArmKind.DEEP_BRAIN_ONLY].supported_answer_time.censored == 1
    assert by_kind[ArmKind.DUAL_BRAIN].false_fix.count == 1
    assert by_kind[ArmKind.DUAL_BRAIN].verified_recovery.count == 0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p50_ci95_ms is None


def test_supported_answer_requires_ordered_measured_milestones() -> None:
    episode = _episode()
    dual = episode.arms[2]
    assert dual.action_attempted_at is not None
    changes: tuple[dict[str, object], ...] = (
        {"supported_answer_at": None},
        {"first_useful_evidence_at": None},
        {"supported_answer_at": dual.oracle_started_at - timedelta(milliseconds=1)},
        {"supported_answer_at": dual.action_attempted_at + timedelta(milliseconds=1)},
    )
    for changed in changes:
        invalid = episode.model_copy(
            update={"arms": (*episode.arms[:2], dual.model_copy(update=changed))}
        )
        with pytest.raises(ValueError, match="supported answer"):
            score_reviewed_episodes((invalid,))


def test_post_arm_oracle_cannot_be_used_as_diagnostic_milestone() -> None:
    episode = _episode()
    deep = episode.arms[1]
    leaked = deep.model_copy(
        update={
            "first_useful_evidence_at": deep.oracle_after_started_at + timedelta(milliseconds=10),
            "supported_answer_at": deep.oracle_after_started_at + timedelta(milliseconds=20),
        }
    )
    episode = episode.model_copy(update={"arms": (episode.arms[0], leaked, episode.arms[2])})
    with pytest.raises(ValueError, match="outside the measured journey"):
        score_reviewed_episodes((episode,))


def test_no_answer_does_not_look_fast_when_arm_stops_early() -> None:
    episode = _episode()
    baseline = episode.arms[0]
    early = baseline.model_copy(update={"wall_ms": 500.0})
    episode = episode.model_copy(update={"arms": (early, *episode.arms[1:])})
    score = score_reviewed_episodes((episode,))
    arm = score.arms[0]
    assert arm.wall_time.p50_ms == 500.0
    assert arm.supported_answer_time.p50_ms == 30_000
    assert arm.supported_answer_time.censored == 1


def test_paired_answer_time_interval_uses_whole_episodes() -> None:
    score = score_reviewed_episodes(tuple(_episode(index) for index in range(10)))
    interval = score.paired_differences[1].supported_answer_time_ci95_ms
    assert interval is not None
    assert interval.low == -29_800
    assert interval.high == -29_800


@pytest.mark.parametrize(
    "change",
    [
        {"source": "fixture"},
        {"source": "controlled_lab_rehearsal"},
        {"source": "vm_protocol_only"},
    ],
)
def test_non_real_sources_cannot_be_scored(change: dict[str, str]) -> None:
    episode = _episode().model_dump()
    episode.update(change)
    with pytest.raises(ValueError):
        ReviewedWindowsEpisode.model_validate(episode)


def test_protocol_only_and_lab_result_cannot_be_scored() -> None:
    with pytest.raises((TypeError, ValueError)):
        score_reviewed_episodes((_protocol_for(_episode()),))  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        score_reviewed_episodes((LabResult.model_construct(),))  # type: ignore[arg-type]


def test_rejects_unadmitted_or_unequal_access_and_missing_arm() -> None:
    episode = _episode()
    with pytest.raises(ValueError, match="protocol"):
        score_reviewed_episodes(
            (
                episode.model_copy(
                    update={
                        "vm_protocol": _protocol_for(episode).model_copy(
                            update={
                                "protocol_admitted": False,
                                "reason_codes": ("reset_state_mismatch",),
                            }
                        )
                    }
                ),
            )
        )
    with pytest.raises(ValueError, match="equal access"):
        score_reviewed_episodes(
            (
                episode.model_copy(
                    update={
                        "arms": (
                            *episode.arms[:2],
                            episode.arms[2].model_copy(update={"access_digest": "b" * 64}),
                        )
                    }
                ),
            )
        )
    with pytest.raises(ValueError, match=r"at least 3|three"):
        score_reviewed_episodes((episode.model_copy(update={"arms": episode.arms[:2]}),))


def test_recovery_requires_reviewed_journal_and_independent_oracle_change() -> None:
    episode = _episode()
    dual = episode.arms[2]
    with pytest.raises(ValueError, match="recovery"):
        score_reviewed_episodes(
            (
                episode.model_copy(
                    update={
                        "arms": (
                            *episode.arms[:2],
                            dual.model_copy(update={"action_journal_digest": None}),
                        )
                    }
                ),
            )
        )


def test_duplicate_episode_and_shared_controller_identity_rejected() -> None:
    episode = _episode()
    with pytest.raises(ValueError, match="duplicate"):
        score_reviewed_episodes((episode, episode))
    bad = episode.model_copy(
        update={
            "qualification": episode.qualification.model_copy(
                update={"oracle_controller_id": "model-worker"}
            ),
            "vm_protocol": _protocol_for(episode).model_copy(
                update={
                    "binding": _protocol_for(episode).binding.model_copy(
                        update={"oracle_controller_id": "model-worker"}
                    )
                }
            ),
        }
    )
    with pytest.raises(ValueError, match="independent"):
        score_reviewed_episodes((bad,))


def test_uncertainty_is_not_zero_width_for_five_identical_paired_wins() -> None:
    score = score_reviewed_episodes(tuple(_episode(index) for index in range(5)))
    comparison = next(
        item
        for item in score.paired_differences
        if item.baseline is ArmKind.KEYWORD_BASELINE and item.comparator is ArmKind.DUAL_BRAIN
    )
    assert comparison.verified_recovery_fraction == 1.0
    assert comparison.recovery_ci95 is not None
    assert comparison.recovery_ci95.low < 1.0
    assert comparison.recovery_ci95.high == 1.0


def test_latency_uncertainty_requires_enough_independent_episodes() -> None:
    ten = score_reviewed_episodes(tuple(_episode(index) for index in range(10)))
    assert ten.arms[2].wall_time.p50_ci95_ms is not None
    assert ten.arms[2].wall_time.p95_ci95_ms is None
    sixty = score_reviewed_episodes(tuple(_episode(index) for index in range(60)))
    assert sixty.arms[2].wall_time.p95_ci95_ms is not None


def test_healthy_control_repair_attempt_is_false_fix() -> None:
    episode = _episode()
    arms = tuple(
        arm.model_copy(
            update={
                "oracle_before": (1.0, 1.0),
                "oracle_after": (1.0, 1.0),
                "claimed_cause_codes": (),
                "cause_supported": arm.kind is ArmKind.KEYWORD_BASELINE,
                "first_useful_evidence_at": (
                    arm.oracle_started_at + timedelta(milliseconds=150)
                    if arm.kind is ArmKind.KEYWORD_BASELINE
                    else arm.first_useful_evidence_at
                ),
                "supported_answer_at": (
                    arm.oracle_started_at + timedelta(milliseconds=200)
                    if arm.kind is ArmKind.KEYWORD_BASELINE
                    else None
                ),
                "recovery_reviewed": False,
                "repair_appropriate": False if arm.repair_attempted else None,
            }
        )
        for arm in episode.arms
    )
    control = episode.model_copy(
        update={
            "sealed_cause_codes": (),
            "expected_symptom": False,
            "arms": arms,
            "vm_protocol": _protocol_for(episode).model_copy(
                update={
                    "binding": _protocol_for(episode).binding.model_copy(
                        update={
                            "scenario_id": "lab.vm.healthy-control",
                            "fault_recipe_id": VmRecipeId.HEALTHY_CONTROL_V1,
                            "sealed_cause_codes": (),
                            "expected_symptom": False,
                        }
                    )
                }
            ),
            "scenario_id": "lab.vm.healthy-control",
            "fault_recipe_id": VmRecipeId.HEALTHY_CONTROL_V1.value,
        }
    )
    score = score_reviewed_episodes((control,))
    assert score.arms[2].false_fix.count == 1
    assert score.arms[2].verified_recovery.count == 0


def test_reused_reset_proof_and_changing_profile_are_rejected() -> None:
    first, second = _episode(0), _episode(1)
    copied_reset = second.arms[0].model_copy(
        update={"reset_proof_digest": first.arms[0].reset_proof_digest}
    )
    with pytest.raises(ValueError, match="reset proof reused"):
        score_reviewed_episodes(
            (first, second.model_copy(update={"arms": (copied_reset, *second.arms[1:])}))
        )
    changed_profile = second.arms[0].model_copy(update={"profile_digest": "b" * 64})
    second_binding = _protocol_for(second).binding
    changed_protocol = _protocol_for(second).model_copy(
        update={
            "binding": second_binding.model_copy(
                update={
                    "arms": (
                        second_binding.arms[0].model_copy(update={"profile_digest": "b" * 64}),
                        *second_binding.arms[1:],
                    )
                }
            )
        }
    )
    with pytest.raises(ValueError, match="profile changed"):
        score_reviewed_episodes(
            (
                first,
                second.model_copy(
                    update={
                        "arms": (changed_profile, *second.arms[1:]),
                        "vm_protocol": changed_protocol,
                    }
                ),
            )
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("episode_id", "windows-run-other"),
        ("scenario_id", "lab.vm.healthy-control"),
        ("fault_recipe_id", VmRecipeId.HEALTHY_CONTROL_V1.value),
        ("sealed_cause_codes", ("gpu_power_limit",)),
        ("oracle_rule", NumericRule(gt=0.5)),
        ("common_budget_ms", 45_000),
    ],
)
def test_vm_protocol_cannot_be_attached_to_a_different_fault(field: str, value: object) -> None:
    episode = _episode()
    with pytest.raises(ValueError, match="VM protocol binding"):
        score_reviewed_episodes((episode.model_copy(update={field: value}),))


def test_vm_protocol_cannot_be_attached_to_a_different_rig_or_arm() -> None:
    episode = _episode()
    changed_rig = episode.qualification.model_copy(update={"rig_controller_id": "other-rig"})
    with pytest.raises(ValueError, match="VM protocol binding"):
        score_reviewed_episodes((episode.model_copy(update={"qualification": changed_rig}),))
    changed_reset = episode.arms[0].model_copy(update={"reset_proof_digest": "f" * 64})
    with pytest.raises(ValueError, match="VM protocol binding"):
        score_reviewed_episodes(
            (episode.model_copy(update={"arms": (changed_reset, *episode.arms[1:])}),)
        )
    changed_trial = episode.arms[0].model_copy(update={"vm_trial_digest": "f" * 64})
    with pytest.raises(ValueError, match="VM protocol binding"):
        score_reviewed_episodes(
            (episode.model_copy(update={"arms": (changed_trial, *episode.arms[1:])}),)
        )


def test_vm_arm_error_cannot_be_relabelled_completed_in_review() -> None:
    episode = _episode()
    protocol = _protocol_for(episode)
    error_arm = protocol.binding.arms[2].model_copy(update={"trial_status": TrialStatus.ARM_ERROR})
    binding = protocol.binding.model_copy(update={"arms": (*protocol.binding.arms[:2], error_arm)})
    altered = episode.model_copy(
        update={"vm_protocol": protocol.model_copy(update={"binding": binding})}
    )
    with pytest.raises(ValueError, match="VM protocol binding"):
        score_reviewed_episodes((altered,))


def test_vm_arm_timeout_cannot_be_relabelled_failed_in_review() -> None:
    episode = _episode()
    protocol = _protocol_for(episode)
    timeout_arm = protocol.binding.arms[2].model_copy(
        update={"trial_status": TrialStatus.ARM_TIMEOUT}
    )
    binding = protocol.binding.model_copy(
        update={"arms": (*protocol.binding.arms[:2], timeout_arm)}
    )
    failed_arm = episode.arms[2].model_copy(update={"status": ArmOutcome.FAILED})
    altered = episode.model_copy(
        update={
            "vm_protocol": protocol.model_copy(update={"binding": binding}),
            "arms": (*episode.arms[:2], failed_arm),
        }
    )

    with pytest.raises(ValueError, match="VM protocol binding"):
        score_reviewed_episodes((altered,))


def test_vm_protocol_proof_and_result_reuse_are_rejected() -> None:
    first, second = _episode(0), _episode(1)
    for field in ("proof_digest", "result_digest"):
        borrowed = _protocol_for(second).binding.model_copy(
            update={field: getattr(_protocol_for(first).binding, field)}
        )
        altered = second.model_copy(
            update={"vm_protocol": _protocol_for(second).model_copy(update={"binding": borrowed})}
        )
        with pytest.raises(ValueError, match="protocol proof or result reused"):
            score_reviewed_episodes((first, altered))


def test_bare_bool_and_unmatched_arm_set_are_not_vm_qualification() -> None:
    episode = _episode()
    with pytest.raises(ValueError, match="binding"):
        VmProtocolAdmission.model_validate({"protocol_admitted": True, "reason_codes": ()})
    one_arm_binding = _protocol_for(episode).binding.model_copy(
        update={"arms": _protocol_for(episode).binding.arms[:1]}
    )
    with pytest.raises(ValueError, match="VM protocol binding"):
        score_reviewed_episodes(
            (
                episode.model_copy(
                    update={
                        "vm_protocol": _protocol_for(episode).model_copy(
                            update={"binding": one_arm_binding}
                        )
                    }
                ),
            )
        )


def test_unreviewed_recovery_and_cause_cannot_be_inferred_from_labels() -> None:
    episode = _episode()
    wrong_cause = episode.arms[0].model_copy(update={"cause_supported": True})
    with pytest.raises(ValueError, match="sealed truth"):
        score_reviewed_episodes(
            (episode.model_copy(update={"arms": (wrong_cause, *episode.arms[1:])}),)
        )
    unjournaled = episode.arms[2].model_copy(update={"action_journal_digest": None})
    with pytest.raises(ValueError, match="recovery"):
        score_reviewed_episodes(
            (episode.model_copy(update={"arms": (*episode.arms[:2], unjournaled)}),)
        )
