"""Scorecard math tests use invented records, never field-performance evidence."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from benchmarks.lab_episodes import ArmKind, LabResult, NumericRule
from benchmarks.vm_lab_contract import VmProtocolAdmission
from benchmarks.windows_scorecard import (
    ArmOutcome,
    IndependentQualification,
    ReviewedArm,
    ReviewedWindowsEpisode,
    score_reviewed_episodes,
)

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
        oracle_finished_at=T0 + timedelta(minutes=index, seconds=20),
        oracle_record_digest=f"{index + 4:x}" * 64,
        recovery_reviewed=index == 2,
    )


def _episode(index: int = 0) -> ReviewedWindowsEpisode:
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
        vm_protocol=VmProtocolAdmission(protocol_admitted=True, reason_codes=()),
        arms=tuple(_arm(kind, index) for kind in ARMS),
    )


def test_matched_scorecard_reports_reviewed_rates_and_wall_time() -> None:
    score = score_reviewed_episodes(tuple(_episode(index) for index in range(5)))

    assert score.episode_count == 5
    assert score.evidence_class == "reviewed_input_only"
    by_kind = {arm.kind: arm for arm in score.arms}
    assert by_kind[ArmKind.KEYWORD_BASELINE].cause_accuracy.count == 0
    assert by_kind[ArmKind.DEEP_BRAIN_ONLY].cause_accuracy.count == 5
    assert by_kind[ArmKind.DUAL_BRAIN].verified_recovery.count == 5
    assert by_kind[ArmKind.DUAL_BRAIN].false_fix.count == 0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p50_ms == 1200.0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p95_ms == 1200.0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p50_ci95_ms is None
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p95_ci95_ms is None
    assert by_kind[ArmKind.DUAL_BRAIN].cause_accuracy.ci95_low < 1
    assert len(score.paired_differences) == 3


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
    assert by_kind[ArmKind.DUAL_BRAIN].false_fix.count == 1
    assert by_kind[ArmKind.DUAL_BRAIN].verified_recovery.count == 0
    assert by_kind[ArmKind.DUAL_BRAIN].wall_time.p50_ci95_ms is None


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
        score_reviewed_episodes((VmProtocolAdmission(protocol_admitted=True, reason_codes=()),))  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        score_reviewed_episodes((LabResult.model_construct(),))  # type: ignore[arg-type]


def test_rejects_unadmitted_or_unequal_access_and_missing_arm() -> None:
    episode = _episode()
    with pytest.raises(ValueError, match="protocol"):
        score_reviewed_episodes(
            (
                episode.model_copy(
                    update={
                        "vm_protocol": VmProtocolAdmission(
                            protocol_admitted=False, reason_codes=("reset_state_mismatch",)
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
            )
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
                "recovery_reviewed": False,
                "repair_appropriate": False if arm.repair_attempted else None,
            }
        )
        for arm in episode.arms
    )
    control = episode.model_copy(
        update={"sealed_cause_codes": (), "expected_symptom": False, "arms": arms}
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
    with pytest.raises(ValueError, match="profile changed"):
        score_reviewed_episodes(
            (first, second.model_copy(update={"arms": (changed_profile, *second.arms[1:])}))
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
