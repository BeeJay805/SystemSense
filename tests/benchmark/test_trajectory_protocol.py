"""Frozen trajectory comparison is conservative about missing and unrun work."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from benchmarks.trajectory_protocol import (
    REQUIRED_ARMS,
    SCENARIO_MATRIX,
    Arm,
    CasePlan,
    Choice,
    Claim,
    ProviderCall,
    Trajectory,
    freeze_protocol,
    main,
    score_trajectories,
    visible_case_input,
)

H = "a" * 64
J = "b" * 64
K = "c" * 64


def _case(**changes: object) -> CasePlan:
    values: dict[str, object] = {
        "case_id": "case-1",
        "source": "synthetic",
        "split": "development",
        "family_group": "wininet_proxy",
        "scenario_role": "network_proxy_fault",
        "objective": "Browser cannot reach the service",
        "visible_input_sha256": H,
        "initial_evidence_sha256": J,
        "ordered_tools_sha256": K,
        "budget_ms": 30000,
        "max_probes": 8,
        "max_model_calls": 5,
    }
    values.update(changes)
    return CasePlan.model_validate(values)


def _trajectory(arm: Arm, **changes: object) -> Trajectory:
    values: dict[str, object] = {
        "case_id": "case-1",
        "arm": arm,
        "status": "completed",
        "visible_input_sha256": H,
        "initial_evidence_sha256": J,
        "ordered_tools_sha256": K,
        "budget_ms": 30000,
        "max_probes": 8,
        "max_model_calls": 5,
        "started_at_ms": 100,
        "finished_at_ms": 1200,
        "capture_sha256": H,
        "review_sha256": J,
        "choices": (),
        "claims": (),
        "provider_calls": (),
    }
    values.update(changes)
    return Trajectory.model_validate(values)


def test_matrix_reserves_both_domains_and_controls_before_tuning() -> None:
    roles = {item.role for item in SCENARIO_MATRIX}
    assert {
        "network_proxy_fault",
        "network_external_control",
        "network_healthy_control",
        "network_misleading_abnormality",
        "network_same_symptom_other_cause",
        "network_counterevidence",
        "application_performance_fault",
        "application_healthy_control",
        "application_misleading_abnormality",
        "application_counterevidence",
    } <= roles
    assert {item.split for item in SCENARIO_MATRIX} == {"development", "holdout"}
    assert all(item.family_group for item in SCENARIO_MATRIX)


def test_freeze_rejects_family_group_crossing_holdout() -> None:
    with pytest.raises(ValueError, match="family group crosses"):
        freeze_protocol(
            (
                _case(),
                _case(
                    case_id="case-2",
                    split="holdout",
                    family_group="wininet_proxy",
                    scenario_role="network_same_symptom_other_cause",
                ),
            )
        )


def test_freeze_rejects_reassigned_holdout_and_modified_digest() -> None:
    with pytest.raises(ValueError, match="reserved role"):
        freeze_protocol((_case(split="holdout"),))
    with pytest.raises(ValueError, match="reserved role"):
        freeze_protocol((_case(family_group="new-recipe"),))
    plan = freeze_protocol((_case(),))
    forged = plan.model_copy(update={"digest": K})
    with pytest.raises(ValueError, match="digest"):
        score_trajectories(forged, ())


def test_source_classes_are_scored_separately() -> None:
    with pytest.raises(ValueError, match="source classes"):
        score_trajectories(
            freeze_protocol((_case(), _case(case_id="case-2", source="windows_vm"))), ()
        )


def test_policy_input_has_only_visible_fields() -> None:
    shown = visible_case_input(_case())
    assert shown["objective"] == "Browser cannot reach the service"
    assert "family_group" not in shown
    assert "scenario_role" not in shown
    assert "split" not in shown
    assert "recipe" not in str(shown)


def test_parity_rejects_different_tools_or_budget() -> None:
    plan = freeze_protocol((_case(),))
    for mismatch in (
        {"ordered_tools_sha256": H},
        {"initial_evidence_sha256": H},
        {"max_probes": 9},
        {"budget_ms": 20000},
    ):
        with pytest.raises(ValueError, match="parity"):
            score_trajectories(plan, (_trajectory(Arm.DETERMINISTIC, **mismatch),))


def test_score_counts_unknowns_failures_cost_and_prefetch_without_inventing_utility() -> None:
    plan = freeze_protocol((_case(),))
    record = _trajectory(
        Arm.FAST_DEEP_SCOUT_ON,
        status="failed",
        choices=(
            Choice(
                kind="probe",
                item_id="probe-1",
                outcome="useful",
                elapsed_ms=200,
                prefetch=True,
                used=True,
            ),
            Choice(kind="probe", item_id="probe-2", outcome="uninformative", elapsed_ms=400),
            Choice(kind="retrieve", item_id="stored-1", outcome="uninformative", elapsed_ms=500),
            Choice(
                kind="probe", item_id="probe-3", outcome="unknown", elapsed_ms=600, prefetch=True
            ),
        ),
        claims=(Claim(code="proxy_fault", supported=False),),
        provider_calls=(
            ProviderCall(
                role="fast",
                attempted_provider_id="laya",
                effective_provider_id=None,
                model_id="laya-0.3.5",
                failed=True,
                invalid_advice=True,
                cost_usd=0.01,
            ),
        ),
        host_impact_ms=37,
        eligible_opportunities=6,
    )
    report = score_trajectories(plan, (record,))
    arm = report["arms"][Arm.FAST_DEEP_SCOUT_ON.value]
    assert arm["eligible"] == 1 and arm["failed"] == 1
    assert arm["useful_evidence"] == 1 and arm["wasted_probes"] == 1
    assert arm["unknown_choices"] == 1 and arm["wrong_claims"] == 1
    assert arm["eligible_opportunities"] == 6 and arm["missed_opportunities"] == 2
    assert arm["first_useful_ms"] == [200]
    assert arm["prefetch_used"] == 1 and arm["prefetch_wasted"] == 0
    assert arm["prefetch_unknown"] == 1
    assert arm["invalid_advice"] == 1 and arm["provider_failures"] == 1
    assert arm["model_cost_usd"] == 0.01 and arm["host_impact_ms"] == 37
    assert report["arms"][Arm.DETERMINISTIC.value]["unrun"] == 1
    assert report["arms"][Arm.DETERMINISTIC.value]["model_cost_usd"] is None
    assert report["arms"][Arm.DETERMINISTIC.value]["host_impact_ms"] is None
    assert report["complete_paired_cases"] == 0
    assert report["diagnostic_performance_admissible"] is False


def test_complete_pair_still_needs_independent_real_episode_qualification() -> None:
    plan = freeze_protocol((_case(),))
    records = tuple(_trajectory(arm) for arm in REQUIRED_ARMS)
    report = score_trajectories(plan, records)
    assert report["complete_paired_cases"] == 1
    assert report["diagnostic_performance_admissible"] is False


def test_duplicate_arm_and_unrun_choice_with_observed_utility_fail_closed() -> None:
    plan = freeze_protocol((_case(),))
    record = _trajectory(Arm.DETERMINISTIC)
    with pytest.raises(ValueError, match="duplicate"):
        score_trajectories(plan, (record, record))
    with pytest.raises(ValueError, match="unrun"):
        Choice(kind="probe", item_id="probe", outcome="unrun", elapsed_ms=100, used=True)


def test_missing_opportunity_count_stays_unknown_and_invalid_counts_fail() -> None:
    plan = freeze_protocol((_case(),))
    report = score_trajectories(plan, (_trajectory(Arm.DETERMINISTIC),))
    arm = report["arms"][Arm.DETERMINISTIC.value]
    assert arm["eligible_opportunities"] is None
    assert arm["missed_opportunities"] is None
    assert arm["missing_opportunity_accounting"] == 1
    with pytest.raises(ValueError, match="eligible opportunities"):
        _trajectory(
            Arm.DETERMINISTIC,
            eligible_opportunities=0,
            choices=(Choice(kind="probe", item_id="p", outcome="useful", elapsed_ms=1),),
        )


def test_supported_discrimination_requires_cited_reviewed_evidence_and_time() -> None:
    plan = freeze_protocol((_case(),))
    with pytest.raises(ValueError, match="cited evidence"):
        Claim(code="proxy_fault", supported=True, alternatives_discriminated=True, elapsed_ms=700)
    with pytest.raises(ValueError, match="supported cause"):
        Claim(code="proxy_fault", supported=False, alternatives_discriminated=True, elapsed_ms=700)
    record = _trajectory(
        Arm.DETERMINISTIC,
        claims=(
            Claim(
                code="proxy_fault",
                supported=True,
                alternatives_discriminated=True,
                cited_evidence_ids=("ev-1",),
                elapsed_ms=700,
            ),
            Claim(code="dns_fault", supported=False, elapsed_ms=800),
        ),
    )
    arm = score_trajectories(plan, (record,))["arms"][Arm.DETERMINISTIC.value]
    assert arm["supported_claims"] == 1
    assert arm["supported_discrimination"] == 1
    assert arm["wrong_claims"] == 1
    assert arm["first_supported_answer_ms"] == [700]


def test_no_update_cli_freezes_then_scores_without_changing_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cases_path = tmp_path / "cases.json"
    plan_path = tmp_path / "frozen.json"
    records_path = tmp_path / "records.json"
    cases_path.write_text(json.dumps([_case().model_dump(mode="json")]), encoding="utf-8")
    records_path.write_text(
        json.dumps([_trajectory(Arm.DETERMINISTIC).model_dump(mode="json")]), encoding="utf-8"
    )
    before = tuple(sha256(path.read_bytes()).hexdigest() for path in (cases_path, records_path))
    assert main(["freeze", "--cases", str(cases_path), "--output", str(plan_path)]) == 0
    with pytest.raises(FileExistsError):
        main(["freeze", "--cases", str(cases_path), "--output", str(plan_path)])
    capsys.readouterr()
    assert main(["score", "--protocol", str(plan_path), "--trajectories", str(records_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["complete_paired_cases"] == 0
    assert report["arms"][Arm.DEEP_ONLY.value]["unrun"] == 1
    assert before == tuple(
        sha256(path.read_bytes()).hexdigest() for path in (cases_path, records_path)
    )
