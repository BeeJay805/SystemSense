"""Development fixtures exercise scoring mechanics without consuming holdouts."""

from dataclasses import replace

import pytest

from benchmarks.private_alpha_blinded import (
    ARMS,
    Contract,
    Review,
    Trial,
    blind_packet,
    compare,
    digest,
)


def _contract() -> Contract:
    return Contract(
        source_revision="a" * 40,
        source_tree_sha256="a" * 64,
        manifest_sha256="b" * 64,
        rubric_sha256="c" * 64,
        objective_sha256="d" * 64,
        access_sha256="e" * 64,
        registry_sha256="f" * 64,
        budget_ms=90_000,
        max_rounds=6,
        max_probe_calls=6,
        max_advisory_tokens=8_000,
    )


def _trial(arm: str) -> Trial:
    return Trial(
        case_id="development-1",
        arm=arm,
        contract=_contract(),
        packet_sha256="1" * 64,
        evidence_ids=("observation-1",),
        execution_receipt_sha256="2" * 64,
        runtime_identity="deterministic" if arm == "basic" else "verified-model-receipt",
        completed=True,
        control_verified=True,
        independent_target_verified=True,
        restoration_verified=True,
        cleanup_verified=True,
        elapsed_ms=10_000,
        probe_calls=3,
        advisory_tokens=0 if arm == "basic" else 1_000,
        rounds=3,
    )


def _review(trial: Trial, **changes: object) -> Review:
    values: dict[str, object] = {
        "case_id": trial.case_id,
        "arm": trial.arm,
        "packet_sha256": trial.packet_sha256,
        "rubric_sha256": trial.contract.rubric_sha256,
        "reviewer_id": "independent-human",
        "classification": "bounded_distinction",
        "rubric_satisfied": True,
        "citations": ("observation-1",),
        "target_and_time_supported": True,
        "rivals_and_limits_preserved": True,
        "unsupported_cause": False,
        "false_healthy_claim": False,
        "rationale": "Same owner sampled during the second request; handler cause unknown.",
    }
    values.update(changes)
    return Review(**values)  # type: ignore[arg-type]


def test_blind_packet_excludes_route_oracle_and_runtime_labels() -> None:
    product = {
        "summary": "Second request timed out while its owner used CPU.",
        "status": "complete",
        "outcome": "uncertain",
        "evidence": [{"evidence_id": "observation-1", "facts": {"cores": 1.0}}],
        "provider_calls": [{"provider_id": "laya"}],
        "evaluator": {"hidden_answer": "never export"},
        "stop_reason": "model-specific closure marker",
    }
    packet = blind_packet(product, "opaque-review-token")
    assert set(packet) == {
        "schema_version",
        "review_token",
        "summary",
        "status",
        "outcome",
        "evidence",
    }
    assert "laya" not in str(packet)
    assert "never export" not in str(packet)
    assert "model-specific" not in str(packet)
    assert digest(packet) == digest(dict(reversed(list(packet.items()))))


def test_three_arm_comparison_requires_full_frozen_case_denominator() -> None:
    trials = [_trial(arm) for arm in ARMS]
    reviews = [_review(trial) for trial in trials]
    report = compare(("development-1", "development-2"), trials, reviews)
    assert report["count_per_arm"] == 2
    assert report["matched_complete_cases"] == 1
    assert report["useful_by_arm"] == dict.fromkeys(ARMS, 1)
    assert len(report["cases"]) == 6
    assert all(
        row["useful"] is False for row in report["cases"] if row["case_id"] == "development-2"
    )


@pytest.mark.parametrize(
    "field,value",
    [("budget_ms", 80_000), ("access_sha256", "9" * 64), ("max_advisory_tokens", 4_000)],
)
def test_parity_mismatch_is_rejected(field: str, value: object) -> None:
    trials = [_trial(arm) for arm in ARMS]
    trials[-1] = replace(trials[-1], contract=replace(trials[-1].contract, **{field: value}))
    with pytest.raises(ValueError, match="matched contract"):
        compare(("development-1",), trials, [])


@pytest.mark.parametrize(
    "change",
    [
        {"classification": "observation_only"},
        {"rubric_satisfied": False},
        {"unsupported_cause": True},
        {"false_healthy_claim": True},
        {"target_and_time_supported": False},
        {"rivals_and_limits_preserved": False},
        {"citations": ("unseen-evidence",)},
    ],
)
def test_symptom_or_unsupported_review_never_earns_usefulness(change: dict[str, object]) -> None:
    trial = _trial("basic")
    report = compare((trial.case_id,), [trial], [_review(trial, **change)])
    assert report["useful_by_arm"]["basic"] == 0


def test_review_is_bound_to_exact_packet_and_frozen_rubric() -> None:
    trial = _trial("basic")
    for change in ({"packet_sha256": "3" * 64}, {"rubric_sha256": "3" * 64}):
        with pytest.raises(ValueError, match="review binding"):
            compare((trial.case_id,), [trial], [_review(trial, **change)])


def test_failure_budget_overrun_and_missing_runtime_identity_are_failures() -> None:
    for change in (
        {"completed": False},
        {"elapsed_ms": 90_001},
        {"runtime_identity": ""},
        {"probe_calls": 7},
        {"independent_target_verified": False},
        {"cleanup_verified": False},
    ):
        trial = replace(_trial("laya_deep"), **change)
        report = compare((trial.case_id,), [trial], [_review(trial)])
        assert report["useful_by_arm"]["laya_deep"] == 0


def test_duplicate_or_unplanned_attempt_cannot_replace_failed_attempt() -> None:
    trial = _trial("basic")
    with pytest.raises(ValueError, match="duplicate"):
        compare((trial.case_id,), [trial, trial], [])
    with pytest.raises(ValueError, match="unplanned"):
        compare(("different-case",), [trial], [])


def test_holdout_scoring_is_disabled() -> None:
    with pytest.raises(ValueError, match="holdouts remain sealed"):
        compare(("case-1",), [], [], split="holdout")
