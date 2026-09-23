"""Diagnostic progress depends on tested distinctions, not raw record novelty."""

import pytest
from pydantic import ValidationError

from systemsense.domain.ids import EvidenceId
from systemsense.evaluation.progress import (
    PredictedOutcome,
    ProgressLedger,
    VerifiedPredicateObservation,
    record_progress,
)
from systemsense.evaluation.progress import (
    TestIntent as DiagnosticTestIntent,
)


def _intent() -> DiagnosticTestIntent:
    return DiagnosticTestIntent(
        intent_id="test.proxy_enabled",
        branch_id="branch.connectivity",
        probe_id="windows.proxy",
        uncertainty_id="uncertainty.proxy_cause",
        predictions=(
            PredictedOutcome(
                hypothesis_id="hyp.proxy", predicate_id="proxy.enabled", expected=True
            ),
            PredictedOutcome(hypothesis_id="hyp.dns", predicate_id="proxy.enabled", expected=False),
        ),
        unresolved_assumption_ids=("assumption.current_config",),
    )


def test_novel_unrelated_observation_does_not_count_as_diagnostic_progress() -> None:
    ledger = record_progress(
        ProgressLedger(),
        intent=_intent(),
        observation=None,
        novel_evidence_ids=(EvidenceId.new(),),
        retrieval_completed=True,
    )

    event = ledger.events[-1]
    assert event.observation_novelty_count == 1
    assert event.retrieval_completed is True
    assert event.diagnostic_progress is False
    assert event.dead_end is True
    assert ledger.consecutive_dead_ends("branch.connectivity") == 1


def test_discriminating_negative_result_counts_as_progress() -> None:
    evidence_id = EvidenceId.new()
    ledger = record_progress(
        ProgressLedger(),
        intent=_intent(),
        observation=VerifiedPredicateObservation(
            predicate_id="proxy.enabled", observed=False, evidence_ids=(evidence_id,)
        ),
        novel_evidence_ids=(),
        retrieval_completed=False,
    )

    event = ledger.events[-1]
    assert event.diagnostic_progress is True
    assert event.dead_end is False
    assert event.prediction_matched_hypothesis_ids == ("hyp.dns",)
    assert event.prediction_disfavored_hypothesis_ids == ("hyp.proxy",)
    assert event.refuted_predicate_ids == ("proxy.enabled",)
    assert event.evidence_ids == (evidence_id,)
    assert ledger.consecutive_dead_ends("branch.connectivity") == 0


def test_repeating_same_test_result_does_not_reset_branch_dead_ends() -> None:
    observation = VerifiedPredicateObservation(
        predicate_id="proxy.enabled", observed=False, evidence_ids=(EvidenceId.new(),)
    )
    first = record_progress(ProgressLedger(), intent=_intent(), observation=observation)
    repeated = record_progress(
        first,
        intent=_intent(),
        observation=observation,
        novel_evidence_ids=(EvidenceId.new(),),
    )

    assert first.events[-1].diagnostic_progress is True
    assert repeated.events[-1].diagnostic_progress is False
    assert repeated.events[-1].dead_end is True
    assert repeated.consecutive_dead_ends("branch.connectivity") == 1


def test_rephrased_hypotheses_do_not_create_progress_for_same_uncertainty() -> None:
    observation = VerifiedPredicateObservation(
        predicate_id="proxy.enabled", observed=False, evidence_ids=(EvidenceId.new(),)
    )
    first = record_progress(ProgressLedger(), intent=_intent(), observation=observation)
    rephrased = _intent().model_copy(
        update={
            "intent_id": "test.proxy_enabled_reworded",
            "predictions": (
                PredictedOutcome(
                    hypothesis_id="hyp.proxy_reworded",
                    predicate_id="proxy.enabled",
                    expected=True,
                ),
                PredictedOutcome(
                    hypothesis_id="hyp.dns_reworded",
                    predicate_id="proxy.enabled",
                    expected=False,
                ),
            ),
        }
    )
    repeated = record_progress(first, intent=rephrased, observation=observation)

    assert repeated.events[-1].diagnostic_progress is False
    assert repeated.consecutive_dead_ends("branch.connectivity") == 1


def test_conflicting_repeat_requires_adjudication() -> None:
    first = record_progress(
        ProgressLedger(),
        intent=_intent(),
        observation=VerifiedPredicateObservation(
            predicate_id="proxy.enabled", observed=False, evidence_ids=(EvidenceId.new(),)
        ),
    )
    conflicting = record_progress(
        first,
        intent=_intent(),
        observation=VerifiedPredicateObservation(
            predicate_id="proxy.enabled", observed=True, evidence_ids=(EvidenceId.new(),)
        ),
    )

    assert conflicting.events[-1].conflicting_result is True
    assert conflicting.events[-1].diagnostic_progress is False
    assert conflicting.events[-1].dead_end is True


def test_intent_requires_competing_predictions_and_negative_evidence_is_cited() -> None:
    with pytest.raises(ValidationError, match="competing predictions"):
        DiagnosticTestIntent(
            intent_id="test.proxy_enabled",
            branch_id="branch.connectivity",
            probe_id="windows.proxy",
            uncertainty_id="uncertainty.proxy_cause",
            predictions=(
                PredictedOutcome(
                    hypothesis_id="hyp.proxy", predicate_id="proxy.enabled", expected=True
                ),
                PredictedOutcome(
                    hypothesis_id="hyp.dns", predicate_id="proxy.enabled", expected=True
                ),
            ),
        )
    with pytest.raises(ValidationError, match="evidence_ids"):
        VerifiedPredicateObservation(predicate_id="proxy.enabled", observed=False, evidence_ids=())
