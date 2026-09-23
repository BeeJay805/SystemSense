"""Evidence-bound progress bookkeeping for a proposed diagnostic test.

The caller owns test registration and independent predicate verification. This
ledger records those results; it never treats model prose or raw evidence count
as proof that an uncertainty was resolved.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId


class PredictedOutcome(FrozenModel):
    hypothesis_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    predicate_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    expected: bool


class TestIntent(FrozenModel):
    """A registered question whose answers separate competing hypotheses."""

    schema_version: Literal[1] = 1
    intent_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    branch_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    uncertainty_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    predictions: tuple[PredictedOutcome, ...] = Field(min_length=2, max_length=16)
    unresolved_assumption_ids: tuple[str, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def require_discrimination(self) -> TestIntent:
        if (
            len({item.hypothesis_id for item in self.predictions}) != len(self.predictions)
            or len({item.predicate_id for item in self.predictions}) != 1
            or {item.expected for item in self.predictions} != {True, False}
        ):
            raise ValueError("test intent requires unique competing predictions for one predicate")
        if len(set(self.unresolved_assumption_ids)) != len(self.unresolved_assumption_ids):
            raise ValueError("unresolved assumptions must be unique")
        return self


class VerifiedPredicateObservation(FrozenModel):
    """A caller-verified test result; false requires cited coverage too."""

    predicate_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    observed: bool
    evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def unique_evidence(self) -> VerifiedPredicateObservation:
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("predicate observation repeats evidence IDs")
        return self


class ProgressEvent(FrozenModel):
    intent_id: str
    branch_id: str
    uncertainty_id: str
    predicate_id: str
    evidence_ids: tuple[EvidenceId, ...]
    observation_novelty_count: int = Field(ge=0)
    retrieval_completed: bool
    accepted_predicate_ids: tuple[str, ...]
    refuted_predicate_ids: tuple[str, ...]
    prediction_matched_hypothesis_ids: tuple[str, ...]
    prediction_disfavored_hypothesis_ids: tuple[str, ...]
    unresolved_assumption_ids: tuple[str, ...]
    conflicting_result: bool
    diagnostic_progress: bool
    dead_end: bool


class ProgressLedger(FrozenModel):
    schema_version: Literal[1] = 1
    events: tuple[ProgressEvent, ...] = Field(default=(), max_length=512)

    def consecutive_dead_ends(self, branch_id: str) -> int:
        """Count branch-local unproductive attempts since its last discrimination."""

        count = 0
        for event in reversed(self.events):
            if event.branch_id != branch_id:
                continue
            if event.diagnostic_progress:
                break
            count += 1
        return count


def record_progress(
    ledger: ProgressLedger,
    *,
    intent: TestIntent,
    observation: VerifiedPredicateObservation | None,
    novel_evidence_ids: tuple[EvidenceId, ...] = (),
    retrieval_completed: bool = False,
) -> ProgressLedger:
    """Record a tested distinction separately from raw novelty and retrieval."""

    predicate_id = intent.predictions[0].predicate_id
    if observation is not None and observation.predicate_id != predicate_id:
        raise ValueError("observation does not answer the test intent predicate")
    if len(set(novel_evidence_ids)) != len(novel_evidence_ids):
        raise ValueError("novel evidence IDs must be unique")
    prior_values = {
        (event.uncertainty_id, event.predicate_id, bool(event.accepted_predicate_ids))
        for event in ledger.events
        if event.accepted_predicate_ids or event.refuted_predicate_ids
    }
    prior_same = (
        observation is not None
        and (intent.uncertainty_id, predicate_id, observation.observed) in prior_values
    )
    prior_opposite = (
        observation is not None
        and (intent.uncertainty_id, predicate_id, not observation.observed) in prior_values
    )
    discriminated = observation is not None and not prior_same and not prior_opposite
    matched: tuple[str, ...] = ()
    disfavored: tuple[str, ...] = ()
    if discriminated and observation is not None:
        matched = tuple(
            item.hypothesis_id
            for item in intent.predictions
            if item.expected == observation.observed
        )
        disfavored = tuple(
            item.hypothesis_id
            for item in intent.predictions
            if item.expected != observation.observed
        )
    event = ProgressEvent(
        intent_id=intent.intent_id,
        branch_id=intent.branch_id,
        uncertainty_id=intent.uncertainty_id,
        predicate_id=predicate_id,
        evidence_ids=observation.evidence_ids if observation is not None else (),
        observation_novelty_count=len(novel_evidence_ids),
        retrieval_completed=retrieval_completed,
        accepted_predicate_ids=(predicate_id,)
        if discriminated and observation is not None and observation.observed
        else (),
        refuted_predicate_ids=(predicate_id,)
        if discriminated and observation is not None and not observation.observed
        else (),
        prediction_matched_hypothesis_ids=matched,
        prediction_disfavored_hypothesis_ids=disfavored,
        unresolved_assumption_ids=intent.unresolved_assumption_ids,
        conflicting_result=bool(prior_opposite),
        diagnostic_progress=discriminated,
        dead_end=not discriminated,
    )
    return ProgressLedger(events=(*ledger.events, event))
