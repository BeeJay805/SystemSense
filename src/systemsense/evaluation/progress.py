"""Evidence-bound progress bookkeeping for a proposed diagnostic test.

The caller owns test registration and independent predicate verification. This
ledger records those results; it never treats model prose or raw evidence count
as proof that an uncertainty was resolved.
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from systemsense.domain.evidence import EvidenceRecord, FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, stable_source_id
from systemsense.domain.probes import MeasurementWindow
from systemsense.domain.time import UtcDateTime
from systemsense.platform.windows.connectivity import ConnectivitySnapshot
from systemsense.platform.windows.deep_collectors import ComponentStatus


class PredicateScope(FrozenModel):
    """The exact case, target, and source-observation interval being tested."""

    case_id: CaseId
    target_handle: str = Field(min_length=1, max_length=120)
    window: MeasurementWindow


class PredicateEvaluation(FrozenModel):
    """A three-valued, cited result, not a diagnosis or causal conclusion."""

    schema_version: Literal[1] = 1
    predicate_id: Literal["network.wifi_associated"] = "network.wifi_associated"
    scope: PredicateScope
    observed: bool | None
    evidence_ids: tuple[EvidenceId, ...] = Field(max_length=64)
    observed_at: tuple[UtcDateTime, ...] = Field(max_length=64)
    reason: str = Field(min_length=1, max_length=240)


def evaluate_wifi_association(
    *, scope: PredicateScope, evidence: tuple[EvidenceRecord, ...]
) -> PredicateEvaluation:
    """Test explicit WLAN association for one GUID within the requested window.

    Connected and disconnected are direct API states. Transitional states, missing
    rows, unavailable sources and contradictory observations are unknown. This
    does not test Internet reachability or identify the cause of a failure.
    """

    if len(evidence) > 64 or len({str(row.evidence_id) for row in evidence}) != len(evidence):
        raise ValueError("predicate evidence must have at most 64 unique IDs")
    try:
        target = str(uuid.UUID(scope.target_handle))
    except ValueError as error:
        raise ValueError("WLAN predicate target must be an interface GUID") from error
    if target != scope.target_handle:
        raise ValueError("WLAN predicate target must be a canonical interface GUID")
    values: set[bool] = set()
    citations: list[EvidenceId] = []
    times: list[UtcDateTime] = []
    incomplete = False
    for record in evidence:
        if record.case_id != scope.case_id or record.collector.id != "network.connectivity":
            continue
        citations.append(record.evidence_id)
        facts = [fact.value for fact in record.facts if fact.name == "connectivity_detail"]
        if (
            record.statement_kind is not StatementKind.OBSERVED_FACT
            or record.collector.version != 1
            or record.source.type != "systemsense.probe"
            or record.source.locator != {"probe_id": "network.connectivity"}
            or record.source.source_id
            != stable_source_id(
                "systemsense.probe", {"probe_id": "network.connectivity", "probe_version": 1}
            )
            or record.extraction.parser != "builtin.probe"
            or record.extraction.parser_version != 1
            or len(facts) != 1
            or record.observed_at > record.captured_at
        ):
            incomplete = True
            continue
        try:
            snapshot = ConnectivitySnapshot.model_validate(facts[0])
        except ValidationError:
            incomplete = True
            continue
        if not snapshot.wifi_observed_at <= snapshot.captured_at <= record.observed_at:
            incomplete = True
            continue
        if not scope.window.start <= snapshot.wifi_observed_at <= scope.window.end:
            citations.pop()
            continue
        times.append(snapshot.wifi_observed_at)
        matched = []
        try:
            matched = [
                row
                for row in snapshot.wifi_interfaces
                if str(uuid.UUID(row.interface_guid)) == target
            ]
        except ValueError:
            incomplete = True
            continue
        if (
            snapshot.wifi_status is not ComponentStatus.AVAILABLE
            or snapshot.omitted_wifi_count != 0
            or len(matched) != 1
            or matched[0].details_status is not ComponentStatus.AVAILABLE
            or matched[0].association_state not in {"connected", "disconnected"}
        ):
            incomplete = True
            continue
        values.add(matched[0].association_state == "connected")
    observed = next(iter(values)) if len(values) == 1 and not incomplete else None
    return PredicateEvaluation(
        scope=scope,
        observed=observed,
        evidence_ids=tuple(citations),
        observed_at=tuple(times),
        reason=(
            "Explicit WLAN association state observed for the scoped interface."
            if observed is not None
            else "No unambiguous complete WLAN association observation covers the requested scope."
        ),
    )


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
    scope: PredicateScope | None = None

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
    scope: PredicateScope | None = None

    @model_validator(mode="after")
    def unique_evidence(self) -> VerifiedPredicateObservation:
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("predicate observation repeats evidence IDs")
        return self


class ProgressEvent(FrozenModel):
    scope: PredicateScope | None = None
    evaluation: PredicateEvaluation | None = None
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
    if observation is not None and observation.scope != intent.scope:
        raise ValueError("observation scope does not match the test intent scope")
    if observation is not None and observation.predicate_id != predicate_id:
        raise ValueError("observation does not answer the test intent predicate")
    if len(set(novel_evidence_ids)) != len(novel_evidence_ids):
        raise ValueError("novel evidence IDs must be unique")
    prior_values = {
        (event.uncertainty_id, event.predicate_id, event.scope, bool(event.accepted_predicate_ids))
        for event in ledger.events
        if event.accepted_predicate_ids or event.refuted_predicate_ids
    }
    prior_same = (
        observation is not None
        and (intent.uncertainty_id, predicate_id, intent.scope, observation.observed)
        in prior_values
    )
    prior_opposite = (
        observation is not None
        and (intent.uncertainty_id, predicate_id, intent.scope, not observation.observed)
        in prior_values
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
        scope=intent.scope,
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


def record_test_progress(
    ledger: ProgressLedger,
    *,
    intent: TestIntent,
    evidence: tuple[EvidenceRecord, ...],
    novel_evidence_ids: tuple[EvidenceId, ...] = (),
    retrieval_completed: bool = False,
) -> ProgressLedger:
    """Execute the registered predicate against trusted local evidence records.

    Callers load records from case storage; provider prose and caller-supplied
    boolean predictions are not used as observations. Unknown results remain
    auditable dead ends and cannot establish or refute a hypothesis.
    """

    if intent.scope is None:
        raise ValueError("registered test requires an exact evidence scope")
    if (
        intent.probe_id != "network.connectivity"
        or intent.predictions[0].predicate_id != "network.wifi_associated"
    ):
        raise ValueError("test intent does not name a registered predicate and probe")
    evaluation = evaluate_wifi_association(scope=intent.scope, evidence=evidence)
    observation = None
    if evaluation.observed is not None:
        observation = VerifiedPredicateObservation(
            predicate_id=evaluation.predicate_id,
            observed=evaluation.observed,
            evidence_ids=evaluation.evidence_ids,
            scope=evaluation.scope,
        )
    updated = record_progress(
        ledger,
        intent=intent,
        observation=observation,
        novel_evidence_ids=novel_evidence_ids,
        retrieval_completed=retrieval_completed,
    )
    event = updated.events[-1].model_copy(
        update={
            "evaluation": evaluation,
            "evidence_ids": evaluation.evidence_ids,
        }
    )
    return ProgressLedger(events=(*updated.events[:-1], event))
