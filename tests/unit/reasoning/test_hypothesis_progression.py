"""Competing advisory hypotheses survive later incomplete reasoning turns."""

from datetime import UTC, datetime, timedelta
from typing import Literal

import pytest

from systemsense.domain.ids import EvidenceId
from systemsense.reasoning.contracts import (
    ExpectedFact,
    Hypothesis,
    HypothesisRevisionIntentV1,
    HypothesisStatus,
    NoncausalHypothesisRefV1,
    NoncausalObservationReviewV1,
    PriorHypothesisRevisionRefV1,
    hypothesis_revision_sha256,
)
from systemsense.reasoning.hypothesis_progression import progress_hypotheses


def _eid(index: int) -> EvidenceId:
    return EvidenceId(root=f"ev_{index:032x}")


def _fact(value: int) -> ExpectedFact:
    return ExpectedFact(probe_id="core.snapshot", fact_name="value", expected_value=value)


def _hypothesis(
    name: str,
    *,
    statement: str | None = None,
    support: tuple[EvidenceId, ...] = (),
    contradiction: tuple[EvidenceId, ...] = (),
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED,
) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=name,
        statement=statement or f"Possible explanation {name}",
        status=status,
        supporting_evidence_ids=support,
        contradicting_evidence_ids=contradiction,
    )


def test_later_advice_cannot_drop_competing_prior_rivals() -> None:
    prior = (
        _hypothesis("h_route", support=(_eid(1),)),
        _hypothesis("h_proxy", support=(_eid(2),), contradiction=(_eid(3),)),
    )
    new = (_hypothesis("h_dns", support=(_eid(4),)),)
    result = progress_hypotheses(
        previous=prior,
        advisory=new,
        custodied_evidence_ids=tuple(_eid(i) for i in range(1, 5)),
        visible_evidence_ids=tuple(_eid(i) for i in range(1, 5)),
    )

    assert tuple(item.hypothesis_id for item in result.hypotheses) == (
        "h_route",
        "h_proxy",
        "h_dns",
    )
    assert result.hypotheses[1].contradicting_evidence_ids == (_eid(3),)
    assert result.hypotheses[1].status is HypothesisStatus.CONTESTED
    assert not result.uncertain


def test_new_contradiction_cannot_erase_old_support_or_trusted_counterevidence() -> None:
    prior = _hypothesis("h_route", support=(_eid(1),), contradiction=(_eid(2),))
    revised = _hypothesis(
        "h_route", statement=prior.statement, support=(_eid(1),), contradiction=(_eid(3),)
    )
    result = progress_hypotheses(
        previous=(prior,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1), _eid(2), _eid(3)),
        visible_evidence_ids=(_eid(1), _eid(2), _eid(3)),
    )

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].supporting_evidence_ids == (_eid(1),)
    assert result.hypotheses[0].contradicting_evidence_ids == (_eid(2), _eid(3))
    assert result.hypotheses[0].status is HypothesisStatus.CONTESTED


def test_advisory_supported_status_never_becomes_causal_proof() -> None:
    result = progress_hypotheses(
        previous=(),
        advisory=(_hypothesis("h_new", support=(_eid(1),), status=HypothesisStatus.SUPPORTED),),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
    )
    assert result.hypotheses[0].status is HypothesisStatus.UNRESOLVED


def test_unavailable_or_unshown_citations_are_reported_without_fake_support() -> None:
    prior = (
        _hypothesis("h_old", support=(_eid(1),)),
        _hypothesis("h_missing", contradiction=(_eid(9),)),
    )
    result = progress_hypotheses(
        previous=prior,
        advisory=(),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(),
    )

    assert tuple(item.hypothesis_id for item in result.hypotheses) == ("h_old",)
    assert result.omitted_hypothesis_ids == ("h_missing",)
    assert result.unavailable_citation_ids == (_eid(9),)
    assert result.unshown_citation_ids == (_eid(1),)
    assert result.uncertain
    assert any("citation" in note.lower() for note in result.notes)


def test_unknown_cause_is_reserved_under_the_sixteen_item_cap() -> None:
    prior = tuple(_hypothesis(f"h_prior_{index}") for index in range(15))
    unknown = _hypothesis("h_unknown", statement="The cause remains unknown.")
    new = _hypothesis("h_new")
    result = progress_hypotheses(
        previous=(*prior, unknown),
        advisory=(new,),
        custodied_evidence_ids=(),
        visible_evidence_ids=(),
        max_hypotheses=16,
    )

    assert len(result.hypotheses) == 16
    assert "h_unknown" in {item.hypothesis_id for item in result.hypotheses}
    assert result.omitted_hypothesis_ids == ("h_new",)
    assert result.uncertain
    assert any("cap" in note.lower() for note in result.notes)


def test_same_id_changed_statement_cannot_steal_old_citations() -> None:
    old = _hypothesis("h_same", support=(_eid(1),))
    changed = _hypothesis("h_same", statement="A different mechanism", support=(_eid(2),))
    result = progress_hypotheses(
        previous=(old,),
        advisory=(changed,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
    )

    assert result.hypotheses[0].statement == old.statement
    assert result.hypotheses[0].supporting_evidence_ids == (_eid(1),)
    assert result.rejected_update_ids == ("h_same",)
    assert result.uncertain


def _retire(old: Hypothesis, *ids: EvidenceId) -> HypothesisRevisionIntentV1:
    return HypothesisRevisionIntentV1(
        hypothesis_id=old.hypothesis_id,
        prior_hypothesis_sha256=hypothesis_revision_sha256(old),
        retired_supporting_evidence_ids=ids,
    )


def test_explicit_memory_revision_retires_old_support_with_immutable_lineage() -> None:
    old = _hypothesis(
        "memory_pressure",
        statement="Only capacity is known; pressure is unmeasured.",
        support=(_eid(1),),
        contradiction=(_eid(2),),
    ).model_copy(
        update={
            "expected_facts": (_fact(1),),
            "expected_facts_observed_after": datetime(2026, 9, 26, tzinfo=UTC),
        }
    )
    revised = _hypothesis(
        "memory_pressure",
        statement="Available memory and sampled pressure contest broad pressure.",
        contradiction=(_eid(2), _eid(3), _eid(4)),
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=tuple(_eid(i) for i in range(1, 5)),
        visible_evidence_ids=tuple(_eid(i) for i in range(1, 5)),
        revision_intents=(_retire(old, _eid(1)),),
        visible_prior_hypothesis_ids=("memory_pressure",),
        source_request_sha256="a" * 64,
    )
    active = result.hypotheses[0]
    assert active.statement == revised.statement
    assert active.supporting_evidence_ids == ()
    assert active.contradicting_evidence_ids == revised.contradicting_evidence_ids
    assert active.expected_facts == old.expected_facts
    assert active.expected_facts_observed_after == old.expected_facts_observed_after
    assert result.revision_links[0].prior_hypothesis_sha256 == hypothesis_revision_sha256(old)
    assert result.revision_links[0].revised_hypothesis_sha256 == hypothesis_revision_sha256(active)
    assert result.revision_links[0].retired_supporting_evidence_ids == (_eid(1),)
    assert result.revision_links[0].source_request_sha256 == "a" * 64


@pytest.mark.parametrize(
    "fault",
    (
        "no_intent",
        "wrong_digest",
        "foreign_retirement",
        "unshown_retirement",
        "missing_contradiction",
        "no_new_observation",
        "missing_prior_visibility",
        "missing_request_digest",
        "prediction_mutation",
        "new_prediction",
        "changed_prior",
    ),
)
def test_retirement_intent_fails_closed_on_broken_authority(fault: str) -> None:
    old = _hypothesis("memory_pressure", support=(_eid(1),), contradiction=(_eid(2),))
    revised = _hypothesis(
        "memory_pressure",
        statement="New scoped observation contests pressure.",
        contradiction=(_eid(2), _eid(3)),
    )
    intent = _retire(old, _eid(1))
    prior = old
    visible = (_eid(1), _eid(2), _eid(3))
    visible_prior = (old.hypothesis_id,)
    source = "a" * 64
    if fault == "no_intent":
        intents = ()
    else:
        intents = (intent,)
    if fault == "wrong_digest":
        intents = (intent.model_copy(update={"prior_hypothesis_sha256": "b" * 64}),)
    if fault == "foreign_retirement":
        intents = (_retire(old, _eid(9)),)
    if fault == "unshown_retirement":
        visible = (_eid(2), _eid(3))
    if fault == "missing_contradiction":
        revised = revised.model_copy(update={"contradicting_evidence_ids": (_eid(3),)})
    if fault == "no_new_observation":
        revised = revised.model_copy(update={"contradicting_evidence_ids": (_eid(2),)})
    if fault == "missing_prior_visibility":
        visible_prior = ()
    if fault == "missing_request_digest":
        source = None
    if fault == "prediction_mutation":
        prior = old.model_copy(update={"expected_facts": (_fact(1),)})
        intents = (_retire(prior, _eid(1)),)
        revised = revised.model_copy(update={"expected_facts": (_fact(2),)})
    if fault == "new_prediction":
        revised = revised.model_copy(update={"expected_facts": (_fact(1),)})
    if fault == "changed_prior":
        prior = old.model_copy(update={"statement": "Prior changed after advice was frozen."})
    result = progress_hypotheses(
        previous=(prior,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1), _eid(2), _eid(3)),
        visible_evidence_ids=visible,
        revision_intents=intents,
        visible_prior_hypothesis_ids=visible_prior,
        source_request_sha256=source,
    )
    assert result.hypotheses[0].statement == prior.statement
    assert result.rejected_update_ids == (old.hypothesis_id,)
    assert result.revision_links == ()


@pytest.mark.parametrize(
    ("name", "old_statement", "revised_statement", "support", "contradiction", "status"),
    (
        (
            "application_fault",
            "A named application fault record is still needed.",
            "A named PageDesk fault event supports an application fault, with timing unverified.",
            (_eid(1), _eid(2)),
            (),
            HypothesisStatus.UNRESOLVED,
        ),
        (
            "resource_pressure",
            "No system pressure was observed yet.",
            "The short CPU and memory readings do not show broad pressure.",
            (),
            (_eid(1), _eid(2)),
            HypothesisStatus.CONTESTED,
        ),
    ),
)
def test_uncited_rival_can_be_revised_by_visible_custodied_observation(
    name: str,
    old_statement: str,
    revised_statement: str,
    support: tuple[EvidenceId, ...],
    contradiction: tuple[EvidenceId, ...],
    status: HypothesisStatus,
) -> None:
    old = _hypothesis(name, statement=old_statement)
    revised = _hypothesis(
        name,
        statement=revised_statement,
        support=support,
        contradiction=contradiction,
        status=HypothesisStatus.SUPPORTED,
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
    )

    assert result.hypotheses[0].statement == revised_statement
    assert result.hypotheses[0].supporting_evidence_ids == support
    assert result.hypotheses[0].contradicting_evidence_ids == contradiction
    assert result.hypotheses[0].status is status
    assert result.rejected_update_ids == ()
    assert result.uncertain
    assert any("revision" in note.lower() for note in result.notes)


@pytest.mark.parametrize("citation_kind", ("none", "missing", "unshown"))
def test_uncited_statement_change_requires_new_visible_support_or_contradiction(
    citation_kind: str,
) -> None:
    old = _hypothesis("application_fault", statement="An application fault is unverified.")
    revised = _hypothesis(
        "application_fault",
        statement="A named event may support an application fault.",
        support=(_eid(1),) if citation_kind == "unshown" else (),
    )
    if citation_kind == "missing":
        revised = revised.model_copy(update={"missing_evidence_ids": (_eid(1),)})
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=() if citation_kind == "unshown" else (_eid(1),),
    )

    assert result.hypotheses == (old,)
    assert result.rejected_update_ids == ("application_fault",)


@pytest.mark.parametrize(
    ("hypothesis_id", "old_statement", "new_statement", "disposition"),
    (
        (
            "gpu_bottleneck",
            "GPU limitation is possible; no GPU measurement is supplied.",
            "A GPU thermal sample exists, but target and slow-frame binding are absent.",
            "target_unbound",
        ),
        (
            "application_fault",
            "No application fault event has been observed.",
            "An OtherTool event exists, but it does not identify the affected application.",
            "unrelated",
        ),
    ),
)
def test_new_per_rival_noncausal_ref_revises_uncited_statement_without_causal_credit(
    hypothesis_id: str,
    old_statement: str,
    new_statement: str,
    disposition: Literal["target_unbound", "time_unbound", "unrelated"],
) -> None:
    old = _hypothesis(hypothesis_id, statement=old_statement)
    ref = NoncausalHypothesisRefV1(evidence_id=_eid(1), disposition=disposition)
    revised = old.model_copy(
        update={
            "statement": new_statement,
            "status": HypothesisStatus.SUPPORTED,
            "noncausal_observation_refs": (ref,),
        }
    )
    review = NoncausalObservationReviewV1(
        evidence_id=ref.evidence_id,
        disposition=ref.disposition,
        explanation="The sampled source is not bound to the affected operation.",
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
        noncausal_reviews=(review,),
        frozen_prior_refs=(
            PriorHypothesisRevisionRefV1(
                hypothesis_id=hypothesis_id,
                hypothesis_sha256=hypothesis_revision_sha256(old),
            ),
        ),
        visible_prior_hypothesis_ids=(hypothesis_id,),
        source_request_sha256="a" * 64,
    )
    active = result.hypotheses[0]
    assert active.statement == new_statement
    assert active.status is HypothesisStatus.UNRESOLVED
    assert active.supporting_evidence_ids == active.contradicting_evidence_ids == ()
    assert active.missing_evidence_ids == ()
    assert active.noncausal_observation_refs == (ref,)
    assert len(result.noncausal_revision_links) == 1
    assert result.noncausal_revision_links[0].added_refs == (ref,)


def test_noncausal_ref_can_accompany_only_verified_new_missing_ids_and_new_probe_advice() -> None:
    old = _hypothesis("gpu_bottleneck", statement="No GPU measurement supplied.")
    ref = NoncausalHypothesisRefV1(evidence_id=_eid(1), disposition="target_unbound")
    revised = old.model_copy(
        update={
            "statement": "GPU thermal data exist but are not bound to slow frames.",
            "noncausal_observation_refs": (ref,),
            "missing_evidence_ids": (_eid(2),),
            "distinguishing_probe_ids": ("power.snapshot",),
        }
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
        verified_unavailable_evidence_ids=(_eid(2),),
        noncausal_reviews=(
            NoncausalObservationReviewV1(
                evidence_id=_eid(1),
                disposition="target_unbound",
                explanation="The adapter is not bound to the affected renderer.",
            ),
        ),
        frozen_prior_refs=(
            PriorHypothesisRevisionRefV1(
                hypothesis_id=old.hypothesis_id,
                hypothesis_sha256=hypothesis_revision_sha256(old),
            ),
        ),
        visible_prior_hypothesis_ids=(old.hypothesis_id,),
        source_request_sha256="a" * 64,
    )
    assert result.hypotheses == (revised,)
    assert result.noncausal_revision_links[0].added_missing_evidence_ids == (_eid(2),)


def test_noncausal_ref_is_carried_but_cannot_be_replayed_as_new_basis() -> None:
    old = _hypothesis("gpu_bottleneck", statement="No GPU measurement supplied.")
    first_ref = NoncausalHypothesisRefV1(evidence_id=_eid(1), disposition="target_unbound")
    first = old.model_copy(
        update={
            "statement": "GPU sample exists but its adapter is unbound.",
            "noncausal_observation_refs": (first_ref,),
        }
    )
    review = NoncausalObservationReviewV1(
        evidence_id=_eid(1),
        disposition="target_unbound",
        explanation="The sampled adapter is not bound to the renderer.",
    )
    first_result = progress_hypotheses(
        previous=(old,),
        advisory=(first,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
        noncausal_reviews=(review,),
        frozen_prior_refs=(
            PriorHypothesisRevisionRefV1(
                hypothesis_id=old.hypothesis_id,
                hypothesis_sha256=hypothesis_revision_sha256(old),
            ),
        ),
        visible_prior_hypothesis_ids=(old.hypothesis_id,),
        source_request_sha256="a" * 64,
    )
    active = first_result.hypotheses[0]
    carried = progress_hypotheses(
        previous=(active,),
        advisory=(active.model_copy(update={"noncausal_observation_refs": ()}),),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
    )
    assert carried.hypotheses[0].noncausal_observation_refs == (first_ref,)
    assert carried.noncausal_revision_links == ()
    broken_custody = progress_hypotheses(
        previous=(active,),
        advisory=(active,),
        custodied_evidence_ids=(),
        visible_evidence_ids=(),
    )
    assert broken_custody.hypotheses == ()
    assert broken_custody.omitted_hypothesis_ids == (active.hypothesis_id,)
    assert broken_custody.unavailable_citation_ids == (_eid(1),)
    second_ref = NoncausalHypothesisRefV1(evidence_id=_eid(2), disposition="time_unbound")
    ref_only_advice = active.model_copy(
        update={"noncausal_observation_refs": (first_ref, second_ref)}
    )
    unchanged_with_new_ref = progress_hypotheses(
        previous=(active,),
        advisory=(ref_only_advice,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
        noncausal_reviews=(
            NoncausalObservationReviewV1(
                evidence_id=_eid(2),
                disposition="time_unbound",
                explanation="The newer sample has no incident-time binding.",
            ),
        ),
        frozen_prior_refs=(
            PriorHypothesisRevisionRefV1(
                hypothesis_id=old.hypothesis_id,
                hypothesis_sha256=hypothesis_revision_sha256(active),
            ),
        ),
        visible_prior_hypothesis_ids=(old.hypothesis_id,),
        source_request_sha256="b" * 64,
    )
    assert unchanged_with_new_ref.hypotheses[0].statement == active.statement
    assert unchanged_with_new_ref.hypotheses[0].noncausal_observation_refs == (
        first_ref,
        second_ref,
    )
    assert unchanged_with_new_ref.noncausal_revision_links[0].added_refs == (second_ref,)
    unbound_ref_only = progress_hypotheses(
        previous=(active,),
        advisory=(ref_only_advice,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
        noncausal_reviews=(
            NoncausalObservationReviewV1(
                evidence_id=_eid(2),
                disposition="time_unbound",
                explanation="The newer sample has no incident-time binding.",
            ),
        ),
        frozen_prior_refs=(
            PriorHypothesisRevisionRefV1(
                hypothesis_id=old.hypothesis_id,
                hypothesis_sha256=hypothesis_revision_sha256(active),
            ),
        ),
        visible_prior_hypothesis_ids=(old.hypothesis_id,),
    )
    assert unbound_ref_only.hypotheses == (active,)
    assert unbound_ref_only.noncausal_revision_links == ()
    for candidate in (
        active.model_copy(update={"statement": "An unrelated new explanation."}),
        active.model_copy(
            update={
                "statement": "The same old sample now proves GPU limitation.",
                "supporting_evidence_ids": (_eid(1),),
                "noncausal_observation_refs": (),
            }
        ),
        active.model_copy(
            update={
                "statement": "The same old sample now refutes GPU limitation.",
                "contradicting_evidence_ids": (_eid(1),),
                "noncausal_observation_refs": (),
            }
        ),
    ):
        rejected = progress_hypotheses(
            previous=(active,),
            advisory=(candidate,),
            custodied_evidence_ids=(_eid(1),),
            visible_evidence_ids=(_eid(1),),
            noncausal_reviews=(review,),
            frozen_prior_refs=(
                PriorHypothesisRevisionRefV1(
                    hypothesis_id=old.hypothesis_id,
                    hypothesis_sha256=hypothesis_revision_sha256(active),
                ),
            ),
            visible_prior_hypothesis_ids=(old.hypothesis_id,),
            source_request_sha256="b" * 64,
        )
        assert rejected.hypotheses == (active,)
        assert rejected.noncausal_revision_links == ()


@pytest.mark.parametrize("failure", ("wrong_hash", "wrong_rival", "unshown", "wrong_review"))
def test_noncausal_revision_requires_exact_prior_and_reviewed_visible_source(
    failure: str,
) -> None:
    old = _hypothesis("application_fault", statement="No affected-app fault measured.")
    ref = NoncausalHypothesisRefV1(evidence_id=_eid(1), disposition="unrelated")
    revised = old.model_copy(
        update={
            "statement": "An OtherTool event exists but does not name the affected app.",
            "noncausal_observation_refs": (ref,),
        }
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=() if failure == "unshown" else (_eid(1),),
        noncausal_reviews=(
            NoncausalObservationReviewV1(
                evidence_id=_eid(1),
                disposition="time_unbound" if failure == "wrong_review" else "unrelated",
                explanation="The event is not bound to the affected app launch.",
            ),
        ),
        frozen_prior_refs=(
            PriorHypothesisRevisionRefV1(
                hypothesis_id=old.hypothesis_id,
                hypothesis_sha256="f" * 64
                if failure == "wrong_hash"
                else hypothesis_revision_sha256(old),
            ),
        ),
        visible_prior_hypothesis_ids=() if failure == "wrong_rival" else (old.hypothesis_id,),
        source_request_sha256="a" * 64,
    )
    assert result.hypotheses == (old,)
    assert result.noncausal_revision_links == ()


def test_uncited_rival_retains_verified_unavailable_id_without_rewriting_prose() -> None:
    issued_at = datetime(2026, 9, 26, tzinfo=UTC)
    old = _hypothesis(
        "security_block", statement="A security block remains possible but unobserved."
    ).model_copy(
        update={
            "distinguishing_probe_ids": ("security.snapshot",),
            "expected_facts": (_fact(1),),
            "expected_facts_observed_after": issued_at,
        }
    )
    advised = old.model_copy(
        update={
            "statement": "A security block is now proven.",
            "status": HypothesisStatus.SUPPORTED,
            "missing_evidence_ids": (_eid(1),),
            "distinguishing_probe_ids": (),
        }
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(advised,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
        verified_unavailable_evidence_ids=(_eid(1),),
        visible_prior_hypothesis_ids=(old.hypothesis_id,),
        source_request_sha256="a" * 64,
    )

    retained = result.hypotheses[0]
    assert retained.statement == old.statement
    assert retained.status is HypothesisStatus.UNRESOLVED
    assert retained.missing_evidence_ids == (_eid(1),)
    assert retained.supporting_evidence_ids == ()
    assert retained.contradicting_evidence_ids == ()
    assert retained.distinguishing_probe_ids == old.distinguishing_probe_ids
    assert retained.expected_facts == old.expected_facts
    assert retained.expected_facts_observed_after == issued_at
    assert result.uncertain
    assert any("unavailable" in note for note in result.notes)


@pytest.mark.parametrize(
    "fault",
    (
        "unverified",
        "unshown",
        "foreign",
        "not_presented",
        "sync",
        "extra_missing",
        "prediction_change",
    ),
)
def test_uncited_missing_only_retention_fails_closed(fault: str) -> None:
    old = _hypothesis("security_block", statement="The control state remains unknown.")
    advised = old.model_copy(
        update={
            "statement": "A security block was confirmed.",
            "missing_evidence_ids": (_eid(1),),
        }
    )
    custody = (_eid(1),)
    visible = custody
    verified = custody
    presented = (old.hypothesis_id,)
    source: str | None = "a" * 64
    if fault == "unverified":
        verified = ()
    elif fault == "unshown":
        visible = ()
        verified = ()
    elif fault == "foreign":
        custody = ()
        visible = ()
        verified = ()
    elif fault == "not_presented":
        presented = ()
    elif fault == "sync":
        source = None
    elif fault == "extra_missing":
        advised = advised.model_copy(update={"missing_evidence_ids": (_eid(1), _eid(2))})
        custody = (_eid(1), _eid(2))
        visible = custody
    elif fault == "prediction_change":
        old = old.model_copy(update={"expected_facts": (_fact(1),)})
        advised = advised.model_copy(update={"expected_facts": (_fact(2),)})
    result = progress_hypotheses(
        previous=(old,),
        advisory=(advised,),
        custodied_evidence_ids=custody,
        visible_evidence_ids=visible,
        verified_unavailable_evidence_ids=verified,
        visible_prior_hypothesis_ids=presented,
        source_request_sha256=source,
    )
    assert result.hypotheses == (old,)
    assert result.rejected_update_ids == (old.hypothesis_id,)


def test_coordinator_unavailable_ids_must_have_visible_custody() -> None:
    with pytest.raises(ValueError, match="visible custody"):
        progress_hypotheses(
            previous=(),
            advisory=(),
            custodied_evidence_ids=(_eid(1),),
            visible_evidence_ids=(),
            verified_unavailable_evidence_ids=(_eid(1),),
        )


def test_retained_missing_id_cannot_become_a_later_prose_revision_basis() -> None:
    old = _hypothesis("security_block", statement="A security block remains unverified.")
    missing = old.model_copy(
        update={
            "statement": "No security data were supplied.",
            "missing_evidence_ids": (_eid(1),),
        }
    )
    first = progress_hypotheses(
        previous=(old,),
        advisory=(missing,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
        verified_unavailable_evidence_ids=(_eid(1),),
        visible_prior_hypothesis_ids=(old.hypothesis_id,),
        source_request_sha256="a" * 64,
    )
    assert first.hypotheses[0].missing_evidence_ids == (_eid(1),)
    second = progress_hypotheses(
        previous=first.hypotheses,
        advisory=(missing.model_copy(update={"statement": "The missing check proves a block."}),),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
    )
    assert second.hypotheses == first.hypotheses
    assert second.rejected_update_ids == (old.hypothesis_id,)


@pytest.mark.parametrize("fault", ("none", "unverified", "drops_prior", "sync"))
def test_missing_only_prior_adds_only_new_verified_unavailable_ids(fault: str) -> None:
    old = _hypothesis("security_block", statement="A security block remains unverified.")
    prior = old.model_copy(update={"missing_evidence_ids": (_eid(1),)})
    incoming = prior.model_copy(
        update={
            "statement": "An absent check proves the block.",
            "missing_evidence_ids": (_eid(1), _eid(2)),
        }
    )
    verified = (_eid(2),)
    source: str | None = "b" * 64
    if fault == "unverified":
        verified = ()
    elif fault == "drops_prior":
        incoming = incoming.model_copy(update={"missing_evidence_ids": (_eid(2),)})
    elif fault == "sync":
        source = None
    result = progress_hypotheses(
        previous=(prior,),
        advisory=(incoming,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
        verified_unavailable_evidence_ids=verified,
        visible_prior_hypothesis_ids=(old.hypothesis_id,),
        source_request_sha256=source,
    )
    if fault == "none":
        assert result.hypotheses[0].statement == old.statement
        assert result.hypotheses[0].missing_evidence_ids == (_eid(1), _eid(2))
        assert result.rejected_update_ids == ()
    else:
        assert result.hypotheses == (prior,)
        assert result.rejected_update_ids == (old.hypothesis_id,)


def test_uncited_rival_revision_keeps_older_prediction_and_observation_boundary() -> None:
    issued_at = datetime(2026, 9, 26, tzinfo=UTC)
    old = _hypothesis("resource_pressure", statement="Pressure is unverified.").model_copy(
        update={"expected_facts": (_fact(1),), "expected_facts_observed_after": issued_at}
    )
    revised = _hypothesis(
        "resource_pressure",
        statement="A newer short reading contests broad pressure.",
        contradiction=(_eid(1),),
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
    )

    assert result.hypotheses[0].statement == revised.statement
    assert result.hypotheses[0].expected_facts == old.expected_facts
    assert result.hypotheses[0].expected_facts_observed_after == issued_at
    assert result.hypotheses[0].status is HypothesisStatus.CONTESTED


def test_explicit_revision_can_reclassify_a_custodied_historical_citation() -> None:
    historical = _eid(9)
    current = _eid(1)
    old = _hypothesis("h_historical", support=(historical,))
    revised = _hypothesis(
        "h_historical",
        statement="Current observation contests the older explanation",
        support=(current,),
        contradiction=(historical,),
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(current, historical),
        visible_evidence_ids=(current,),
    )

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].statement == revised.statement
    assert result.hypotheses[0].contradicting_evidence_ids == (historical,)
    assert result.hypotheses[0].status is HypothesisStatus.CONTESTED
    assert result.unshown_citation_ids == (historical,)
    assert result.uncertain


def test_statement_revision_cannot_reclassify_prediction_counterevidence_as_support() -> None:
    issued_at = datetime(2026, 9, 26, tzinfo=UTC)
    counterevidence = _eid(3)
    old = _hypothesis(
        "h_prediction",
        statement="Direct origin is reachable",
        contradiction=(counterevidence,),
        status=HypothesisStatus.CONTESTED,
    ).model_copy(
        update={
            "expected_facts": (
                ExpectedFact(
                    probe_id="core.snapshot",
                    fact_name="value",
                    expected_value=1,
                    probe_version=1,
                ),
            ),
            "expected_facts_observed_after": issued_at,
        }
    )
    revision = _hypothesis(
        "h_prediction",
        statement="A revised mechanism",
        support=(counterevidence,),
    )
    result = progress_hypotheses(
        previous=(old,),
        advisory=(revision,),
        custodied_evidence_ids=(counterevidence,),
        visible_evidence_ids=(counterevidence,),
    )

    retained = result.hypotheses[0]
    assert retained.expected_facts == old.expected_facts
    assert retained.expected_facts_observed_after == issued_at
    assert counterevidence in retained.contradicting_evidence_ids
    assert counterevidence not in retained.supporting_evidence_ids
    assert retained.status is HypothesisStatus.CONTESTED


def test_omitted_prediction_keeps_older_fact_and_observation_boundary() -> None:
    issued_at = datetime(2026, 9, 26, tzinfo=UTC)
    old = _hypothesis("h_prediction", support=(_eid(1),)).model_copy(
        update={"expected_facts": (_fact(1),), "expected_facts_observed_after": issued_at}
    )
    advice = _hypothesis("h_prediction", support=(_eid(2),))
    result = progress_hypotheses(
        previous=(old,),
        advisory=(advice,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
    )

    assert result.hypotheses[0].expected_facts == old.expected_facts
    assert result.hypotheses[0].expected_facts_observed_after == issued_at
    assert result.hypotheses[0].supporting_evidence_ids == (_eid(1), _eid(2))


def test_repeated_prediction_keeps_earlier_boundary_and_conflict_is_rejected() -> None:
    issued_at = datetime(2026, 9, 26, tzinfo=UTC)
    old = _hypothesis("h_prediction", support=(_eid(1),)).model_copy(
        update={"expected_facts": (_fact(1),), "expected_facts_observed_after": issued_at}
    )
    repeated = _hypothesis("h_prediction", support=(_eid(2),)).model_copy(
        update={
            "expected_facts": (_fact(1),),
            "expected_facts_observed_after": issued_at + timedelta(days=1),
        }
    )
    conflicting = repeated.model_copy(update={"expected_facts": (_fact(2),)})
    repeated_result = progress_hypotheses(
        previous=(old,),
        advisory=(repeated,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
    )
    assert repeated_result.hypotheses[0].expected_facts == old.expected_facts
    assert repeated_result.hypotheses[0].expected_facts_observed_after == issued_at

    conflict_result = progress_hypotheses(
        previous=(old,),
        advisory=(conflicting,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
    )
    assert conflict_result.hypotheses == (old,)
    assert conflict_result.rejected_update_ids == ("h_prediction",)
    assert conflict_result.uncertain


def test_explicit_statement_revision_retains_old_prediction_and_new_stamp_survives() -> None:
    issued_at = datetime(2026, 9, 26, tzinfo=UTC)
    old = _hypothesis("h_prediction", support=(_eid(1),)).model_copy(
        update={"expected_facts": (_fact(1),), "expected_facts_observed_after": issued_at}
    )
    revised = _hypothesis(
        "h_prediction",
        statement="A revised explanation accounting for old evidence",
        support=(_eid(1), _eid(2)),
    )
    revised_result = progress_hypotheses(
        previous=(old,),
        advisory=(revised,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
    )
    assert revised_result.hypotheses[0].statement == revised.statement
    assert revised_result.hypotheses[0].expected_facts == old.expected_facts
    assert revised_result.hypotheses[0].expected_facts_observed_after == issued_at

    new_prediction = _hypothesis("h_prediction", support=(_eid(2),)).model_copy(
        update={"expected_facts": (_fact(1),), "expected_facts_observed_after": issued_at}
    )
    new_result = progress_hypotheses(
        previous=(_hypothesis("h_prediction", support=(_eid(1),)),),
        advisory=(new_prediction,),
        custodied_evidence_ids=(_eid(1), _eid(2)),
        visible_evidence_ids=(_eid(1), _eid(2)),
    )
    assert new_result.hypotheses[0].expected_facts_observed_after == issued_at


def test_valid_new_advice_can_replace_unavailable_prior_version_without_false_omission() -> None:
    prior = _hypothesis("h_same", support=(_eid(9),))
    current = _hypothesis("h_same", support=(_eid(1),))
    result = progress_hypotheses(
        previous=(prior,),
        advisory=(current,),
        custodied_evidence_ids=(_eid(1),),
        visible_evidence_ids=(_eid(1),),
    )

    assert result.hypotheses == (current,)
    assert result.omitted_hypothesis_ids == ()
    assert result.unavailable_citation_ids == (_eid(9),)
    assert result.uncertain


def test_invalid_scope_and_duplicate_hypothesis_ids_fail_closed() -> None:
    old = _hypothesis("h_old")
    with pytest.raises(ValueError, match="visible"):
        progress_hypotheses(
            previous=(old,),
            advisory=(),
            custodied_evidence_ids=(),
            visible_evidence_ids=(_eid(1),),
        )
    with pytest.raises(ValueError, match="duplicate"):
        progress_hypotheses(
            previous=(old, old),
            advisory=(),
            custodied_evidence_ids=(),
            visible_evidence_ids=(),
        )
