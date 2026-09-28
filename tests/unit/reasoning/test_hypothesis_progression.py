"""Competing advisory hypotheses survive later incomplete reasoning turns."""

from datetime import UTC, datetime, timedelta

import pytest

from systemsense.domain.ids import EvidenceId
from systemsense.reasoning.contracts import (
    ExpectedFact,
    Hypothesis,
    HypothesisRevisionIntentV1,
    HypothesisStatus,
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
