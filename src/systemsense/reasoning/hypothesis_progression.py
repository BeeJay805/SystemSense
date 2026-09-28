"""Pure bounded continuity for advisory hypotheses across reasoning turns."""

from __future__ import annotations

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisRevisionIntentV1,
    HypothesisRevisionLinkV1,
    HypothesisStatus,
    hypothesis_revision_sha256,
)


class HypothesisProgression(FrozenModel):
    """Advisory rivals plus explicit custody, visibility, and capacity losses."""

    hypotheses: tuple[Hypothesis, ...] = Field(max_length=16)
    omitted_hypothesis_ids: tuple[str, ...] = ()
    rejected_update_ids: tuple[str, ...] = ()
    revision_links: tuple[HypothesisRevisionLinkV1, ...] = ()
    unavailable_citation_ids: tuple[EvidenceId, ...] = ()
    unshown_citation_ids: tuple[EvidenceId, ...] = ()
    uncertain: bool
    notes: tuple[str, ...] = ()


def _unique_ids(ids: tuple[EvidenceId, ...]) -> tuple[EvidenceId, ...]:
    return tuple(dict.fromkeys(ids))


def _citations(hypothesis: Hypothesis) -> tuple[EvidenceId, ...]:
    return _unique_ids(
        (
            *hypothesis.supporting_evidence_ids,
            *hypothesis.contradicting_evidence_ids,
            *hypothesis.missing_evidence_ids,
        )
    )


def _advisory_status(hypothesis: Hypothesis) -> HypothesisStatus:
    return (
        HypothesisStatus.CONTESTED
        if hypothesis.contradicting_evidence_ids
        else HypothesisStatus.UNRESOLVED
    )


def progress_hypotheses(
    *,
    previous: tuple[Hypothesis, ...],
    advisory: tuple[Hypothesis, ...],
    custodied_evidence_ids: tuple[EvidenceId, ...],
    visible_evidence_ids: tuple[EvidenceId, ...],
    verified_unavailable_evidence_ids: tuple[EvidenceId, ...] = (),
    revision_intents: tuple[HypothesisRevisionIntentV1, ...] = (),
    visible_prior_hypothesis_ids: tuple[str, ...] = (),
    source_request_sha256: str | None = None,
    max_hypotheses: int = 16,
    unknown_hypothesis_ids: tuple[str, ...] = ("h_unknown",),
) -> HypothesisProgression:
    """Retain custodied rivals without treating model claims as causal proof.

    The caller supplies exact IDs from deterministic custody: current-case
    observations and validated historical sources, never reference prose or
    model-minted IDs. Visible IDs describe the validated reasoning request.
    Missing request visibility is a coverage gap, not disproof of an old rival.
    A provider's fitted text may contain fewer IDs than the reasoning request.
    """
    if not 1 <= max_hypotheses <= 16 or len(previous) > 16 or len(advisory) > 16:
        raise ValueError("hypothesis progression bounds are outside the allowed range")
    for label, items in (("previous", previous), ("advisory", advisory)):
        ids = [item.hypothesis_id for item in items]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate {label} hypothesis IDs")
    custody_ids = {str(item) for item in custodied_evidence_ids}
    visible_ids = {str(item) for item in visible_evidence_ids}
    if len(custody_ids) != len(custodied_evidence_ids) or len(visible_ids) != len(
        visible_evidence_ids
    ):
        raise ValueError("duplicate custodied or visible evidence IDs")
    if not visible_ids <= custody_ids:
        raise ValueError("visible evidence IDs are not all custodied")
    verified_unavailable = {str(item) for item in verified_unavailable_evidence_ids}
    if len(verified_unavailable) != len(verified_unavailable_evidence_ids) or not (
        verified_unavailable <= custody_ids & visible_ids
    ):
        raise ValueError("verified unavailable IDs lack exact visible custody")
    if len({item.hypothesis_id for item in revision_intents}) != len(revision_intents):
        raise ValueError("duplicate revision intent hypothesis IDs")
    intents = {item.hypothesis_id: item for item in revision_intents}
    original_prior = {item.hypothesis_id: item for item in previous}
    visible_prior = set(visible_prior_hypothesis_ids)

    unavailable: list[EvidenceId] = []
    omitted: list[str] = []
    rejected_updates: list[str] = []
    revised_updates: list[str] = []
    retained_missing_updates: list[str] = []
    revision_links: list[HypothesisRevisionLinkV1] = []
    # Keep the old rival's position so new advice cannot reorder away a
    # contradiction or silently replace an explanation with the same ID.
    rows: list[tuple[Hypothesis, bool]] = []
    positions: dict[str, int] = {}

    def has_custodied_citations(hypothesis: Hypothesis) -> bool:
        missing = tuple(
            evidence_id
            for evidence_id in _citations(hypothesis)
            if str(evidence_id) not in custody_ids
        )
        unavailable.extend(missing)
        return not missing

    for hypothesis in previous:
        if not has_custodied_citations(hypothesis):
            omitted.append(hypothesis.hypothesis_id)
            continue
        positions[hypothesis.hypothesis_id] = len(rows)
        rows.append((hypothesis.model_copy(update={"status": _advisory_status(hypothesis)}), True))

    for hypothesis in advisory:
        if not has_custodied_citations(hypothesis):
            if hypothesis.hypothesis_id in positions:
                rejected_updates.append(hypothesis.hypothesis_id)
            else:
                omitted.append(hypothesis.hypothesis_id)
            continue
        position = positions.get(hypothesis.hypothesis_id)
        if position is None:
            if hypothesis.hypothesis_id in intents:
                rejected_updates.append(hypothesis.hypothesis_id)
                continue
            positions[hypothesis.hypothesis_id] = len(rows)
            rows.append(
                (hypothesis.model_copy(update={"status": _advisory_status(hypothesis)}), False)
            )
            continue
        prior, was_prior = rows[position]
        if prior.expected_facts:
            old_facts = {(fact.probe_id, fact.fact_name): fact for fact in prior.expected_facts}
            if any(
                old_facts.get((fact.probe_id, fact.fact_name)) != fact
                for fact in hypothesis.expected_facts
            ):
                rejected_updates.append(hypothesis.hypothesis_id)
                continue
            # A single hypothesis has one observation boundary for all of its
            # predictions. Keep prior facts and their original boundary when
            # advice omits or repeats them. Added facts cannot share this old
            # boundary, so the update is rejected above.
            expected_facts = prior.expected_facts
            observed_after = (
                prior.expected_facts_observed_after
                if prior.expected_facts_observed_after is not None
                else hypothesis.expected_facts_observed_after
            )
        else:
            # The coordinator may have already stamped a genuinely new fact.
            expected_facts = hypothesis.expected_facts
            observed_after = hypothesis.expected_facts_observed_after
        if prior.statement != hypothesis.statement:
            intent = intents.get(hypothesis.hypothesis_id)
            prior_citations = {str(item) for item in _citations(prior)}
            prior_positive_citations = {
                str(item)
                for item in (
                    *prior.supporting_evidence_ids,
                    *prior.contradicting_evidence_ids,
                )
            }
            new_citations = {str(item) for item in _citations(hypothesis)}
            new_positive_citations = {
                str(item)
                for item in (
                    *hypothesis.supporting_evidence_ids,
                    *hypothesis.contradicting_evidence_ids,
                )
            }
            prior_contradictions = {str(item) for item in prior.contradicting_evidence_ids}
            new_contradictions = {str(item) for item in hypothesis.contradicting_evidence_ids}
            prior_support = {str(item) for item in prior.supporting_evidence_ids}
            new_support = {str(item) for item in hypothesis.supporting_evidence_ids}
            retired_support = prior_support - new_support
            prior_missing = {str(item) for item in prior.missing_evidence_ids}
            intent_valid = (
                intent is not None
                and source_request_sha256 is not None
                and hypothesis.hypothesis_id in visible_prior
                and hypothesis.hypothesis_id in original_prior
                and intent.prior_hypothesis_sha256
                == hypothesis_revision_sha256(original_prior[hypothesis.hypothesis_id])
                and {str(item) for item in intent.retired_supporting_evidence_ids}
                == retired_support
                and bool(retired_support)
                and retired_support <= custody_ids & visible_ids
                and not retired_support & new_citations
                and prior_missing <= {str(item) for item in hypothesis.missing_evidence_ids}
                and bool((new_positive_citations - prior_citations) & visible_ids)
                and prior.expected_facts == expected_facts
                and prior.expected_facts_observed_after == observed_after
            )
            # An absence can account for a failed check without licensing a
            # new explanation. Retain only its coordinator-verified ID; the
            # model's changed prose, status and probe list are not adopted.
            missing_ids = tuple(str(item) for item in hypothesis.missing_evidence_ids)
            if (
                not prior_citations
                and not new_positive_citations
                and intent is None
                and source_request_sha256 is not None
                and hypothesis.hypothesis_id in visible_prior
                and bool(missing_ids)
                and len(missing_ids) == len(set(missing_ids))
                and len(missing_ids) <= 64
                and set(missing_ids) <= verified_unavailable
                and prior.expected_facts == expected_facts
                and prior.expected_facts_observed_after == observed_after
            ):
                rows[position] = (
                    prior.model_copy(
                        update={"missing_evidence_ids": hypothesis.missing_evidence_ids}
                    ),
                    was_prior,
                )
                retained_missing_updates.append(hypothesis.hypothesis_id)
                continue
            if (
                (
                    not prior_positive_citations
                    and not new_positive_citations.intersection(visible_ids)
                )
                or not (prior_citations <= new_citations or intent_valid)
                or not prior_contradictions <= new_contradictions
                or (intent is not None and not intent_valid)
            ):
                rejected_updates.append(hypothesis.hypothesis_id)
                continue
            # A rival without positive citations needs newly visible support or
            # counterevidence. Missing IDs never become a later prose basis.
            # Cited rivals still transfer every old ID, and old contradictions
            # cannot become support or missing because advisory prose changes.
            revised = hypothesis.model_copy(
                update={
                    "status": _advisory_status(hypothesis),
                    "expected_facts": expected_facts,
                    "expected_facts_observed_after": observed_after,
                }
            )
            rows[position] = (revised, was_prior)
            if intent_valid and intent is not None and source_request_sha256 is not None:
                revision_links.append(
                    HypothesisRevisionLinkV1(
                        hypothesis_id=hypothesis.hypothesis_id,
                        prior_hypothesis_sha256=intent.prior_hypothesis_sha256,
                        revised_hypothesis_sha256=hypothesis_revision_sha256(revised),
                        retired_supporting_evidence_ids=intent.retired_supporting_evidence_ids,
                        source_request_sha256=source_request_sha256,
                    )
                )
            revised_updates.append(hypothesis.hypothesis_id)
            continue
        if hypothesis.hypothesis_id in intents:
            rejected_updates.append(hypothesis.hypothesis_id)
            continue
        contradiction = _unique_ids(
            (*prior.contradicting_evidence_ids, *hypothesis.contradicting_evidence_ids)
        )
        contradictory_ids = {str(item) for item in contradiction}
        support = tuple(
            evidence_id
            for evidence_id in _unique_ids(
                (*prior.supporting_evidence_ids, *hypothesis.supporting_evidence_ids)
            )
            if str(evidence_id) not in contradictory_ids
        )
        missing = _unique_ids((*prior.missing_evidence_ids, *hypothesis.missing_evidence_ids))
        if max(len(support), len(contradiction), len(missing)) > 64:
            rejected_updates.append(hypothesis.hypothesis_id)
            continue
        merged = hypothesis.model_copy(
            update={
                "supporting_evidence_ids": support,
                "contradicting_evidence_ids": contradiction,
                "missing_evidence_ids": missing,
                "status": HypothesisStatus.CONTESTED
                if contradiction
                else HypothesisStatus.UNRESOLVED,
                "expected_facts": expected_facts,
                "expected_facts_observed_after": observed_after,
            }
        )
        rows[position] = (merged, was_prior)

    unknown_ids = set(unknown_hypothesis_ids)

    def priority(row: tuple[Hypothesis, bool]) -> int:
        hypothesis, was_prior = row
        if hypothesis.hypothesis_id in unknown_ids:
            return 0
        if hypothesis.status is HypothesisStatus.CONTESTED:
            return 1 if was_prior else 2
        return 3 if was_prior else 4

    ranked = sorted(range(len(rows)), key=lambda index: (priority(rows[index]), index))
    retained_positions = set(ranked[:max_hypotheses])
    retained = tuple(row[0] for index, row in enumerate(rows) if index in retained_positions)
    capacity_omissions = [
        row[0].hypothesis_id for index, row in enumerate(rows) if index not in retained_positions
    ]
    omitted.extend(capacity_omissions)
    retained_ids = {item.hypothesis_id for item in retained}
    revision_links = [item for item in revision_links if item.hypothesis_id in retained_ids]
    omitted_ids = tuple(
        hypothesis_id
        for hypothesis_id in dict.fromkeys(omitted)
        if hypothesis_id not in retained_ids
    )
    unshown = _unique_ids(
        tuple(
            evidence_id
            for hypothesis in retained
            for evidence_id in _citations(hypothesis)
            if str(evidence_id) not in visible_ids
        )
    )
    unavailable_ids = _unique_ids(tuple(unavailable))
    notes: list[str] = []
    if unavailable_ids:
        notes.append(f"Citation custody unavailable for {len(unavailable_ids)} IDs.")
    if unshown:
        notes.append(f"Custodied citations outside this reasoning request: {len(unshown)}.")
    if capacity_omissions:
        notes.append(f"Hypothesis cap omitted {len(capacity_omissions)} competing explanations.")
    if rejected_updates:
        notes.append(
            "Same-ID advisory updates rejected without visible evidence or citation continuity: "
            f"{len(rejected_updates)}."
        )
    if revised_updates:
        notes.append(f"Explicit same-ID advisory revisions: {len(revised_updates)}.")
    if retained_missing_updates:
        notes.append(
            "Verified unavailable IDs retained for "
            f"{len(retained_missing_updates)} uncited rivals; changed prose was not accepted."
        )
    if not retained:
        notes.append("No custodied advisory hypothesis remains; cause is unresolved.")
    return HypothesisProgression(
        hypotheses=retained,
        omitted_hypothesis_ids=omitted_ids,
        rejected_update_ids=tuple(dict.fromkeys(rejected_updates)),
        revision_links=tuple(revision_links),
        unavailable_citation_ids=unavailable_ids,
        unshown_citation_ids=unshown,
        uncertain=bool(
            omitted_ids
            or rejected_updates
            or revised_updates
            or retained_missing_updates
            or unavailable_ids
            or unshown
            or not retained
        ),
        notes=tuple(notes),
    )
