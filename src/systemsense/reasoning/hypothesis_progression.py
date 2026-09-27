"""Pure bounded continuity for advisory hypotheses across reasoning turns."""

from __future__ import annotations

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus


class HypothesisProgression(FrozenModel):
    """Advisory rivals plus explicit custody, visibility, and capacity losses."""

    hypotheses: tuple[Hypothesis, ...] = Field(max_length=16)
    omitted_hypothesis_ids: tuple[str, ...] = ()
    rejected_update_ids: tuple[str, ...] = ()
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

    unavailable: list[EvidenceId] = []
    omitted: list[str] = []
    rejected_updates: list[str] = []
    revised_updates: list[str] = []
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
            positions[hypothesis.hypothesis_id] = len(rows)
            rows.append(
                (hypothesis.model_copy(update={"status": _advisory_status(hypothesis)}), False)
            )
            continue
        prior, was_prior = rows[position]
        if prior.statement != hypothesis.statement:
            prior_citations = {str(item) for item in _citations(prior)}
            new_citations = {str(item) for item in _citations(hypothesis)}
            if not prior_citations or not prior_citations <= new_citations:
                rejected_updates.append(hypothesis.hypothesis_id)
                continue
            # A changed explanation is an explicit revision only when the new
            # row accounts for every old cited ID. Never silently inherit old
            # roles: a historical observation may now be contradiction.
            rows[position] = (
                hypothesis.model_copy(
                    update={
                        "status": _advisory_status(hypothesis),
                        "expected_facts_observed_after": None,
                    }
                ),
                was_prior,
            )
            revised_updates.append(hypothesis.hypothesis_id)
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
                "expected_facts_observed_after": None,
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
            f"Same-ID advisory updates rejected without citation transfer: {len(rejected_updates)}."
        )
    if revised_updates:
        notes.append(f"Explicit same-ID advisory revisions: {len(revised_updates)}.")
    if not retained:
        notes.append("No custodied advisory hypothesis remains; cause is unresolved.")
    return HypothesisProgression(
        hypotheses=retained,
        omitted_hypothesis_ids=omitted_ids,
        rejected_update_ids=tuple(dict.fromkeys(rejected_updates)),
        unavailable_citation_ids=unavailable_ids,
        unshown_citation_ids=unshown,
        uncertain=bool(
            omitted_ids
            or rejected_updates
            or revised_updates
            or unavailable_ids
            or unshown
            or not retained
        ),
        notes=tuple(notes),
    )
