"""Deterministic evidence ranking with category diversity."""

from collections import Counter
from collections.abc import Iterable

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId


class RankableEvidence(FrozenModel):
    evidence_id: EvidenceId
    category: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    relevance: float = Field(ge=0.0, le=1.0)
    severity: float = Field(ge=0.0, le=1.0)
    proximity: float = Field(ge=0.0, le=1.0)
    novelty: float = Field(ge=0.0, le=1.0)
    coverage: float = Field(default=0.5, ge=0.0, le=1.0)
    is_change: bool = False
    is_contradiction: bool = False


class RankedEvidence(FrozenModel):
    evidence: RankableEvidence
    score: float = Field(ge=0.0, le=1.0)


def _score(evidence: RankableEvidence) -> float:
    return (
        (0.30 * evidence.relevance)
        + (0.15 * evidence.severity)
        + (0.15 * evidence.proximity)
        + (0.10 * evidence.novelty)
        + (0.10 * evidence.coverage)
        + (0.10 if evidence.is_change else 0.0)
        + (0.10 if evidence.is_contradiction else 0.0)
    )


def rank_evidence(
    candidates: Iterable[RankableEvidence],
    *,
    limit: int,
    max_per_category: int = 3,
) -> tuple[RankedEvidence, ...]:
    """Rank candidates, then cap repeated categories to preserve breadth."""

    if limit < 1:
        raise ValueError("limit must be at least 1")
    if max_per_category < 1:
        raise ValueError("max_per_category must be at least 1")

    scored = sorted(
        (RankedEvidence(evidence=item, score=_score(item)) for item in candidates),
        key=lambda item: (-item.score, str(item.evidence.evidence_id)),
    )
    category_counts: Counter[str] = Counter()
    selected: list[RankedEvidence] = []
    for item in scored:
        category = item.evidence.category
        if category_counts[category] >= max_per_category:
            continue
        selected.append(item)
        category_counts[category] += 1
        if len(selected) == limit:
            break
    return tuple(selected)
