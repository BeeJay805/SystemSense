from systemsense.domain.ids import EvidenceId
from systemsense.evidence.ranking import RankableEvidence, rank_evidence


def _candidate(
    suffix: str,
    *,
    category: str,
    relevance: float,
    change: bool = False,
    contradiction: bool = False,
    coverage: float = 0.5,
) -> RankableEvidence:
    return RankableEvidence(
        evidence_id=EvidenceId(root=f"ev_{suffix * 32}"),
        category=category,
        relevance=relevance,
        severity=0.5,
        proximity=0.5,
        novelty=0.5,
        is_change=change,
        is_contradiction=contradiction,
        coverage=coverage,
    )


def test_ranking_rewards_change_and_contradiction() -> None:
    ordinary = _candidate("1", category="application", relevance=0.8)
    changed = _candidate("2", category="application", relevance=0.8, change=True)
    contradiction = _candidate(
        "3",
        category="application",
        relevance=0.8,
        contradiction=True,
    )

    ranked = rank_evidence((ordinary, changed, contradiction), limit=3)

    assert ranked[0].evidence in (changed, contradiction)
    assert ranked[-1].evidence == ordinary


def test_diversity_cap_prevents_one_category_from_filling_results() -> None:
    candidates = (
        _candidate("1", category="application", relevance=1.0),
        _candidate("2", category="application", relevance=0.9),
        _candidate("3", category="network", relevance=0.5),
    )

    ranked = rank_evidence(candidates, limit=3, max_per_category=1)

    assert [item.evidence.category for item in ranked] == ["application", "network"]


def test_ranking_rewards_better_source_coverage() -> None:
    incomplete = _candidate("1", category="application", relevance=0.8, coverage=0.0)
    complete = _candidate("2", category="application", relevance=0.8, coverage=1.0)

    ranked = rank_evidence((incomplete, complete), limit=2)

    assert ranked[0].evidence == complete
