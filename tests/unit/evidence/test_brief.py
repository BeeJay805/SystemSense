from datetime import UTC, datetime
from pathlib import Path

from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    DiagnosticCase,
)
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import StatementKind
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.evidence.brief import BriefEvidence, BriefGenerator

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_CASE_ID = CaseId(root="case_11111111111111111111111111111111")
_OBSERVATION_ID = EvidenceId(root="ev_11111111111111111111111111111111")
_COVERAGE_ID = EvidenceId(root="ev_22222222222222222222222222222222")


def _case(*, coverage: tuple[CoverageRecord, ...] = ()) -> DiagnosticCase:
    return DiagnosticCase(
        case_id=_CASE_ID,
        kind=CaseKind.GENERAL,
        status=CaseStatus.READY,
        symptom="Audio disappeared after update.",
        created_at=_NOW,
        time_window=CaseTimeWindow(
            start=datetime(2026, 7, 30, 11, 0, tzinfo=UTC),
            end=datetime(2026, 7, 30, 13, 0, tzinfo=UTC),
        ),
        coverage=coverage,
    )


def _evidence(
    evidence_id: EvidenceId = _OBSERVATION_ID,
    *,
    score: float = 0.9,
    summary: str = "Audio endpoint count changed from 2 to 0.",
) -> BriefEvidence:
    return BriefEvidence(
        evidence_id=evidence_id,
        category="devices.audio",
        statement_kind=StatementKind.CHANGE,
        observed_at=datetime(2026, 7, 30, 11, 58, tzinfo=UTC),
        captured_at=_NOW,
        summary=summary,
        score=score,
    )


def test_brief_matches_stable_golden_output() -> None:
    coverage = CoverageRecord(
        evidence_id=_COVERAGE_ID,
        case_id=_CASE_ID,
        category="event_log",
        status=CoverageStatus.PARTIAL,
        captured_at=_NOW,
        reason="Security channel access denied.",
    )

    brief = BriefGenerator(max_chars=2_000).generate(
        case=_case(coverage=(coverage,)),
        evidence=(_evidence(),),
        pending_probe_ids=("devices.driver_inventory",),
        generated_at=_NOW,
    )

    expected = (Path(__file__).parents[2] / "golden" / "briefs" / "revision_1.txt").read_text(
        encoding="utf-8"
    )
    assert brief.text == expected.rstrip("\n")


def test_brief_obeys_hard_budget_and_keeps_every_section() -> None:
    evidence = tuple(
        _evidence(
            EvidenceId(root=f"ev_{number:032x}"),
            score=1 - (number / 100),
            summary="A" * 1_000,
        )
        for number in range(1, 9)
    )

    brief = BriefGenerator(max_chars=512).generate(
        case=_case(),
        evidence=evidence,
        pending_probe_ids=("core.system", "eventlog.application"),
        generated_at=_NOW,
    )

    assert len(brief.text) <= 512
    assert brief.omitted_evidence_count > 0
    assert brief.text.index("\nCASE\n") < brief.text.index("\nEVIDENCE\n")
    assert brief.text.index("\nEVIDENCE\n") < brief.text.index("\nCOVERAGE\n")
    assert brief.text.index("\nCOVERAGE\n") < brief.text.index("\nPENDING PROBES\n")
    assert brief.text.index("\nPENDING PROBES\n") < brief.text.index("\nDELTA\n")
    assert brief.text.index("\nDELTA\n") < brief.text.index("\nLIMITATIONS\n")


def test_revision_delta_contains_only_newly_cited_evidence() -> None:
    first = BriefGenerator(max_chars=2_000).generate(
        case=_case(),
        evidence=(_evidence(),),
        pending_probe_ids=(),
        generated_at=_NOW,
    )
    new_id = EvidenceId(root="ev_33333333333333333333333333333333")

    second = BriefGenerator(max_chars=2_000).generate(
        case=_case(),
        evidence=(_evidence(), _evidence(new_id, score=0.8)),
        pending_probe_ids=(),
        generated_at=_NOW,
        previous=first,
    )

    assert second.revision == 2
    assert second.delta_evidence_ids == (new_id,)
    assert f"- added [{new_id}]" in second.text
    assert f"- added [{_OBSERVATION_ID}]" not in second.text


def test_factual_bullets_carry_evidence_ids() -> None:
    coverage = CoverageRecord(
        evidence_id=_COVERAGE_ID,
        case_id=_CASE_ID,
        category="event_log",
        status=CoverageStatus.COVERED,
        captured_at=_NOW,
    )
    brief = BriefGenerator(max_chars=2_000).generate(
        case=_case(coverage=(coverage,)),
        evidence=(_evidence(),),
        pending_probe_ids=(),
        generated_at=_NOW,
    )

    for section_name in ("EVIDENCE", "COVERAGE", "DELTA"):
        section = brief.text.split(section_name, maxsplit=1)[1].split("\n", maxsplit=1)[1]
        section = section.split("\n" + _next_section(section_name), maxsplit=1)[0]
        factual_lines = [
            line for line in section.splitlines() if line.startswith("- ") and "[" in line
        ]
        assert all("[ev_" in line for line in factual_lines)


def _next_section(section_name: str) -> str:
    sections = {
        "EVIDENCE": "COVERAGE",
        "COVERAGE": "PENDING PROBES",
        "DELTA": "LIMITATIONS",
    }
    return sections[section_name]
