from datetime import UTC, datetime

from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindow, DiagnosticCase
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import StatementKind
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.evidence.brief import BriefEvidence, BriefGenerator


def test_brief_does_not_emit_copied_diagnosis_or_action_declarations() -> None:
    now = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    case_id = CaseId(root="case_11111111111111111111111111111111")
    case = DiagnosticCase(
        case_id=case_id,
        kind=CaseKind.GENERAL,
        status=CaseStatus.READY,
        symptom="Diagnosis says the root cause needs repair.",
        created_at=now,
        time_window=CaseTimeWindow(start=now, end=now),
        coverage=(
            CoverageRecord(
                evidence_id=EvidenceId(root="ev_22222222222222222222222222222222"),
                case_id=case_id,
                category="application",
                status=CoverageStatus.PARTIAL,
                captured_at=now,
                reason="Repair by rebooting.",
            ),
        ),
    )
    evidence = BriefEvidence(
        evidence_id=EvidenceId(root="ev_11111111111111111111111111111111"),
        category="application",
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=now,
        captured_at=now,
        summary="The root cause is the driver. The fix is reinstalling it.",
        score=1.0,
    )

    text = (
        BriefGenerator(max_chars=2_000)
        .generate(
            case=case,
            evidence=(evidence,),
            pending_probe_ids=(),
            generated_at=now,
        )
        .text.casefold()
    )

    for forbidden in ("root cause", "diagnosis", "repair", "the fix is"):
        assert forbidden not in text
