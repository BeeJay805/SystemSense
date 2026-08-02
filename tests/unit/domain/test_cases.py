from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTarget,
    CaseTimeWindow,
    DiagnosticCase,
    TargetType,
)
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.ids import CaseId, EvidenceId, TargetId


def case_window() -> CaseTimeWindow:
    return CaseTimeWindow(
        start=datetime(2026, 7, 30, 17, 45, tzinfo=UTC),
        failure_start=datetime(2026, 7, 30, 17, 59, tzinfo=UTC),
        failure_end=datetime(2026, 7, 30, 18, 1, tzinfo=UTC),
        end=datetime(2026, 7, 30, 18, 15, tzinfo=UTC),
    )


def test_case_window_rejects_invalid_order() -> None:
    with pytest.raises(ValidationError, match="time window"):
        CaseTimeWindow(
            start=datetime(2026, 7, 30, 18, 0, tzinfo=UTC),
            end=datetime(2026, 7, 30, 17, 0, tzinfo=UTC),
        )


def test_case_window_rejects_failure_outside_window() -> None:
    with pytest.raises(ValidationError, match="time window"):
        CaseTimeWindow(
            start=datetime(2026, 7, 30, 18, 0, tzinfo=UTC),
            failure_start=datetime(2026, 7, 30, 17, 0, tzinfo=UTC),
            end=datetime(2026, 7, 30, 19, 0, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "status",
    [
        CoverageStatus.MISSING,
        CoverageStatus.UNAVAILABLE,
        CoverageStatus.DENIED,
        CoverageStatus.FAILED,
        CoverageStatus.TRUNCATED,
        CoverageStatus.STALE,
        CoverageStatus.UNSUPPORTED,
    ],
)
def test_coverage_represents_explicit_failure_states(status: CoverageStatus) -> None:
    coverage = CoverageRecord(
        evidence_id=EvidenceId.new(),
        case_id=CaseId.new(),
        category="event_log",
        status=status,
        captured_at=datetime(2026, 7, 30, 18, 5, tzinfo=UTC),
        reason="fixture",
    )

    assert coverage.status is status


def test_coverage_v2_can_read_persisted_v1_records() -> None:
    coverage = CoverageRecord.model_validate(
        {
            "schema_version": 1,
            "evidence_id": str(EvidenceId.new()),
            "case_id": str(CaseId.new()),
            "category": "eventlog",
            "status": "failed",
            "captured_at": "2026-07-30T18:05:00Z",
            "reason": "legacy fixture",
            "execution_id": None,
            "limitations": [],
        }
    )

    assert coverage.schema_version == 1
    assert coverage.collector_id is None


def test_diagnostic_case_supports_broad_case_kind() -> None:
    case = DiagnosticCase(
        case_id=CaseId.new(),
        kind=CaseKind.GENERAL,
        status=CaseStatus.OPEN,
        symptom="Audio disappeared after Windows Update.",
        created_at=datetime(2026, 7, 30, 18, 2, tzinfo=UTC),
        time_window=case_window(),
        targets=(
            CaseTarget(
                target_id=TargetId.new(),
                type=TargetType.HOST,
                display_name="This PC",
            ),
        ),
    )

    assert case.targets[0].display_name == "This PC"


def test_diagnostic_case_requires_nonempty_symptom() -> None:
    with pytest.raises(ValidationError):
        DiagnosticCase(
            case_id=CaseId.new(),
            kind=CaseKind.GENERAL,
            status=CaseStatus.OPEN,
            symptom=" ",
            created_at=datetime(2026, 7, 30, 18, 2, tzinfo=UTC),
            time_window=case_window(),
            targets=(),
        )


def test_case_models_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        CaseTarget.model_validate(
            {
                "target_id": str(TargetId.new()),
                "type": "host",
                "display_name": "This PC",
                "path": "C:\\secret",
            }
        )
