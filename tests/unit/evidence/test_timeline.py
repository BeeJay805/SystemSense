from datetime import UTC, datetime, timedelta

from systemsense.domain.evidence import StatementKind
from systemsense.domain.ids import EvidenceId
from systemsense.evidence.timeline import TimelineEntry, build_timeline

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_timeline_sorts_by_observed_time_and_keeps_capture_time() -> None:
    later_observed = TimelineEntry(
        evidence_id=EvidenceId(root="ev_11111111111111111111111111111111"),
        observed_at=_NOW + timedelta(minutes=2),
        captured_at=_NOW + timedelta(minutes=3),
        statement_kind=StatementKind.OBSERVED_FACT,
        summary="Later event",
    )
    earlier_observed = TimelineEntry(
        evidence_id=EvidenceId(root="ev_22222222222222222222222222222222"),
        observed_at=_NOW,
        captured_at=_NOW + timedelta(minutes=5),
        statement_kind=StatementKind.CHANGE,
        summary="Earlier event captured later",
    )

    timeline = build_timeline((later_observed, earlier_observed))

    assert timeline == (earlier_observed, later_observed)
    assert timeline[0].captured_at == _NOW + timedelta(minutes=5)
