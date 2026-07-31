from datetime import UTC, datetime, timedelta

from systemsense.collection.envelope import CoverageEnvelope, EvidenceEnvelope
from systemsense.collection.queue import BoundedEnvelopeQueue, EnvelopePriority
from systemsense.domain.coverage import CoverageStatus
from systemsense.domain.evidence import StatementKind
from systemsense.domain.ids import CaseId

_CASE_ID = CaseId(root="case_0123456789abcdef0123456789abcdef")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _evidence(
    index: int,
    *,
    statement_kind: StatementKind = StatementKind.OBSERVED_FACT,
) -> EvidenceEnvelope:
    return EvidenceEnvelope.create(
        case_id=_CASE_ID,
        category="application",
        source_id=f"src_{index:064x}",
        statement_kind=statement_kind,
        observed_at=_NOW + timedelta(seconds=index),
        captured_at=_NOW + timedelta(seconds=index),
        payload={"event_id": index},
    )


def test_queue_pops_high_value_evidence_first_and_preserves_arrival_order() -> None:
    queue = BoundedEnvelopeQueue(max_size=4)
    ordinary = _evidence(1)
    first_change = _evidence(2, statement_kind=StatementKind.CHANGE)
    second_change = _evidence(3, statement_kind=StatementKind.CHANGE)

    queue.offer(ordinary)
    queue.offer(first_change)
    queue.offer(second_change)

    assert queue.pop() == first_change
    assert queue.pop() == second_change
    assert queue.pop() == ordinary


def test_failure_displaces_ordinary_evidence_when_queue_is_full() -> None:
    queue = BoundedEnvelopeQueue(max_size=2)
    ordinary_one = _evidence(1)
    ordinary_two = _evidence(2)
    failure = CoverageEnvelope.create(
        case_id=_CASE_ID,
        category="eventlog",
        source_id=f"src_{3:064x}",
        status=CoverageStatus.FAILED,
        captured_at=_NOW,
        reason="collector failed",
    )
    queue.offer(ordinary_one)
    queue.offer(ordinary_two)

    result = queue.offer(failure)

    assert result.accepted
    assert result.evicted == ordinary_two
    assert result.overflow is not None
    assert result.overflow.status is CoverageStatus.TRUNCATED
    assert queue.pop() == failure
    assert len(queue) == 1


def test_lower_priority_overflow_is_reported_without_exceeding_capacity() -> None:
    queue = BoundedEnvelopeQueue(max_size=1)
    change = _evidence(1, statement_kind=StatementKind.CHANGE)
    queue.offer(change)

    result = queue.offer(_evidence(2))

    assert not result.accepted
    assert result.evicted is None
    assert result.overflow is not None
    assert result.overflow.priority is EnvelopePriority.CRITICAL
    assert result.overflow.status is CoverageStatus.TRUNCATED
    assert len(queue) == 1
    assert queue.pop() == change
