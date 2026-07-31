import tracemalloc
from datetime import UTC, datetime

from systemsense.collection.coalescer import EnvelopeCoalescer
from systemsense.collection.envelope import EvidenceEnvelope
from systemsense.collection.queue import BoundedEnvelopeQueue
from systemsense.domain.evidence import StatementKind
from systemsense.domain.ids import CaseId

_CASE_ID = CaseId(root="case_0123456789abcdef0123456789abcdef")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_synthetic_event_storm_keeps_queue_and_group_memory_bounded() -> None:
    queue = BoundedEnvelopeQueue(max_size=64)
    coalescer = EnvelopeCoalescer(max_groups=32)
    tracemalloc.start()

    for index in range(25_000):
        envelope = EvidenceEnvelope.create(
            case_id=_CASE_ID,
            category="eventlog",
            source_id=f"src_{index % 100:064x}",
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=_NOW,
            captured_at=_NOW,
            payload={"event_id": index % 100},
        )
        queue.offer(envelope)
        coalescer.add(envelope)

    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(queue) == 64
    assert len(coalescer) == 32
    assert peak_bytes < 16_000_000
