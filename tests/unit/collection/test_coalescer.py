from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from systemsense.collection.coalescer import EnvelopeCoalescer
from systemsense.collection.envelope import EvidenceEnvelope, normalized_fingerprint
from systemsense.domain.evidence import StatementKind
from systemsense.domain.ids import CaseId, JsonValue

_CASE_ID = CaseId(root="case_0123456789abcdef0123456789abcdef")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _event(
    source_index: int,
    observed_offset: int,
    payload: Mapping[str, JsonValue],
) -> EvidenceEnvelope:
    return EvidenceEnvelope.create(
        case_id=_CASE_ID,
        category="application",
        source_id=f"src_{source_index:064x}",
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=_NOW + timedelta(seconds=observed_offset),
        captured_at=_NOW + timedelta(seconds=observed_offset),
        payload=payload,
    )


def test_identical_source_and_fingerprint_coalesce_with_first_last_and_count() -> None:
    coalescer = EnvelopeCoalescer(max_groups=4)

    first = coalescer.add(_event(1, 0, {"event_id": 1000, "module": "example.dll"}))
    second = coalescer.add(_event(1, 5, {"module": "example.dll", "event_id": 1000}))

    assert first.count == 1
    assert second.count == 2
    assert second.first_observed_at == _NOW
    assert second.last_observed_at == _NOW + timedelta(seconds=5)
    assert len(coalescer) == 1


def test_same_fingerprint_from_different_sources_remains_separate() -> None:
    coalescer = EnvelopeCoalescer(max_groups=4)
    payload = {"event_id": 1000}

    coalescer.add(_event(1, 0, payload))
    coalescer.add(_event(2, 1, payload))

    assert len(coalescer) == 2


def test_fingerprint_is_independent_of_mapping_order() -> None:
    assert normalized_fingerprint({"a": 1, "b": "two"}) == normalized_fingerprint(
        {"b": "two", "a": 1}
    )


def test_unique_group_count_is_bounded_and_oldest_group_is_evicted() -> None:
    coalescer = EnvelopeCoalescer(max_groups=2)
    first = _event(1, 0, {"event_id": 1})
    second = _event(2, 1, {"event_id": 2})
    third = _event(3, 2, {"event_id": 3})

    coalescer.add(first)
    coalescer.add(second)
    coalescer.add(third)

    assert len(coalescer) == 2
    assert coalescer.evicted_count == 1
    assert (first.source_id, first.fingerprint) not in coalescer.keys()
