"""Fixed-capacity priority queue with explicit overflow coverage."""

from dataclasses import dataclass

from systemsense.collection.envelope import (
    CollectionEnvelope,
    CoverageEnvelope,
    EnvelopePriority,
)
from systemsense.domain.coverage import CoverageStatus
from systemsense.domain.evidence import FrozenModel


@dataclass(frozen=True, slots=True)
class _QueuedEnvelope:
    sequence: int
    envelope: CollectionEnvelope


class OfferResult(FrozenModel):
    accepted: bool
    evicted: CollectionEnvelope | None = None
    overflow: CoverageEnvelope | None = None


class BoundedEnvelopeQueue:
    def __init__(self, *, max_size: int) -> None:
        if max_size < 1:
            raise ValueError("max_size must be positive")
        self._max_size = max_size
        self._items: list[_QueuedEnvelope] = []
        self._next_sequence = 0

    def __len__(self) -> int:
        return len(self._items)

    def offer(self, envelope: CollectionEnvelope) -> OfferResult:
        queued = _QueuedEnvelope(sequence=self._next_sequence, envelope=envelope)
        self._next_sequence += 1
        if len(self._items) < self._max_size:
            self._items.append(queued)
            return OfferResult(accepted=True)

        worst = max(
            self._items,
            key=lambda item: (item.envelope.priority, item.sequence),
        )
        if envelope.priority < worst.envelope.priority:
            self._items.remove(worst)
            self._items.append(queued)
            return OfferResult(
                accepted=True,
                evicted=worst.envelope,
                overflow=self._overflow_for(worst.envelope),
            )
        return OfferResult(
            accepted=False,
            overflow=self._overflow_for(envelope),
        )

    def pop(self) -> CollectionEnvelope:
        if not self._items:
            raise IndexError("queue is empty")
        best = min(
            self._items,
            key=lambda item: (item.envelope.priority, item.sequence),
        )
        self._items.remove(best)
        return best.envelope

    @staticmethod
    def _overflow_for(dropped: CollectionEnvelope) -> CoverageEnvelope:
        return CoverageEnvelope.create(
            case_id=dropped.case_id,
            category="ingestion",
            source_id=dropped.source_id,
            status=CoverageStatus.TRUNCATED,
            captured_at=dropped.captured_at,
            reason=f"bounded queue dropped {dropped.category} envelope",
        )


__all__ = ["BoundedEnvelopeQueue", "EnvelopePriority", "OfferResult"]
