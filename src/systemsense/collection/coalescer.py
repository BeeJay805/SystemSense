"""Bounded grouping of repeated source events."""

from collections import OrderedDict

from pydantic import Field

from systemsense.collection.envelope import EvidenceEnvelope
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime

type CoalescingKey = tuple[str, str]


class CoalescedGroup(FrozenModel):
    source_id: str
    fingerprint: str
    representative: EvidenceEnvelope
    first_observed_at: UtcDateTime
    last_observed_at: UtcDateTime
    count: int = Field(ge=1)


class EnvelopeCoalescer:
    def __init__(self, *, max_groups: int) -> None:
        if max_groups < 1:
            raise ValueError("max_groups must be positive")
        self._max_groups = max_groups
        self._groups: OrderedDict[CoalescingKey, CoalescedGroup] = OrderedDict()
        self._evicted_count = 0

    def __len__(self) -> int:
        return len(self._groups)

    @property
    def evicted_count(self) -> int:
        return self._evicted_count

    def keys(self) -> tuple[CoalescingKey, ...]:
        return tuple(self._groups)

    def add(self, envelope: EvidenceEnvelope) -> CoalescedGroup:
        key = (envelope.source_id, envelope.fingerprint)
        existing = self._groups.get(key)
        if existing is not None:
            updated = existing.model_copy(
                update={
                    "last_observed_at": max(
                        existing.last_observed_at,
                        envelope.observed_at,
                    ),
                    "first_observed_at": min(
                        existing.first_observed_at,
                        envelope.observed_at,
                    ),
                    "count": existing.count + 1,
                }
            )
            self._groups[key] = updated
            self._groups.move_to_end(key)
            return updated

        if len(self._groups) == self._max_groups:
            self._groups.popitem(last=False)
            self._evicted_count += 1
        group = CoalescedGroup(
            source_id=envelope.source_id,
            fingerprint=envelope.fingerprint,
            representative=envelope,
            first_observed_at=envelope.observed_at,
            last_observed_at=envelope.observed_at,
            count=1,
        )
        self._groups[key] = group
        return group

    def flush(self) -> tuple[CoalescedGroup, ...]:
        groups = tuple(self._groups.values())
        self._groups.clear()
        return groups
