"""Dual-time ordering for evidence captured after an event occurred."""

from collections.abc import Iterable

from pydantic import Field

from systemsense.domain.evidence import FrozenModel, StatementKind
from systemsense.domain.ids import EvidenceId
from systemsense.domain.time import UtcDateTime


class TimelineEntry(FrozenModel):
    evidence_id: EvidenceId
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    statement_kind: StatementKind
    summary: str = Field(min_length=1, max_length=1000)


def build_timeline(entries: Iterable[TimelineEntry]) -> tuple[TimelineEntry, ...]:
    """Sort by when facts occurred while preserving when they were captured."""

    return tuple(
        sorted(
            entries,
            key=lambda entry: (
                entry.observed_at,
                entry.captured_at,
                str(entry.evidence_id),
            ),
        )
    )
