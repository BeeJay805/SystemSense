"""Incremental Event Log collection with atomic bookmark persistence."""

import json
import time
from collections.abc import Callable

from pydantic import Field

from systemsense.collection.envelope import CoverageEnvelope
from systemsense.domain.coverage import CoverageStatus
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, stable_source_id
from systemsense.domain.time import UtcDateTime
from systemsense.platform.windows.eventlog import (
    EventQuery,
    FixedEventLogAdapter,
    QueryStatus,
)
from systemsense.storage.sqlite_store import SQLiteStore


class SentinelPollResult(FrozenModel):
    inserted: int = Field(ge=0)
    bookmark: int | None = Field(default=None, ge=0)
    coverage: CoverageEnvelope | None = None


class SentinelRunResult(FrozenModel):
    polls: int = Field(ge=0)
    inserted: int = Field(ge=0)
    coverage_events: int = Field(ge=0)
    stop_reason: str


class Sentinel:
    def __init__(self, adapter: FixedEventLogAdapter, store: SQLiteStore) -> None:
        self._adapter = adapter
        self._store = store

    def poll(
        self,
        case_id: CaseId,
        channel: str,
        *,
        limit: int,
        captured_at: UtcDateTime,
    ) -> SentinelPollResult:
        bookmark_name = f"eventlog.{channel}"
        saved_bookmark = self._store.bookmark(bookmark_name)
        try:
            after_record_id = None if saved_bookmark is None else int(saved_bookmark)
        except ValueError:
            return self._coverage_result(
                case_id,
                channel,
                captured_at,
                CoverageStatus.STALE,
                "stored bookmark is invalid",
            )

        query = self._adapter.query(
            channel,
            after_record_id=after_record_id,
            limit=limit,
        )
        if query.status is not QueryStatus.OK:
            return self._query_failure(case_id, channel, captured_at, query)
        if not query.events:
            return SentinelPollResult(inserted=0, bookmark=after_record_id)

        inserted = 0
        last_record_id = max(event.record_id for event in query.events)
        with self._store.transaction() as transaction:
            for event in query.events:
                if transaction.insert_evidence(
                    case_id=str(case_id),
                    evidence_id=str(EvidenceId.new()),
                    source_id=event.source_id,
                    record_json=json.dumps(
                        event.model_dump(mode="json"),
                        allow_nan=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    captured_at=captured_at.isoformat(),
                ):
                    inserted += 1
            transaction.advance_bookmark(
                source=bookmark_name,
                position=str(last_record_id),
                updated_at=captured_at.isoformat(),
            )
        return SentinelPollResult(inserted=inserted, bookmark=last_record_id)

    @staticmethod
    def _query_failure(
        case_id: CaseId,
        channel: str,
        captured_at: UtcDateTime,
        query: EventQuery,
    ) -> SentinelPollResult:
        status = {
            QueryStatus.DENIED: CoverageStatus.DENIED,
            QueryStatus.STALE: CoverageStatus.STALE,
            QueryStatus.FAILED: CoverageStatus.FAILED,
        }[query.status]
        return Sentinel._coverage_result(
            case_id,
            channel,
            captured_at,
            status,
            query.reason or "event query failed",
        )

    @staticmethod
    def _coverage_result(
        case_id: CaseId,
        channel: str,
        captured_at: UtcDateTime,
        status: CoverageStatus,
        reason: str,
    ) -> SentinelPollResult:
        source_id = stable_source_id(
            "windows.eventlog.coverage",
            {"channel": channel, "status": status.value},
        )
        return SentinelPollResult(
            inserted=0,
            coverage=CoverageEnvelope.create(
                case_id=case_id,
                category="eventlog",
                source_id=source_id,
                status=status,
                captured_at=captured_at,
                reason=reason,
            ),
        )


class SentinelRunner:
    """Run bounded polling cycles with explicit stop and wait seams."""

    def __init__(
        self,
        sentinel: Sentinel,
        *,
        wait: Callable[[float], None] = time.sleep,
        now: Callable[[], UtcDateTime],
    ) -> None:
        self._sentinel = sentinel
        self._wait = wait
        self._now = now

    def run(
        self,
        *,
        case_id: CaseId,
        channels: tuple[str, ...],
        limit: int,
        max_polls: int,
        interval_seconds: float,
        stop_requested: Callable[[], bool] | None = None,
    ) -> SentinelRunResult:
        if not channels:
            raise ValueError("at least one channel is required")
        if max_polls < 1 or max_polls > 10_000:
            raise ValueError("max_polls must be between 1 and 10000")
        if interval_seconds < 0 or interval_seconds > 3600:
            raise ValueError("interval_seconds must be between 0 and 3600")

        should_stop = stop_requested or (lambda: False)
        polls = 0
        inserted = 0
        coverage_events = 0
        while polls < max_polls:
            if should_stop():
                return SentinelRunResult(
                    polls=polls,
                    inserted=inserted,
                    coverage_events=coverage_events,
                    stop_reason="requested",
                )
            captured_at = self._now()
            for channel in channels:
                result = self._sentinel.poll(
                    case_id,
                    channel,
                    limit=limit,
                    captured_at=captured_at,
                )
                inserted += result.inserted
                coverage_events += int(result.coverage is not None)
            polls += 1
            if polls < max_polls:
                self._wait(interval_seconds)
        return SentinelRunResult(
            polls=polls,
            inserted=inserted,
            coverage_events=coverage_events,
            stop_reason="poll_limit",
        )
