"""Incremental Event Log collection with atomic bookmark persistence."""

import time
from collections.abc import Callable

from pydantic import Field

from systemsense.collection.envelope import CoverageEnvelope
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    FrozenModel,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import (
    CaseId,
    EvidenceId,
    ExecutionId,
    stable_source_id,
)
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.redaction import Redactor
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
    def __init__(
        self,
        adapter: FixedEventLogAdapter,
        store: SQLiteStore,
        *,
        redactor: Redactor | None = None,
    ) -> None:
        self._adapter = adapter
        self._store = store
        self._redactor = redactor or Redactor()

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
            result = self._coverage_result(
                case_id,
                channel,
                captured_at,
                CoverageStatus.STALE,
                "stored bookmark is invalid",
            )
            self._persist_coverage(result.coverage)
            return result

        query = self._adapter.query(
            channel,
            after_record_id=after_record_id,
            limit=limit,
        )
        if query.status is not QueryStatus.OK:
            result = self._query_failure(case_id, channel, captured_at, query)
            self._persist_coverage(result.coverage)
            return result
        if not query.events:
            return SentinelPollResult(inserted=0, bookmark=after_record_id)

        inserted = 0
        last_record_id = max(event.record_id for event in query.events)
        execution_id = ExecutionId.new()
        with self._store.transaction() as transaction:
            for event in query.events:
                facts = [
                    EvidenceFact(name="event.id", value=event.event_id),
                    EvidenceFact(name="event.level", value=event.level),
                    EvidenceFact(name="event.provider", value=event.provider),
                    EvidenceFact(name="event.computer", value=event.computer),
                    EvidenceFact(
                        name="event.data",
                        value={
                            name: self._redactor.redact_field(name, value)
                            for name, value in event.event_data.items()
                        },
                    ),
                ]
                if event.rendered_message is not None:
                    facts.append(
                        EvidenceFact(
                            name="event.rendered_message",
                            value=self._redactor.redact_text(event.rendered_message).text,
                        )
                    )
                record = EvidenceRecord(
                    evidence_id=EvidenceId.new(),
                    case_id=case_id,
                    statement_kind=StatementKind.OBSERVED_FACT,
                    observed_at=event.observed_at,
                    captured_at=captured_at,
                    source=EvidenceSource(
                        type="windows.eventlog",
                        source_id=event.source_id,
                        locator={
                            "channel": event.channel,
                            "record_id": event.record_id,
                        },
                    ),
                    collector=CollectorReference(
                        id="core.eventlog",
                        version=1,
                        execution_id=execution_id,
                    ),
                    summary=(
                        f"Windows Event {event.event_id} from {event.provider} in {event.channel}"
                    ),
                    facts=tuple(facts),
                    extraction=Extraction(
                        confidence=1.0,
                        parser="eventlog.xml",
                        parser_version=1,
                    ),
                    sensitivity=Sensitivity.SYSTEM_METADATA,
                )
                if transaction.insert_evidence(
                    case_id=str(case_id),
                    evidence_id=str(record.evidence_id),
                    source_id=event.source_id,
                    record_json=record.model_dump_json(),
                    captured_at=captured_at.isoformat(),
                ):
                    inserted += 1
            transaction.advance_bookmark(
                source=bookmark_name,
                position=str(last_record_id),
                updated_at=captured_at.isoformat(),
            )
        return SentinelPollResult(inserted=inserted, bookmark=last_record_id)

    def _persist_coverage(self, envelope: CoverageEnvelope | None) -> None:
        if envelope is None:
            return
        coverage = CoverageRecord(
            evidence_id=EvidenceId.new(),
            case_id=envelope.case_id,
            category=envelope.category,
            status=envelope.status,
            captured_at=envelope.captured_at,
            reason=self._redactor.redact_text(envelope.reason).text,
        )
        with self._store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(envelope.case_id),
                evidence_id=str(coverage.evidence_id),
                source_id=envelope.source_id,
                record_json=coverage.model_dump_json(),
                captured_at=envelope.captured_at.isoformat(),
            )

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
