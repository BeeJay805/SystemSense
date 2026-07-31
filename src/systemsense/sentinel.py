"""Incremental Event Log collection with atomic bookmark persistence."""

import json

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
