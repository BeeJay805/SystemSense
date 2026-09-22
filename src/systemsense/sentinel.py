"""Incremental Event Log collection with atomic bookmark persistence."""

import time
from collections.abc import Callable

from pydantic import Field

from systemsense.audit import AuditChain, AuditEntry, AuditOutcome
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
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.redaction import Redactor
from systemsense.platform.windows.eventlog import (
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
        now: Callable[[], UtcDateTime] = utc_now,
        audit: AuditChain | None = None,
    ) -> None:
        self._adapter = adapter
        self._store = store
        self._redactor = redactor or Redactor()
        self._now = now
        if audit is not None and audit.entries:
            raise ValueError("an injected Sentinel audit chain must be empty")
        self._audit_seed = audit
        self._audits: dict[str, AuditChain] = {}

    def poll(
        self,
        case_id: CaseId,
        channel: str,
        *,
        limit: int,
    ) -> SentinelPollResult:
        case = self._store.case(str(case_id))
        if case is None:
            raise ValueError(f"case does not exist: {case_id}")
        state_version = case.state_version
        started_at = self._now()
        bookmark_name = f"eventlog.{case_id}.{channel}"
        saved_bookmark = self._store.bookmark(bookmark_name)
        try:
            after_record_id = None if saved_bookmark is None else int(saved_bookmark)
        except ValueError:
            finished_at = self._now()
            result = self._coverage_result(
                case_id,
                channel,
                finished_at,
                CoverageStatus.STALE,
                "stored bookmark is invalid",
            )
            self._persist_attempt(
                case_id=case_id,
                channel=channel,
                state_version=state_version,
                started_at=started_at,
                finished_at=finished_at,
                status=CoverageStatus.STALE.value,
                coverage=result.coverage,
                reason="stored bookmark is invalid",
            )
            return result

        query = self._adapter.query(
            channel,
            after_record_id=after_record_id,
            limit=limit,
        )
        finished_at = self._now()
        if query.status is not QueryStatus.OK:
            status = {
                QueryStatus.DENIED: CoverageStatus.DENIED,
                QueryStatus.STALE: CoverageStatus.STALE,
                QueryStatus.FAILED: CoverageStatus.FAILED,
            }[query.status]
            result = self._coverage_result(
                case_id,
                channel,
                finished_at,
                status,
                query.reason or "event query failed",
            )
            self._persist_attempt(
                case_id=case_id,
                channel=channel,
                state_version=state_version,
                started_at=started_at,
                finished_at=finished_at,
                status=status.value,
                coverage=result.coverage,
                reason=query.reason or "event query failed",
                after_record_id=after_record_id,
            )
            return result
        if not query.events:
            result = self._coverage_result(
                case_id,
                channel,
                finished_at,
                CoverageStatus.COVERED,
                "query completed; no events matched",
            )
            self._persist_attempt(
                case_id=case_id,
                channel=channel,
                state_version=state_version,
                started_at=started_at,
                finished_at=finished_at,
                status="ok",
                coverage=result.coverage,
                reason=None,
                after_record_id=after_record_id,
                result_count=0,
            )
            return SentinelPollResult(
                inserted=0,
                bookmark=after_record_id,
                coverage=result.coverage,
            )

        inserted = 0
        last_record_id = max(event.record_id for event in query.events)
        execution_id = ExecutionId.new()
        audit = self._audit_candidate(case_id)
        audit_entry = audit.append(
            event_id=f"sentinel_{execution_id}",
            case_id=case_id,
            probe_id="core.eventlog",
            outcome=AuditOutcome.ALLOWED,
            occurred_at=finished_at,
            parameters={
                "channel": channel,
                "limit": limit,
                "after_record_id": after_record_id,
                "result_count": len(query.events),
            },
        )
        persisted_at = self._now()
        with self._store.transaction() as transaction:
            transaction.require_case_state(
                case_id=str(case_id),
                expected_state_version=state_version,
            )
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id="core.eventlog",
                probe_version=1,
                status="ok",
                parameters_json="{}",
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                state_version=state_version,
            )
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
                    captured_at=finished_at,
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
                    observed_at=event.observed_at.isoformat(),
                    captured_at=finished_at.isoformat(),
                    execution_id=str(execution_id),
                    dedupe_key=event.source_id,
                    time_basis="source_event",
                    time_quality="exact",
                ):
                    inserted += 1
            transaction.advance_bookmark(
                source=bookmark_name,
                position=str(last_record_id),
                updated_at=finished_at.isoformat(),
            )
            transaction.append_audit(
                event_id=audit_entry.event_id,
                case_id=str(case_id),
                event_json=audit_entry.model_dump_json(),
                created_at=finished_at.isoformat(),
                occurred_at=finished_at.isoformat(),
                persisted_at=persisted_at.isoformat(),
            )
        self._audits[str(case_id)] = audit
        return SentinelPollResult(inserted=inserted, bookmark=last_record_id)

    def _persist_attempt(
        self,
        *,
        case_id: CaseId,
        channel: str,
        state_version: int,
        started_at: UtcDateTime,
        finished_at: UtcDateTime,
        status: str,
        coverage: CoverageEnvelope | None,
        reason: str | None,
        after_record_id: int | None = None,
        result_count: int = 0,
    ) -> None:
        execution_id = ExecutionId.new()
        audit = self._audit_candidate(case_id)
        audit_entry = audit.append(
            event_id=f"sentinel_{execution_id}",
            case_id=case_id,
            probe_id="core.eventlog",
            outcome=(
                AuditOutcome.ALLOWED
                if status == "ok"
                else AuditOutcome.DENIED
                if status == CoverageStatus.DENIED.value
                else AuditOutcome.FAILED
            ),
            occurred_at=finished_at,
            parameters={
                "channel": channel,
                "after_record_id": after_record_id,
                "result_count": result_count,
            },
            error=None if reason is None else self._redact_reason(reason),
        )
        persisted_at = self._now()
        with self._store.transaction() as transaction:
            transaction.require_case_state(
                case_id=str(case_id),
                expected_state_version=state_version,
            )
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id="core.eventlog",
                probe_version=1,
                status=status,
                parameters_json="{}",
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                state_version=state_version,
            )
            if coverage is not None:
                coverage_record = CoverageRecord(
                    evidence_id=EvidenceId.new(),
                    case_id=coverage.case_id,
                    category=coverage.category,
                    status=coverage.status,
                    captured_at=coverage.captured_at,
                    reason=self._redact_reason(coverage.reason),
                    execution_id=execution_id,
                )
                transaction.insert_evidence(
                    case_id=str(case_id),
                    evidence_id=str(coverage_record.evidence_id),
                    source_id=coverage.source_id,
                    record_json=coverage_record.model_dump_json(),
                    observed_at=finished_at.isoformat(),
                    captured_at=finished_at.isoformat(),
                    execution_id=str(execution_id),
                    dedupe_key=f"{coverage.source_id}:{execution_id}",
                    time_basis="probe_attempt_finish",
                    time_quality="exact",
                )
            transaction.append_audit(
                event_id=audit_entry.event_id,
                case_id=str(case_id),
                event_json=audit_entry.model_dump_json(),
                created_at=finished_at.isoformat(),
                occurred_at=finished_at.isoformat(),
                persisted_at=persisted_at.isoformat(),
            )
        self._audits[str(case_id)] = audit

    def _audit_candidate(self, case_id: CaseId) -> AuditChain:
        current = self._audit_for_case(case_id)
        return AuditChain.from_verified_entries(
            current.entries,
            checkpoint=current.checkpoint(),
            redactor=self._redactor,
        )

    def _audit_for_case(self, case_id: CaseId) -> AuditChain:
        case_key = str(case_id)
        checkpoint = self._store.audit_checkpoint(case_id=case_key)
        cached = self._audits.get(case_key)
        if cached is not None and cached.checkpoint() == checkpoint:
            return cached
        self._audits.pop(case_key, None)

        entry_count = checkpoint.entry_count
        if entry_count == 0:
            chain = self._audit_seed or AuditChain(redactor=self._redactor)
            self._audit_seed = None
            self._audits[case_key] = chain
            return chain

        entries: list[AuditEntry] = []
        page_size = 1000
        for offset in range(0, entry_count, page_size):
            entries.extend(
                self._store.audit_entries(
                    case_id=case_key,
                    limit=min(page_size, entry_count - offset),
                    offset=offset,
                )
            )
        if len(entries) != entry_count:
            raise RuntimeError("case audit chain changed while it was being reconstructed")
        chain = AuditChain.from_verified_entries(
            tuple(entries),
            checkpoint=checkpoint,
            redactor=self._redactor,
        )
        self._audits[case_key] = chain
        return chain

    def _coverage_result(
        self,
        case_id: CaseId,
        channel: str,
        captured_at: UtcDateTime,
        status: CoverageStatus,
        reason: str,
    ) -> SentinelPollResult:
        source_id = stable_source_id(
            "windows.eventlog.coverage",
            {"channel": channel},
        )
        return SentinelPollResult(
            inserted=0,
            coverage=CoverageEnvelope.create(
                case_id=case_id,
                category="eventlog",
                source_id=source_id,
                status=status,
                captured_at=captured_at,
                reason=self._redact_reason(reason),
            ),
        )

    def _redact_reason(self, reason: str) -> str:
        lowered = reason.lower()
        sensitive_assignment = any(
            f"{token}{separator}" in lowered
            for token in ("password", "passwd", "secret", "token", "credential", "key")
            for separator in ("=", ":")
        )
        if sensitive_assignment:
            return self._redactor.redact_field("password", reason)
        return self._redactor.redact_text(reason).text


class SentinelRunner:
    """Run bounded polling cycles with explicit stop and wait seams."""

    def __init__(
        self,
        sentinel: Sentinel,
        *,
        wait: Callable[[float], None] = time.sleep,
    ) -> None:
        self._sentinel = sentinel
        self._wait = wait

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
            for channel in channels:
                result = self._sentinel.poll(
                    case_id,
                    channel,
                    limit=limit,
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
