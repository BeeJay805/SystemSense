"""Bounded passive evidence capture as an explicit application service."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from threading import Event, Lock
from time import monotonic
from typing import Protocol, cast

from pydantic import Field, field_validator

from systemsense.audit import AuditChain, AuditOutcome
from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindowBasis
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
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.projection import ExplicitRelationProjector
from systemsense.evidence.redaction import Redactor
from systemsense.evidence.retrieval import EvidenceRelationRepository
from systemsense.orchestration.executor import CancellationSignal
from systemsense.orchestration.probe_capacity_ledger import LedgerUnavailable
from systemsense.orchestration.probes import ProbeRun, ProbeRunStatus, ProbeTreeExitStatus
from systemsense.orchestration.scheduler import (
    HostQueueFull,
    HostWorkArbiter,
    HostWorkSlot,
    ResourceClass,
)
from systemsense.platform.windows.eventlog import (
    REGISTERED_CHANNELS,
    EventQuery,
    QueryStatus,
    WindowsEvent,
)
from systemsense.storage.sqlite_store import SQLiteStore, StoreTransaction

_PASSIVE_PROBE_IDS = ("core.system", "core.resources")
_OBSERVER_LIMITATION = "passive observer sample; not a user-reported incident"


class _ProbeManifest(Protocol):
    version: int


class PassiveProbeRunner(Protocol):
    def manifest(self, probe_id: str) -> _ProbeManifest | None: ...

    def run(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
        host_slot: HostWorkSlot | None = None,
    ) -> ProbeRun: ...


class PassiveEventLog(Protocol):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> EventQuery: ...


class PassiveRecorderConfig(FrozenModel):
    interval_seconds: int = Field(default=30, ge=5, le=3600)
    event_channels: tuple[str, ...] = ("Application", "System")
    event_limit: int = Field(default=50, ge=1, le=100)
    max_passive_cases: int = Field(default=288, ge=1, le=500)
    max_case_age_days: int = Field(default=7, ge=1, le=365)

    @field_validator("event_channels")
    @classmethod
    def channels_are_fixed_and_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError("at least one Event Log channel is required")
        if len(values) > len(REGISTERED_CHANNELS):
            raise ValueError("too many Event Log channels")
        if len(set(values)) != len(values):
            raise ValueError("Event Log channels must be unique")
        if any(value not in REGISTERED_CHANNELS for value in values):
            raise ValueError("Event Log channel is not registered")
        return values


class PassiveCycleResult(FrozenModel):
    case_id: CaseId
    started_at: UtcDateTime
    finished_at: UtcDateTime
    active_observer: bool = True
    evidence_persisted: int = Field(ge=0)
    coverage_persisted: int = Field(ge=0)
    relations_persisted: int = Field(ge=0)
    dropped_records: int = Field(ge=0)
    failure_count: int = Field(ge=0)
    passive_cases_pruned: int = Field(ge=0)
    pinned_cases_preserved: int = Field(ge=0)


class PassiveRecorderStatus(FrozenModel):
    active: bool
    observer_label: str = "passive"
    cycles_completed: int = Field(ge=0)
    dropped_cycles: int = Field(ge=0)
    evidence_persisted: int = Field(ge=0)
    coverage_persisted: int = Field(ge=0)
    relations_persisted: int = Field(ge=0)
    dropped_records: int = Field(ge=0)
    failure_count: int = Field(ge=0)
    passive_cases_pruned: int = Field(ge=0)
    pinned_cases_preserved: int = Field(ge=0)
    last_case_id: CaseId | None = None


class PassiveRecorder:
    """Record low-frequency local context into isolated passive cases.

    The recorder must be constructed and used on the thread owning ``store``.
    It installs no service, startup task, timer, or background thread itself.
    """

    def __init__(
        self,
        *,
        store: SQLiteStore,
        runner: PassiveProbeRunner,
        event_log: PassiveEventLog,
        config: PassiveRecorderConfig | None = None,
        now: Callable[[], UtcDateTime] = utc_now,
        host_arbiter: HostWorkArbiter | None = None,
    ) -> None:
        self._store = store
        self._runner = runner
        self._event_log = event_log
        self._config = config or PassiveRecorderConfig()
        self._now = now
        self._host_arbiter = host_arbiter
        self._redactor = Redactor()
        self._projector = ExplicitRelationProjector(max_relations=256)
        self._relations = EvidenceRelationRepository(store)
        self._lock = Lock()
        self._active = False
        self._cycles_completed = 0
        self._dropped_cycles = 0
        self._evidence_persisted = 0
        self._coverage_persisted = 0
        self._relations_persisted = 0
        self._dropped_records = 0
        self._failure_count = 0
        self._passive_cases_pruned = 0
        self._pinned_cases_preserved = 0
        self._last_case_id: CaseId | None = None

    def status(self) -> PassiveRecorderStatus:
        with self._lock:
            return PassiveRecorderStatus(
                active=self._active,
                cycles_completed=self._cycles_completed,
                dropped_cycles=self._dropped_cycles,
                evidence_persisted=self._evidence_persisted,
                coverage_persisted=self._coverage_persisted,
                relations_persisted=self._relations_persisted,
                dropped_records=self._dropped_records,
                failure_count=self._failure_count,
                passive_cases_pruned=self._passive_cases_pruned,
                pinned_cases_preserved=self._pinned_cases_preserved,
                last_case_id=self._last_case_id,
            )

    def run(
        self,
        cancel: Event,
        *,
        max_cycles: int | None = None,
    ) -> PassiveRecorderStatus:
        if max_cycles is not None and (max_cycles < 1 or max_cycles > 10_000):
            raise ValueError("max_cycles must be between 1 and 10000")
        with self._lock:
            if self._active:
                raise RuntimeError("passive recorder is already active")
            self._active = True
        attempted_this_run = 0
        cancellation = _EventCancellation(cancel)
        try:
            while not cancel.is_set() and (max_cycles is None or attempted_this_run < max_cycles):
                attempted_this_run += 1
                try:
                    self.capture_once(cancellation=cancellation)
                except Exception:
                    with self._lock:
                        self._dropped_cycles += 1
                        self._failure_count += 1
                if max_cycles is not None and attempted_this_run >= max_cycles:
                    break
                if cancel.wait(self._config.interval_seconds):
                    break
        finally:
            with self._lock:
                self._active = False
        return self.status()

    def capture_once(
        self,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> PassiveCycleResult:
        captured_at = self._now()
        cancellation_signal = cancellation or _NeverCancelled()
        deadline_at = captured_at + timedelta(seconds=min(self._config.interval_seconds, 15))
        admission_deadline = monotonic() + min(self._config.interval_seconds, 15)
        case_id = CaseId.new()
        self._store.create_case(
            case_id=str(case_id),
            kind=CaseKind.PASSIVE.value,
            symptom="Passive observer cycle; not a user-reported incident",
            created_at=captured_at.isoformat(),
            status=CaseStatus.COLLECTING.value,
            time_window_start=captured_at.isoformat(),
            time_window_end=captured_at.isoformat(),
            time_window_basis=CaseTimeWindowBasis.UNKNOWN.value,
        )
        audit = AuditChain.from_verified_entries(
            self._store.audit_entries(case_id=str(case_id)),
            checkpoint=self._store.audit_checkpoint(case_id=str(case_id)),
            redactor=self._redactor,
        )
        evidence_count = 0
        coverage_count = 0
        relation_count = 0
        dropped_count = 0
        failure_count = 0

        for probe_id in _PASSIVE_PROBE_IDS:
            counts = self._capture_probe(
                case_id=case_id,
                probe_id=probe_id,
                deadline_at=deadline_at,
                admission_deadline=admission_deadline,
                cancellation=cancellation_signal,
                audit=audit,
            )
            evidence_count += counts[0]
            coverage_count += counts[1]
            relation_count += counts[2]
            dropped_count += counts[3]
            failure_count += counts[4]

        for channel in self._config.event_channels:
            counts = self._capture_event_channel(
                case_id=case_id,
                channel=channel,
                deadline_at=deadline_at,
                cancellation=cancellation_signal,
                audit=audit,
            )
            evidence_count += counts[0]
            coverage_count += counts[1]
            relation_count += counts[2]
            dropped_count += counts[3]
            failure_count += counts[4]

        with self._store.transaction() as transaction:
            transaction.transition_case(
                case_id=str(case_id),
                expected_state_version=0,
                status=CaseStatus.COMPLETE.value,
            )
        finished_at = self._now()
        pruned, pinned = self._prune_passive_cases(now=finished_at)
        result = PassiveCycleResult(
            case_id=case_id,
            started_at=captured_at,
            finished_at=finished_at,
            evidence_persisted=evidence_count,
            coverage_persisted=coverage_count,
            relations_persisted=relation_count,
            dropped_records=dropped_count,
            failure_count=failure_count,
            passive_cases_pruned=pruned,
            pinned_cases_preserved=pinned,
        )
        with self._lock:
            self._cycles_completed += 1
            self._evidence_persisted += evidence_count
            self._coverage_persisted += coverage_count
            self._relations_persisted += relation_count
            self._dropped_records += dropped_count
            self._failure_count += failure_count
            self._passive_cases_pruned += pruned
            self._pinned_cases_preserved += pinned
            self._last_case_id = case_id
        return result

    def _capture_probe(
        self,
        *,
        case_id: CaseId,
        probe_id: str,
        deadline_at: UtcDateTime,
        admission_deadline: float,
        cancellation: CancellationSignal,
        audit: AuditChain,
    ) -> tuple[int, int, int, int, int]:
        manifest = self._runner.manifest(probe_id)
        if manifest is None:
            attempted_at = self._now()
            return self._persist_probe_coverage(
                case_id=case_id,
                probe_id=probe_id,
                captured_at=attempted_at,
                status=CoverageStatus.UNSUPPORTED,
                reason="fixed passive probe is unavailable",
                execution_id=ExecutionId.new(),
                probe_status=ProbeRunStatus.UNAVAILABLE,
                probe_version=0,
                started_at=attempted_at,
                audit=audit,
            )
        run_id = f"passive:{case_id}:{probe_id}"
        slot: HostWorkSlot | None = None
        try:
            if self._host_arbiter is not None:
                while not cancellation.cancelled and monotonic() < admission_deadline:
                    slot = self._host_arbiter.try_acquire(
                        run_id, probe_id, ResourceClass.CPU, 0, isolated_probe=True
                    )
                    if slot is not None:
                        break
                    remaining = admission_deadline - monotonic()
                    if remaining > 0:
                        self._host_arbiter.wait_for_change(min(0.05, remaining))
                if slot is None:
                    reason = (
                        "blocked: passive probe admission cancelled"
                        if cancellation.cancelled
                        else "blocked: passive probe admission deadline elapsed"
                    )
                    attempted_at = self._now()
                    return self._persist_probe_coverage(
                        case_id=case_id,
                        probe_id=probe_id,
                        captured_at=attempted_at,
                        status=CoverageStatus.UNAVAILABLE,
                        reason=reason,
                        execution_id=ExecutionId.new(),
                        probe_status=ProbeRunStatus.UNAVAILABLE,
                        probe_version=manifest.version,
                        started_at=attempted_at,
                        audit=audit,
                    )
            run = self._runner.run(
                probe_id,
                {},
                deadline_at=deadline_at,
                cancellation=cancellation,
                host_slot=slot,
            )
        except (HostQueueFull, LedgerUnavailable) as error:
            attempted_at = self._now()
            reason = (
                "blocked: shared host work queue is full"
                if isinstance(error, HostQueueFull)
                else "blocked: durable probe capacity ledger unavailable"
            )
            return self._persist_probe_coverage(
                case_id=case_id,
                probe_id=probe_id,
                captured_at=attempted_at,
                status=CoverageStatus.UNAVAILABLE,
                reason=reason,
                execution_id=ExecutionId.new(),
                probe_status=ProbeRunStatus.UNAVAILABLE,
                probe_version=manifest.version,
                started_at=attempted_at,
                audit=audit,
            )
        except Exception as error:
            attempted_at = self._now()
            return self._persist_probe_coverage(
                case_id=case_id,
                probe_id=probe_id,
                captured_at=self._now(),
                status=CoverageStatus.FAILED,
                reason=_safe_exception(error),
                execution_id=ExecutionId.new(),
                probe_status=ProbeRunStatus.FAILED,
                probe_version=manifest.version,
                started_at=attempted_at,
                audit=audit,
            )
        finally:
            if slot is not None:
                slot.release()
            if self._host_arbiter is not None:
                self._host_arbiter.forget_run(run_id)

        status = _probe_coverage_status(run.status)
        finished_at = self._now()
        reason = None if run.error is None else self._redactor.redact_text(run.error).text
        if run.status is ProbeRunStatus.OK and run.observation is None:
            status = CoverageStatus.FAILED
            reason = "probe returned no observation"
        evidence_count = 0
        relation_count = 0
        dropped = 0
        with self._store.transaction() as transaction:
            if run.status is ProbeRunStatus.OK and run.observation is not None:
                record = _probe_record(
                    case_id=case_id,
                    run=run,
                    probe_version=manifest.version,
                    captured_at=finished_at,
                    redactor=self._redactor,
                )
                inserted = _insert_record(transaction, record, dedupe_key=str(run.execution_id))
                if inserted:
                    evidence_count = 1
                    for relation in self._projector.project(record).relations:
                        relation_count += int(self._relations.append(relation))
                else:
                    dropped = 1
            coverage = _coverage_record(
                case_id=case_id,
                category=probe_id.split(".", maxsplit=1)[0],
                status=status,
                captured_at=finished_at,
                reason=reason,
                execution_id=run.execution_id,
            )
            _insert_coverage(transaction, coverage, source_key=f"probe:{run.execution_id}")
            transaction.record_probe_execution(
                execution_id=str(run.execution_id),
                case_id=str(case_id),
                probe_id=probe_id,
                probe_version=manifest.version,
                status=run.status.value,
                parameters_json="{}",
                started_at=run.started_at.isoformat(),
                finished_at=run.finished_at.isoformat(),
                state_version=0,
                tree_exit_status=run.tree_exit_status,
            )
            _append_audit(
                transaction,
                audit=audit,
                case_id=case_id,
                execution_id=run.execution_id,
                probe_id=probe_id,
                status=run.status,
                occurred_at=run.finished_at,
                persisted_at=finished_at,
                elapsed_ms=run.elapsed_ms,
                error=run.error,
                tree_exit_status=run.tree_exit_status,
            )
        failure = int(status is not CoverageStatus.COVERED)
        return evidence_count, 1, relation_count, dropped, failure

    def _persist_probe_coverage(
        self,
        *,
        case_id: CaseId,
        probe_id: str,
        captured_at: UtcDateTime,
        status: CoverageStatus,
        reason: str,
        execution_id: ExecutionId,
        probe_status: ProbeRunStatus,
        probe_version: int,
        started_at: UtcDateTime,
        audit: AuditChain,
    ) -> tuple[int, int, int, int, int]:
        coverage = _coverage_record(
            case_id=case_id,
            category=probe_id.split(".", maxsplit=1)[0],
            status=status,
            captured_at=captured_at,
            reason=reason,
            execution_id=execution_id,
        )
        with self._store.transaction() as transaction:
            _insert_coverage(transaction, coverage, source_key=f"missing:{probe_id}")
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id=probe_id,
                probe_version=probe_version,
                status=probe_status.value,
                parameters_json="{}",
                started_at=started_at.isoformat(),
                finished_at=captured_at.isoformat(),
                state_version=0,
            )
            _append_audit(
                transaction,
                audit=audit,
                case_id=case_id,
                execution_id=execution_id,
                probe_id=probe_id,
                status=probe_status,
                occurred_at=captured_at,
                persisted_at=captured_at,
                elapsed_ms=max(0.0, (captured_at - started_at).total_seconds() * 1000),
                error=reason,
            )
        return 0, 1, 0, 0, 1

    def _capture_event_channel(
        self,
        *,
        case_id: CaseId,
        channel: str,
        deadline_at: UtcDateTime,
        cancellation: CancellationSignal,
        audit: AuditChain,
    ) -> tuple[int, int, int, int, int]:
        bookmark_key = f"passive.eventlog:{channel}"
        raw_bookmark = self._store.bookmark(bookmark_key)
        after_record_id = None if raw_bookmark is None else int(raw_bookmark)
        query_execution = ExecutionId.new()
        started_at = self._now()
        try:
            if cancellation.cancelled:
                result = EventQuery(
                    status=QueryStatus.FAILED,
                    reason="passive cycle cancelled before Event Log query",
                )
            else:
                result = self._event_log.query(
                    channel,
                    after_record_id=after_record_id,
                    limit=self._config.event_limit,
                    deadline_at=deadline_at,
                    cancellation=cancellation,
                )
        except Exception as error:
            result = EventQuery(
                status=QueryStatus.FAILED,
                reason=_safe_exception(error),
            )
        captured_at = self._now()
        status = _event_coverage_status(result.status)
        reason = None if result.reason is None else self._redactor.redact_text(result.reason).text
        evidence_count = 0
        relation_count = 0
        dropped = 0
        events = (
            result.events[: self._config.event_limit] if result.status is QueryStatus.OK else ()
        )
        dropped += len(result.events) - len(events)
        with self._store.transaction() as transaction:
            for event in events:
                record = _event_record(
                    case_id=case_id,
                    execution_id=query_execution,
                    event=event,
                    captured_at=captured_at,
                    redactor=self._redactor,
                )
                if _insert_record(transaction, record, dedupe_key=event.source_id):
                    evidence_count += 1
                    for relation in self._projector.project(record).relations:
                        relation_count += int(self._relations.append(relation))
                else:
                    dropped += 1
            coverage = _coverage_record(
                case_id=case_id,
                category=_event_probe_id(channel),
                status=status,
                captured_at=captured_at,
                reason=reason,
                execution_id=query_execution,
            )
            _insert_coverage(
                transaction,
                coverage,
                source_key=f"eventlog:{channel}:{query_execution}",
            )
            transaction.record_probe_execution(
                execution_id=str(query_execution),
                case_id=str(case_id),
                probe_id=f"eventlog.{channel.casefold()}",
                probe_version=1,
                status=result.status.value,
                parameters_json="{}",
                started_at=started_at.isoformat(),
                finished_at=captured_at.isoformat(),
                state_version=0,
            )
            if result.status is QueryStatus.OK and events:
                transaction.advance_bookmark(
                    source=bookmark_key,
                    position=str(max(event.record_id for event in events)),
                    updated_at=captured_at.isoformat(),
                )
            _append_event_audit(
                transaction,
                audit=audit,
                case_id=case_id,
                execution_id=query_execution,
                channel=channel,
                status=result.status,
                occurred_at=captured_at,
                persisted_at=captured_at,
                elapsed_ms=max(0.0, (captured_at - started_at).total_seconds() * 1000),
                error=result.reason,
            )
        failure = int(status is not CoverageStatus.COVERED)
        return evidence_count, 1, relation_count, dropped, failure

    def _prune_passive_cases(self, *, now: UtcDateTime) -> tuple[int, int]:
        rows = self._store.cases(kinds=(CaseKind.PASSIVE.value,), limit=500)
        excess_rows = self._store.cases(
            kinds=(CaseKind.PASSIVE.value,),
            limit=500,
            offset=self._config.max_passive_cases,
        )
        pinned_rows = self._store.connection.execute(
            """
            SELECT DISTINCT history.value
            FROM investigation_checkpoints AS checkpoint,
                 json_each(checkpoint.record_json, '$.historical_case_ids') AS history
            WHERE history.type = 'text'
            """
        )
        pinned = {str(row[0]) for row in pinned_rows}
        cutoff = now - timedelta(days=self._config.max_case_age_days)
        candidates = {row.case_id for row in rows if _case_created_at(row.created_at) < cutoff}
        candidates.update(row.case_id for row in excess_rows)
        preserved = len(candidates & pinned)
        deletable = sorted(candidates - pinned)
        for case_id in deletable:
            self._store.connection.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        return len(deletable), preserved


def _probe_record(
    *,
    case_id: CaseId,
    run: ProbeRun,
    probe_version: int,
    captured_at: UtcDateTime,
    redactor: Redactor,
) -> EvidenceRecord:
    assert run.observation is not None
    source_id = stable_source_id(
        "systemsense.passive_probe",
        {"execution_id": str(run.execution_id), "probe_id": run.probe_id},
    )
    return EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=run.observation.observed_at,
        captured_at=captured_at,
        source=EvidenceSource(
            type="systemsense.passive_probe",
            source_id=source_id,
            locator={"probe_id": run.probe_id},
        ),
        collector=CollectorReference(
            id=run.probe_id,
            version=probe_version,
            execution_id=run.execution_id,
        ),
        summary=redactor.redact_text(run.observation.summary).text,
        facts=tuple(
            EvidenceFact(name=name, value=_redact_json(redactor, name, value))
            for name, value in sorted(run.observation.facts.items())
        ),
        extraction=Extraction(confidence=1.0, parser="builtin.passive", parser_version=1),
        limitations=(
            *(redactor.redact_text(item).text for item in run.observation.limitations),
            _OBSERVER_LIMITATION,
        ),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )


def _event_record(
    *,
    case_id: CaseId,
    execution_id: ExecutionId,
    event: WindowsEvent,
    captured_at: UtcDateTime,
    redactor: Redactor,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=event.observed_at,
        captured_at=captured_at,
        source=EvidenceSource(
            type="windows.eventlog",
            source_id=event.source_id,
            locator={"channel": event.channel, "record_id": event.record_id},
        ),
        collector=CollectorReference(
            id=_event_probe_id(event.channel),
            version=1,
            execution_id=execution_id,
        ),
        summary=redactor.redact_text(
            f"{event.provider} event {event.event_id} at level {event.level}"
        ).text,
        facts=(
            EvidenceFact(name="provider", value=redactor.redact_text(event.provider).text),
            EvidenceFact(name="event_id", value=event.event_id),
            EvidenceFact(name="record_id", value=event.record_id),
            EvidenceFact(name="level", value=event.level),
            EvidenceFact(name="computer", value=redactor.redact_text(event.computer).text),
            EvidenceFact(
                name="event_data",
                value=_redact_json(
                    redactor,
                    "event_data",
                    cast("JsonValue", event.event_data),
                ),
            ),
        ),
        extraction=Extraction(confidence=1.0, parser="builtin.eventlog", parser_version=1),
        limitations=(_OBSERVER_LIMITATION,),
        sensitivity=Sensitivity.SENSITIVE,
    )


def _coverage_record(
    *,
    case_id: CaseId,
    category: str,
    status: CoverageStatus,
    captured_at: UtcDateTime,
    reason: str | None,
    execution_id: ExecutionId | None,
) -> CoverageRecord:
    return CoverageRecord(
        evidence_id=EvidenceId.new(),
        case_id=case_id,
        category=category,
        status=status,
        captured_at=captured_at,
        reason=reason,
        execution_id=execution_id,
        limitations=(_OBSERVER_LIMITATION,),
    )


def _insert_record(
    transaction: StoreTransaction,
    record: EvidenceRecord,
    *,
    dedupe_key: str,
) -> bool:
    return transaction.insert_evidence(
        case_id=str(record.case_id),
        evidence_id=str(record.evidence_id),
        source_id=record.source.source_id,
        record_json=record.model_dump_json(),
        observed_at=record.observed_at.isoformat(),
        captured_at=record.captured_at.isoformat(),
        execution_id=str(record.collector.execution_id),
        dedupe_key=dedupe_key,
        time_basis="source_observed",
        time_quality="exact",
    )


def _insert_coverage(
    transaction: StoreTransaction,
    record: CoverageRecord,
    *,
    source_key: str,
) -> None:
    source_id = stable_source_id(
        "systemsense.passive_coverage",
        {"case_id": str(record.case_id), "source_key": source_key},
    )
    transaction.insert_evidence(
        case_id=str(record.case_id),
        evidence_id=str(record.evidence_id),
        source_id=source_id,
        record_json=record.model_dump_json(),
        captured_at=record.captured_at.isoformat(),
        execution_id=(None if record.execution_id is None else str(record.execution_id)),
        dedupe_key=f"coverage:{source_key}",
        time_basis="collector_captured",
        time_quality="exact",
    )


def _append_audit(
    transaction: StoreTransaction,
    *,
    audit: AuditChain,
    case_id: CaseId,
    execution_id: ExecutionId,
    probe_id: str,
    status: ProbeRunStatus,
    occurred_at: UtcDateTime,
    persisted_at: UtcDateTime,
    elapsed_ms: float,
    error: str | None,
    tree_exit_status: ProbeTreeExitStatus = "not_tracked",
) -> None:
    entry = audit.append(
        event_id=f"probe_{execution_id}",
        case_id=case_id,
        probe_id=probe_id,
        outcome=_probe_audit_outcome(status),
        occurred_at=occurred_at,
        parameters={"elapsed_ms": elapsed_ms, "tree_exit_status": tree_exit_status},
        error=error,
    )
    transaction.append_audit(
        event_id=entry.event_id,
        case_id=str(case_id),
        event_json=entry.model_dump_json(),
        created_at=occurred_at.isoformat(),
        occurred_at=occurred_at.isoformat(),
        persisted_at=persisted_at.isoformat(),
    )


def _append_event_audit(
    transaction: StoreTransaction,
    *,
    audit: AuditChain,
    case_id: CaseId,
    execution_id: ExecutionId,
    channel: str,
    status: QueryStatus,
    occurred_at: UtcDateTime,
    persisted_at: UtcDateTime,
    elapsed_ms: float,
    error: str | None,
) -> None:
    entry = audit.append(
        event_id=f"probe_{execution_id}",
        case_id=case_id,
        probe_id=_event_probe_id(channel),
        outcome=_event_audit_outcome(status),
        occurred_at=occurred_at,
        parameters={"elapsed_ms": elapsed_ms},
        error=error,
    )
    transaction.append_audit(
        event_id=entry.event_id,
        case_id=str(case_id),
        event_json=entry.model_dump_json(),
        created_at=occurred_at.isoformat(),
        occurred_at=occurred_at.isoformat(),
        persisted_at=persisted_at.isoformat(),
    )


def _probe_audit_outcome(status: ProbeRunStatus) -> AuditOutcome:
    return {
        ProbeRunStatus.OK: AuditOutcome.ALLOWED,
        ProbeRunStatus.DENIED: AuditOutcome.DENIED,
        ProbeRunStatus.UNAVAILABLE: AuditOutcome.FAILED,
        ProbeRunStatus.FAILED: AuditOutcome.FAILED,
        ProbeRunStatus.TIMED_OUT: AuditOutcome.TIMED_OUT,
        ProbeRunStatus.CANCELLED: AuditOutcome.CANCELLED,
        ProbeRunStatus.TRUNCATED: AuditOutcome.TRUNCATED,
    }[status]


def _event_audit_outcome(status: QueryStatus) -> AuditOutcome:
    return {
        QueryStatus.OK: AuditOutcome.ALLOWED,
        QueryStatus.DENIED: AuditOutcome.DENIED,
        QueryStatus.STALE: AuditOutcome.FAILED,
        QueryStatus.FAILED: AuditOutcome.FAILED,
    }[status]


def _event_probe_id(channel: str) -> str:
    normalized = "".join(character if character.isalnum() else "." for character in channel)
    normalized = ".".join(part for part in normalized.casefold().split(".") if part)
    return f"eventlog.{normalized}"


def _probe_coverage_status(status: ProbeRunStatus) -> CoverageStatus:
    return {
        ProbeRunStatus.OK: CoverageStatus.COVERED,
        ProbeRunStatus.DENIED: CoverageStatus.DENIED,
        ProbeRunStatus.UNAVAILABLE: CoverageStatus.UNAVAILABLE,
        ProbeRunStatus.FAILED: CoverageStatus.FAILED,
        ProbeRunStatus.TIMED_OUT: CoverageStatus.FAILED,
        ProbeRunStatus.CANCELLED: CoverageStatus.UNAVAILABLE,
        ProbeRunStatus.TRUNCATED: CoverageStatus.TRUNCATED,
    }[status]


def _event_coverage_status(status: QueryStatus) -> CoverageStatus:
    return {
        QueryStatus.OK: CoverageStatus.COVERED,
        QueryStatus.DENIED: CoverageStatus.DENIED,
        QueryStatus.STALE: CoverageStatus.STALE,
        QueryStatus.FAILED: CoverageStatus.FAILED,
    }[status]


def _case_created_at(value: str) -> UtcDateTime:
    from datetime import datetime

    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("passive case timestamp must be timezone aware")
    return parsed


class _NeverCancelled:
    @property
    def cancelled(self) -> bool:
        return False


class _EventCancellation:
    def __init__(self, event: Event) -> None:
        self._event = event

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


def _redact_json(redactor: Redactor, field_name: str, value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return redactor.redact_field(field_name, value)
    if isinstance(value, list):
        return [_redact_json(redactor, field_name, item) for item in value]
    if isinstance(value, dict):
        return {name: _redact_json(redactor, name, item) for name, item in value.items()}
    return cast("JsonValue", value)


def _safe_exception(error: Exception) -> str:
    return f"{type(error).__name__}: <redacted-error-detail>"
