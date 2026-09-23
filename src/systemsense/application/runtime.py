"""Execute a case plan and atomically persist normalized evidence and audit data."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import cast

from systemsense.application.case_service import CaseService, OpenedCase
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.audit import AuditChain, AuditOutcome
from systemsense.domain.cases import CaseKind, CaseStatus
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import (
    EntityId,
    EvidenceId,
    ExecutionId,
    JsonValue,
    stable_source_id,
)
from systemsense.domain.inventory import InventoryFact
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.redaction import Redactor
from systemsense.orchestration.probes import (
    ProbeObservation,
    ProbeRun,
    ProbeRunner,
    ProbeRunStatus,
)
from systemsense.orchestration.scheduler import (
    BoundedScheduler,
    ResourceBudget,
    ResourceClass,
    Task,
    TaskResult,
    TaskStatus,
)
from systemsense.storage.sqlite_store import SQLiteStore

_HOST_ENTITY_ID = EntityId(
    root=f"entity_{hashlib.sha256(b'systemsense.local-host').hexdigest()[:32]}"
)


class DiagnosticRuntime:
    """Complete case creation, execution, normalization, and persistence."""

    def __init__(
        self,
        *,
        store: SQLiteStore,
        case_service: CaseService,
        probe_runner: ProbeRunner,
        redactor: Redactor | None = None,
        scheduler: BoundedScheduler | None = None,
    ) -> None:
        self._store = store
        self._case_service = case_service
        self._probe_runner = probe_runner
        self._redactor = redactor or Redactor()
        self._scheduler = scheduler or BoundedScheduler(
            budget=ResourceBudget(
                global_limit=4,
                per_resource={
                    ResourceClass.DISK: 1,
                    ResourceClass.GPU: 1,
                    ResourceClass.INFERENCE: 1,
                },
            )
        )

    def open_case(
        self,
        *,
        kind: CaseKind,
        symptom: str,
        target_traits: tuple[str, ...],
        created_at: UtcDateTime,
        budget_ms: int,
        max_probes: int,
    ) -> OpenedCase:
        opened = self._case_service.open_case(
            kind=kind,
            symptom=symptom,
            target_traits=frozenset(target_traits),
            created_at=created_at,
            budget_ms=budget_ms,
            max_probes=max_probes,
        )
        self.execute_plan(opened)
        with self._store.transaction() as transaction:
            state_version = transaction.transition_case(
                case_id=str(opened.case.case_id),
                expected_state_version=opened.case.state_version,
                status=CaseStatus.READY.value,
            )
        return OpenedCase(
            case=opened.case.model_copy(
                update={"status": CaseStatus.READY, "state_version": state_version}
            ),
            plan=opened.plan,
            deadline_at=opened.deadline_at,
        )

    def execute_plan(
        self,
        opened: OpenedCase,
        *,
        cancel_event: threading.Event | None = None,
        on_persisted: Callable[[ProbeRun], None] | None = None,
    ) -> tuple[TaskResult, ...]:
        """Execute one plan, persisting each completion on the owning thread."""
        return self._execute_plan(
            opened,
            cancel_event=cancel_event,
            on_persisted=on_persisted,
            parameters_by_probe={},
            audit_binding={},
        )

    def execute_bound_target_pressure(
        self,
        opened: OpenedCase,
        *,
        cancel_event: threading.Event | None = None,
    ) -> tuple[TaskResult, ...]:
        """Run only the selected process probe from a revalidated case binding."""
        if len(opened.plan.probes) != 1 or opened.plan.probes[0].probe_id != (
            "application.target_pressure"
        ):
            raise ValueError("bound target execution requires only application.target_pressure")
        current_case = self._store.case(str(opened.case.case_id))
        if (
            current_case is None
            or current_case.state_version != opened.case.state_version
            or current_case.status != CaseStatus.COLLECTING.value
        ):
            raise ValueError("target execution case is no longer collecting at this version")
        try:
            binding = ProcessTargetRepository(self._store).resolve_process_target_for_sampling(
                opened.case.case_id
            )
        except TargetSelectionError as error:
            now = datetime.now(UTC)
            unavailable = ProbeRun(
                execution_id=ExecutionId.new(),
                probe_id="application.target_pressure",
                status=ProbeRunStatus.UNAVAILABLE,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                error=f"Bound process target unavailable: {error}",
            )
            return self._execute_plan(
                opened,
                cancel_event=cancel_event,
                on_persisted=None,
                parameters_by_probe={},
                audit_binding={"target_binding_status": "unavailable"},
                preflight_runs={"application.target_pressure": unavailable},
            )
        if opened.case.state_version < binding.case_state_version:
            raise ValueError("target binding is newer than the execution case version")
        parameters: dict[str, JsonValue] = {
            "pid": binding.pid,
            "creation_time": binding.creation_time.isoformat(),
        }
        return self._execute_plan(
            opened,
            cancel_event=cancel_event,
            on_persisted=None,
            parameters_by_probe={"application.target_pressure": parameters},
            audit_binding={
                "target_candidate_id": binding.candidate_id,
                "target_evidence_id": str(binding.evidence_id),
                "target_evidence_sha256": binding.evidence_sha256,
            },
        )

    def _execute_plan(
        self,
        opened: OpenedCase,
        *,
        cancel_event: threading.Event | None,
        on_persisted: Callable[[ProbeRun], None] | None,
        parameters_by_probe: Mapping[str, dict[str, JsonValue]],
        audit_binding: Mapping[str, JsonValue],
        preflight_runs: Mapping[str, ProbeRun] | None = None,
    ) -> tuple[TaskResult, ...]:
        preflight = preflight_runs or {}
        tasks: list[Task] = []
        task_id_by_probe = {
            planned.probe_id: f"probe-{index}-{planned.probe_id}"
            for index, planned in enumerate(opened.plan.probes)
        }
        for planned in opened.plan.probes:
            manifest = self._probe_runner.manifest(planned.probe_id)
            parameters = parameters_by_probe.get(planned.probe_id, {})
            tasks.append(
                Task(
                    task_id=task_id_by_probe[planned.probe_id],
                    action=lambda context, probe_id=planned.probe_id, probe_parameters=parameters: (
                        preflight[probe_id]
                        if probe_id in preflight
                        else self._probe_runner.run(
                            probe_id,
                            probe_parameters,
                            deadline_at=context.deadline_at,
                            cancellation=context.cancellation,
                        )
                    ),
                    accept_result=lambda value: (
                        isinstance(value, ProbeRun) and value.status is ProbeRunStatus.OK
                    ),
                    dependencies=tuple(
                        task_id_by_probe[dependency] for dependency in planned.depends_on
                    ),
                    resource=_resource_class(
                        "orchestration" if manifest is None else manifest.category
                    ),
                    priority=max(0, round(planned.value * 100)),
                    dedupe_key=(
                        f"{planned.probe_id}:"
                        f"{json.dumps(parameters, sort_keys=True, separators=(',', ':'))}"
                    ),
                    state_version=opened.case.state_version,
                    timeout_seconds=(
                        None if manifest is None else manifest.limits.timeout_ms / 1000
                    ),
                )
            )
        audit = AuditChain.from_verified_entries(
            self._store.audit_entries(case_id=str(opened.case.case_id)),
            checkpoint=self._store.audit_checkpoint(case_id=str(opened.case.case_id)),
            redactor=self._redactor,
        )
        probe_by_task = {task_id: probe for probe, task_id in task_id_by_probe.items()}

        def persist(result: TaskResult) -> None:
            if result.status is TaskStatus.DEDUPLICATED:
                return
            probe_id = probe_by_task[result.task_id]
            run = _probe_run(result, probe_id=probe_id)
            manifest = self._probe_runner.manifest(probe_id)
            category = "orchestration" if manifest is None else manifest.category
            parameters_json = json.dumps(
                parameters_by_probe.get(probe_id, {}),
                sort_keys=True,
                separators=(",", ":"),
            )
            audit_entry = audit.append(
                event_id=f"probe_{run.execution_id}",
                case_id=opened.case.case_id,
                probe_id=probe_id,
                outcome=_audit_outcome(run.status),
                occurred_at=run.finished_at,
                parameters={
                    "elapsed_ms": run.elapsed_ms,
                    "parameters_sha256": hashlib.sha256(
                        parameters_json.encode("utf-8")
                    ).hexdigest(),
                    **audit_binding,
                },
                error=run.error,
            )
            with self._store.transaction() as transaction:
                transaction.require_case_state(
                    case_id=str(opened.case.case_id),
                    expected_state_version=opened.case.state_version,
                )
                transaction.record_probe_execution(
                    execution_id=str(run.execution_id),
                    case_id=str(opened.case.case_id),
                    probe_id=run.probe_id,
                    probe_version=0 if manifest is None else manifest.version,
                    status=run.status.value,
                    parameters_json=parameters_json,
                    started_at=run.started_at.isoformat(),
                    finished_at=run.finished_at.isoformat(),
                    state_version=opened.case.state_version,
                )
                if run.status is ProbeRunStatus.OK and run.observation is not None:
                    self._persist_observation(
                        transaction=transaction,
                        opened=opened,
                        run=run,
                        category=category,
                        probe_version=1 if manifest is None else manifest.version,
                        captured_at=run.finished_at,
                    )
                else:
                    self._persist_coverage(
                        transaction=transaction,
                        opened=opened,
                        run=run,
                        category=category,
                        probe_version=0 if manifest is None else manifest.version,
                        captured_at=run.finished_at,
                    )
                transaction.append_audit(
                    event_id=audit_entry.event_id,
                    case_id=str(opened.case.case_id),
                    event_json=audit_entry.model_dump_json(),
                    created_at=run.finished_at.isoformat(),
                    occurred_at=run.finished_at.isoformat(),
                    persisted_at=datetime.now(UTC).isoformat(),
                )
            if on_persisted is not None:
                on_persisted(run)

        return self._scheduler.run_blocking(
            tasks,
            case_deadline_at=opened.deadline_at,
            state_version=opened.case.state_version,
            cancel_event=cancel_event,
            on_result=persist,
        )

    def _persist_observation(
        self,
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        category: str,
        probe_version: int,
        captured_at: UtcDateTime,
    ) -> None:
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        assert run.observation is not None
        observation = self._redact_observation(run.observation)
        observed_at = observation.observed_at
        time_basis = (
            "collector_upper_bound"
            if observation.time_quality == "bounded_interval"
            else "collector_observed"
        )
        collector = CollectorReference(
            id=run.probe_id,
            version=probe_version,
            execution_id=run.execution_id,
        )
        source_id = stable_source_id(
            "systemsense.probe",
            {
                "probe_id": run.probe_id,
                "probe_version": collector.version,
            },
        )
        source = EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": run.probe_id},
        )
        record = EvidenceRecord(
            evidence_id=EvidenceId.new(),
            case_id=opened.case.case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=observed_at,
            captured_at=captured_at,
            source=source,
            collector=collector,
            summary=observation.summary,
            facts=tuple(
                EvidenceFact(name=name, value=value)
                for name, value in sorted(observation.facts.items())
            ),
            extraction=Extraction(
                confidence=1.0,
                parser="builtin.probe",
                parser_version=1,
            ),
            limitations=observation.limitations,
            sensitivity=_sensitivity(category),
        )
        inventory = InventoryFact(
            entity_id=_HOST_ENTITY_ID,
            category=category,
            name=run.probe_id,
            value=observation.facts,
            source=source,
            collector=collector,
            observed_at=observed_at,
            captured_at=captured_at,
            extraction=record.extraction,
            freshness_ttl_seconds=_freshness_ttl(category),
            sensitivity=_sensitivity(category),
            limitations=observation.limitations,
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(record.evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=observed_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(run.execution_id),
            dedupe_key=f"execution:{run.execution_id}",
            time_basis=time_basis,
            time_quality=observation.time_quality,
        )
        transaction.upsert_inventory(
            category=inventory.category,
            fact_key=f"{inventory.entity_id}:{inventory.name}",
            record_json=inventory.model_dump_json(),
            observed_at=observed_at.isoformat(),
            captured_at=captured_at.isoformat(),
            time_basis=time_basis,
            time_quality=observation.time_quality,
        )
        if run.probe_id == "incident.events":
            self._persist_incident_event_children(
                transaction=transaction,
                opened=opened,
                run=run,
                observation=observation,
                collector=collector,
                captured_at=captured_at,
            )

    def _persist_incident_event_children(
        self,
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        observation: ProbeObservation,
        collector: CollectorReference,
        captured_at: UtcDateTime,
    ) -> None:
        from systemsense.platform.windows.deep_collectors import IncidentProfileEvent
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        raw_events = observation.facts.get("events")
        if not isinstance(raw_events, list):
            self._persist_child_coverage(
                transaction=transaction,
                opened=opened,
                run=run,
                captured_at=captured_at,
                status=CoverageStatus.FAILED,
                reason="incident event facts were not a list",
            )
            return
        invalid = 0
        for raw_event in raw_events[:512]:
            try:
                event = IncidentProfileEvent.model_validate(raw_event)
                source = EvidenceSource(
                    type="windows.eventlog",
                    source_id=event.source_id,
                    locator={
                        "channel": event.channel,
                        "provider": event.provider,
                        "event_id": event.event_id,
                        "record_id": event.record_id,
                    },
                )
                facts = (
                    EvidenceFact(name="profile", value=event.profile),
                    EvidenceFact(name="provider", value=event.provider),
                    EvidenceFact(name="event_id", value=event.event_id),
                    EvidenceFact(name="record_id", value=event.record_id),
                    EvidenceFact(name="level", value=event.level),
                    EvidenceFact(name="event_data", value=cast("JsonValue", event.event_data)),
                )
                if event.rendered_message is not None:
                    facts = (
                        *facts,
                        EvidenceFact(name="rendered_message", value=event.rendered_message),
                    )
                child = EvidenceRecord(
                    evidence_id=EvidenceId.new(),
                    case_id=opened.case.case_id,
                    statement_kind=StatementKind.OBSERVED_FACT,
                    observed_at=event.observed_at,
                    captured_at=captured_at,
                    source=source,
                    collector=collector,
                    summary=(
                        f"{event.channel} event {event.event_id} from {event.provider} "
                        f"matched the {event.profile} incident profile"
                    ),
                    facts=facts,
                    extraction=Extraction(
                        confidence=1.0,
                        parser="builtin.incident_event_profile",
                        parser_version=1,
                    ),
                    limitations=("selected from a bounded fixed-profile Event Log query",),
                    sensitivity=Sensitivity.PERSONAL,
                )
            except (TypeError, ValueError):
                invalid += 1
                continue
            transaction.insert_evidence(
                case_id=str(opened.case.case_id),
                evidence_id=str(child.evidence_id),
                source_id=event.source_id,
                record_json=child.model_dump_json(),
                observed_at=event.observed_at.isoformat(),
                captured_at=captured_at.isoformat(),
                execution_id=str(run.execution_id),
                dedupe_key=f"execution:{run.execution_id}:event:{event.source_id}",
                time_basis="source_event",
                time_quality="exact",
            )
        omitted = max(0, len(raw_events) - 512)
        if invalid or omitted:
            details: list[str] = []
            if invalid:
                details.append(f"{invalid} malformed event records were rejected")
            if omitted:
                details.append(f"{omitted} event records exceeded the 512-record child limit")
            self._persist_child_coverage(
                transaction=transaction,
                opened=opened,
                run=run,
                captured_at=captured_at,
                status=CoverageStatus.FAILED if invalid else CoverageStatus.TRUNCATED,
                reason="; ".join(details),
            )

    @staticmethod
    def _persist_child_coverage(
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        captured_at: UtcDateTime,
        status: CoverageStatus,
        reason: str,
    ) -> None:
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        coverage = CoverageRecord(
            evidence_id=EvidenceId.new(),
            case_id=opened.case.case_id,
            category="events.child",
            status=status,
            captured_at=captured_at,
            reason=reason,
            execution_id=run.execution_id,
        )
        source_id = stable_source_id(
            "systemsense.probe.coverage",
            {
                "probe_id": run.probe_id,
                "execution_id": str(run.execution_id),
                "scope": "event_children",
            },
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(coverage.evidence_id),
            source_id=source_id,
            record_json=coverage.model_dump_json(),
            observed_at=captured_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(run.execution_id),
            dedupe_key=f"execution:{run.execution_id}:events-child-coverage",
            time_basis="probe_attempt_finish",
            time_quality="exact",
        )

    def _persist_coverage(
        self,
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        category: str,
        probe_version: int,
        captured_at: UtcDateTime,
    ) -> None:
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        coverage = CoverageRecord(
            evidence_id=EvidenceId.new(),
            case_id=opened.case.case_id,
            category=category,
            status=_coverage_status(run.status),
            captured_at=captured_at,
            reason=(None if run.error is None else self._redactor.redact_text(run.error).text)
            or f"probe ended with {run.status.value}",
            execution_id=run.execution_id,
        )
        source_id = stable_source_id(
            "systemsense.probe.coverage",
            {
                "probe_id": run.probe_id,
                "probe_version": probe_version,
            },
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(coverage.evidence_id),
            source_id=source_id,
            record_json=coverage.model_dump_json(),
            observed_at=captured_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(run.execution_id),
            dedupe_key=f"execution:{run.execution_id}",
            time_basis="probe_attempt_finish",
            time_quality="exact",
        )

    def _redact_observation(self, observation: ProbeObservation) -> ProbeObservation:
        return ProbeObservation(
            summary=self._redactor.redact_text(observation.summary).text,
            facts={
                name: self._redact_json(name, value) for name, value in observation.facts.items()
            },
            limitations=tuple(
                self._redactor.redact_text(item).text for item in observation.limitations
            ),
            observed_at=observation.observed_at,
            captured_at=observation.captured_at,
            time_quality=observation.time_quality,
        )

    def _redact_json(self, field_name: str, value: JsonValue) -> JsonValue:
        if isinstance(value, str):
            return self._redactor.redact_field(field_name, value)
        if isinstance(value, list):
            return [self._redact_json(field_name, item) for item in value]
        if isinstance(value, dict):
            return {name: self._redact_json(name, item) for name, item in value.items()}
        return cast("JsonValue", value)


def _audit_outcome(status: ProbeRunStatus) -> AuditOutcome:
    return {
        ProbeRunStatus.OK: AuditOutcome.ALLOWED,
        ProbeRunStatus.DENIED: AuditOutcome.DENIED,
        ProbeRunStatus.UNAVAILABLE: AuditOutcome.UNAVAILABLE,
        ProbeRunStatus.FAILED: AuditOutcome.FAILED,
        ProbeRunStatus.TIMED_OUT: AuditOutcome.TIMED_OUT,
        ProbeRunStatus.TRUNCATED: AuditOutcome.TRUNCATED,
        ProbeRunStatus.CANCELLED: AuditOutcome.CANCELLED,
    }[status]


def _coverage_status(status: ProbeRunStatus) -> CoverageStatus:
    return {
        ProbeRunStatus.OK: CoverageStatus.COVERED,
        ProbeRunStatus.DENIED: CoverageStatus.DENIED,
        ProbeRunStatus.UNAVAILABLE: CoverageStatus.UNAVAILABLE,
        ProbeRunStatus.FAILED: CoverageStatus.FAILED,
        ProbeRunStatus.TIMED_OUT: CoverageStatus.FAILED,
        ProbeRunStatus.TRUNCATED: CoverageStatus.TRUNCATED,
        ProbeRunStatus.CANCELLED: CoverageStatus.UNAVAILABLE,
    }[status]


def _freshness_ttl(category: str) -> int:
    return 300 if category in {"core", "application", "network", "performance"} else 3600


def _sensitivity(category: str) -> Sensitivity:
    if category in {"application", "storage", "network", "events", "performance"}:
        return Sensitivity.PERSONAL
    return Sensitivity.SYSTEM_METADATA


def _resource_class(category: str) -> ResourceClass:
    if category in {"network"}:
        return ResourceClass.NETWORK
    if category in {"servicing", "storage", "events"}:
        return ResourceClass.DISK
    if category in {"local_ai"}:
        return ResourceClass.GPU
    if category in {"application", "devices", "power", "security"}:
        return ResourceClass.PROCESS
    return ResourceClass.CPU


def _probe_run(result: TaskResult, *, probe_id: str) -> ProbeRun:
    if result.status in {TaskStatus.SUCCEEDED, TaskStatus.FAILED} and isinstance(
        result.value, ProbeRun
    ):
        return result.value
    now = datetime.now(UTC)
    status = {
        TaskStatus.TIMED_OUT: ProbeRunStatus.TIMED_OUT,
        TaskStatus.CANCELLED: ProbeRunStatus.CANCELLED,
        TaskStatus.BLOCKED: ProbeRunStatus.UNAVAILABLE,
        TaskStatus.STALE: ProbeRunStatus.UNAVAILABLE,
        TaskStatus.FAILED: ProbeRunStatus.FAILED,
        TaskStatus.SUCCEEDED: ProbeRunStatus.FAILED,
        TaskStatus.DEDUPLICATED: ProbeRunStatus.UNAVAILABLE,
    }[result.status]
    return ProbeRun(
        execution_id=ExecutionId.new(),
        probe_id=probe_id,
        status=status,
        started_at=result.started_at or now,
        finished_at=result.finished_at or now,
        elapsed_ms=result.duration_ms,
        error=result.error or f"scheduler ended with {result.status.value}",
    )
