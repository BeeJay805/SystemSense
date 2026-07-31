"""Execute a case plan and atomically persist normalized evidence and audit data."""

from __future__ import annotations

import hashlib
from typing import cast

from systemsense.application.case_service import CaseService, OpenedCase
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
from systemsense.domain.ids import EntityId, EvidenceId, JsonValue, stable_source_id
from systemsense.domain.inventory import InventoryFact
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.redaction import Redactor
from systemsense.orchestration.probes import (
    ProbeObservation,
    ProbeRun,
    ProbeRunner,
    ProbeRunStatus,
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
    ) -> None:
        self._store = store
        self._case_service = case_service
        self._probe_runner = probe_runner
        self._redactor = redactor or Redactor()

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
        audit = AuditChain(redactor=self._redactor)
        for planned in opened.plan.probes:
            run = self._probe_runner.run(planned.probe_id, {})
            manifest = self._probe_runner.manifest(planned.probe_id)
            category = "orchestration" if manifest is None else manifest.category
            audit_entry = audit.append(
                event_id=f"probe_{run.execution_id}",
                case_id=opened.case.case_id,
                probe_id=planned.probe_id,
                outcome=_audit_outcome(run.status),
                occurred_at=created_at,
                parameters={"elapsed_ms": run.elapsed_ms},
                error=run.error,
            )
            with self._store.transaction() as transaction:
                if run.status is ProbeRunStatus.OK and run.observation is not None:
                    self._persist_observation(
                        transaction=transaction,
                        opened=opened,
                        run=run,
                        category=category,
                        captured_at=created_at,
                    )
                else:
                    self._persist_coverage(
                        transaction=transaction,
                        opened=opened,
                        run=run,
                        category=category,
                        captured_at=created_at,
                    )
                transaction.append_audit(
                    event_id=audit_entry.event_id,
                    case_id=str(opened.case.case_id),
                    event_json=audit_entry.model_dump_json(),
                    created_at=created_at.isoformat(),
                )
        return OpenedCase(
            case=opened.case.model_copy(update={"status": CaseStatus.READY}),
            plan=opened.plan,
        )

    def _persist_observation(
        self,
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        category: str,
        captured_at: UtcDateTime,
    ) -> None:
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        assert run.observation is not None
        observation = self._redact_observation(run.observation)
        source_id = stable_source_id(
            "systemsense.probe",
            {
                "case_id": str(opened.case.case_id),
                "probe_id": run.probe_id,
            },
        )
        source = EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": run.probe_id},
        )
        collector = CollectorReference(
            id=run.probe_id,
            version=1,
            execution_id=run.execution_id,
        )
        record = EvidenceRecord(
            evidence_id=EvidenceId.new(),
            case_id=opened.case.case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=captured_at,
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
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        inventory = InventoryFact(
            entity_id=_HOST_ENTITY_ID,
            category=category,
            name=run.probe_id,
            value=observation.facts,
            source=source,
            collector=collector,
            observed_at=captured_at,
            captured_at=captured_at,
            extraction=record.extraction,
            freshness_ttl_seconds=_freshness_ttl(category),
            sensitivity=Sensitivity.SYSTEM_METADATA,
            limitations=observation.limitations,
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(record.evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            captured_at=captured_at.isoformat(),
        )
        transaction.upsert_inventory(
            category=inventory.category,
            fact_key=f"{inventory.entity_id}:{inventory.name}",
            record_json=inventory.model_dump_json(),
            observed_at=captured_at.isoformat(),
        )

    @staticmethod
    def _persist_coverage(
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        category: str,
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
            reason=run.error or f"probe ended with {run.status.value}",
            execution_id=run.execution_id,
        )
        source_id = stable_source_id(
            "systemsense.probe.coverage",
            {
                "case_id": str(opened.case.case_id),
                "probe_id": run.probe_id,
            },
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(coverage.evidence_id),
            source_id=source_id,
            record_json=coverage.model_dump_json(),
            captured_at=captured_at.isoformat(),
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
        ProbeRunStatus.FAILED: AuditOutcome.FAILED,
        ProbeRunStatus.TIMED_OUT: AuditOutcome.TIMED_OUT,
        ProbeRunStatus.TRUNCATED: AuditOutcome.TRUNCATED,
    }[status]


def _coverage_status(status: ProbeRunStatus) -> CoverageStatus:
    return {
        ProbeRunStatus.OK: CoverageStatus.COVERED,
        ProbeRunStatus.DENIED: CoverageStatus.DENIED,
        ProbeRunStatus.FAILED: CoverageStatus.FAILED,
        ProbeRunStatus.TIMED_OUT: CoverageStatus.FAILED,
        ProbeRunStatus.TRUNCATED: CoverageStatus.TRUNCATED,
    }[status]


def _freshness_ttl(category: str) -> int:
    return 300 if category in {"core", "application", "network"} else 3600
