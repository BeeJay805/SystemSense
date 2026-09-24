"""Append-only custody for the registered read-only WLAN diagnostic test.

Writes participate in the caller's transaction. An intent never grants probe
authority. The coordinator binds its plan to the actual audited execution;
evaluation only reads that execution's source-owned evidence.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from systemsense.audit import AuditEntry
from systemsense.domain.evidence import EvidenceRecord, FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue, stable_source_id
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evaluation.progress import (
    PredicateEvaluation,
    TestIntent,
    evaluate_wifi_association,
)
from systemsense.packs.runtime import default_probe_definitions
from systemsense.platform.windows.connectivity import ConnectivitySnapshot
from systemsense.platform.windows.deep_collectors import ComponentStatus
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DiagnosticEvidenceReferenceV1(FrozenModel):
    evidence_id: EvidenceId
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class DiagnosticIntentAdmissionV1(FrozenModel):
    schema_version: Literal[1] = 1
    admission_id: str = Field(pattern=r"^diagnostic_intent_[0-9a-f]{32}$")
    case_id: CaseId
    epoch_state_version: int = Field(ge=0)
    intent: TestIntent
    plan_instance_id: str = Field(min_length=1, max_length=255)
    probe_id: Literal["network.connectivity"] = "network.connectivity"
    probe_version: Literal[3] = 3
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    parameters_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    invocation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    objective_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hypotheses_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_evidence_id: EvidenceId
    source_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    admitted_at: UtcDateTime


class DiagnosticIntentExecutionLinkV1(FrozenModel):
    schema_version: Literal[1] = 1
    admission_id: str
    case_id: CaseId
    execution_id: str
    audit_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    linked_at: UtcDateTime


class DiagnosticIntentDispatchClaimV1(FrozenModel):
    schema_version: Literal[1] = 1
    claim_id: str = Field(pattern=r"^diagnostic_claim_[0-9a-f]{32}$")
    admission_id: str
    case_id: CaseId
    epoch_state_version: int = Field(ge=0)
    plan_instance_id: str = Field(min_length=1, max_length=255)
    claimed_at: UtcDateTime


class DiagnosticIntentTerminalV1(FrozenModel):
    schema_version: Literal[1] = 1
    admission_id: str
    case_id: CaseId
    execution_id: str | None
    status: Literal["evaluated", "unknown", "failed", "interrupted"]
    evaluation: PredicateEvaluation | None = None
    sources: tuple[DiagnosticEvidenceReferenceV1, ...] = Field(default=(), max_length=64)
    rejected_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    reason: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=100)
    evaluated_at: UtcDateTime


class DiagnosticIntentRepository:
    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    def _require_transaction(self) -> None:
        if not self._store.connection.in_transaction:
            raise ValueError("diagnostic write requires caller-owned transaction")

    def admit(
        self,
        intent: TestIntent,
        *,
        expected_state_version: int,
        source_evidence_id: EvidenceId,
        plan_instance_id: str,
        parameters: dict[str, JsonValue],
        probe_version: int = 3,
    ) -> DiagnosticIntentAdmissionV1:
        self._require_transaction()
        scope = intent.scope
        if (
            scope is None
            or intent.probe_id != "network.connectivity"
            or intent.predictions[0].predicate_id != "network.wifi_associated"
            or probe_version != 3
            or parameters
        ):
            raise ValueError("diagnostic intent is not the registered scoped WLAN test")
        if str(UUID(scope.target_handle)) != scope.target_handle:
            raise ValueError("diagnostic target must be a canonical interface GUID")
        state = InvestigationRepository(self._store).load(str(scope.case_id))
        case = self._store.case(str(scope.case_id))
        if (
            case is None
            or case.state_version != expected_state_version
            or state.state_version != expected_state_version
            or case.status != "collecting"
            or state.status.value != "running"
            or state.deadline_at <= utc_now()
        ):
            raise ValueError("diagnostic admission has stale or inactive case state")
        record, source_digest = self._source(scope.case_id, source_evidence_id)
        snapshot = self._snapshot(record)
        targets = [
            row
            for row in snapshot.wifi_interfaces
            if str(UUID(row.interface_guid)) == scope.target_handle
        ]
        if (
            snapshot.wifi_status is not ComponentStatus.AVAILABLE
            or snapshot.omitted_wifi_count != 0
            or len(targets) != 1
            or targets[0].details_status is not ComponentStatus.AVAILABLE
        ):
            raise ValueError("diagnostic target is not uniquely present in trusted source")
        manifest = next(
            item.manifest
            for item in default_probe_definitions()
            if item.manifest.probe_id == intent.probe_id
        )
        if manifest.version != probe_version:
            raise ValueError("diagnostic registered manifest changed")
        admission = DiagnosticIntentAdmissionV1(
            admission_id=f"diagnostic_intent_{uuid4().hex}",
            case_id=scope.case_id,
            epoch_state_version=expected_state_version,
            intent=intent,
            plan_instance_id=plan_instance_id,
            manifest_sha256=_digest(_canonical(manifest.model_dump(mode="json"))),
            parameters_sha256=_digest(_canonical(parameters)),
            invocation_sha256=_digest(
                _canonical(
                    {
                        "probe_id": intent.probe_id,
                        "probe_version": probe_version,
                        "parameters": parameters,
                    }
                )
            ),
            objective_sha256=_digest(
                _canonical(
                    {
                        "objective": state.objective,
                        "incident_start": state.incident_start.isoformat(),
                        "incident_end": state.incident_end.isoformat(),
                    }
                )
            ),
            hypotheses_sha256=_digest(
                _canonical([h.model_dump(mode="json") for h in state.hypotheses])
            ),
            source_evidence_id=source_evidence_id,
            source_evidence_sha256=source_digest,
            admitted_at=utc_now(),
        )
        raw = _canonical(admission.model_dump(mode="json"))
        self._store.connection.execute(
            "INSERT INTO diagnostic_intent_admissions "
            "(admission_id,case_id,intent_id,epoch_state_version,plan_instance_id,"
            "record_json,record_sha256,admitted_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                admission.admission_id,
                str(admission.case_id),
                intent.intent_id,
                expected_state_version,
                plan_instance_id,
                raw,
                _digest(raw),
                admission.admitted_at.isoformat(),
            ),
        )
        return admission

    def readback(self, admission_id: str) -> DiagnosticIntentAdmissionV1:
        result = self._admission_record(admission_id)
        _, digest = self._source(result.case_id, result.source_evidence_id)
        if digest != result.source_evidence_sha256:
            raise ValueError("diagnostic admission source changed")
        return result

    def _admission_record(self, admission_id: str) -> DiagnosticIntentAdmissionV1:
        """Validate frozen custody bytes without granting missing source trust."""
        row = self._store.connection.execute(
            "SELECT record_json,record_sha256,case_id,intent_id,epoch_state_version,"
            "plan_instance_id,admitted_at FROM diagnostic_intent_admissions WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None or _digest(str(row[0])) != row[1]:
            raise ValueError("diagnostic admission is unavailable or corrupt")
        result = DiagnosticIntentAdmissionV1.model_validate_json(str(row[0]))
        if (
            result.admission_id != admission_id
            or str(result.case_id) != row[2]
            or result.intent.intent_id != row[3]
            or result.epoch_state_version != row[4]
            or result.plan_instance_id != row[5]
            or result.admitted_at.isoformat() != row[6]
            or result.intent.scope is None
            or result.intent.scope.case_id != result.case_id
            or result.intent.probe_id != result.probe_id
            or _canonical(result.model_dump(mode="json")) != row[0]
        ):
            raise ValueError("diagnostic admission binding is invalid")
        return result

    def link_execution(
        self, admission_id: str, execution_id: str
    ) -> DiagnosticIntentExecutionLinkV1:
        self._require_transaction()
        admission = self.readback(admission_id)
        if self.terminal(admission_id) is not None:
            raise ValueError("diagnostic intent is already terminal")
        _, audit_digest = self._execution(admission, execution_id)
        link = DiagnosticIntentExecutionLinkV1(
            admission_id=admission_id,
            case_id=admission.case_id,
            execution_id=execution_id,
            audit_event_sha256=audit_digest,
            linked_at=utc_now(),
        )
        raw = _canonical(link.model_dump(mode="json"))
        self._store.connection.execute(
            "INSERT INTO diagnostic_intent_execution_links "
            "(admission_id,execution_id,record_json,record_sha256) VALUES (?,?,?,?)",
            (admission_id, execution_id, raw, _digest(raw)),
        )
        return link

    def claim_dispatch(self, admission_id: str) -> DiagnosticIntentDispatchClaimV1:
        """Consume dispatch once before scheduling; uncertain claims are never replayed."""
        self._require_transaction()
        admission = self.readback(admission_id)
        if self.dispatch_claim(admission_id) is not None:
            raise ValueError("diagnostic dispatch was already claimed")
        if self.terminal(admission_id) is not None or self.execution_link(admission_id) is not None:
            raise ValueError("diagnostic dispatch is already terminal or linked")
        state = InvestigationRepository(self._store).load(str(admission.case_id))
        case = self._store.case(str(admission.case_id))
        now = utc_now()
        objective_digest = _digest(
            _canonical(
                {
                    "objective": state.objective,
                    "incident_start": state.incident_start.isoformat(),
                    "incident_end": state.incident_end.isoformat(),
                }
            )
        )
        hypotheses_digest = _digest(
            _canonical([h.model_dump(mode="json") for h in state.hypotheses])
        )
        if (
            case is None
            or case.state_version != admission.epoch_state_version
            or state.state_version != admission.epoch_state_version
            or case.status != "collecting"
            or state.status.value != "running"
            or state.deadline_at <= now
            or admission.admitted_at > now
            or objective_digest != admission.objective_sha256
            or hypotheses_digest != admission.hypotheses_sha256
        ):
            raise ValueError("diagnostic dispatch has stale or inactive case state")
        claim = DiagnosticIntentDispatchClaimV1(
            claim_id=f"diagnostic_claim_{uuid4().hex}",
            admission_id=admission_id,
            case_id=admission.case_id,
            epoch_state_version=admission.epoch_state_version,
            plan_instance_id=admission.plan_instance_id,
            claimed_at=now,
        )
        raw = _canonical(claim.model_dump(mode="json"))
        self._store.connection.execute(
            "INSERT INTO diagnostic_intent_dispatch_claims "
            "(admission_id,claim_id,record_json,record_sha256,claimed_at) VALUES (?,?,?,?,?)",
            (admission_id, claim.claim_id, raw, _digest(raw), claim.claimed_at.isoformat()),
        )
        return claim

    def dispatch_claim(self, admission_id: str) -> DiagnosticIntentDispatchClaimV1 | None:
        """Read a consumed claim without treating it as permission to dispatch again."""
        admission = self.readback(admission_id)
        return self._dispatch_claim_record(admission)

    def _dispatch_claim_record(
        self,
        admission: DiagnosticIntentAdmissionV1,
    ) -> DiagnosticIntentDispatchClaimV1 | None:
        """Validate historical dispatch bytes; this does not restore source trust."""
        admission_id = admission.admission_id
        row = self._store.connection.execute(
            "SELECT claim_id,record_json,record_sha256,claimed_at "
            "FROM diagnostic_intent_dispatch_claims WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None:
            return None
        if _digest(str(row[1])) != row[2]:
            raise ValueError("diagnostic dispatch claim is corrupt")
        claim = DiagnosticIntentDispatchClaimV1.model_validate_json(str(row[1]))
        if (
            claim.claim_id != row[0]
            or claim.admission_id != admission_id
            or claim.case_id != admission.case_id
            or claim.epoch_state_version != admission.epoch_state_version
            or claim.plan_instance_id != admission.plan_instance_id
            or claim.claimed_at.isoformat() != row[3]
            or not admission.admitted_at <= claim.claimed_at <= utc_now()
            or _canonical(claim.model_dump(mode="json")) != row[1]
        ):
            raise ValueError("diagnostic dispatch claim binding is invalid")
        return claim

    def execution_link(self, admission_id: str) -> DiagnosticIntentExecutionLinkV1 | None:
        admission = self.readback(admission_id)
        return self._execution_link_record(admission)

    def _execution_link_record(
        self,
        admission: DiagnosticIntentAdmissionV1,
    ) -> DiagnosticIntentExecutionLinkV1 | None:
        """Validate an actual execution independently of retained baseline evidence."""
        admission_id = admission.admission_id
        row = self._store.connection.execute(
            "SELECT record_json,record_sha256,execution_id FROM diagnostic_intent_execution_links "
            "WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None:
            return None
        if _digest(str(row[0])) != row[1]:
            raise ValueError("diagnostic execution link is corrupt")
        link = DiagnosticIntentExecutionLinkV1.model_validate_json(str(row[0]))
        if (
            link.admission_id != admission_id
            or link.case_id != admission.case_id
            or link.execution_id != row[2]
            or link.linked_at < admission.admitted_at
            or _canonical(link.model_dump(mode="json")) != row[0]
        ):
            raise ValueError("diagnostic execution link binding is invalid")
        _, audit_digest = self._execution(admission, link.execution_id)
        if audit_digest != link.audit_event_sha256:
            raise ValueError("diagnostic execution audit changed")
        return link

    def evaluate(self, admission_id: str) -> DiagnosticIntentTerminalV1:
        self._require_transaction()
        previous = self.terminal(admission_id)
        if previous is not None:
            return previous
        admission = self.readback(admission_id)
        link = self.execution_link(admission_id)
        if link is None:
            raise ValueError("diagnostic test has no bound execution")
        status, _ = self._execution(admission, link.execution_id)
        records: list[EvidenceRecord] = []
        sources: list[DiagnosticEvidenceReferenceV1] = []
        rows = self._store.connection.execute(
            "SELECT evidence_id FROM evidence WHERE case_id=? AND execution_id=? AND dedupe_key=?",
            (str(admission.case_id), link.execution_id, f"execution:{link.execution_id}"),
        ).fetchall()
        if status == "ok":
            for row in rows:
                try:
                    record, digest = self._source(admission.case_id, EvidenceId(str(row[0])))
                    snapshot = self._snapshot(record)
                except ValueError:
                    return self._insert_terminal(
                        DiagnosticIntentTerminalV1(
                            admission_id=admission_id,
                            case_id=admission.case_id,
                            execution_id=link.execution_id,
                            status="unknown",
                            reason="source_unverifiable",
                            evaluated_at=utc_now(),
                            rejected_evidence_ids=(EvidenceId(str(row[0])),),
                        )
                    )
                if snapshot.wifi_observed_at < admission.admitted_at:
                    return self._insert_terminal(
                        DiagnosticIntentTerminalV1(
                            admission_id=admission_id,
                            case_id=admission.case_id,
                            execution_id=link.execution_id,
                            status="unknown",
                            reason="source_precedes_admission",
                            evaluated_at=utc_now(),
                            rejected_evidence_ids=(record.evidence_id,),
                        )
                    )
                records.append(record)
                sources.append(
                    DiagnosticEvidenceReferenceV1(
                        evidence_id=record.evidence_id, evidence_sha256=digest
                    )
                )
        assert admission.intent.scope is not None
        evaluation = (
            evaluate_wifi_association(scope=admission.intent.scope, evidence=tuple(records))
            if status == "ok"
            else None
        )
        terminal = DiagnosticIntentTerminalV1(
            admission_id=admission_id,
            case_id=admission.case_id,
            execution_id=link.execution_id,
            status="failed"
            if status != "ok"
            else (
                "evaluated"
                if evaluation is not None and evaluation.observed is not None
                else "unknown"
            ),
            evaluation=evaluation,
            sources=tuple(sources),
            reason="execution_failed"
            if status != "ok"
            else (
                "predicate_evaluated"
                if evaluation is not None and evaluation.observed is not None
                else "predicate_unknown"
            ),
            evaluated_at=utc_now(),
        )
        return self._insert_terminal(terminal)

    def interrupt(self, admission_id: str, *, reason: str) -> DiagnosticIntentTerminalV1:
        self._require_transaction()
        previous = self.terminal(admission_id)
        if previous is not None:
            return previous
        admission = self.readback(admission_id)
        if self.execution_link(admission_id) is not None:
            raise ValueError("linked diagnostic execution must be evaluated")
        return self._insert_terminal(
            DiagnosticIntentTerminalV1(
                admission_id=admission_id,
                case_id=admission.case_id,
                execution_id=None,
                status="interrupted",
                reason=reason,
                evaluated_at=utc_now(),
            )
        )

    def _insert_terminal(self, terminal: DiagnosticIntentTerminalV1) -> DiagnosticIntentTerminalV1:
        raw = _canonical(terminal.model_dump(mode="json"))
        self._store.connection.execute(
            "INSERT INTO diagnostic_intent_terminals (admission_id,record_json,record_sha256) "
            "VALUES (?,?,?)",
            (terminal.admission_id, raw, _digest(raw)),
        )
        return terminal

    def record_custody_gap(self, admission_id: str) -> DiagnosticIntentTerminalV1:
        """Close lost baseline custody without asserting a predicate or inventing execution.

        A linked attempt preserves its independently validated execution ID.
        Already evaluated terminals remain immutable and fail ordinary trusted
        readback if their evidence is subsequently unavailable.
        """
        self._require_transaction()
        admission = self._admission_record(admission_id)
        previous = self.terminal(admission_id)
        if previous is not None:
            if previous.reason != "admission_source_unverifiable":
                raise ValueError("diagnostic intent already has another terminal")
            return previous
        try:
            self.readback(admission_id)
        except ValueError:
            pass
        else:
            raise ValueError("diagnostic admission source custody is intact")
        self._dispatch_claim_record(admission)
        link = self._execution_link_record(admission)
        return self._insert_terminal(
            DiagnosticIntentTerminalV1(
                admission_id=admission_id,
                case_id=admission.case_id,
                execution_id=None if link is None else link.execution_id,
                status="unknown",
                reason="admission_source_unverifiable",
                evaluated_at=utc_now(),
                rejected_evidence_ids=(admission.source_evidence_id,),
            )
        )

    def terminal(self, admission_id: str) -> DiagnosticIntentTerminalV1 | None:
        admission = self._admission_record(admission_id)
        row = self._store.connection.execute(
            "SELECT record_json,record_sha256 FROM diagnostic_intent_terminals "
            "WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None:
            return None
        if _digest(str(row[0])) != row[1]:
            raise ValueError("diagnostic terminal is corrupt")
        result = DiagnosticIntentTerminalV1.model_validate_json(str(row[0]))
        if result.reason == "admission_source_unverifiable":
            self._dispatch_claim_record(admission)
            link = self._execution_link_record(admission)
            if (
                result.admission_id != admission_id
                or result.case_id != admission.case_id
                or result.evaluated_at < admission.admitted_at
                or result.status != "unknown"
                or result.execution_id != (None if link is None else link.execution_id)
                or (link is not None and result.evaluated_at < link.linked_at)
                or result.evaluation is not None
                or result.sources
                or result.rejected_evidence_ids != (admission.source_evidence_id,)
                or _canonical(result.model_dump(mode="json")) != row[0]
            ):
                raise ValueError("diagnostic custody gap binding is invalid")
            return result
        admission = self.readback(admission_id)
        link = self.execution_link(admission_id)
        if (
            result.admission_id != admission_id
            or result.case_id != admission.case_id
            or result.evaluated_at < admission.admitted_at
            or result.execution_id != (None if link is None else link.execution_id)
            or _canonical(result.model_dump(mode="json")) != row[0]
            or (result.status == "interrupted") != (link is None)
        ):
            raise ValueError("diagnostic terminal binding is invalid")
        for source in result.sources:
            record, digest = self._source(result.case_id, source.evidence_id)
            if (
                digest != source.evidence_sha256
                or str(record.collector.execution_id) != result.execution_id
            ):
                raise ValueError("diagnostic terminal source changed")
        if result.evaluation is not None and result.evaluation.scope != admission.intent.scope:
            raise ValueError("diagnostic terminal scope changed")
        return result

    def pending(self, case_id: CaseId) -> tuple[DiagnosticIntentAdmissionV1, ...]:
        rows = self._store.connection.execute(
            "SELECT a.admission_id FROM diagnostic_intent_admissions a "
            "LEFT JOIN diagnostic_intent_terminals t ON t.admission_id=a.admission_id "
            "WHERE a.case_id=? AND t.admission_id IS NULL ORDER BY a.admitted_at,a.admission_id "
            "LIMIT 513",
            (str(case_id),),
        ).fetchall()
        if len(rows) > 512:
            raise ValueError("diagnostic pending intent bound exceeded")
        return tuple(self.readback(str(row[0])) for row in rows)

    def recover_consumed(self, case_id: CaseId) -> tuple[DiagnosticIntentTerminalV1, ...]:
        """Reconcile consumed claims under exclusive case ownership, never redispatch.

        The application must hold its recovered-case lease with no live workers.
        A SQLite transaction alone does not establish that ownership. Raw IDs
        permit recovery of vanished baseline sources without trusting them.
        Invalid claim/link custody raises and leaves the caller to roll back.
        """
        self._require_transaction()
        rows = self._store.connection.execute(
            "SELECT c.admission_id FROM diagnostic_intent_dispatch_claims c "
            "JOIN diagnostic_intent_admissions a ON a.admission_id=c.admission_id "
            "LEFT JOIN diagnostic_intent_terminals t ON t.admission_id=c.admission_id "
            "WHERE a.case_id=? AND t.admission_id IS NULL "
            "ORDER BY c.claimed_at,c.admission_id LIMIT 513",
            (str(case_id),),
        ).fetchall()
        if len(rows) > 512:
            raise ValueError("diagnostic consumed claim recovery bound exceeded")
        terminals: list[DiagnosticIntentTerminalV1] = []
        for row in rows:
            admission_id = str(row[0])
            admission = self._admission_record(admission_id)
            if admission.case_id != case_id or self._dispatch_claim_record(admission) is None:
                raise ValueError("diagnostic recovery claim binding is invalid")
            try:
                link = self.execution_link(admission_id)
                terminal = (
                    self.interrupt(admission_id, reason="dispatch_outcome_unknown")
                    if link is None
                    else self.evaluate(admission_id)
                )
            except ValueError:
                # Only demonstrable baseline source loss can create this gap;
                # corrupted claims, executions or links still fail closed.
                terminal = self.record_custody_gap(admission_id)
            terminals.append(terminal)
        return tuple(terminals)

    def _source(self, case_id: CaseId, evidence_id: EvidenceId) -> tuple[EvidenceRecord, str]:
        row = self._store.connection.execute(
            "SELECT case_id,source_id,record_json,observed_at,captured_at,execution_id,dedupe_key "
            "FROM evidence WHERE evidence_id=?",
            (str(evidence_id),),
        ).fetchone()
        if row is None or row[0] != str(case_id):
            raise ValueError("diagnostic source is unavailable or belongs to another case")
        record = EvidenceRecord.model_validate_json(str(row[2]))
        if (
            record.evidence_id != evidence_id
            or record.case_id != case_id
            or record.source.source_id != row[1]
            or record.observed_at != datetime.fromisoformat(str(row[3]))
            or record.captured_at != datetime.fromisoformat(str(row[4]))
            or str(record.collector.execution_id) != row[5]
            or row[6] != f"execution:{record.collector.execution_id}"
            or record.collector.id != "network.connectivity"
            or record.collector.version != 3
            or record.statement_kind is not StatementKind.OBSERVED_FACT
            or record.source.type != "systemsense.probe"
            or record.source.locator != {"probe_id": "network.connectivity"}
            or record.source.source_id
            != stable_source_id(
                "systemsense.probe", {"probe_id": "network.connectivity", "probe_version": 3}
            )
            or record.extraction.parser != "builtin.probe"
            or record.extraction.parser_version != 1
            or record.observed_at > record.captured_at
            or record.captured_at > utc_now()
        ):
            raise ValueError("diagnostic source provenance binding is invalid")
        execution = self._store.connection.execute(
            "SELECT status,probe_id,probe_version,started_at,finished_at FROM probe_executions "
            "WHERE execution_id=? AND case_id=?",
            (row[5], str(case_id)),
        ).fetchone()
        if (
            execution is None
            or execution[0] != "ok"
            or execution[1] != record.collector.id
            or execution[2] != record.collector.version
            or execution[4] is None
            or not datetime.fromisoformat(str(execution[3]))
            <= record.observed_at
            <= record.captured_at
            <= datetime.fromisoformat(str(execution[4]))
        ):
            raise ValueError("diagnostic source execution is invalid")
        return record, _digest(_canonical(list(row)))

    @staticmethod
    def _snapshot(record: EvidenceRecord) -> ConnectivitySnapshot:
        facts = [fact.value for fact in record.facts if fact.name == "connectivity_detail"]
        if len(facts) != 1:
            raise ValueError("diagnostic source lacks one connectivity snapshot")
        snapshot = ConnectivitySnapshot.model_validate(facts[0])
        if not snapshot.wifi_observed_at <= snapshot.captured_at <= record.observed_at:
            raise ValueError("diagnostic snapshot chronology is invalid")
        return snapshot

    def _execution(
        self, admission: DiagnosticIntentAdmissionV1, execution_id: str
    ) -> tuple[str, str]:
        claim = self._dispatch_claim_record(admission)
        if claim is None:
            raise ValueError("diagnostic execution has no one-shot dispatch claim")
        row = self._store.connection.execute(
            "SELECT case_id,probe_id,probe_version,state_version,parameters_json,started_at,"
            "finished_at,status FROM probe_executions WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
        if (
            row is None
            or row[0] != str(admission.case_id)
            or row[1] != admission.probe_id
            or row[2] != admission.probe_version
            or row[3] != admission.epoch_state_version
            or _digest(_canonical(json.loads(str(row[4])))) != admission.parameters_sha256
            or row[6] is None
            or not claim.claimed_at
            <= datetime.fromisoformat(str(row[5]))
            <= datetime.fromisoformat(str(row[6]))
            <= utc_now()
        ):
            raise ValueError("diagnostic execution does not match admitted scope and chronology")
        audit_row = self._store.connection.execute(
            "SELECT event_json FROM audit_events WHERE event_id=? AND case_id=?",
            (f"probe_{execution_id}", str(admission.case_id)),
        ).fetchone()
        if audit_row is None:
            raise ValueError("diagnostic execution audit is unavailable")
        audit = AuditEntry.model_validate_json(str(audit_row[0]))
        if (
            audit.case_id != admission.case_id
            or audit.probe_id != admission.probe_id
            or audit.event_id != f"probe_{execution_id}"
            or audit.parameters.get("plan_instance_id") != admission.plan_instance_id
            or audit.parameters.get("parameters_sha256") != admission.parameters_sha256
            or audit.parameters.get("diagnostic_claim_id") != claim.claim_id
            or audit.occurred_at != datetime.fromisoformat(str(row[6]))
        ):
            raise ValueError("diagnostic execution audit does not bind admitted plan instance")
        return str(row[7]), _digest(str(audit_row[0]))
