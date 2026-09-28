"""Read-back-verifiable links from accepted async deep advice to observed runs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from systemsense.application.deep_proposal_origin import (
    DeepProposalOriginV1,
    canonical_model_sha256,
)
from systemsense.application.deep_worker import DeepWorkerResultV1, FrozenDeepTaskV1
from systemsense.audit import AuditChain, AuditEntry, AuditOutcome
from systemsense.domain.probes import ProbeInvocation, ProbeManifest
from systemsense.storage.decision_snapshots import ProbeManifestRef
from systemsense.storage.sqlite_store import SQLiteStore


class DeepProposalExecutionRepository:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def link_observed_execution_in_transaction(
        self,
        *,
        origin: DeepProposalOriginV1,
        selected_state_version: int,
        plan_instance_id: str,
        execution_id: str,
        invocation: ProbeInvocation,
        manifest: ProbeManifest,
    ) -> None:
        """Validate the immutable source and run before inserting one causal link.

        The caller owns the same transaction that persists the probe execution
        and its observed evidence. A failed provenance check cannot authorize a
        probe; the runtime treats it as an unattributed execution.
        """
        if not self.store.connection.in_transaction:
            raise RuntimeError("deep execution link requires an owned transaction")
        if not plan_instance_id:
            raise ValueError("deep origin plan instance is empty")
        if selected_state_version < origin.accepted_state_version:
            raise ValueError("deep proposal was accepted after selection")
        reference = ProbeManifestRef.from_manifest(origin.probe_id, manifest)
        if (
            reference.manifest_version != origin.probe_version
            or reference.catalog_sha256 != origin.manifest_sha256
            or invocation.probe_id != origin.probe_id
            or invocation.probe_version != origin.probe_version
        ):
            raise ValueError("deep proposal manifest or invocation changed")
        source = self.store.connection.execute(
            "SELECT status,task_json,result_json,updated_at FROM deep_mailbox "
            "WHERE case_id=? AND request_sha256=?",
            (str(origin.case_id), origin.request_sha256),
        ).fetchone()
        if source is None or source[0] != "applied" or source[2] is None:
            raise ValueError("deep proposal has no applied mailbox source")
        task = FrozenDeepTaskV1.model_validate_json(str(source[1]))
        result = DeepWorkerResultV1.model_validate_json(str(source[2]))
        response = result.response
        if (
            task.request_sha256 != origin.request_sha256
            or task.request.case_id != origin.case_id
            or result.request_sha256 != origin.request_sha256
            or result.status != "completed"
            or response is None
            or response.degraded
        ):
            raise ValueError("deep proposal mailbox result is not attributable")
        response.validate_against(task.request)
        matching = tuple(
            proposal
            for proposal in response.distinguishing_probes
            if proposal.probe_id == origin.probe_id
            and canonical_model_sha256(proposal) == origin.proposal_sha256
        )
        if len(matching) != 1:
            raise ValueError("deep proposal differs from accepted advisory")
        need = matching[0].measurement_need
        if need is None:
            if invocation.target_handle is not None or invocation.window is not None:
                raise ValueError("generic deep proposal gained a selector")
        elif (
            need.capability_id != invocation.probe_id
            or need.observable != invocation.observable
            or need.target_handle != invocation.target_handle
            or need.window != invocation.window
        ):
            raise ValueError("deep proposal target, observable, or window changed")
        accepted = self.store.connection.execute(
            "SELECT record_json FROM investigation_steps WHERE case_id=? AND state_version=?",
            (str(origin.case_id), origin.accepted_state_version),
        ).fetchone()
        if accepted is None:
            raise ValueError("deep acceptance checkpoint is unavailable")
        step = json.loads(str(accepted[0]))
        if step.get("event") != "deep_applied" or origin.request_sha256 not in str(
            step.get("detail", "")
        ):
            raise ValueError("deep origin is not bound to its acceptance checkpoint")
        execution = self.store.connection.execute(
            "SELECT case_id,probe_id,probe_version,status,parameters_json,state_version,"
            "started_at,finished_at FROM probe_executions WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
        if execution is None or (
            str(execution[0]) != str(origin.case_id)
            or str(execution[1]) != origin.probe_id
            or int(execution[2]) != origin.probe_version
            or str(execution[3]) != "ok"
            or json.loads(str(execution[4])) != invocation.parameters
            or int(execution[5]) != selected_state_version
        ):
            raise ValueError("deep origin does not match the persisted execution")
        evidence = self.store.connection.execute(
            "SELECT 1 FROM evidence WHERE case_id=? AND execution_id=? "
            "AND json_extract(record_json,'$.statement_kind')='observed_fact' LIMIT 1",
            (str(origin.case_id), execution_id),
        ).fetchone()
        if evidence is None:
            raise ValueError("deep origin execution has no observed evidence")
        accepted_at = datetime.fromisoformat(str(source[3]))
        started_at = datetime.fromisoformat(str(execution[6]))
        finished_at = datetime.fromisoformat(str(execution[7]))
        if not accepted_at <= started_at <= finished_at:
            raise ValueError("deep origin execution chronology is invalid")
        audit_entries = self.store.audit_entries(case_id=str(origin.case_id))
        if not AuditChain.verify(
            audit_entries, checkpoint=self.store.audit_checkpoint(case_id=str(origin.case_id))
        ).valid:
            raise ValueError("deep origin probe audit chain is invalid")
        audit = next(
            (item for item in audit_entries if item.event_id == f"probe_{execution_id}"), None
        )
        audit_row = self.store.connection.execute(
            "SELECT event_json FROM audit_events WHERE case_id=? AND event_id=?",
            (str(origin.case_id), f"probe_{execution_id}"),
        ).fetchone()
        parameters_sha256 = hashlib.sha256(
            json.dumps(invocation.parameters, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if (
            audit is None
            or audit_row is None
            or AuditEntry.model_validate_json(str(audit_row[0])) != audit
            or audit.case_id != origin.case_id
            or audit.probe_id != origin.probe_id
            or audit.outcome is not AuditOutcome.ALLOWED
            or audit.occurred_at != finished_at
            or audit.parameters.get("plan_instance_id") != plan_instance_id
            or audit.parameters.get("parameters_sha256") != parameters_sha256
        ):
            raise ValueError("deep origin plan does not match durable probe audit")
        invocation_json = json.dumps(
            invocation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        manifest_json = json.dumps(
            manifest.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        self.store.connection.execute(
            "INSERT INTO deep_proposal_execution_links "
            "(case_id,request_sha256,proposal_sha256,accepted_state_version,"
            "selected_state_version,plan_instance_id,execution_id,probe_id,probe_version,"
            "manifest_sha256,manifest_json,invocation_json,invocation_sha256,schema_version) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
            (
                str(origin.case_id),
                origin.request_sha256,
                origin.proposal_sha256,
                origin.accepted_state_version,
                selected_state_version,
                plan_instance_id,
                execution_id,
                origin.probe_id,
                origin.probe_version,
                origin.manifest_sha256,
                manifest_json,
                invocation_json,
                canonical_model_sha256(invocation),
            ),
        )
