"""A candidate decision needs a durable, one-shot dispatch intent."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict

import pytest

from systemsense.application.runtime import DiagnosticRuntime, PersistedProbeResult
from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
)
from systemsense.decision.contracts import DiagnosticPurpose, ProviderIdentity
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.probes import ProbeInvocation, SafetyClass
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import (
    CandidateDispatchAdmissionRepository,
)
from systemsense.storage.case_candidates import CandidateGap, CandidateRecord, CandidateResolution
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.sqlite_store import SQLiteStore

_now = datetime.now(UTC)
_EPOCH = 3


class _AdmissionArgs(TypedDict):
    snapshot_id: str
    candidate_id: str
    case_id: CaseId
    epoch_state_version: int
    task_id: str
    invocation_sha256: str
    cost_ms: int


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _BoundRegistry:
    """Only the local registry boundary is replaced; SQLite custody remains real."""

    def __init__(self, candidate: CandidateRecord, invocation: ProbeInvocation) -> None:
        self.candidate = candidate
        self.invocation = invocation
        self.available = True

    def resolve(
        self, case_id: CaseId, epoch_state_version: int, candidate_id: str
    ) -> CandidateResolution | CandidateGap:
        if not self.available or candidate_id != self.candidate.candidate_id:
            raise ValueError("candidate is no longer resolvable")
        return CandidateResolution(candidate=self.candidate, invocation=self.invocation)


def _setup(
    store: SQLiteStore,
    *,
    case_id: CaseId | None = None,
    suffix: str = "a",
    probe_id: str = "fixture.pressure",
) -> tuple[CaseId, str, CandidateRecord, ProbeInvocation, _BoundRegistry]:
    global _now
    _now = datetime.now(UTC)
    now = _now
    if case_id is None:
        case_id = CaseId.new()
        store.create_case(
            case_id=str(case_id),
            kind="general",
            symptom="Slow app",
            created_at=(now - timedelta(seconds=10)).isoformat(),
            status="collecting",
            state_version=_EPOCH,
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
            (
                str(case_id),
                _canonical(
                    {
                        "case_id": str(case_id),
                        "state_version": _EPOCH,
                        "status": "running",
                        "deadline_at": (now + timedelta(minutes=5)).isoformat(),
                        "budget_ms": 200,
                        "spent_cost_ms": 0,
                        "max_probes": 2,
                        "completed_probe_ids": [],
                        "pending_probe_ids": [],
                        "interrupted_probe_ids": [],
                        "unrecorded_attempt_count": 0,
                    }
                ),
            ),
        )
    candidate_id = "cand_v1_" + suffix * 32
    invocation = ProbeInvocation(
        probe_id=probe_id,
        probe_version=1,
        observable="fixture.pressure",
        target_handle="proc_" + suffix * 32,
        parameters={"pid": 101},
    )
    invocation_json = _canonical(invocation.model_dump(mode="json"))
    manifest_sha256 = _digest("fixture-manifest")
    record = CandidateRecord(
        candidate_id=candidate_id,
        probe_id=invocation.probe_id,
        description="Read bounded fixture process pressure",
        manifest_sha256=manifest_sha256,
        invocation_sha256=_digest(invocation_json),
        cost_ms=100,
        resource_class=ResourceClass.CPU,
        safety_class=SafetyClass.R1,
    )
    store.connection.execute(
        "INSERT INTO case_measurement_candidates ("
        "candidate_id,schema_version,case_id,epoch_state_version,probe_id,manifest_version,"
        "manifest_sha256,invocation_json,invocation_sha256,observable,target_handle,"
        "source_evidence_id,source_evidence_sha256,dependency_bindings_json,dependency_sha256,"
        "binding_sha256,cost_ms,resource_class,safety_class,description,issued_at,expires_at) "
        "VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            candidate_id,
            str(case_id),
            _EPOCH,
            invocation.probe_id,
            invocation.probe_version,
            manifest_sha256,
            invocation_json,
            record.invocation_sha256,
            invocation.observable,
            invocation.target_handle,
            "ev_" + "f" * 32,
            _digest("source"),
            "[]",
            _digest("[]"),
            _digest(candidate_id),
            record.cost_ms,
            record.resource_class.value,
            record.safety_class.value,
            record.description,
            (now - timedelta(seconds=5)).isoformat(),
            (now + timedelta(minutes=5)).isoformat(),
        ),
    )
    request = CandidateDecisionRequestV1(
        case_id=case_id,
        state_version=_EPOCH,
        correlation_id=f"fixture:dispatch:{suffix}",
        deadline_at=now + timedelta(minutes=5),
        symptom="Slow app",
        available_candidates=(
            AdmittedCandidateRefV1(**record.model_dump(exclude={"schema_version"})),
        ),
        budget_ms=200,
        max_candidates=1,
    )
    response = CandidateDecisionResponseV1(
        provider=ProviderIdentity(
            provider_id="fixture-fast", provider_version="1", role="fast_decision"
        ),
        case_id=case_id,
        state_version=_EPOCH,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        ranked_candidate_ids=(candidate_id,),
        considered_candidate_ids=(candidate_id,),
        proposals=(
            CandidateProposalV1(
                candidate_id=candidate_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
            ),
        ),
    )
    snapshot = CandidateDecisionSnapshotRepository(store, clock=lambda: now).capture(
        request, response, request_frozen_at=now
    )
    return case_id, snapshot.snapshot_id, record, invocation, _BoundRegistry(record, invocation)


def test_setup_refreshes_stale_module_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys.modules[__name__], "_now", datetime.now(UTC) - timedelta(minutes=10))
    with SQLiteStore(tmp_path / "fresh-setup.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        snapshot = CandidateDecisionSnapshotRepository(store).readback(snapshot_id)
        assert snapshot.request.deadline_at > datetime.now(UTC) + timedelta(minutes=4)
        admission = CandidateDispatchAdmissionRepository(store, registry=registry).admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="fixture-fresh-setup",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )
        assert admission.candidate_id == candidate.candidate_id


def _persist_parent(store: SQLiteStore, case_id: CaseId) -> tuple[str, str]:
    execution_id = "exec_" + "e" * 32
    evidence_id = "ev_" + "e" * 32
    finished = _now - timedelta(seconds=1)
    source_id = stable_source_id("fixture.parent", {"case_id": str(case_id)})
    record = EvidenceRecord(
        evidence_id=EvidenceId(root=evidence_id),
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=finished,
        captured_at=finished,
        source=EvidenceSource(type="fixture.parent", source_id=source_id, locator={}),
        collector=CollectorReference(
            id="fixture.parent", version=1, execution_id=ExecutionId(root=execution_id)
        ),
        summary="Parent observation",
        extraction=Extraction(confidence=1.0, parser="fixture.parent", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=execution_id,
            case_id=str(case_id),
            probe_id="fixture.parent",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(finished - timedelta(seconds=1)).isoformat(),
            finished_at=finished.isoformat(),
            state_version=_EPOCH,
        )
        store.connection.execute(
            "INSERT INTO evidence (evidence_id,case_id,source_id,record_json,observed_at,"
            "captured_at,execution_id,dedupe_key,time_basis,time_quality) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                evidence_id,
                str(case_id),
                source_id,
                record.model_dump_json(),
                finished.isoformat(),
                finished.isoformat(),
                execution_id,
                f"fixture.parent:{case_id}",
                "source_observed",
                "exact",
            ),
        )
    digest = FollowupAdmissionRepository(store).parent_evidence_digest(str(case_id), execution_id)
    return execution_id, digest


def test_async_candidate_admission_binds_exact_persisted_parent(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "parent-bound.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        parent_id, digest = _persist_parent(store, case_id)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry, clock=lambda: _now)
        with pytest.raises(ValueError, match="parent"):
            repo.admit_after_parent(
                snapshot_id=snapshot_id,
                candidate_id=candidate.candidate_id,
                case_id=case_id,
                epoch_state_version=_EPOCH,
                task_id="probe-followup-exact",
                invocation_sha256=candidate.invocation_sha256,
                cost_ms=candidate.cost_ms,
                trigger_execution_id=parent_id,
                trigger_evidence_sha256="0" * 64,
            )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM candidate_dispatch_admissions"
            ).fetchone()[0]
            == 0
        )
        admission = repo.admit_after_parent(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="probe-followup-exact",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
            trigger_execution_id=parent_id,
            trigger_evidence_sha256=digest,
        )
        assert repo.parent_binding(admission.admission_id) == (parent_id, digest)
        assert (
            repo.claim_for_worker(
                admission.admission_id,
                case_id=case_id,
                epoch_state_version=_EPOCH,
                task_id="probe-followup-exact",
                invocation_sha256=candidate.invocation_sha256,
            ).claimed_at
            is not None
        )


def test_runtime_reserves_parent_bound_target_candidate_without_host_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "runtime-parent-bound.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(
            store, probe_id="application.target_pressure"
        )
        parent_id, digest = _persist_parent(store, case_id)
        runtime = object.__new__(DiagnosticRuntime)
        runtime._store = store  # pyright: ignore[reportPrivateUsage]

        def catalog(_case_id: CaseId) -> tuple[_BoundRegistry, tuple[()]]:
            return registry, ()

        monkeypatch.setattr(runtime, "candidate_catalog", catalog)
        parent = PersistedProbeResult(
            task_id="probe-parent",
            case_id=str(case_id),
            epoch_state_version=_EPOCH,
            probe_id="fixture.parent",
            execution_id=ExecutionId(root=parent_id),
            evidence_generation=1,
            trigger_evidence_sha256=digest,
        )
        admission = runtime.admit_persisted_candidate_followup(
            parent,
            candidate_id=candidate.candidate_id,
            snapshot_id=snapshot_id,
            task_id="probe-followup-exact",
        )
        assert admission.candidate_id == candidate.candidate_id
        assert CandidateDispatchAdmissionRepository(store).parent_binding(
            admission.admission_id
        ) == (parent_id, digest)


def test_parent_bound_admission_rolls_back_with_outer_frontier_transaction(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "atomic-parent-bound.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        parent_id, digest = _persist_parent(store, case_id)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry, clock=lambda: _now)

        with pytest.raises(RuntimeError, match="frontier transition failed"):
            with store.transaction():
                repo.admit_after_parent(
                    snapshot_id=snapshot_id,
                    candidate_id=candidate.candidate_id,
                    case_id=case_id,
                    epoch_state_version=_EPOCH,
                    task_id="probe-followup-exact",
                    invocation_sha256=candidate.invocation_sha256,
                    cost_ms=candidate.cost_ms,
                    trigger_execution_id=parent_id,
                    trigger_evidence_sha256=digest,
                )
                raise RuntimeError("frontier transition failed")

        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_followup_parents WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)


def test_worker_claim_rolls_back_with_outer_frontier_transaction(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "atomic-worker-claim.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry, clock=lambda: _now)
        admission = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="probe-followup-exact",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )

        with pytest.raises(RuntimeError, match="frontier transition failed"):
            with store.transaction():
                repo.claim_for_worker_in_transaction(
                    admission.admission_id,
                    case_id=case_id,
                    epoch_state_version=_EPOCH,
                    task_id="probe-followup-exact",
                    invocation_sha256=candidate.invocation_sha256,
                )
                raise RuntimeError("frontier transition failed")

        assert repo.readback(admission.admission_id).claimed_at is None


def test_parent_evidence_change_prevents_async_candidate_worker_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "changed-parent.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        parent_id, digest = _persist_parent(store, case_id)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry, clock=lambda: _now)
        admission = repo.admit_after_parent(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="probe-followup-exact",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
            trigger_execution_id=parent_id,
            trigger_evidence_sha256=digest,
        )
        store.connection.execute(
            "INSERT INTO evidence (evidence_id,case_id,source_id,record_json,observed_at,"
            "captured_at,execution_id,dedupe_key,time_basis,time_quality) "
            "SELECT ?,case_id,source_id,record_json,observed_at,captured_at,execution_id,"
            "?,time_basis,time_quality FROM evidence WHERE execution_id=? LIMIT 1",
            ("ev_" + "d" * 32, "changed-parent", parent_id),
        )
        with pytest.raises(ValueError, match="parent evidence changed"):
            repo.claim_for_worker(
                admission.admission_id,
                case_id=case_id,
                epoch_state_version=_EPOCH,
                task_id="probe-followup-exact",
                invocation_sha256=candidate.invocation_sha256,
            )
        assert repo.readback(admission.admission_id).claimed_at is None


def test_admission_reserves_exact_candidate_once_and_claims_once(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "dispatch.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry)
        admission = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=100,
        )
        assert admission.candidate_id == candidate.candidate_id
        assert admission.cost_ms == 100
        assert admission.outcome_status == "unclaimed"
        assert admission.replay_allowed is False
        assert (
            repo.verify_admitted(
                admission.admission_id,
                case_id=case_id,
                epoch_state_version=_EPOCH,
                task_id="case:target-pressure:a",
                invocation_sha256=candidate.invocation_sha256,
            ).admission_id
            == admission.admission_id
        )
        claimed = repo.claim_for_worker(
            admission.admission_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
        )
        assert claimed.outcome_status == "claimed_unlinked"
        with pytest.raises(ValueError, match="already claimed"):
            repo.claim_for_worker(
                admission.admission_id,
                case_id=case_id,
                epoch_state_version=_EPOCH,
                task_id="case:target-pressure:a",
                invocation_sha256=candidate.invocation_sha256,
            )
        with pytest.raises(ValueError, match="already admitted"):
            repo.admit(
                snapshot_id=snapshot_id,
                candidate_id=candidate.candidate_id,
                case_id=case_id,
                epoch_state_version=_EPOCH,
                task_id="case:target-pressure:b",
                invocation_sha256=candidate.invocation_sha256,
                cost_ms=100,
            )


def test_admission_rejects_wrong_cost_task_epoch_and_stale_selection(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "reject.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(
            store, registry=registry, clock=lambda: _now + timedelta(seconds=1)
        )
        common: _AdmissionArgs = {
            "snapshot_id": snapshot_id,
            "candidate_id": candidate.candidate_id,
            "case_id": case_id,
            "epoch_state_version": _EPOCH,
            "task_id": "case:target-pressure:a",
            "invocation_sha256": candidate.invocation_sha256,
            "cost_ms": 100,
        }
        wrong_cost: _AdmissionArgs = {**common, "cost_ms": 1}
        wrong_epoch: _AdmissionArgs = {**common, "epoch_state_version": _EPOCH + 1}
        with pytest.raises(ValueError, match="cost"):
            repo.admit(**wrong_cost)
        with pytest.raises(ValueError):
            repo.admit(**wrong_epoch)
        registry.available = False
        with pytest.raises(ValueError):
            repo.admit(**common)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions"
        ).fetchone() == (0,)


def test_decision_deadline_and_case_budget_reject_without_intent(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "deadline.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        args: _AdmissionArgs = {
            "snapshot_id": snapshot_id,
            "candidate_id": candidate.candidate_id,
            "case_id": case_id,
            "epoch_state_version": _EPOCH,
            "task_id": "case:target-pressure:a",
            "invocation_sha256": candidate.invocation_sha256,
            "cost_ms": 100,
        }
        expired = CandidateDispatchAdmissionRepository(
            store, registry=registry, clock=lambda: _now + timedelta(minutes=5, seconds=1)
        )
        with pytest.raises(ValueError, match="current frozen proposal"):
            expired.admit(**args)
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json="
            "json_set(record_json, '$.spent_cost_ms', 101) WHERE case_id=?",
            (str(case_id),),
        )
        repo = CandidateDispatchAdmissionRepository(
            store, registry=registry, clock=lambda: _now + timedelta(seconds=1)
        )
        with pytest.raises(ValueError, match="budget"):
            repo.admit(**args)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions"
        ).fetchone() == (0,)


def test_unlinked_claim_is_uncertain_not_replayable_or_refunded(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "crash.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(
            store, registry=registry, clock=lambda: _now + timedelta(seconds=1)
        )
        admission = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=100,
        )
        repo.claim_for_worker(
            admission.admission_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
        )
        reopened = CandidateDispatchAdmissionRepository(
            store, clock=lambda: _now + timedelta(seconds=1)
        )
        record = reopened.readback(admission.admission_id)
        assert record.outcome_status == "claimed_unlinked"
        assert record.execution_id is None
        assert record.replay_allowed is False
        with pytest.raises(ValueError):
            reopened.claim_for_worker(
                admission.admission_id,
                case_id=case_id,
                epoch_state_version=_EPOCH,
                task_id="case:target-pressure:a",
                invocation_sha256=candidate.invocation_sha256,
            )


def test_unlinked_admission_consumes_one_probe_slot_not_two(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "unlinked-budget.db") as store:
        case_id, snapshot_id, candidate, _invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry)
        first = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=100,
        )
        repo.claim_for_worker(
            first.admission_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
        )
        assert repo.readback(first.admission_id).outcome_status == "claimed_unlinked"

        _, second_snapshot_id, second, _second_invocation, second_registry = _setup(
            store, case_id=case_id, suffix="b"
        )
        second_admission = CandidateDispatchAdmissionRepository(
            store, registry=second_registry
        ).admit(
            snapshot_id=second_snapshot_id,
            candidate_id=second.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:b",
            invocation_sha256=second.invocation_sha256,
            cost_ms=100,
        )
        assert second_admission.outcome_status == "unclaimed"
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (2,)


def test_linked_execution_counts_one_slot_and_one_cost(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "linked.db") as store:
        case_id, snapshot_id, candidate, invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry)
        admission = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=100,
        )
        claim = repo.claim_for_worker(
            admission.admission_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
        )
        execution_id = str(ExecutionId.new())
        assert claim.claimed_at is not None
        execution_started_at = claim.claimed_at
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(case_id),
                probe_id=invocation.probe_id,
                probe_version=invocation.probe_version,
                status="ok",
                parameters_json=_canonical(invocation.parameters),
                started_at=execution_started_at.isoformat(),
                finished_at=datetime.now(UTC).isoformat(),
                state_version=_EPOCH,
            )
            repo.link_execution(admission.admission_id, execution_id, invocation)
        assert repo.readback(admission.admission_id).execution_id == execution_id
        assert repo.readback(admission.admission_id).outcome_status == "linked"


def test_execution_that_predates_worker_claim_is_not_accepted_as_linked(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "premature.db") as store:
        case_id, snapshot_id, candidate, invocation, registry = _setup(store)
        clock = [_now + timedelta(seconds=1)]
        repo = CandidateDispatchAdmissionRepository(
            store, registry=registry, clock=lambda: clock[0]
        )
        admission = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=100,
        )
        claimed = repo.claim_for_worker(
            admission.admission_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
        )
        assert claimed.claimed_at is not None
        execution_id = str(ExecutionId.new())
        snapshot = CandidateDecisionSnapshotRepository(store).readback(snapshot_id)
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(case_id),
                probe_id=invocation.probe_id,
                probe_version=invocation.probe_version,
                status="ok",
                parameters_json=_canonical(invocation.parameters),
                started_at=snapshot.captured_at.isoformat(),
                finished_at=datetime.now(UTC).isoformat(),
                state_version=_EPOCH,
            )
            CandidateDecisionSnapshotRepository(store).link_execution(
                snapshot_id, candidate.candidate_id, execution_id, invocation
            )
        with pytest.raises(ValueError, match=r"precedes.*claim"):
            repo.readback(admission.admission_id)


def test_link_wrapper_rejects_execution_without_worker_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "unclaimed-link.db") as store:
        case_id, snapshot_id, candidate, invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry)
        admission = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="case:target-pressure:a",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=100,
        )
        execution_id = str(ExecutionId.new())
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(case_id),
                probe_id=invocation.probe_id,
                probe_version=invocation.probe_version,
                status="ok",
                parameters_json=_canonical(invocation.parameters),
                started_at=datetime.now(UTC).isoformat(),
                finished_at=datetime.now(UTC).isoformat(),
                state_version=_EPOCH,
            )
            with pytest.raises(ValueError, match="claim"):
                repo.link_execution(admission.admission_id, execution_id, invocation)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_execution_links"
        ).fetchone() == (0,)


def test_task_id_can_be_reused_only_in_a_new_case_epoch(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "epoch-task.db") as store:
        case_id, snapshot_id, candidate, invocation, registry = _setup(store)
        repo = CandidateDispatchAdmissionRepository(store, registry=registry)
        task_id = "case:target-pressure:reuse"
        first = repo.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id=task_id,
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=100,
        )
        next_candidate = candidate.model_copy(update={"candidate_id": "cand_v1_" + "b" * 32})
        store.connection.execute(
            "INSERT INTO case_measurement_candidates SELECT ?,schema_version,case_id,?,"
            "probe_id,manifest_version,manifest_sha256,invocation_json,invocation_sha256,"
            "observable,target_handle,source_evidence_id,source_evidence_sha256,"
            "dependency_bindings_json,dependency_sha256,?,cost_ms,resource_class,"
            "safety_class,description,issued_at,expires_at "
            "FROM case_measurement_candidates WHERE candidate_id=?",
            (
                next_candidate.candidate_id,
                _EPOCH + 1,
                _digest(next_candidate.candidate_id),
                candidate.candidate_id,
            ),
        )
        store.connection.execute(
            "UPDATE cases SET state_version=? WHERE case_id=?",
            (_EPOCH + 1, str(case_id)),
        )
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json="
            "json_set(record_json, '$.state_version', ?) WHERE case_id=?",
            (_EPOCH + 1, str(case_id)),
        )
        old_request = CandidateDecisionSnapshotRepository(store).readback(snapshot_id).request
        next_request = old_request.model_copy(
            update={
                "state_version": _EPOCH + 1,
                "correlation_id": "fixture:dispatch:next",
                "available_candidates": (
                    AdmittedCandidateRefV1(**next_candidate.model_dump(exclude={"schema_version"})),
                ),
            }
        )
        old_response = CandidateDecisionSnapshotRepository(store).readback(snapshot_id).response
        assert isinstance(old_response, CandidateDecisionResponseV1)
        next_response = old_response.model_copy(
            update={
                "state_version": _EPOCH + 1,
                "correlation_id": next_request.correlation_id,
                "ranked_candidate_ids": (next_candidate.candidate_id,),
                "considered_candidate_ids": (next_candidate.candidate_id,),
                "proposals": (
                    CandidateProposalV1(
                        candidate_id=next_candidate.candidate_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                    ),
                ),
            }
        )
        next_snapshot = CandidateDecisionSnapshotRepository(store).capture(
            next_request, next_response, request_frozen_at=datetime.now(UTC)
        )
        registry.candidate = next_candidate
        registry.invocation = invocation
        second = repo.admit(
            snapshot_id=next_snapshot.snapshot_id,
            candidate_id=next_candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH + 1,
            task_id=task_id,
            invocation_sha256=next_candidate.invocation_sha256,
            cost_ms=100,
        )
        assert first.admission_id != second.admission_id
