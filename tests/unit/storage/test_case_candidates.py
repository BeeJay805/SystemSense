"""Case-scoped candidate IDs never become operating-system authority."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel

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
from systemsense.domain.probes import (
    MeasurementNeed,
    MeasurementWindow,
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import (
    CandidateGap,
    CandidateGapReason,
    CandidateRecord,
    CandidateRegistration,
    CandidateResolution,
    CandidateTargetBinding,
    CaseCandidateRegistry,
)
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)
_EPOCH = 3
_TARGET_A = "proc_" + "a" * 32
_TARGET_B = "proc_" + "b" * 32


class TargetWindowParametersV1(BaseModel):
    pid: int
    creation_time: datetime
    window_start: datetime | None = None
    window_end: datetime | None = None


def _manifest(version: int = 1) -> ProbeManifest:
    return ProbeManifest(
        probe_id="fixture.pressure",
        version=version,
        implementation_id="builtin.fixture.pressure",
        question="Measure process pressure in a bounded window",
        safety=ProbeSafety(
            safety_class=SafetyClass.R1,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
            outbound_network=False,
        ),
        input_model="TargetWindowParametersV1",
        limits=ProbeLimits(timeout_ms=2000, max_output_bytes=4096, max_records=8),
        category="application",
    )


def _case_with_source(
    store: SQLiteStore, case_id: CaseId, *, observed_at: datetime | None = None
) -> EvidenceId:
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    captured_at = _NOW - timedelta(seconds=5)
    source_observed_at = observed_at or captured_at
    source_id = stable_source_id("fixture.inventory", {"case_id": str(case_id)})
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=source_observed_at,
        captured_at=captured_at,
        source=EvidenceSource(type="fixture.inventory", source_id=source_id, locator={}),
        collector=CollectorReference(id="fixture.inventory", version=1, execution_id=execution_id),
        summary="Two locally enumerated processes",
        extraction=Extraction(confidence=1.0, parser="fixture.inventory", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    store.create_case(
        case_id=str(case_id),
        kind="general",
        symptom="Process performance",
        created_at=(_NOW - timedelta(minutes=1)).isoformat(),
        status="collecting",
        state_version=_EPOCH,
    )
    store.connection.execute(
        "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
        (
            str(case_id),
            json.dumps(
                {
                    "case_id": str(case_id),
                    "state_version": _EPOCH,
                    "status": "running",
                    "deadline_at": (_NOW + timedelta(minutes=10)).isoformat(),
                    "budget_ms": 1000,
                    "spent_cost_ms": 0,
                    "max_probes": 10,
                    "completed_probe_ids": [],
                    "pending_probe_ids": [],
                    "interrupted_probe_ids": [],
                    "unrecorded_attempt_count": 0,
                }
            ),
        ),
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="fixture.inventory",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(captured_at - timedelta(seconds=1)).isoformat(),
            finished_at=captured_at.isoformat(),
            state_version=_EPOCH,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=source_observed_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"fixture:{execution_id}",
            time_basis="source_observed",
            time_quality="exact",
        )
    return evidence_id


def _registry(
    store: SQLiteStore,
    *,
    case_id: CaseId,
    evidence_id: EvidenceId,
    clock: list[datetime],
    manifests: dict[str, ProbeManifest],
    approved_targets: set[str] | None = None,
) -> CaseCandidateRegistry:
    targets = (
        CandidateTargetBinding(
            handle=_TARGET_A,
            parameters={"pid": 101, "creation_time": (_NOW - timedelta(hours=1)).isoformat()},
        ),
        CandidateTargetBinding(
            handle=_TARGET_B,
            parameters={"pid": 202, "creation_time": (_NOW - timedelta(hours=2)).isoformat()},
        ),
    )
    allowed = approved_targets if approved_targets is not None else {_TARGET_A, _TARGET_B}
    return CaseCandidateRegistry(
        store,
        registrations=(
            CandidateRegistration(
                manifest=manifests["fixture.pressure"],
                parameter_model=TargetWindowParametersV1,
                observable="fixture.pressure",
                description="Read process pressure for a known local process",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                source_evidence_id=evidence_id,
                freshness_ttl_seconds=60,
                supports_window=True,
                max_window_lookback_seconds=3600,
                targets=targets,
            ),
        ),
        manifest_lookup=manifests.get,
        revalidate_target=lambda candidate_case, target, invocation: (
            candidate_case == case_id
            and target.handle in allowed
            and invocation.target_handle == target.handle
        ),
        clock=lambda: clock[0],
    )


def _need(target: str, window: MeasurementWindow | None = None) -> MeasurementNeed:
    return MeasurementNeed(
        capability_id="fixture.pressure",
        observable="fixture.pressure",
        target_handle=target,
        window=window,
    )


def test_two_inventory_targets_mint_distinct_opaque_candidates_and_resolve_exactly(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id)
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        registry = _registry(
            store, case_id=case_id, evidence_id=source, clock=clock, manifests=manifests
        )
        first = registry.issue(case_id, _EPOCH, _need(_TARGET_A))
        second = registry.issue(case_id, _EPOCH, _need(_TARGET_B))
        assert not isinstance(first, CandidateGap)
        assert not isinstance(second, CandidateGap)
        assert first.candidate_id.startswith("cand_v1_")
        assert first.candidate_id != second.candidate_id
        assert first.probe_id == second.probe_id == "fixture.pressure"
        assert first.invocation_sha256 != second.invocation_sha256
        assert registry.issue(case_id, _EPOCH, _need(_TARGET_A)).candidate_id == first.candidate_id
        a = registry.resolve(case_id, _EPOCH, first.candidate_id)
        b = registry.resolve(case_id, _EPOCH, second.candidate_id)
        assert isinstance(a, CandidateResolution)
        assert isinstance(b, CandidateResolution)
        assert a.invocation.parameters["pid"] == 101
        assert b.invocation.parameters["pid"] == 202
        assert a.dispatch_authorized is False
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=?", (str(case_id),)
            ).fetchone()[0]
            == 1
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM case_process_targets WHERE case_id=?", (str(case_id),)
            ).fetchone()[0]
            == 0
        )


def test_two_windows_and_restart_keep_exact_identity_without_replay_authority(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "windows.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id)
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        registry = _registry(
            store, case_id=case_id, evidence_id=source, clock=clock, manifests=manifests
        )
        one = MeasurementWindow(start=_NOW - timedelta(minutes=5), end=_NOW - timedelta(minutes=4))
        two = MeasurementWindow(start=_NOW - timedelta(minutes=3), end=_NOW - timedelta(minutes=2))
        first = registry.issue(case_id, _EPOCH, _need(_TARGET_A, one))
        second = registry.issue(case_id, _EPOCH, _need(_TARGET_A, two))
        assert not isinstance(first, CandidateGap)
        assert not isinstance(second, CandidateGap)
        assert first.candidate_id != second.candidate_id
        reopened = _registry(
            store, case_id=case_id, evidence_id=source, clock=clock, manifests=manifests
        )
        assert (
            reopened.issue(case_id, _EPOCH, _need(_TARGET_A, one)).candidate_id
            == first.candidate_id
        )
        resolved = reopened.resolve(case_id, _EPOCH, second.candidate_id)
        assert isinstance(resolved, CandidateResolution)
        assert resolved.invocation.window == two
        assert resolved.dispatch_authorized is False
        assert len(reopened.readback(case_id, _EPOCH)) == 2


def test_two_observables_of_one_registered_probe_have_distinct_candidates(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "observables.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id)
        clock = [_NOW]
        manifest = _manifest()
        target = CandidateTargetBinding(
            handle=_TARGET_A,
            parameters={"pid": 101, "creation_time": (_NOW - timedelta(hours=1)).isoformat()},
            description="Pressure for inventory process A",
        )
        registrations = tuple(
            CandidateRegistration(
                manifest=manifest,
                parameter_model=TargetWindowParametersV1,
                observable=observable,
                description=f"Read {observable}",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                source_evidence_id=source,
                freshness_ttl_seconds=60,
                targets=(target,),
            )
            for observable in ("fixture.cpu", "fixture.memory")
        )
        registry = CaseCandidateRegistry(
            store,
            registrations=registrations,
            manifest_lookup=lambda _probe_id: manifest,
            revalidate_target=lambda bound_case, binding, invocation: (
                bound_case == case_id
                and binding.handle == _TARGET_A
                and invocation.parameters["pid"] == 101
            ),
            clock=lambda: clock[0],
        )
        cpu = registry.issue(
            case_id,
            _EPOCH,
            MeasurementNeed(
                capability_id=manifest.probe_id,
                observable="fixture.cpu",
                target_handle=_TARGET_A,
            ),
        )
        memory = registry.issue(
            case_id,
            _EPOCH,
            MeasurementNeed(
                capability_id=manifest.probe_id,
                observable="fixture.memory",
                target_handle=_TARGET_A,
            ),
        )
        assert not isinstance(cpu, CandidateGap)
        assert not isinstance(memory, CandidateGap)
        assert cpu.candidate_id != memory.candidate_id
        assert cpu.invocation_sha256 != memory.invocation_sha256
        assert cpu.description == memory.description == "Pressure for inventory process A"
        resolved = registry.resolve(case_id, _EPOCH, memory.candidate_id)
        assert isinstance(resolved, CandidateResolution)
        assert resolved.invocation.observable == "fixture.memory"


def test_unknown_cross_case_stale_and_forged_ids_fail_closed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "boundaries.db") as store:
        case_a = CaseId.new()
        case_b = CaseId.new()
        source_a = _case_with_source(store, case_a)
        source_b = _case_with_source(store, case_b)
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        registry_a = _registry(
            store, case_id=case_a, evidence_id=source_a, clock=clock, manifests=manifests
        )
        registry_b = _registry(
            store, case_id=case_b, evidence_id=source_b, clock=clock, manifests=manifests
        )
        candidate = registry_a.issue(case_a, _EPOCH, _need(_TARGET_A))
        assert not isinstance(candidate, CandidateGap)
        assert isinstance(registry_b.resolve(case_b, _EPOCH, candidate.candidate_id), CandidateGap)
        assert isinstance(registry_a.resolve(case_a, _EPOCH, "cand_v1_" + "f" * 32), CandidateGap)
        assert isinstance(registry_a.issue(case_a, _EPOCH, _need("proc_" + "f" * 32)), CandidateGap)
        store.connection.execute(
            "UPDATE cases SET state_version=? WHERE case_id=?", (_EPOCH + 1, str(case_a))
        )
        assert isinstance(registry_a.resolve(case_a, _EPOCH, candidate.candidate_id), CandidateGap)


def test_expired_source_changed_binding_version_drift_and_budget_reject(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "stale.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id)
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        approved = {_TARGET_A, _TARGET_B}
        registry = _registry(
            store,
            case_id=case_id,
            evidence_id=source,
            clock=clock,
            manifests=manifests,
            approved_targets=approved,
        )
        candidate = registry.issue(case_id, _EPOCH, _need(_TARGET_A))
        assert not isinstance(candidate, CandidateGap)
        approved.remove(_TARGET_A)
        assert isinstance(registry.resolve(case_id, _EPOCH, candidate.candidate_id), CandidateGap)
        approved.add(_TARGET_A)
        manifests["fixture.pressure"] = _manifest(version=2)
        assert isinstance(registry.resolve(case_id, _EPOCH, candidate.candidate_id), CandidateGap)
        manifests["fixture.pressure"] = _manifest()
        clock[0] = _NOW + timedelta(seconds=61)
        assert isinstance(registry.resolve(case_id, _EPOCH, candidate.candidate_id), CandidateGap)
        clock[0] = _NOW
        store.connection.execute(
            "UPDATE investigation_checkpoints "
            "SET record_json=json_set(record_json, '$.budget_ms', 50) WHERE case_id=?",
            (str(case_id),),
        )
        assert isinstance(registry.resolve(case_id, _EPOCH, candidate.candidate_id), CandidateGap)


def test_old_observation_is_not_refreshed_by_late_collection(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "observed-age.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id, observed_at=_NOW - timedelta(minutes=5))
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        registry = _registry(
            store, case_id=case_id, evidence_id=source, clock=clock, manifests=manifests
        )
        assert isinstance(registry.issue(case_id, _EPOCH, _need(_TARGET_A)), CandidateGap)


def test_source_provenance_requires_consistent_times_and_quality(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "source-provenance.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id, observed_at=_NOW - timedelta(seconds=20))
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        registry = _registry(
            store, case_id=case_id, evidence_id=source, clock=clock, manifests=manifests
        )
        assert isinstance(registry.issue(case_id, _EPOCH, _need(_TARGET_A)), CandidateRecord)
        store.connection.execute(
            "UPDATE evidence SET time_quality='unknown' WHERE evidence_id=?",
            (str(source),),
        )
        assert isinstance(registry.issue(case_id, _EPOCH, _need(_TARGET_B)), CandidateGap)
        store.connection.execute(
            "UPDATE evidence SET time_quality='exact' WHERE evidence_id=?",
            (str(source),),
        )
        store.connection.execute(
            "UPDATE probe_executions SET started_at=? WHERE execution_id=("
            "SELECT execution_id FROM evidence WHERE evidence_id=?)",
            ((_NOW - timedelta(seconds=4)).isoformat(), str(source)),
        )
        assert isinstance(registry.issue(case_id, _EPOCH, _need(_TARGET_B)), CandidateGap)


def test_source_observed_after_capture_is_not_admitted(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "source-clock.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id, observed_at=_NOW)
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        registry = _registry(
            store, case_id=case_id, evidence_id=source, clock=clock, manifests=manifests
        )
        assert isinstance(registry.issue(case_id, _EPOCH, _need(_TARGET_A)), CandidateGap)


def test_candidate_admission_cost_remains_reserved_after_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "candidate-budget.db") as store:
        case_id = CaseId.new()
        source = _case_with_source(store, case_id)
        clock = [_NOW]
        manifests = {"fixture.pressure": _manifest()}
        registry = _registry(
            store, case_id=case_id, evidence_id=source, clock=clock, manifests=manifests
        )
        first = registry.issue(case_id, _EPOCH, _need(_TARGET_A))
        second = registry.issue(case_id, _EPOCH, _need(_TARGET_B))
        assert isinstance(first, CandidateRecord)
        assert isinstance(second, CandidateRecord)
        refs = tuple(
            AdmittedCandidateRefV1(**item.model_dump(exclude={"schema_version"}))
            for item in (first, second)
        )
        request = CandidateDecisionRequestV1(
            case_id=case_id,
            state_version=_EPOCH,
            correlation_id="fixture:budget",
            deadline_at=_NOW + timedelta(minutes=5),
            symptom="Slow app",
            available_candidates=refs,
            budget_ms=1000,
            max_candidates=2,
        )
        response = CandidateDecisionResponseV1(
            provider=ProviderIdentity(
                provider_id="fixture-fast", provider_version="1", role="fast_decision"
            ),
            case_id=case_id,
            state_version=_EPOCH,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            ranked_candidate_ids=(first.candidate_id, second.candidate_id),
            considered_candidate_ids=(first.candidate_id, second.candidate_id),
            proposals=(
                CandidateProposalV1(
                    candidate_id=first.candidate_id,
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=1.0,
                ),
            ),
        )
        snapshot = CandidateDecisionSnapshotRepository(store, clock=lambda: clock[0]).capture(
            request, response, request_frozen_at=_NOW
        )
        admission_repo = CandidateDispatchAdmissionRepository(
            store, registry=registry, clock=lambda: clock[0]
        )
        admission = admission_repo.admit(
            snapshot_id=snapshot.snapshot_id,
            candidate_id=first.candidate_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="fixture:pressure:a",
            invocation_sha256=first.invocation_sha256,
            cost_ms=first.cost_ms,
        )
        admission_repo.claim_for_worker(
            admission.admission_id,
            case_id=case_id,
            epoch_state_version=_EPOCH,
            task_id="fixture:pressure:a",
            invocation_sha256=first.invocation_sha256,
        )
        store.connection.execute(
            "UPDATE investigation_checkpoints "
            "SET record_json=json_set(record_json, '$.budget_ms', 150) WHERE case_id=?",
            (str(case_id),),
        )
        result = registry.resolve(case_id, _EPOCH, second.candidate_id)
        assert isinstance(result, CandidateGap)
        assert result.reason is CandidateGapReason.BUDGET_EXHAUSTED
