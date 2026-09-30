"""Exact-target streaming beyond the ordinary 64-entry menu."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from systemsense.application.candidate_catalog import (
    process_pressure_candidate_catalog,
)
from systemsense.application.case_service import CaseService
from systemsense.application.exact_process_sampling import exact_process_streaming_name
from systemsense.application.investigation_state import (
    InvestigationState,
    InvestigationStatus,
)
from systemsense.application.investigator import (
    Investigator,
    _prioritize_literal_process_needs,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.runtime import (
    DiagnosticRuntime,
    PersistedProbeResult,
    _trusted_exact_process_name,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.targets import (
    ProcessTargetRepository,
    TargetSelectionError,
)
from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
)
from systemsense.decision.contracts import DiagnosticPurpose, ProviderIdentity
from systemsense.domain.cases import CaseId, CaseKind
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
    EvidenceId,
    ExecutionId,
    JsonValue,
    stable_source_id,
)
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRunner,
)
from systemsense.packs.runtime import (
    TargetPressureParametersV1,
    default_probe_runner,
)
from systemsense.storage.candidate_decision_snapshots import (
    CandidateDecisionSnapshotRepository,
)
from systemsense.storage.candidate_dispatch_admissions import (
    CandidateDispatchAdmissionRepository,
)
from systemsense.storage.case_candidates import CandidateGap, CandidateResolution
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime.now(UTC)


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind="general",
        symptom="exact process pressure",
        created_at=NOW.isoformat(),
    )
    return case_id


def _process(pid: int, created: datetime = NOW - timedelta(minutes=1)) -> dict[str, JsonValue]:
    return {
        "pid": pid,
        "ppid": 1,
        "name": "sample.exe",
        "creation_time": created.isoformat(),
        "identity": f"{pid}@{created.isoformat()}",
    }


def _snapshot(
    store: SQLiteStore,
    case_id: CaseId,
    *,
    processes: list[dict[str, JsonValue]],
    at: datetime = NOW,
    omitted: int = 0,
) -> EvidenceId:
    evidence_id, execution_id = EvidenceId.new(), ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "application.snapshot", "probe_version": 1}
    )
    facts: dict[str, JsonValue] = {
        "collection_started_at": (at - timedelta(seconds=1)).isoformat(),
        "collection_completed_at": at.isoformat(),
        "collection_status": "partial" if omitted else "available",
        "processes": cast("JsonValue", processes),
        "omitted_counts": {"processes": omitted, "services": 0, "startup": 0},
    }
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=at,
        captured_at=at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "application.snapshot"},
        ),
        collector=CollectorReference(
            id="application.snapshot", version=1, execution_id=execution_id
        ),
        summary="Application topology",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.PERSONAL,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="application.snapshot",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(at - timedelta(seconds=2)).isoformat(),
            finished_at=at.isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=at.isoformat(),
            captured_at=at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )
    return evidence_id


def _active_streaming_checkpoint(
    store: SQLiteStore, case_id: CaseId, *, at: datetime = NOW
) -> None:
    store.connection.execute(
        "UPDATE cases SET status='collecting' WHERE case_id=?", (str(case_id),)
    )
    store.connection.execute(
        "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
        (
            str(case_id),
            json.dumps(
                {
                    "case_id": str(case_id),
                    "state_version": 0,
                    "status": "running",
                    "deadline_at": (at + timedelta(minutes=2)).isoformat(),
                    "budget_ms": 30_000,
                    "spent_cost_ms": 0,
                    "max_probes": 6,
                    # The snapshot has persisted, but collection has not yet
                    # advanced the checkpoint or finished its other probes.
                    "completed_probe_ids": ["core.system"],
                    "pending_probe_ids": ["application.snapshot", "core.resources"],
                    "interrupted_probe_ids": [],
                    "unrecorded_attempt_count": 0,
                }
            ),
        ),
    )


def _large_process_inventory(
    *, target_birth: datetime = NOW - timedelta(hours=2)
) -> list[dict[str, JsonValue]]:
    processes = [_process(pid) for pid in range(1, 201)]
    processes[180] = {
        **_process(57_900, target_birth),
        "name": "target-app.exe",
    }
    return processes


def test_exact_name_streaming_catalog_exposes_unique_target_beyond_64_without_dispatch(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        processes = _large_process_inventory()
        _snapshot(store, case_id, processes=processes)
        _active_streaming_checkpoint(store, case_id)

        def clock() -> datetime:
            return NOW + timedelta(seconds=1)

        ordinary_registry, ordinary_needs = process_pressure_candidate_catalog(
            store, default_probe_runner(), case_id, clock=clock
        )
        assert len(ordinary_needs) == 64
        assert all(item.target_handle is not None for item in ordinary_needs)
        ordinary_inventory = ProcessTargetRepository(store, clock=clock).list_process_candidates(
            case_id
        )
        assert len(ordinary_inventory.candidates) == 64
        assert all(item.name != "target-app.exe" for item in ordinary_inventory.candidates)
        ordinary_records = [ordinary_registry.issue(case_id, 0, need) for need in ordinary_needs]
        assert all(not isinstance(record, CandidateGap) for record in ordinary_records)
        assert all(
            record.probe_id == "application.target_pressure"
            for record in ordinary_records
            if not isinstance(record, CandidateGap)
        )

        registry, needs = process_pressure_candidate_catalog(
            store,
            default_probe_runner(),
            case_id,
            exact_process_name="target-app.exe",
            clock=clock,
        )
        assert len(needs) == 1
        candidate = registry.issue(case_id, 0, needs[0])
        assert not isinstance(candidate, CandidateGap)
        resolved = registry.resolve(case_id, 0, candidate.candidate_id)
        assert isinstance(resolved, CandidateResolution)
        assert resolved.invocation.probe_id == "application.target_pressure"
        assert resolved.invocation.parameters["pid"] == 57_900
        assert resolved.invocation.parameters["creation_time"] == (
            NOW - timedelta(hours=2)
        ).isoformat().replace("+00:00", "Z")
        assert resolved.dispatch_authorized is False

        checkpoint = json.loads(
            store.connection.execute(
                "SELECT record_json FROM investigation_checkpoints WHERE case_id=?",
                (str(case_id),),
            ).fetchone()[0]
        )
        assert "application.snapshot" not in checkpoint["completed_probe_ids"]
        assert checkpoint["pending_probe_ids"] == [
            "application.snapshot",
            "core.resources",
        ]
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='application.target_pressure'",
            (str(case_id),),
        ).fetchone() == (0,)
        assert ProcessTargetRepository(store, clock=clock).selected_process_target(case_id) is None


@pytest.mark.parametrize("failure", ["incomplete", "ambiguous", "stale"])
def test_exact_name_streaming_catalog_fails_closed_without_unique_fresh_complete_identity(
    tmp_path: Path, failure: str
) -> None:
    with SQLiteStore(tmp_path / f"{failure}.db") as store:
        case_id = _case(store)
        processes = _large_process_inventory()
        omitted = 0
        snapshot_at = NOW
        if failure == "incomplete":
            omitted = 1
        elif failure == "ambiguous":
            processes.append({**_process(58_001), "name": "target-app.exe"})
        else:
            snapshot_at = NOW - timedelta(seconds=301)
        _snapshot(store, case_id, processes=processes, at=snapshot_at, omitted=omitted)
        with pytest.raises(TargetSelectionError):
            process_pressure_candidate_catalog(
                store,
                default_probe_runner(),
                case_id,
                exact_process_name="target-app.exe",
                clock=lambda: NOW,
            )
        assert (
            ProcessTargetRepository(store, clock=lambda: NOW).selected_process_target(case_id)
            is None
        )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='application.target_pressure'",
            (str(case_id),),
        ).fetchone() == (0,)


@pytest.mark.parametrize("change", ["birth", "source"])
def test_exact_name_streaming_registry_rejects_changed_pid_birth_and_snapshot_source(
    tmp_path: Path, change: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=_large_process_inventory())
        _active_streaming_checkpoint(store, case_id)
        registry, needs = process_pressure_candidate_catalog(
            store,
            default_probe_runner(),
            case_id,
            exact_process_name="target-app.exe",
            clock=lambda: NOW + timedelta(seconds=1),
        )
        candidate = registry.issue(case_id, 0, needs[0])
        assert not isinstance(candidate, CandidateGap)

        changed_birth = NOW - timedelta(hours=1) if change == "birth" else NOW - timedelta(hours=2)
        _snapshot(
            store,
            case_id,
            processes=_large_process_inventory(target_birth=changed_birth),
            at=NOW + timedelta(seconds=2),
        )
        result = registry.resolve(case_id, 0, candidate.candidate_id)
        assert isinstance(result, CandidateGap)


def test_exact_name_is_validated_by_shared_identity_resolver(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=_large_process_inventory())
        targets = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=1))
        resolved = targets.resolve_exact_process_candidate_for_sampling(case_id, "TARGET-APP.EXE")
        assert resolved.pid == 57_900
        assert resolved.name == "target-app.exe"
        assert resolved.evidence_sha256
        assert targets.selected_process_target(case_id) is None


def test_investigator_streaming_seam_uses_exact_catalog_before_checkpoint_completion(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    # This seam uses production's real freshness clock. Collection may have
    # happened much earlier in a full suite, so timestamp this source now.
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        evidence_id = _snapshot(store, case_id, processes=_large_process_inventory(), at=now)
        _active_streaming_checkpoint(store, case_id, at=now)
        execution_row = store.connection.execute(
            "SELECT execution_id FROM evidence WHERE case_id=? AND evidence_id=?",
            (str(case_id), str(evidence_id)),
        ).fetchone()
        assert execution_row is not None
        calls: list[str | None] = []

        class RuntimeSpy:
            def candidate_catalog(
                self,
                requested_case: CaseId,
                *,
                exact_process_name: str | None = None,
                store: SQLiteStore | None = None,
            ) -> tuple[object, tuple[object, ...]]:
                calls.append(exact_process_name)
                assert store is not None
                return process_pressure_candidate_catalog(
                    store,
                    default_probe_runner(),
                    requested_case,
                    exact_process_name=exact_process_name,
                    clock=lambda: now + timedelta(seconds=1),
                )

        investigator = Investigator(
            store=store,
            runtime=cast(Any, RuntimeSpy()),
            capabilities=(),
            decision=cast(Any, None),
            reasoning=cast(Any, None),
        )
        state = InvestigationState(
            case_id=case_id,
            objective="Is target-app.exe monopolizing a core?",
            created_at=now,
            updated_at=now,
            deadline_at=now + timedelta(minutes=2),
            incident_start=now - timedelta(minutes=1),
            incident_end=now,
            budget_ms=30_000,
            completed_probe_ids=("core.system",),
            pending_probe_ids=("application.snapshot", "core.resources"),
        )
        parent = PersistedProbeResult(
            task_id="probe-application.snapshot",
            case_id=str(case_id),
            epoch_state_version=0,
            probe_id="application.snapshot",
            execution_id=ExecutionId(root=str(execution_row[0])),
            evidence_generation=1,
            trigger_evidence_sha256="0" * 64,
        )

        registry, needs = investigator._streaming_candidate_catalog(  # pyright: ignore[reportPrivateUsage]
            state, parent, store, None, []
        )
        assert calls == ["target-app.exe"]
        assert registry is not None and len(needs) == 1
        # This exact-path filter is used immediately after catalog creation in
        # the real streaming offer path; it must share the 512-entry resolver.
        assert _prioritize_literal_process_needs(store, case_id, state.objective, needs) == needs
        candidate = registry.issue(case_id, 0, needs[0])
        assert not isinstance(candidate, CandidateGap)
        resolved = registry.resolve(case_id, 0, candidate.candidate_id)
        assert isinstance(resolved, CandidateResolution)
        assert resolved.invocation.parameters["pid"] == 57_900
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='application.target_pressure'",
            (str(case_id),),
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    ("objective", "exact_expected"),
    [
        ("Is target-app.exe monopolizing a core?", True),
        ("Is target-app.exe slow in the PDF viewer?", False),
        ("Is target-app.exe running?", False),
    ],
    ids=("generic-pressure", "pdf-broad-menu", "liveness-inventory-menu"),
)
def test_exact_or_broad_candidate_dispatch_revalidates_shared_objective_eligibility(
    tmp_path: Path, objective: str, exact_expected: bool
) -> None:
    with SQLiteStore(tmp_path / "dispatch.db") as store:
        sampled: list[dict[str, JsonValue]] = []
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None

        def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
            sampled.append(parameters)
            now = datetime.now(UTC)
            return ProbeObservation(
                summary="Synthetic target pressure receipt",
                facts={"target_pid": parameters["pid"]},
                observed_at=now,
                captured_at=now,
            )

        runner = ProbeRunner(
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=collect,
                    isolated=False,
                ),
            )
        )
        service = CaseService(
            store,
            DeterministicPlanner(
                candidates=(
                    ProbeCandidate(
                        probe_id="application.target_pressure",
                        cost_ms=10_000,
                        value=1.0,
                        common=True,
                    ),
                )
            ),
        )
        started = datetime.now(UTC)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom=objective,
            target_traits=frozenset(),
            created_at=started,
            budget_ms=60_000,
            max_probes=4,
        )
        target_process = {
            **_process(57_900, started - timedelta(hours=2)),
            "name": "target-app.exe",
        }
        processes = (
            _large_process_inventory(target_birth=started - timedelta(hours=2))
            if exact_expected
            else [target_process, {**_process(57_901), "name": "helper.exe"}]
        )
        _snapshot(store, opened.case.case_id, processes=processes, at=started)
        investigation = InvestigationState(
            case_id=opened.case.case_id,
            objective=objective,
            status=InvestigationStatus.RUNNING,
            created_at=started,
            updated_at=started,
            deadline_at=opened.deadline_at,
            incident_start=started - timedelta(minutes=1),
            incident_end=started,
            budget_ms=60_000,
            completed_probe_ids=("core.system",),
            pending_probe_ids=("application.snapshot", "core.resources"),
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
            (str(opened.case.case_id), investigation.model_dump_json()),
        )
        shared_name = _trusted_exact_process_name(  # pyright: ignore[reportPrivateUsage]
            store, opened.case.case_id
        )
        assert exact_process_streaming_name(objective) == (
            "target-app.exe" if exact_expected else None
        )
        assert shared_name == ("target-app.exe" if exact_expected else None)
        runtime = DiagnosticRuntime(store=store, case_service=service, probe_runner=runner)
        registry, needs = runtime.candidate_catalog(
            opened.case.case_id, exact_process_name=shared_name
        )
        # PDF/liveness retain the ordinary selectable target menu. The fixture
        # chooses the named process from that menu; it does not force a check.
        assert (len(needs) == 1) if exact_expected else (len(needs) == 2)
        if not exact_expected:
            inventory = ProcessTargetRepository(store).list_process_candidates(opened.case.case_id)
            target_id = next(
                item.candidate_id for item in inventory.candidates if item.name == "target-app.exe"
            )
            selected_need = next(need for need in needs if need.target_handle == target_id)
        else:
            selected_need = needs[0]
        candidate = registry.issue(opened.case.case_id, opened.case.state_version, selected_need)
        assert not isinstance(candidate, CandidateGap)
        issued_candidates = [
            registry.issue(opened.case.case_id, opened.case.state_version, need) for need in needs
        ]
        selectable_candidates = [
            item for item in issued_candidates if not isinstance(item, CandidateGap)
        ]
        assert len(selectable_candidates) == len(needs)
        request = CandidateDecisionRequestV1(
            case_id=opened.case.case_id,
            state_version=opened.case.state_version,
            correlation_id="test:streaming-target-beyond-64",
            deadline_at=opened.deadline_at,
            symptom=objective,
            available_candidates=tuple(
                AdmittedCandidateRefV1(**item.model_dump(exclude={"schema_version"}))
                for item in selectable_candidates
            ),
            budget_ms=60_000,
            max_candidates=len(needs),
        )
        response = CandidateDecisionResponseV1(
            provider=ProviderIdentity(
                provider_id="fixture",
                provider_version="1",
                role="fast_decision",
            ),
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            ranked_candidate_ids=(
                candidate.candidate_id,
                *(
                    item.candidate_id
                    for item in selectable_candidates
                    if item.candidate_id != candidate.candidate_id
                ),
            ),
            considered_candidate_ids=tuple(item.candidate_id for item in selectable_candidates),
            proposals=(
                CandidateProposalV1(
                    candidate_id=candidate.candidate_id,
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=1.0,
                ),
            ),
        )
        snapshot = CandidateDecisionSnapshotRepository(store).capture(
            request, response, request_frozen_at=datetime.now(UTC)
        )
        rebuilt_registry, _ = runtime.candidate_catalog(
            opened.case.case_id,
            exact_process_name=_trusted_exact_process_name(  # pyright: ignore[reportPrivateUsage]
                store, opened.case.case_id
            ),
        )
        assert isinstance(
            rebuilt_registry.resolve(
                opened.case.case_id, opened.case.state_version, candidate.candidate_id
            ),
            CandidateResolution,
        )

        result = runtime.execute_candidate_measurement(
            opened, candidate.candidate_id, snapshot.snapshot_id
        )
        assert isinstance(result, tuple) and result
        assert sampled == [
            {
                "pid": 57_900,
                "creation_time": (started - timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
            }
        ]
        assert store.connection.execute(
            "SELECT COUNT(*) FROM case_process_targets WHERE case_id=?",
            (str(opened.case.case_id),),
        ).fetchone() == (0,)
        admission_row = store.connection.execute(
            "SELECT admission_id FROM candidate_dispatch_admissions WHERE candidate_id=?",
            (candidate.candidate_id,),
        ).fetchone()
        assert admission_row is not None
        admission = CandidateDispatchAdmissionRepository(store).readback(str(admission_row[0]))
        assert admission.outcome_status == "linked"
