"""A process target is selected from persisted case evidence, never a caller PID."""

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from systemsense.application import runtime as runtime_module
from systemsense.application.candidate_catalog import process_pressure_candidate_catalog
from systemsense.application.case_service import CaseService
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.application.targets import (
    InventoryProcessBinding,
    ProcessTargetBinding,
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
from systemsense.domain.cases import CaseKind
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.time import utc_now
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass, Task, TaskResult, TaskStatus
from systemsense.packs.runtime import TargetPressureParametersV1, default_probe_runner
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import CandidateGap, CandidateResolution
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id), kind="general", symptom="PDF is slow", created_at=NOW.isoformat()
    )
    return case_id


def _snapshot(
    store: SQLiteStore,
    case_id: CaseId,
    *,
    processes: list[dict[str, JsonValue]],
    at: datetime = NOW,
    omitted: int = 0,
    collector_version: int = 1,
) -> EvidenceId:
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe",
        {"probe_id": "application.snapshot", "probe_version": collector_version},
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
            id="application.snapshot", version=collector_version, execution_id=execution_id
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
            probe_version=collector_version,
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


def _process(pid: int, created: datetime = NOW - timedelta(minutes=1)) -> dict[str, JsonValue]:
    return {
        "pid": pid,
        "ppid": 1,
        "name": "sample.exe",
        "creation_time": created.isoformat(),
        "identity": f"{pid}@{created.isoformat()}",
    }


def test_bind_persists_exact_candidate_provenance_and_is_idempotent(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        evidence_id = _snapshot(store, case_id, processes=[_process(42)], omitted=2)
        targets = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=1))

        inventory = targets.list_process_candidates(case_id)
        assert len(inventory.candidates) == 1
        assert inventory.omitted_process_count == 2
        assert inventory.inventory_complete is False
        candidate = inventory.candidates[0]
        assert candidate.evidence_id == evidence_id
        assert candidate.pid == 42
        assert candidate.creation_time == NOW - timedelta(minutes=1)
        assert candidate.collection_started_at == NOW - timedelta(seconds=1)
        assert candidate.collection_completed_at == NOW

        bound = targets.bind_process_target(case_id, candidate.candidate_id)
        assert bound == targets.bind_process_target(case_id, candidate.candidate_id)
        assert bound.evidence_id == evidence_id
        assert bound.selected_at == NOW + timedelta(seconds=1)
        assert bound.case_state_version == 0
        assert targets.selected_process_target(case_id) == bound
        assert targets.resolve_process_target_for_sampling(case_id) == bound
        assert store.connection.execute("SELECT COUNT(*) FROM case_process_targets").fetchone() == (
            1,
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            store.connection.execute(
                "UPDATE case_process_targets SET pid = 43 WHERE case_id = ?", (str(case_id),)
            )


def test_pid_reuse_and_cross_case_identifiers_do_not_bind(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        first = _case(store)
        second = _case(store)
        _snapshot(store, first, processes=[_process(42)])
        _snapshot(store, second, processes=[_process(42, NOW - timedelta(seconds=20))])
        targets = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=1))
        first_id = targets.list_process_candidates(first).candidates[0].candidate_id
        second_id = targets.list_process_candidates(second).candidates[0].candidate_id
        assert first_id != second_id
        with pytest.raises(TargetSelectionError):
            targets.bind_process_target(second, first_id)
        with pytest.raises(TargetSelectionError):
            targets.bind_process_target(first, "proc_" + "0" * 32)


def test_inventory_resolution_supports_multiple_targets_without_selection(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        other_case = _case(store)
        evidence_id = _snapshot(store, case_id, processes=[_process(42), _process(43)])
        _snapshot(store, other_case, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=1))
        inventory = targets.list_process_candidates(case_id)

        first = targets.resolve_process_candidate_for_sampling(
            case_id, inventory.candidates[0].candidate_id
        )
        second = targets.resolve_process_candidate_for_sampling(
            case_id, inventory.candidates[1].candidate_id
        )
        assert {first.pid, second.pid} == {42, 43}
        assert first.evidence_id == second.evidence_id == evidence_id
        assert first.evidence_sha256 == second.evidence_sha256
        assert first.validated_at == second.validated_at == NOW + timedelta(seconds=1)
        assert targets.selected_process_target(case_id) is None
        assert store.connection.execute("SELECT COUNT(*) FROM case_process_targets").fetchone() == (
            0,
        )

        other_id = targets.list_process_candidates(other_case).candidates[0].candidate_id
        with pytest.raises(TargetSelectionError, match="unavailable or stale"):
            targets.resolve_process_candidate_for_sampling(case_id, other_id)


def test_inventory_resolution_rejects_superseded_or_expired_target(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        expired = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=301))
        with pytest.raises(TargetSelectionError, match="stale"):
            expired.resolve_process_candidate_for_sampling(case_id, candidate_id)

        _snapshot(store, case_id, processes=[_process(43)], at=NOW + timedelta(seconds=2))
        current = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=3))
        with pytest.raises(TargetSelectionError, match="unavailable or stale"):
            current.resolve_process_candidate_for_sampling(case_id, candidate_id)


def test_read_only_catalog_issues_two_process_instances_without_selection(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42), _process(43)])
        store.connection.execute(
            "UPDATE cases SET status='collecting' WHERE case_id=?", (str(case_id),)
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id, record_json) VALUES (?, ?)",
            (
                str(case_id),
                json.dumps(
                    {
                        "case_id": str(case_id),
                        "state_version": 0,
                        "status": "running",
                        "deadline_at": (NOW + timedelta(minutes=2)).isoformat(),
                        "budget_ms": 30_000,
                        "spent_cost_ms": 0,
                        "max_probes": 4,
                        "completed_probe_ids": ["application.snapshot"],
                        "pending_probe_ids": [],
                        "interrupted_probe_ids": [],
                        "unrecorded_attempt_count": 0,
                    }
                ),
            ),
        )
        clock = [NOW + timedelta(seconds=1)]
        registry, needs = process_pressure_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: clock[0]
        )
        assert len(needs) == 2
        first = registry.issue(case_id, 0, needs[0])
        second = registry.issue(case_id, 0, needs[1])
        assert not isinstance(first, CandidateGap)
        assert not isinstance(second, CandidateGap)
        assert first.candidate_id != second.candidate_id
        first_resolution = registry.resolve(case_id, 0, first.candidate_id)
        second_resolution = registry.resolve(case_id, 0, second.candidate_id)
        assert isinstance(first_resolution, CandidateResolution)
        assert isinstance(second_resolution, CandidateResolution)
        assert first_resolution.invocation.parameters["pid"] == 42
        assert second_resolution.invocation.parameters["pid"] == 43
        targets = ProcessTargetRepository(store, clock=lambda: clock[0])
        assert targets.selected_process_target(case_id) is None

        _snapshot(store, case_id, processes=[_process(44)], at=NOW + timedelta(seconds=2))
        clock[0] = NOW + timedelta(seconds=3)
        assert isinstance(registry.resolve(case_id, 0, first.candidate_id), CandidateGap)

        token_name = "sk-" + "A" * 20 + ".exe"
        unsafe_process = _process(45)
        unsafe_process["name"] = token_name
        _snapshot(store, case_id, processes=[unsafe_process], at=NOW + timedelta(seconds=4))
        clock[0] = NOW + timedelta(seconds=5)
        fresh_registry, fresh_needs = process_pressure_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: clock[0]
        )
        fresh = fresh_registry.issue(case_id, 0, fresh_needs[0])
        assert not isinstance(fresh, CandidateGap)
        assert token_name not in fresh.description
        assert "inventory process PID 45" in fresh.description


@pytest.mark.parametrize(
    "dispatch_mode",
    ["normal", "queued_target_change", "preflight_change", "claimed_timeout", "stale_epoch"],
)
def test_candidate_decision_dispatches_exact_inventory_process_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dispatch_mode: str
) -> None:
    with SQLiteStore(tmp_path / "candidate.db") as store:
        sampled: list[dict[str, JsonValue]] = []
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None

        def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
            sampled.append(parameters)
            now = utc_now()
            return ProbeObservation(
                summary="Target sampled",
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
                        cost_ms=100,
                        value=1.0,
                        common=True,
                    ),
                )
            ),
        )
        started = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF stalls",
            target_traits=frozenset(),
            created_at=started,
            budget_ms=30_000,
            max_probes=2,
        )
        _snapshot(
            store,
            opened.case.case_id,
            processes=[_process(42, started - timedelta(minutes=1))],
            at=started,
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
            (
                str(opened.case.case_id),
                json.dumps(
                    {
                        "case_id": str(opened.case.case_id),
                        "state_version": opened.case.state_version,
                        "status": "running",
                        "deadline_at": opened.deadline_at.isoformat(),
                        "budget_ms": 30_000,
                        "spent_cost_ms": 0,
                        "max_probes": 2,
                        "completed_probe_ids": ["application.snapshot"],
                        "pending_probe_ids": [],
                        "interrupted_probe_ids": [],
                        "unrecorded_attempt_count": 0,
                    }
                ),
            ),
        )
        runtime = DiagnosticRuntime(store=store, case_service=service, probe_runner=runner)
        registry, needs = runtime.candidate_catalog(opened.case.case_id)
        assert len(needs) == 1
        candidate = registry.issue(opened.case.case_id, opened.case.state_version, needs[0])
        assert not isinstance(candidate, CandidateGap)
        request = CandidateDecisionRequestV1(
            case_id=opened.case.case_id,
            state_version=opened.case.state_version,
            correlation_id="test:exact-process",
            deadline_at=opened.deadline_at,
            symptom="PDF stalls",
            available_candidates=(
                AdmittedCandidateRefV1(**candidate.model_dump(exclude={"schema_version"})),
            ),
            budget_ms=30_000,
            max_candidates=1,
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
            ranked_candidate_ids=(candidate.candidate_id,),
            considered_candidate_ids=(candidate.candidate_id,),
            proposals=(
                CandidateProposalV1(
                    candidate_id=candidate.candidate_id,
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=1.0,
                ),
            ),
        )
        snapshot = CandidateDecisionSnapshotRepository(store).capture(
            request,
            response,
            request_frozen_at=utc_now(),
        )
        original_run = runtime._scheduler.run_blocking  # pyright: ignore[reportPrivateUsage]
        dispatched_resources: list[ResourceClass] = []

        def inspect_dispatch(*args: object, **kwargs: object) -> object:
            scheduled = cast("list[Task]", args[0])
            assert isinstance(scheduled, list)
            for item in scheduled:
                assert isinstance(item, Task)
                dispatched_resources.append(item.resource)
            if dispatch_mode in {"claimed_timeout", "stale_epoch"}:
                admission_row = store.connection.execute(
                    "SELECT admission_id FROM candidate_dispatch_admissions WHERE candidate_id=?",
                    (candidate.candidate_id,),
                ).fetchone()
                assert admission_row is not None
                repo = CandidateDispatchAdmissionRepository(store)
                admission = repo.readback(str(admission_row[0]))
                repo.claim_for_worker(
                    admission.admission_id,
                    case_id=opened.case.case_id,
                    epoch_state_version=opened.case.state_version,
                    task_id=scheduled[0].task_id,
                    invocation_sha256=candidate.invocation_sha256,
                )
                if dispatch_mode == "stale_epoch":
                    store.connection.execute(
                        "UPDATE cases SET state_version=? WHERE case_id=?",
                        (opened.case.state_version + 1, str(opened.case.case_id)),
                    )
                terminal = TaskResult(
                    task_id=scheduled[0].task_id,
                    status=(
                        TaskStatus.STALE if dispatch_mode == "stale_epoch" else TaskStatus.TIMED_OUT
                    ),
                    started_at=admission.admitted_at,
                    finished_at=utc_now(),
                    duration_ms=1.0,
                    state_version=opened.case.state_version,
                )
                persist = cast("Callable[[TaskResult], None]", kwargs["on_result"])
                persist(terminal)
                return (terminal,)
            if dispatch_mode == "queued_target_change":
                _snapshot(
                    store,
                    opened.case.case_id,
                    processes=[_process(43, started - timedelta(minutes=1))],
                    at=utc_now(),
                )
            return original_run(*args, **kwargs)  # pyright: ignore[reportArgumentType]

        monkeypatch.setattr(
            runtime._scheduler,  # pyright: ignore[reportPrivateUsage]
            "run_blocking",
            inspect_dispatch,
        )
        if dispatch_mode == "preflight_change":

            def no_longer_current(
                _store: SQLiteStore,
                _case_id: CaseId,
                _binding: ProcessTargetBinding | InventoryProcessBinding,
            ) -> bool:
                return False

            monkeypatch.setattr(runtime_module, "_process_binding_still_current", no_longer_current)
        result = runtime.execute_candidate_measurement(
            opened,
            candidate.candidate_id,
            snapshot.snapshot_id,
        )
        assert isinstance(result, tuple) is (dispatch_mode != "preflight_change")
        assert dispatched_resources == (
            [] if dispatch_mode == "preflight_change" else [ResourceClass.PROCESS]
        )
        assert sampled[0]["pid"] == 42 if dispatch_mode == "normal" else not sampled
        admission_row = store.connection.execute(
            "SELECT admission_id FROM candidate_dispatch_admissions WHERE candidate_id=?",
            (candidate.candidate_id,),
        ).fetchone()
        assert admission_row is not None
        admission = CandidateDispatchAdmissionRepository(store).readback(str(admission_row[0]))
        assert admission.outcome_status == (
            "linked"
            if dispatch_mode == "normal"
            else "claimed_unlinked"
            if dispatch_mode in {"claimed_timeout", "stale_epoch"}
            else "unclaimed"
        )
        assert len(
            CandidateDecisionSnapshotRepository(store).execution_links(snapshot.snapshot_id)
        ) == (1 if dispatch_mode == "normal" else 0)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='application.target_pressure'",
            (str(opened.case.case_id),),
        ).fetchone() == ((1 if dispatch_mode == "normal" else 0),)
        assert store.connection.execute("SELECT COUNT(*) FROM case_process_targets").fetchone() == (
            0,
        )
        replay = runtime.execute_candidate_measurement(
            opened,
            candidate.candidate_id,
            snapshot.snapshot_id,
        )
        assert not isinstance(replay, tuple)
        assert len(sampled) == (1 if dispatch_mode == "normal" else 0)


def test_stale_snapshot_rejects_binding_but_case_progress_keeps_candidate(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)], at=NOW - timedelta(minutes=6))
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        with pytest.raises(TargetSelectionError, match="stale"):
            targets.list_process_candidates(case_id)

        _snapshot(store, case_id, processes=[_process(42)], at=NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        store.connection.execute(
            "UPDATE cases SET state_version = 1 WHERE case_id = ?", (str(case_id),)
        )
        assert targets.bind_process_target(case_id, candidate_id).case_state_version == 1


def test_candidate_cap_reports_unlisted_processes_without_inference(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(pid) for pid in range(1, 71)], omitted=3)
        inventory = ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(
            case_id
        )
        assert len(inventory.candidates) == 64
        assert inventory.omitted_process_count == 9
        assert all(candidate.omitted_process_count == 9 for candidate in inventory.candidates)
        assert inventory.inventory_complete is False


@pytest.mark.parametrize("status", ["failed", "unsupported", "permission_denied"])
def test_failed_snapshot_cannot_supply_process_target(tmp_path: Path, status: str) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        evidence_id = _snapshot(store, case_id, processes=[_process(42)])
        assert store.connection.execute(
            "SELECT json_extract(record_json, '$.facts[2].name') FROM evidence "
            "WHERE case_id = ? AND evidence_id = ?",
            (str(case_id), str(evidence_id)),
        ).fetchone() == ("collection_status",)
        store.connection.execute(
            "UPDATE evidence SET record_json = json_set(record_json, '$.facts[2].value', ?) "
            "WHERE case_id = ? AND evidence_id = ?",
            (status, str(case_id), str(evidence_id)),
        )
        with pytest.raises(TargetSelectionError):
            ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(case_id)


def test_sampling_resolver_rejects_expired_and_superseded_binding(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        bound = targets.bind_process_target(case_id, candidate_id)
        assert targets.resolve_process_target_for_sampling(case_id) == bound

        expired = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=301))
        assert expired.selected_process_target(case_id) == bound  # Display only.
        with pytest.raises(TargetSelectionError, match="stale"):
            expired.resolve_process_target_for_sampling(case_id)

        _snapshot(store, case_id, processes=[_process(43)], at=NOW + timedelta(seconds=2))
        with pytest.raises(TargetSelectionError):
            targets.resolve_process_target_for_sampling(case_id)


def test_sampling_resolver_keeps_binding_across_case_progress(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        bound = targets.bind_process_target(case_id, candidate_id)
        store.connection.execute(
            "UPDATE cases SET state_version = 1 WHERE case_id = ?", (str(case_id),)
        )
        assert targets.resolve_process_target_for_sampling(case_id) == bound


@pytest.mark.parametrize("checkpoint_status", ["complete", "cancelled", "failed"])
def test_terminal_investigation_rejects_selection(tmp_path: Path, checkpoint_status: str) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id, record_json) VALUES (?, ?)",
            (str(case_id), f'{{"status":"{checkpoint_status}"}}'),
        )
        with pytest.raises(TargetSelectionError, match="not active"):
            targets.bind_process_target(case_id, candidate_id)


def test_unregistered_snapshot_version_rejects_candidates(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)], collector_version=2)
        with pytest.raises(TargetSelectionError, match="binding"):
            ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(case_id)


def test_newer_snapshot_invalidates_old_candidate_even_with_same_pid(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)], at=NOW - timedelta(seconds=30))
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        old_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        _snapshot(store, case_id, processes=[_process(42, NOW - timedelta(seconds=10))])

        with pytest.raises(TargetSelectionError):
            targets.bind_process_target(case_id, old_id)
        new_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        assert new_id != old_id


def test_ambiguous_process_identity_rejects_inventory(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42), _process(42)])
        with pytest.raises(TargetSelectionError, match="ambiguous"):
            ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(case_id)
