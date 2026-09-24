"""A candidate choice is bound to a frozen local registry row, not a probe name."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
)
from systemsense.decision.contracts import DiagnosticPurpose, ProviderIdentity
from systemsense.domain.ids import CaseId, ExecutionId
from systemsense.domain.probes import ProbeInvocation, SafetyClass
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime.now(UTC)
_EPOCH = 3
_PROVIDER = ProviderIdentity(provider_id="fixture-fast", provider_version="1", role="fast_decision")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidate(
    store: SQLiteStore, case_id: CaseId, ordinal: int
) -> tuple[AdmittedCandidateRefV1, ProbeInvocation]:
    candidate_id = f"cand_v1_{ordinal:032x}"
    invocation = ProbeInvocation(
        probe_id="fixture.pressure",
        probe_version=1,
        observable="fixture.pressure",
        target_handle=f"proc_{ordinal:032x}",
        parameters={"pid": 100 + ordinal},
    )
    invocation_json = _canonical(invocation.model_dump(mode="json"))
    manifest_hash = _digest("fixture-manifest")
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
            manifest_hash,
            invocation_json,
            _digest(invocation_json),
            invocation.observable,
            invocation.target_handle,
            "ev_" + "f" * 32,
            _digest("source"),
            "[]",
            _digest("[]"),
            _digest(candidate_id),
            100,
            ResourceClass.CPU.value,
            SafetyClass.R1.value,
            f"Pressure for local process {ordinal}",
            (_NOW - timedelta(seconds=5)).isoformat(),
            (_NOW + timedelta(hours=1)).isoformat(),
        ),
    )
    return (
        AdmittedCandidateRefV1(
            candidate_id=candidate_id,
            probe_id=invocation.probe_id,
            description=f"Pressure for local process {ordinal}",
            manifest_sha256=manifest_hash,
            invocation_sha256=_digest(invocation_json),
            cost_ms=100,
            resource_class=ResourceClass.CPU,
            safety_class=SafetyClass.R1,
        ),
        invocation,
    )


def _setup(
    store: SQLiteStore,
) -> tuple[CandidateDecisionRequestV1, CandidateDecisionResponseV1, tuple[ProbeInvocation, ...]]:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind="general",
        symptom="Slow app",
        created_at=_NOW.isoformat(),
        status="collecting",
        state_version=_EPOCH,
    )
    pairs = (_candidate(store, case_id, 1), _candidate(store, case_id, 2))
    refs = tuple(pair[0] for pair in pairs)
    request = CandidateDecisionRequestV1(
        case_id=case_id,
        state_version=_EPOCH,
        correlation_id="fixture:1",
        deadline_at=_NOW + timedelta(hours=1),
        symptom="Slow app",
        available_candidates=refs,
        budget_ms=500,
        max_candidates=2,
    )
    response = CandidateDecisionResponseV1(
        provider=_PROVIDER,
        case_id=case_id,
        state_version=_EPOCH,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        ranked_candidate_ids=(refs[1].candidate_id, refs[0].candidate_id),
        considered_candidate_ids=(refs[0].candidate_id, refs[1].candidate_id),
        proposals=(
            CandidateProposalV1(
                candidate_id=refs[1].candidate_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
            ),
        ),
    )
    return request, response, tuple(pair[1] for pair in pairs)


def test_capture_readback_and_exact_selected_identity(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "candidate-snapshot.db") as store:
        request, response, invocations = _setup(store)
        repo = CandidateDecisionSnapshotRepository(store)
        captured = repo.capture(request, response, request_frozen_at=_NOW)
        readback = repo.readback(captured.snapshot_id)
        assert readback.request == request
        assert readback.response == response
        assert readback.registry_source_eligibility_proven is False
        assert readback.training_admissible is False
        assert readback.candidate_ids == tuple(
            candidate.candidate_id for candidate in request.available_candidates
        )
        selected_id = request.available_candidates[1].candidate_id
        assert (
            repo.verify_selection(
                captured.snapshot_id,
                request.case_id,
                _EPOCH,
                selected_id,
                request.available_candidates[1].invocation_sha256,
            ).candidate_id
            == selected_id
        )
        with pytest.raises(ValueError):
            repo.verify_selection(
                captured.snapshot_id,
                request.case_id,
                _EPOCH,
                request.available_candidates[0].candidate_id,
                request.available_candidates[0].invocation_sha256,
            )
        with pytest.raises(ValueError):
            repo.verify_selection(
                captured.snapshot_id,
                request.case_id,
                _EPOCH + 1,
                selected_id,
                request.available_candidates[1].invocation_sha256,
            )
        assert invocations[0].probe_id == invocations[1].probe_id
        assert invocations[0].target_handle != invocations[1].target_handle


def test_gap_and_registry_tamper_fail_closed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "candidate-gap.db") as store:
        request, response, _ = _setup(store)
        repo = CandidateDecisionSnapshotRepository(store)
        gap = CandidateDecisionGapV1(
            provider=_PROVIDER,
            case_id=request.case_id,
            state_version=_EPOCH,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            reason_code="ranker_unavailable",
        )
        snapshot = repo.capture(request, gap, request_frozen_at=_NOW)
        assert repo.readback(snapshot.snapshot_id).response == gap
        with pytest.raises(ValueError):
            repo.verify_selection(
                snapshot.snapshot_id,
                request.case_id,
                _EPOCH,
                request.available_candidates[0].candidate_id,
                request.available_candidates[0].invocation_sha256,
            )
        with pytest.raises(ValueError):
            repo.capture(
                request.model_copy(
                    update={"available_candidates": tuple(reversed(request.available_candidates))}
                ),
                response,
                request_frozen_at=_NOW,
            )
        store.connection.execute("DROP TRIGGER case_measurement_candidates_no_update")
        store.connection.execute(
            "UPDATE case_measurement_candidates SET description='tampered' WHERE candidate_id=?",
            (request.available_candidates[0].candidate_id,),
        )
        with pytest.raises(ValueError):
            repo.readback(snapshot.snapshot_id)


def test_expired_decision_or_non_collecting_case_cannot_dispatch(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "candidate-deadline.db") as store:
        request, response, _ = _setup(store)
        clock = [_NOW + timedelta(seconds=1)]
        repo = CandidateDecisionSnapshotRepository(store, clock=lambda: clock[0])
        selected = request.available_candidates[1]
        captured = repo.capture(request, response, request_frozen_at=_NOW)
        clock[0] = request.deadline_at
        with pytest.raises(ValueError):
            repo.verify_selection(
                captured.snapshot_id,
                request.case_id,
                _EPOCH,
                selected.candidate_id,
                selected.invocation_sha256,
            )
        with pytest.raises(ValueError):
            repo.capture(request, response, request_frozen_at=_NOW)
        gap = CandidateDecisionGapV1(
            provider=_PROVIDER,
            case_id=request.case_id,
            state_version=_EPOCH,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            reason_code="deadline_unavailable",
        )
        assert isinstance(
            repo.capture(request, gap, request_frozen_at=_NOW).response, CandidateDecisionGapV1
        )
        clock[0] = _NOW + timedelta(seconds=2)
        store.connection.execute(
            "UPDATE cases SET status='resolved' WHERE case_id=?", (str(request.case_id),)
        )
        with pytest.raises(ValueError):
            repo.verify_selection(
                captured.snapshot_id,
                request.case_id,
                _EPOCH,
                selected.candidate_id,
                selected.invocation_sha256,
            )
        with pytest.raises(ValueError):
            repo.capture(request, response, request_frozen_at=_NOW)


def test_execution_link_requires_exact_selected_invocation_and_caller_transaction(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "candidate-link.db") as store:
        request, response, invocations = _setup(store)
        repo = CandidateDecisionSnapshotRepository(store)
        snapshot = repo.capture(request, response, request_frozen_at=_NOW)
        selected_id = request.available_candidates[1].candidate_id
        execution_id = str(ExecutionId.new())
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(request.case_id),
                probe_id=invocations[1].probe_id,
                probe_version=invocations[1].probe_version,
                status="ok",
                parameters_json=_canonical(invocations[1].parameters),
                started_at=snapshot.captured_at.isoformat(),
                finished_at=datetime.now(UTC).isoformat(),
                state_version=_EPOCH,
            )
            with pytest.raises(ValueError):
                repo.link_execution(snapshot.snapshot_id, selected_id, execution_id, invocations[0])
            repo.link_execution(snapshot.snapshot_id, selected_id, execution_id, invocations[1])
        links = repo.execution_links(snapshot.snapshot_id)
        assert len(links) == 1
        assert links[0].candidate_id == selected_id
        assert links[0].executed_invocation == invocations[1]
        assert links[0].runner_consumption_proven is False
        assert links[0].same_transaction_insert_proven is False
        with pytest.raises((ValueError, sqlite3.IntegrityError)):
            repo.link_execution(snapshot.snapshot_id, selected_id, execution_id, invocations[1])
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute(
                "UPDATE candidate_decision_execution_links SET candidate_id=? WHERE execution_id=?",
                (request.available_candidates[0].candidate_id, execution_id),
            )
        second_snapshot = repo.capture(request, response, request_frozen_at=_NOW)
        with pytest.raises(sqlite3.IntegrityError):
            with store.transaction() as transaction:
                second_execution = str(ExecutionId.new())
                transaction.record_probe_execution(
                    execution_id=second_execution,
                    case_id=str(request.case_id),
                    probe_id=invocations[1].probe_id,
                    probe_version=invocations[1].probe_version,
                    status="ok",
                    parameters_json=_canonical(invocations[1].parameters),
                    started_at=second_snapshot.captured_at.isoformat(),
                    finished_at=datetime.now(UTC).isoformat(),
                    state_version=_EPOCH,
                )
                repo.link_execution(
                    second_snapshot.snapshot_id, selected_id, second_execution, invocations[1]
                )


def test_execution_started_before_decision_deadline_can_link_after_finish(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "late-finish.db") as store:
        request, response, invocations = _setup(store)
        clock = [_NOW]
        repo = CandidateDecisionSnapshotRepository(store, clock=lambda: clock[0])
        snapshot = repo.capture(request, response, request_frozen_at=_NOW)
        candidate_id = request.available_candidates[1].candidate_id
        execution_id = str(ExecutionId.new())
        started = request.deadline_at - timedelta(seconds=1)
        finished = request.deadline_at + timedelta(seconds=1)
        clock[0] = finished + timedelta(seconds=1)
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(request.case_id),
                probe_id=invocations[1].probe_id,
                probe_version=invocations[1].probe_version,
                status="ok",
                parameters_json=_canonical(invocations[1].parameters),
                started_at=started.isoformat(),
                finished_at=finished.isoformat(),
                state_version=_EPOCH,
            )
            repo.link_execution(snapshot.snapshot_id, candidate_id, execution_id, invocations[1])
        assert repo.execution_links(snapshot.snapshot_id)[0].execution_id == execution_id
