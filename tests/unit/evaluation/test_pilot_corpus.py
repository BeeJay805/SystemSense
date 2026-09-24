"""A pilot inventory must not turn candidate custody into training labels."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
)
from systemsense.decision.contracts import DiagnosticPurpose, ProviderIdentity
from systemsense.domain.ids import CaseId, ExecutionId
from systemsense.domain.probes import ProbeInvocation, SafetyClass
from systemsense.evaluation.pilot_corpus import (
    PilotCaseRegistration,
    assemble_pilot_corpus,
    verify_pilot_corpus,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime.now(UTC) - timedelta(minutes=1)
_EPOCH = 3
_PROVIDER = ProviderIdentity(provider_id="fixture-fast", provider_version="1", role="fast_decision")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _snapshot(
    store: SQLiteStore, *, machine_key: str = "machine-a"
) -> tuple[CandidateDecisionSnapshotRepository, str, tuple[ProbeInvocation, ...]]:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind="general",
        symptom="Slow application",
        created_at=_NOW.isoformat(),
        status="collecting",
        state_version=_EPOCH,
    )
    references: list[AdmittedCandidateRefV1] = []
    invocations: list[ProbeInvocation] = []
    for ordinal in (1, 2):
        candidate_id = (
            f"cand_v1_{ordinal:032x}"
            if machine_key == "machine-a"
            else f"cand_v1_{ordinal + 10:032x}"
        )
        invocation = ProbeInvocation(
            probe_id="fixture.pressure",
            probe_version=1,
            observable="fixture.pressure",
            target_handle=f"proc_{ordinal:032x}",
            parameters={"pid": 100 + ordinal},
        )
        invocation_json = _canonical(invocation.model_dump(mode="json"))
        description = f"Pressure for process {ordinal}"
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
                _digest("fixture-manifest"),
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
                description,
                (_NOW - timedelta(seconds=5)).isoformat(),
                (_NOW + timedelta(hours=1)).isoformat(),
            ),
        )
        references.append(
            AdmittedCandidateRefV1(
                candidate_id=candidate_id,
                probe_id=invocation.probe_id,
                description=description,
                manifest_sha256=_digest("fixture-manifest"),
                invocation_sha256=_digest(invocation_json),
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                safety_class=SafetyClass.R1,
            )
        )
        invocations.append(invocation)
    request = CandidateDecisionRequestV1(
        case_id=case_id,
        state_version=_EPOCH,
        correlation_id="fixture:1",
        deadline_at=_NOW + timedelta(hours=1),
        symptom="Slow application",
        available_candidates=tuple(references),
        budget_ms=500,
        max_candidates=2,
    )
    response = CandidateDecisionResponseV1(
        provider=_PROVIDER,
        case_id=case_id,
        state_version=_EPOCH,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        ranked_candidate_ids=(references[1].candidate_id, references[0].candidate_id),
        considered_candidate_ids=(references[0].candidate_id, references[1].candidate_id),
        proposals=(
            CandidateProposalV1(
                candidate_id=references[1].candidate_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
            ),
        ),
    )
    snapshots = CandidateDecisionSnapshotRepository(
        store, clock=lambda: _NOW + timedelta(seconds=1)
    )
    return (
        snapshots,
        snapshots.capture(request, response, request_frozen_at=_NOW).snapshot_id,
        tuple(invocations),
    )


def _registration(
    snapshot_id: str, *, split: str = "train", machine: str = "machine-a"
) -> PilotCaseRegistration:
    return PilotCaseRegistration(
        snapshot_id=snapshot_id,
        split=split,
        source_kind="fixture_contract",
        source_artifact_sha256=_digest("fixture-artifact"),
        machine_key=machine,
        fault_family="process-pressure",
        application_key="pdf-reader",
        application_version="1",
    )


def test_two_targets_of_one_probe_remain_distinct_and_unknown(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshots, snapshot_id, _ = _snapshot(store)
        corpus = assemble_pilot_corpus(store, snapshots, (_registration(snapshot_id),))
    assert corpus.training_admissible is False
    assert corpus.diagnostic_performance_admissible is False
    assert corpus.source_counts == {"fixture_contract": 1}
    assert corpus.label_quality_counts == {"unknown": 2}
    assert len(corpus.split_groups) == 5
    assert len(corpus.episodes) == 1
    candidates = corpus.episodes[0].candidates
    assert candidates[0].probe_id == candidates[1].probe_id
    assert candidates[0].candidate_id != candidates[1].candidate_id
    assert candidates[0].invocation_sha256 != candidates[1].invocation_sha256
    assert all(item.utility == "unknown" and item.execution_id is None for item in candidates)
    assert verify_pilot_corpus(corpus) == corpus.manifest_sha256


def test_linked_observation_is_unreviewed_not_a_usefulness_label(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshots, snapshot_id, invocations = _snapshot(store)
        snapshots = CandidateDecisionSnapshotRepository(store)
        snapshot = snapshots.readback(snapshot_id)
        chosen = snapshot.request.available_candidates[1]
        admission_id = "candidate_admission_" + "1" * 32
        execution_id = str(ExecutionId.new())
        admitted = _NOW + timedelta(seconds=2)
        claimed = _NOW + timedelta(seconds=3)
        started = _NOW + timedelta(seconds=4)
        finished = _NOW + timedelta(seconds=5)
        with store.transaction() as transaction:
            store.connection.execute(
                "INSERT INTO candidate_dispatch_admissions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    admission_id,
                    1,
                    snapshot_id,
                    chosen.candidate_id,
                    str(snapshot.case_id),
                    _EPOCH,
                    "fixture:task",
                    chosen.invocation_sha256,
                    100,
                    admitted.isoformat(),
                ),
            )
            store.connection.execute(
                "INSERT INTO candidate_dispatch_claims VALUES (?,?,?,?,?,?)",
                (
                    admission_id,
                    str(snapshot.case_id),
                    _EPOCH,
                    "fixture:task",
                    chosen.invocation_sha256,
                    claimed.isoformat(),
                ),
            )
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(snapshot.case_id),
                probe_id=invocations[1].probe_id,
                probe_version=invocations[1].probe_version,
                status="ok",
                parameters_json=_canonical(invocations[1].parameters),
                started_at=started.isoformat(),
                finished_at=finished.isoformat(),
                state_version=_EPOCH,
            )
            snapshots.link_execution(snapshot_id, chosen.candidate_id, execution_id, invocations[1])
        corpus = assemble_pilot_corpus(store, snapshots, (_registration(snapshot_id),))
    assert corpus.label_quality_counts == {"unknown": 1, "execution_recorded_unreviewed": 1}
    assert corpus.episodes[0].candidates[0].execution_id is None
    observed = corpus.episodes[0].candidates[1]
    assert observed.execution_id == execution_id
    assert observed.execution_status == "ok"
    assert observed.utility == "unknown"


def test_snapshot_link_without_one_shot_dispatch_custody_is_rejected(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshots, snapshot_id, invocations = _snapshot(store)
        snapshots = CandidateDecisionSnapshotRepository(store)
        snapshot = snapshots.readback(snapshot_id)
        execution_id = str(ExecutionId.new())
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(snapshot.case_id),
                probe_id=invocations[1].probe_id,
                probe_version=invocations[1].probe_version,
                status="ok",
                parameters_json=_canonical(invocations[1].parameters),
                started_at=(_NOW + timedelta(seconds=2)).isoformat(),
                finished_at=(_NOW + timedelta(seconds=3)).isoformat(),
                state_version=_EPOCH,
            )
            snapshots.link_execution(
                snapshot_id,
                snapshot.request.available_candidates[1].candidate_id,
                execution_id,
                invocations[1],
            )
        with pytest.raises(ValueError, match="dispatch admission"):
            assemble_pilot_corpus(store, snapshots, (_registration(snapshot_id),))


def test_split_groups_and_duplicate_snapshot_fail_closed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshots_a, snapshot_a, _ = _snapshot(store)
        snapshots_b, snapshot_b, _ = _snapshot(store, machine_key="machine-b")
        with pytest.raises(ValueError, match="group crosses"):
            assemble_pilot_corpus(
                store,
                snapshots_a,
                (
                    _registration(snapshot_a),
                    _registration(snapshot_b, split="heldout", machine="machine-a"),
                ),
            )
        with pytest.raises(ValueError, match="duplicate snapshot"):
            assemble_pilot_corpus(
                store, snapshots_b, (_registration(snapshot_a), _registration(snapshot_a))
            )


def test_pilot_manifest_rejects_promoted_labels_and_mutation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshots, snapshot_id, _ = _snapshot(store)
        corpus = assemble_pilot_corpus(store, snapshots, (_registration(snapshot_id),))
    with pytest.raises(ValueError):
        verify_pilot_corpus(corpus.model_copy(update={"training_admissible": True}))
    altered = corpus.episodes[0].candidates[0].model_copy(update={"utility": "negative"})
    episode = corpus.episodes[0].model_copy(
        update={"candidates": (altered, *corpus.episodes[0].candidates[1:])}
    )
    with pytest.raises(ValueError):
        verify_pilot_corpus(corpus.model_copy(update={"episodes": (episode,)}))
    conflicting = corpus.split_groups[0].model_copy(update={"split": "heldout"})
    with pytest.raises(ValueError, match="group crosses"):
        verify_pilot_corpus(
            corpus.model_copy(update={"split_groups": (*corpus.split_groups, conflicting)})
        )


def test_unqualified_source_cannot_be_promoted_into_pilot(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshots, snapshot_id, _ = _snapshot(store)
        claim = _registration(snapshot_id).model_copy(
            update={"source_kind": "controlled_windows_vm"}
        )
        with pytest.raises(ValueError):
            assemble_pilot_corpus(store, snapshots, (claim,))


def test_unclaimed_dispatch_consumes_attempt_but_not_measurement(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshots, snapshot_id, _ = _snapshot(store)
        snapshot = snapshots.readback(snapshot_id)
        chosen = snapshot.request.available_candidates[1]
        store.connection.execute(
            "INSERT INTO candidate_dispatch_admissions VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                "candidate_admission_" + "2" * 32,
                1,
                snapshot_id,
                chosen.candidate_id,
                str(snapshot.case_id),
                _EPOCH,
                "fixture:pending",
                chosen.invocation_sha256,
                100,
                (_NOW + timedelta(seconds=2)).isoformat(),
            ),
        )
        corpus = assemble_pilot_corpus(store, snapshots, (_registration(snapshot_id),))
    pending = corpus.episodes[0].candidates[1]
    assert pending.dispatch_status == "unclaimed"
    assert pending.execution_id is None
    assert pending.label_quality == "unknown"
