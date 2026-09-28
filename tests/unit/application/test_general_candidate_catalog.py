"""General measurements are bound to exact current-case baseline evidence."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application import candidate_catalog
from systemsense.application.case_service import CaseService
from systemsense.application.frontier_discovery import seed_frontier_discovery
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime, PersistedProbeResult
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
from systemsense.domain.probes import MeasurementNeed, MeasurementWindow, ProbeInvocation
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.knowledge.models import KnowledgePacket
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import TaskStatus
from systemsense.packs.runtime import (
    LiveSampleWindowParametersV1,
    default_probe_definitions,
    default_probe_runner,
)
from systemsense.policy import PolicyDenied
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import CandidateGap, CandidateGapReason, CandidateRecord
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.search_frontier import RelevantVersionsV1, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime.now(UTC)
EPOCH = 2


@pytest.fixture(autouse=True)
def _refresh_case_clock() -> None:  # pyright: ignore[reportUnusedFunction]
    # This module is collected before a long suite reaches these tests. Keep
    # per-test deadlines current while preserving a shared anchor within each test.
    global NOW
    NOW = datetime.now(UTC)  # pyright: ignore[reportConstantRedefinition]


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind="general",
        symptom="Intermittent slowdown",
        created_at=(NOW - timedelta(minutes=1)).isoformat(),
        status="collecting",
        state_version=EPOCH,
    )
    store.connection.execute(
        "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
        (
            str(case_id),
            json.dumps(
                {
                    "case_id": str(case_id),
                    "state_version": EPOCH,
                    "status": "running",
                    "deadline_at": (NOW + timedelta(minutes=5)).isoformat(),
                    "budget_ms": 20_000,
                    "spent_cost_ms": 0,
                    "max_probes": 3,
                    "completed_probe_ids": [],
                    "pending_probe_ids": [],
                    "interrupted_probe_ids": [],
                    "unrecorded_attempt_count": 0,
                }
            ),
        ),
    )
    return case_id


def _source(
    store: SQLiteStore,
    case_id: CaseId,
    *,
    age_seconds: int,
    status: str = "ok",
    time_basis: str = "collector_observed",
    epoch: int = EPOCH,
    probe_id: str = "core.resources",
    source_type: str = "systemsense.probe",
    collector_probe_id: str | None = None,
) -> EvidenceId:
    evidence_id, execution_id = EvidenceId.new(), ExecutionId.new()
    observed = NOW - timedelta(seconds=age_seconds)
    manifest = default_probe_runner().manifest(probe_id)
    assert manifest is not None
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": probe_id, "probe_version": manifest.version}
    )
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed,
        captured_at=observed,
        source=EvidenceSource(
            type=source_type,
            source_id=source_id,
            locator={"probe_id": probe_id},
        ),
        collector=CollectorReference(
            id=probe_id if collector_probe_id is None else collector_probe_id,
            version=manifest.version,
            execution_id=execution_id,
        ),
        summary="Resource baseline",
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id=probe_id,
            probe_version=manifest.version,
            status=status,
            parameters_json="{}",
            started_at=(observed - timedelta(seconds=1)).isoformat(),
            finished_at=observed.isoformat(),
            state_version=epoch,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=observed.isoformat(),
            captured_at=observed.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis=time_basis,
            time_quality="exact",
        )
    return evidence_id


@pytest.mark.parametrize(
    ("parent_probe", "choice_probe"),
    (
        ("core.resources", "storage.snapshot"),
        ("network.connectivity", "network.configuration"),
    ),
)
def test_passive_choice_uses_exact_registered_no_parameter_parent(
    tmp_path: Path, parent_probe: str, choice_probe: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        source = _source(store, case_id, age_seconds=1, probe_id=parent_probe)
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        need = next(item for item in needs if item.capability_id == choice_probe)
        candidate = registry.issue(case_id, EPOCH, need)
        assert not isinstance(candidate, CandidateGap)
        resolved = registry.resolve(case_id, EPOCH, candidate.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        assert resolved.invocation.probe_id == choice_probe
        assert resolved.invocation.parameters == {}
        assert resolved.invocation.target_handle is None
        assert resolved.invocation.window is None
        row = store.connection.execute(
            "SELECT source_evidence_id FROM case_measurement_candidates WHERE candidate_id=?",
            (candidate.candidate_id,),
        ).fetchone()
        assert row == (str(source),)


@pytest.mark.parametrize(
    ("parent_probe", "choice_probe", "ttl"),
    (
        ("core.resources", "storage.snapshot", 300),
        ("network.connectivity", "network.configuration", 60),
    ),
)
def test_passive_choice_rejects_failed_stale_or_foreign_source(
    tmp_path: Path, parent_probe: str, choice_probe: str, ttl: int
) -> None:
    runner = default_probe_runner()
    for label, age, status in (("failed", 1, "failed"), ("stale", ttl + 1, "ok")):
        with SQLiteStore(tmp_path / f"{label}.db") as store:
            case_id = _case(store)
            _source(store, case_id, age_seconds=age, status=status, probe_id=parent_probe)
            _, needs = candidate_catalog.general_measurement_candidate_catalog(
                store, runner, case_id, clock=lambda: NOW
            )
            assert choice_probe not in {need.capability_id for need in needs}
    with SQLiteStore(tmp_path / "foreign.db") as store:
        case_id = _case(store)
        other_case_id = _case(store)
        _source(store, other_case_id, age_seconds=1, probe_id=parent_probe)
        _, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        assert choice_probe not in {need.capability_id for need in needs}
    for label, source_type, collector_probe_id, time_basis in (
        ("wrong-collector", "systemsense.probe", "core.system", "collector_observed"),
        ("wrong-source", "fixture.parent", None, "collector_observed"),
        ("untrusted-time", "systemsense.probe", None, "source_event"),
    ):
        with SQLiteStore(tmp_path / f"{label}.db") as store:
            case_id = _case(store)
            _source(
                store,
                case_id,
                age_seconds=1,
                probe_id=parent_probe,
                source_type=source_type,
                collector_probe_id=collector_probe_id,
                time_basis=time_basis,
            )
            _, needs = candidate_catalog.general_measurement_candidate_catalog(
                store, runner, case_id, clock=lambda: NOW
            )
            assert choice_probe not in {need.capability_id for need in needs}


@pytest.mark.parametrize(
    ("parent_probe", "choice_probe"),
    (("core.resources", "storage.snapshot"), ("network.connectivity", "network.configuration")),
)
def test_passive_choice_refuses_model_selectors_and_unknown_probe(
    tmp_path: Path, parent_probe: str, choice_probe: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=1, probe_id=parent_probe)
        registry, _ = candidate_catalog.general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        manifest = default_probe_runner().manifest(choice_probe)
        assert manifest is not None
        with pytest.raises(PolicyDenied):
            default_probe_runner().prepare_invocation(
                choice_probe,
                {"path": "https://untrusted.example"},
                expected_version=manifest.version,
            )
        with pytest.raises(ValueError):
            MeasurementNeed(
                capability_id=choice_probe,
                observable=choice_probe,
                target_handle="https://untrusted.example/path",
            )
        for need in (
            MeasurementNeed(
                capability_id=choice_probe,
                observable=choice_probe,
                target_handle="target:untrusted",
            ),
            MeasurementNeed(
                capability_id=choice_probe,
                observable=choice_probe,
                window=MeasurementWindow(
                    start=NOW - timedelta(seconds=6), end=NOW + timedelta(seconds=6)
                ),
            ),
            MeasurementNeed(capability_id="arbitrary.command", observable="arbitrary.command"),
        ):
            assert isinstance(registry.issue(case_id, EPOCH, need), CandidateGap)


@pytest.mark.parametrize(
    ("parent_probe", "choice_probe"),
    (("core.resources", "storage.snapshot"), ("network.connectivity", "network.configuration")),
)
def test_passive_claim_reconstructs_admitted_source_not_newest(
    tmp_path: Path, parent_probe: str, choice_probe: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        runner = default_probe_runner()
        first = _source(store, case_id, age_seconds=10, probe_id=parent_probe)
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        need = next(item for item in needs if item.capability_id == choice_probe)
        candidate = registry.issue(case_id, EPOCH, need)
        assert not isinstance(candidate, CandidateGap)
        snapshot_id = _snapshot_for_candidate(store, case_id, candidate, NOW + timedelta(minutes=3))
        admission = CandidateDispatchAdmissionRepository(store, registry=registry).admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=EPOCH,
            task_id=f"probe-0-{choice_probe}",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )
        _source(store, case_id, age_seconds=1, probe_id=parent_probe)
        exact, new_needs = candidate_catalog.general_measurement_candidate_catalog(
            store,
            runner,
            case_id,
            for_existing_admission=True,
            for_existing_candidate_id=candidate.candidate_id,
            clock=lambda: NOW,
        )
        assert new_needs == ()
        resolved = exact.resolve_for_claim(
            case_id, EPOCH, candidate.candidate_id, admission.admission_id
        )
        assert not isinstance(resolved, CandidateGap)
        row = store.connection.execute(
            "SELECT source_evidence_id FROM case_measurement_candidates WHERE candidate_id=?",
            (candidate.candidate_id,),
        ).fetchone()
        assert row == (str(first),)


@pytest.mark.parametrize(
    ("parent_probe", "choice_probe"),
    (("core.resources", "storage.snapshot"), ("network.connectivity", "network.configuration")),
)
def test_passive_admission_rejects_a_different_valid_parent_execution(
    tmp_path: Path, parent_probe: str, choice_probe: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10, probe_id=parent_probe)
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        need = next(item for item in needs if item.capability_id == choice_probe)
        candidate = registry.issue(case_id, EPOCH, need)
        assert not isinstance(candidate, CandidateGap)
        snapshot_id = _snapshot_for_candidate(store, case_id, candidate, NOW + timedelta(minutes=3))
        wrong_source = _source(store, case_id, age_seconds=5, probe_id="core.system")
        row = store.connection.execute(
            "SELECT execution_id FROM evidence WHERE case_id=? AND evidence_id=?",
            (str(case_id), str(wrong_source)),
        ).fetchone()
        assert row is not None
        wrong_execution = str(row[0])
        wrong_digest = FollowupAdmissionRepository(store).parent_evidence_digest(
            str(case_id), wrong_execution
        )
        repo = CandidateDispatchAdmissionRepository(store, registry=registry)
        with pytest.raises(ValueError, match="exact parent"):
            repo.admit_after_parent(
                snapshot_id=snapshot_id,
                candidate_id=candidate.candidate_id,
                case_id=case_id,
                epoch_state_version=EPOCH,
                task_id=f"probe-0-{choice_probe}",
                invocation_sha256=candidate.invocation_sha256,
                cost_ms=candidate.cost_ms,
                trigger_execution_id=wrong_execution,
                trigger_evidence_sha256=wrong_digest,
            )
        assert (
            store.connection.execute(
                "SELECT 1 FROM candidate_dispatch_admissions WHERE candidate_id=?",
                (candidate.candidate_id,),
            ).fetchone()
            is None
        )


@pytest.mark.parametrize(
    ("parent_probe", "choice_probe"),
    (("core.resources", "storage.snapshot"), ("network.connectivity", "network.configuration")),
)
def test_passive_choice_fails_closed_on_manifest_change_expiry_or_case_closure(
    tmp_path: Path, parent_probe: str, choice_probe: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=1, probe_id=parent_probe)
        now = [NOW]
        runner = default_probe_runner()
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, clock=lambda: now[0]
        )
        need = next(item for item in needs if item.capability_id == choice_probe)
        candidate = registry.issue(case_id, EPOCH, need)
        assert not isinstance(candidate, CandidateGap)
        definitions = tuple(
            replace(
                definition,
                manifest=definition.manifest.model_copy(
                    update={"version": definition.manifest.version + 1}
                ),
                discovery=(
                    None
                    if definition.discovery is None
                    else definition.discovery.model_copy(
                        update={"probe_version": definition.manifest.version + 1}
                    )
                ),
            )
            if definition.manifest.probe_id == choice_probe
            else definition
            for definition in default_probe_definitions()
        )
        changed, _ = candidate_catalog.general_measurement_candidate_catalog(
            store, ProbeRunner(definitions=definitions), case_id, clock=lambda: NOW
        )
        assert isinstance(changed.resolve(case_id, EPOCH, candidate.candidate_id), CandidateGap)
        now[0] = NOW + timedelta(minutes=10)
        assert isinstance(registry.resolve(case_id, EPOCH, candidate.candidate_id), CandidateGap)
        now[0] = NOW
        store.connection.execute(
            "UPDATE cases SET status='completed' WHERE case_id=?", (str(case_id),)
        )
        assert isinstance(registry.resolve(case_id, EPOCH, candidate.candidate_id), CandidateGap)


@pytest.mark.parametrize(
    ("parent_probe", "choice_probe"),
    (("core.resources", "storage.snapshot"), ("network.connectivity", "network.configuration")),
)
def test_passive_choice_is_not_reoffered_after_any_execution(
    tmp_path: Path, parent_probe: str, choice_probe: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=1, probe_id=parent_probe)
        manifest = default_probe_runner().manifest(choice_probe)
        assert manifest is not None
        execution_id = ExecutionId.new()
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id=choice_probe,
                probe_version=manifest.version,
                status="failed",
                parameters_json="{}",
                started_at=NOW.isoformat(),
                finished_at=NOW.isoformat(),
                state_version=EPOCH,
            )
        _, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        assert choice_probe not in {need.capability_id for need in needs}


def _gpu_source(
    store: SQLiteStore,
    case_id: CaseId,
    *,
    age_seconds: float = 10,
    status: str = "ok",
    gpu_uuid: str | None = "GPU-verified",
    source_type: str = "systemsense.probe",
    epoch: int = EPOCH,
) -> EvidenceId:
    evidence_id, execution_id = EvidenceId.new(), ExecutionId.new()
    observed = NOW - timedelta(seconds=age_seconds)
    finished = observed + timedelta(milliseconds=100)
    captured = observed + timedelta(milliseconds=200)
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "local_ai.snapshot", "probe_version": 1}
    )
    telemetry: dict[str, JsonValue] = {
        "sample_started_at": (observed - timedelta(milliseconds=200)).isoformat(),
        "captured_at": observed.isoformat(),
        "status": "available" if gpu_uuid is not None else "unsupported",
        "gpus": [] if gpu_uuid is None else [{"uuid": gpu_uuid, "name": "NVIDIA GPU", "index": 0}],
        "limitation": "nvidia-smi sample instant is unknown within the bounded query interval",
    }
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed,
        captured_at=captured,
        source=EvidenceSource(
            type=source_type,
            source_id=source_id,
            locator={"probe_id": "local_ai.snapshot"},
        ),
        collector=CollectorReference(id="local_ai.snapshot", version=1, execution_id=execution_id),
        summary="GPU inventory",
        facts=(
            EvidenceFact(
                name="collection_started_at", value=(observed - timedelta(seconds=1)).isoformat()
            ),
            EvidenceFact(name="collection_completed_at", value=observed.isoformat()),
            EvidenceFact(name="nvidia_telemetry", value=telemetry),
        ),
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="local_ai.snapshot",
            probe_version=1,
            status=status,
            parameters_json="{}",
            started_at=(observed - timedelta(seconds=1)).isoformat(),
            finished_at=finished.isoformat(),
            state_version=epoch,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=observed.isoformat(),
            captured_at=captured.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )
    return evidence_id


def test_general_measurement_catalog_offers_deterministic_pressure_then_gpu(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        gpu_source = _gpu_source(store, case_id)
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        assert [need.capability_id for need in needs] == [
            "pressure.sample",
            "gpu.telemetry.sample",
            "storage.snapshot",
        ]
        gpu = registry.issue(case_id, EPOCH, needs[1])
        assert not isinstance(gpu, CandidateGap)
        assert gpu.probe_id == "gpu.telemetry.sample"
        resolved = registry.resolve(case_id, EPOCH, gpu.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        assert resolved.invocation.parameters == {}
        assert resolved.invocation.target_handle is None
        assert resolved.invocation.window is None
        row = store.connection.execute(
            "SELECT source_evidence_id FROM case_measurement_candidates WHERE candidate_id=?",
            (gpu.candidate_id,),
        ).fetchone()
        assert row == (str(gpu_source),)


def test_new_live_window_has_distinct_exact_no_target_candidates(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "live-windows.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        _gpu_source(store, case_id)
        runner = default_probe_runner()
        first_window = MeasurementWindow(
            start=NOW + timedelta(seconds=2), end=NOW + timedelta(seconds=9)
        )
        second_window = MeasurementWindow(
            start=NOW + timedelta(seconds=10), end=NOW + timedelta(seconds=17)
        )
        first_registry, first_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=first_window, clock=lambda: NOW
        )
        second_registry, second_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=second_window, clock=lambda: NOW
        )
        assert [need.capability_id for need in first_needs] == [
            "pressure.sample",
            "gpu.telemetry.sample",
            "storage.snapshot",
        ]
        assert first_needs[2].window is None and second_needs[2].window is None
        for first_need, second_need in zip(first_needs[:2], second_needs[:2], strict=True):
            first = first_registry.issue(case_id, EPOCH, first_need)
            repeated = first_registry.issue(case_id, EPOCH, first_need)
            second = second_registry.issue(case_id, EPOCH, second_need)
            assert isinstance(first, CandidateRecord)
            assert isinstance(repeated, CandidateRecord)
            assert isinstance(second, CandidateRecord)
            assert repeated.candidate_id == first.candidate_id
            assert second.candidate_id != first.candidate_id
            assert second.invocation_sha256 != first.invocation_sha256
            resolved = second_registry.resolve(case_id, EPOCH, second.candidate_id)
            assert not isinstance(resolved, CandidateGap)
            assert resolved.invocation.window == second_window
            assert resolved.invocation.target_handle is None
            assert resolved.invocation.parameters == {
                "window_start": second_window.start.isoformat(),
                "window_end": second_window.end.isoformat(),
            }


def test_streaming_window_reuses_parent_observation_and_new_source_changes_identity(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "parent-windows.db") as store:
        case_id = _case(store)
        runner = default_probe_runner()

        def parent_for(source_id: EvidenceId) -> PersistedProbeResult:
            row = store.connection.execute(
                "SELECT execution_id FROM evidence WHERE case_id=? AND evidence_id=?",
                (str(case_id), str(source_id)),
            ).fetchone()
            assert row is not None
            return PersistedProbeResult(
                task_id="baseline-core-resources",
                case_id=str(case_id),
                epoch_state_version=EPOCH,
                probe_id="core.resources",
                execution_id=ExecutionId(root=str(row[0])),
                evidence_generation=0,
                trigger_evidence_sha256="a" * 64,
            )

        first_source = _source(store, case_id, age_seconds=2)
        first_parent = parent_for(first_source)
        first_window = Investigator._streaming_parent_window(  # pyright: ignore[reportPrivateUsage]
            case_id, NOW + timedelta(minutes=5), first_parent, store
        )
        repeated_window = Investigator._streaming_parent_window(  # pyright: ignore[reportPrivateUsage]
            case_id, NOW + timedelta(minutes=5), first_parent, store
        )
        assert first_window is not None and repeated_window == first_window
        first_registry, first_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=first_window, clock=lambda: NOW
        )
        first = first_registry.issue(case_id, EPOCH, first_needs[0])
        repeated = first_registry.issue(case_id, EPOCH, first_needs[0])
        assert isinstance(first, CandidateRecord) and isinstance(repeated, CandidateRecord)
        assert repeated.candidate_id == first.candidate_id

        second_source = _source(store, case_id, age_seconds=0)
        second_window = Investigator._streaming_parent_window(  # pyright: ignore[reportPrivateUsage]
            case_id, NOW + timedelta(minutes=5), parent_for(second_source), store
        )
        assert second_window is not None and second_window != first_window
        second_registry, second_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=second_window, clock=lambda: NOW
        )
        second = second_registry.issue(case_id, EPOCH, second_needs[0])
        assert isinstance(second, CandidateRecord)
        assert second.candidate_id != first.candidate_id


def test_gpu_windowed_admissions_keep_exact_claim_source(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "gpu-window-claims.db") as store:
        case_id = _case(store)
        source = _gpu_source(store, case_id)
        runner = default_probe_runner()
        windows = (
            MeasurementWindow(start=NOW + timedelta(seconds=2), end=NOW + timedelta(seconds=9)),
            MeasurementWindow(start=NOW + timedelta(seconds=10), end=NOW + timedelta(seconds=17)),
        )
        records: list[CandidateRecord] = []
        admission_ids: list[str] = []
        for index, window in enumerate(windows):
            registry, needs = candidate_catalog.general_measurement_candidate_catalog(
                store, runner, case_id, observation_window=window, clock=lambda: NOW
            )
            gpu_need = next(item for item in needs if item.capability_id == "gpu.telemetry.sample")
            record = registry.issue(case_id, EPOCH, gpu_need)
            assert isinstance(record, CandidateRecord)
            snapshot = _snapshot_for_candidate(store, case_id, record, NOW + timedelta(minutes=3))
            admission = CandidateDispatchAdmissionRepository(store, registry=registry).admit(
                snapshot_id=snapshot,
                candidate_id=record.candidate_id,
                case_id=case_id,
                epoch_state_version=EPOCH,
                task_id=f"gpu-window-{index}",
                invocation_sha256=record.invocation_sha256,
                cost_ms=record.cost_ms,
            )
            records.append(record)
            admission_ids.append(admission.admission_id)
        for record, window, admission_id in zip(records, windows, admission_ids, strict=True):
            registry, needs = candidate_catalog.general_measurement_candidate_catalog(
                store,
                runner,
                case_id,
                for_existing_admission=True,
                for_existing_candidate_id=record.candidate_id,
                clock=lambda: NOW,
            )
            assert needs == ()
            resolved = registry.resolve_for_claim(case_id, EPOCH, record.candidate_id, admission_id)
            assert not isinstance(resolved, CandidateGap)
            assert resolved.invocation.window == window
            row = store.connection.execute(
                "SELECT source_evidence_id,invocation_json FROM case_measurement_candidates "
                "WHERE candidate_id=?",
                (record.candidate_id,),
            ).fetchone()
            assert row is not None and row[0] == str(source)
            assert json.loads(str(row[1]))["window"] == window.model_dump(mode="json")


def test_admitted_live_interval_is_not_reoffered_after_source_refresh(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "interval-dedup.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        window = MeasurementWindow(start=NOW + timedelta(seconds=2), end=NOW + timedelta(seconds=9))
        runner = default_probe_runner()
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=window, clock=lambda: NOW
        )
        candidate = registry.issue(case_id, EPOCH, needs[0])
        assert isinstance(candidate, CandidateRecord)
        snapshot_id = _snapshot_for_candidate(store, case_id, candidate, NOW + timedelta(minutes=3))
        CandidateDispatchAdmissionRepository(store, registry=registry).admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=EPOCH,
            task_id="same-interval-pressure",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )
        _source(store, case_id, age_seconds=1)
        _, duplicate = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=window, clock=lambda: NOW
        )
        assert [item.capability_id for item in duplicate] == ["storage.snapshot"]
        next_window = MeasurementWindow(
            start=NOW + timedelta(seconds=10), end=NOW + timedelta(seconds=17)
        )
        _, distinct = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=next_window, clock=lambda: NOW
        )
        assert [need.capability_id for need in distinct] == ["pressure.sample", "storage.snapshot"]


def test_live_interval_admission_rechecks_competing_inflight_candidate(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "interval-race.db") as store:
        case_id = _case(store)
        window = MeasurementWindow(start=NOW + timedelta(seconds=2), end=NOW + timedelta(seconds=9))
        runner = default_probe_runner()
        _source(store, case_id, age_seconds=10)
        first_registry, first_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=window, clock=lambda: NOW
        )
        first = first_registry.issue(case_id, EPOCH, first_needs[0])
        assert isinstance(first, CandidateRecord)
        _source(store, case_id, age_seconds=1)
        second_registry, second_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, observation_window=window, clock=lambda: NOW
        )
        second = second_registry.issue(case_id, EPOCH, second_needs[0])
        assert isinstance(second, CandidateRecord)
        assert first.candidate_id != second.candidate_id
        checkpoint_row = store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(case_id),)
        ).fetchone()
        assert checkpoint_row is not None
        checkpoint = json.loads(str(checkpoint_row[0]))
        checkpoint["budget_ms"] = 40_000
        checkpoint["max_probes"] = 6
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
            (json.dumps(checkpoint), str(case_id)),
        )
        first_snapshot = _snapshot_for_candidate(store, case_id, first, NOW + timedelta(minutes=3))
        second_snapshot = _snapshot_for_candidate(
            store, case_id, second, NOW + timedelta(minutes=3)
        )
        CandidateDispatchAdmissionRepository(store, registry=first_registry).admit(
            snapshot_id=first_snapshot,
            candidate_id=first.candidate_id,
            case_id=case_id,
            epoch_state_version=EPOCH,
            task_id="first-window-attempt",
            invocation_sha256=first.invocation_sha256,
            cost_ms=first.cost_ms,
        )
        with pytest.raises(ValueError, match="no longer eligible"):
            CandidateDispatchAdmissionRepository(store, registry=second_registry).admit(
                snapshot_id=second_snapshot,
                candidate_id=second.candidate_id,
                case_id=case_id,
                epoch_state_version=EPOCH,
                task_id="competing-window-attempt",
                invocation_sha256=second.invocation_sha256,
                cost_ms=second.cost_ms,
            )


def test_frontier_discovery_keeps_registry_window_on_measure_reference(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "window-frontier.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        window = MeasurementWindow(start=NOW + timedelta(seconds=2), end=NOW + timedelta(seconds=9))
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, observation_window=window, clock=lambda: NOW
        )
        record = registry.issue(case_id, EPOCH, needs[0])
        assert isinstance(record, CandidateRecord)
        retriever = EvidenceRetriever(store)
        generation = retriever.discover(
            EvidenceCatalogQuery(case_id=case_id, limit=1)
        ).case_evidence_generation
        discovered = seed_frontier_discovery(
            case_id=case_id,
            retriever=retriever,
            frontier=SearchFrontierRepository(store),
            versions=RelevantVersionsV1(objective=1, evidence=generation),
            candidates=(AdmittedCandidateRefV1(**record.model_dump(exclude={"schema_version"})),),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            knowledge=KnowledgePacket(
                schema_version=3,
                pack_id="test",
                pack_version=1,
                nodes=(),
                relations=(),
                sources=(),
                truncated=False,
                omitted_relation_count=0,
                limitations=(),
                disclaimer="Reference relationships are not proof of a case cause.",
            ),
            max_items=4,
        )
        measures = [item for item in discovered.items if item.reference.kind == "measure"]
        assert len(measures) == 1
        assert measures[0].reference.window == window


def test_general_measurement_catalog_rejects_unavailable_or_untrusted_gpu_source(
    tmp_path: Path,
) -> None:
    for label, age_seconds, status, gpu_uuid, source_type in (
        ("failed", 10, "failed", "GPU-verified", "systemsense.probe"),
        ("unsupported", 10, "ok", None, "systemsense.probe"),
        ("imported", 10, "ok", "GPU-verified", "imported"),
        ("stale", 360, "ok", "GPU-verified", "systemsense.probe"),
    ):
        with SQLiteStore(tmp_path / f"{label}.db") as store:
            case_id = _case(store)
            _gpu_source(
                store,
                case_id,
                age_seconds=age_seconds,
                status=status,
                gpu_uuid=gpu_uuid,
                source_type=source_type,
            )
            _, needs = candidate_catalog.general_measurement_candidate_catalog(
                store, default_probe_runner(), case_id, clock=lambda: NOW
            )
            assert needs == ()


def test_general_measurement_catalog_does_not_reoffer_gpu_after_attempt(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _gpu_source(store, case_id)
        store.connection.execute(
            "INSERT INTO probe_executions (execution_id,case_id,probe_id,probe_version,status,"
            "parameters_json,started_at,finished_at,state_version) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(ExecutionId.new()),
                str(case_id),
                "gpu.telemetry.sample",
                1,
                "failed",
                "{}",
                (NOW - timedelta(seconds=5)).isoformat(),
                (NOW - timedelta(seconds=4)).isoformat(),
                EPOCH,
            ),
        )
        _, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        assert needs == ()


def test_gpu_admission_keeps_exact_source_for_worker_after_new_inventory(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        runner = default_probe_runner()
        original_source = _gpu_source(store, case_id, age_seconds=10)
        registry, needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        candidate = registry.issue(case_id, EPOCH, needs[0])
        assert not isinstance(candidate, CandidateGap)
        snapshot_id = _snapshot_for_candidate(store, case_id, candidate, NOW + timedelta(minutes=3))
        admission = CandidateDispatchAdmissionRepository(store, registry=registry).admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=EPOCH,
            task_id="probe-0-gpu.telemetry.sample",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )
        _gpu_source(store, case_id, age_seconds=1)
        ordinary, new_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        assert new_needs == ()
        assert isinstance(ordinary.resolve(case_id, EPOCH, candidate.candidate_id), CandidateGap)
        for_worker, worker_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, for_existing_admission=True, clock=lambda: NOW
        )
        assert worker_needs == ()
        resolved = for_worker.resolve_for_claim(
            case_id, EPOCH, candidate.candidate_id, admission.admission_id
        )
        assert not isinstance(resolved, CandidateGap)
        assert resolved.candidate.probe_id == "gpu.telemetry.sample"
        row = store.connection.execute(
            "SELECT source_evidence_id FROM case_measurement_candidates WHERE candidate_id=?",
            (candidate.candidate_id,),
        ).fetchone()
        assert row == (str(original_source),)


def _snapshot_for_candidate(
    store: SQLiteStore, case_id: CaseId, candidate: CandidateRecord, deadline_at: datetime
) -> str:
    reference = AdmittedCandidateRefV1(**candidate.model_dump(exclude={"schema_version"}))
    request = CandidateDecisionRequestV1(
        case_id=case_id,
        state_version=EPOCH,
        correlation_id="general:pressure",
        deadline_at=deadline_at,
        symptom="Host pressure",
        available_candidates=(reference,),
        budget_ms=20_000,
        max_candidates=1,
    )
    response = CandidateDecisionResponseV1(
        provider=ProviderIdentity(
            provider_id="fixture-fast", provider_version="1", role="fast_decision"
        ),
        case_id=case_id,
        state_version=EPOCH,
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
    return (
        CandidateDecisionSnapshotRepository(store)
        .capture(request, response, request_frozen_at=datetime.now(UTC))
        .snapshot_id
    )


def test_general_catalog_issues_no_target_pressure_from_exact_fresh_source(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        old = _source(store, case_id, age_seconds=100)
        newest = _source(store, case_id, age_seconds=10)
        registry, needs = candidate_catalog.general_pressure_candidate_catalog(
            store,
            default_probe_runner(),
            case_id,
            clock=lambda: NOW,
        )
        assert len(needs) == 1
        record = registry.issue(case_id, EPOCH, needs[0])
        assert not isinstance(record, CandidateGap)
        resolved = registry.resolve(case_id, EPOCH, record.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        assert record.probe_id == "pressure.sample"
        assert resolved.invocation.parameters == {}
        assert resolved.invocation.target_handle is None
        runner = default_probe_runner()
        manifest = runner.manifest("pressure.sample")
        assert manifest is not None
        assert manifest.input_model == "LiveSampleWindowParametersV1"
        assert (
            runner.prepare_invocation(
                "pressure.sample", {}, expected_version=manifest.version
            ).parameters
            == {}
        )
        row = store.connection.execute(
            "SELECT source_evidence_id FROM case_measurement_candidates WHERE candidate_id=?",
            (record.candidate_id,),
        ).fetchone()
        assert row == (str(newest),)
        assert row != (str(old),)


def test_general_catalog_does_not_offer_failed_or_stale_source(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=360, status="ok")
        _source(store, case_id, age_seconds=10, status="failed")
        _, needs = candidate_catalog.general_pressure_candidate_catalog(
            store,
            default_probe_runner(),
            case_id,
            clock=lambda: NOW,
        )
        assert needs == ()


def test_general_catalog_rejects_non_probe_source_even_with_ok_execution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        evidence_id = _source(store, case_id, age_seconds=10)
        row = store.connection.execute(
            "SELECT record_json FROM evidence WHERE evidence_id=?", (str(evidence_id),)
        ).fetchone()
        assert row is not None
        record = EvidenceRecord.model_validate_json(str(row[0]))
        forged = record.model_copy(
            update={
                "source": EvidenceSource(
                    type="imported",
                    source_id=record.source.source_id,
                    locator={"probe_id": "core.resources"},
                )
            }
        )
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (forged.model_dump_json(), str(evidence_id)),
        )
        _, needs = candidate_catalog.general_pressure_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        assert needs == ()


def test_general_catalog_rejects_untrusted_source_time(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10, time_basis="case_open_derived")
        _, needs = candidate_catalog.general_pressure_candidate_catalog(
            store,
            default_probe_runner(),
            case_id,
            clock=lambda: NOW,
        )
        assert needs == ()


@pytest.mark.parametrize("windowed", [False, True])
def test_general_catalog_skips_successful_sample_after_baseline(
    tmp_path: Path, windowed: bool
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        parameters_json = (
            json.dumps(
                {
                    "window_start": (NOW - timedelta(seconds=8)).isoformat(),
                    "window_end": (NOW - timedelta(seconds=1)).isoformat(),
                }
            )
            if windowed
            else "{}"
        )
        store.connection.execute(
            "INSERT INTO probe_executions (execution_id,case_id,probe_id,probe_version,status,"
            "parameters_json,started_at,finished_at,state_version) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(ExecutionId.new()),
                str(case_id),
                "pressure.sample",
                1,
                "ok",
                parameters_json,
                (NOW - timedelta(seconds=5)).isoformat(),
                (NOW - timedelta(seconds=4)).isoformat(),
                EPOCH,
            ),
        )
        _, needs = candidate_catalog.general_pressure_candidate_catalog(
            store,
            default_probe_runner(),
            case_id,
            clock=lambda: NOW,
        )
        assert needs == ()


def test_general_catalog_skips_failed_sample_after_baseline(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        store.connection.execute(
            "INSERT INTO probe_executions (execution_id,case_id,probe_id,probe_version,status,"
            "parameters_json,started_at,finished_at,state_version) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(ExecutionId.new()),
                str(case_id),
                "pressure.sample",
                1,
                "failed",
                "{}",
                (NOW - timedelta(seconds=5)).isoformat(),
                (NOW - timedelta(seconds=4)).isoformat(),
                EPOCH,
            ),
        )
        _, needs = candidate_catalog.general_pressure_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        assert needs == ()


def test_general_catalog_does_not_reissue_unlinked_admission(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        runner = default_probe_runner()
        registry, needs = candidate_catalog.general_pressure_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        candidate = registry.issue(case_id, EPOCH, needs[0])
        assert not isinstance(candidate, CandidateGap)
        snapshot_id = _snapshot_for_candidate(store, case_id, candidate, NOW + timedelta(minutes=3))
        admission = CandidateDispatchAdmissionRepository(store, registry=registry).admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=EPOCH,
            task_id="probe-0-pressure.sample",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )
        assert admission.execution_id is None
        _, new_needs = candidate_catalog.general_pressure_candidate_catalog(
            store, runner, case_id, clock=lambda: datetime.now(UTC)
        )
        assert new_needs == ()
        claim_registry, claim_needs = candidate_catalog.general_pressure_candidate_catalog(
            store,
            runner,
            case_id,
            for_existing_admission=True,
            clock=lambda: datetime.now(UTC),
        )
        assert claim_needs == ()
        assert not isinstance(
            claim_registry.resolve_for_claim(
                case_id, EPOCH, candidate.candidate_id, admission.admission_id
            ),
            CandidateGap,
        )


def test_no_window_pressure_does_not_repeat_same_source_windowed_admission(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cross-route-pressure.db") as store:
        case_id = _case(store)
        original_source = _source(store, case_id, age_seconds=10)
        _gpu_source(store, case_id)
        runner = default_probe_runner()
        first_window = MeasurementWindow(
            start=NOW + timedelta(seconds=2), end=NOW + timedelta(seconds=9)
        )
        next_window = MeasurementWindow(
            start=NOW + timedelta(seconds=10), end=NOW + timedelta(seconds=17)
        )
        registry, needs = candidate_catalog.general_pressure_candidate_catalog(
            store, runner, case_id, observation_window=first_window, clock=lambda: NOW
        )
        candidate = registry.issue(case_id, EPOCH, needs[0])
        assert isinstance(candidate, CandidateRecord)
        snapshot_id = _snapshot_for_candidate(store, case_id, candidate, NOW + timedelta(minutes=3))
        CandidateDispatchAdmissionRepository(store, registry=registry).admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=EPOCH,
            task_id="windowed-pressure",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )

        _, no_window_needs = candidate_catalog.general_pressure_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        assert no_window_needs == ()
        _, mixed_needs = candidate_catalog.general_measurement_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        assert [need.capability_id for need in mixed_needs] == [
            "gpu.telemetry.sample",
            "storage.snapshot",
        ]

        _, explicit_needs = candidate_catalog.general_pressure_candidate_catalog(
            store, runner, case_id, observation_window=next_window, clock=lambda: NOW
        )
        assert [need.window for need in explicit_needs] == [next_window]

        refreshed_source = _source(store, case_id, age_seconds=1)
        assert refreshed_source != original_source
        _, refreshed_needs = candidate_catalog.general_pressure_candidate_catalog(
            store, runner, case_id, clock=lambda: NOW
        )
        assert [need.capability_id for need in refreshed_needs] == ["pressure.sample"]


def test_no_window_pressure_ignores_other_probe_and_targeted_raw_execution(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "pressure-target-scope.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        for probe_id, parameters_json in (
            ("application.target_pressure", json.dumps({"pid": 101})),
            ("pressure.sample", json.dumps({"pid": 202})),
        ):
            store.connection.execute(
                "INSERT INTO probe_executions "
                "(execution_id,case_id,probe_id,probe_version,status,parameters_json,"
                "started_at,finished_at,state_version) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    str(ExecutionId.new()),
                    str(case_id),
                    probe_id,
                    1,
                    "ok",
                    parameters_json,
                    (NOW - timedelta(seconds=5)).isoformat(),
                    (NOW - timedelta(seconds=4)).isoformat(),
                    EPOCH,
                ),
            )
        _, needs = candidate_catalog.general_pressure_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        assert [need.capability_id for need in needs] == ["pressure.sample"]


def test_general_candidate_source_change_closes_resolution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        case_id = _case(store)
        _source(store, case_id, age_seconds=10)
        runner: ProbeRunner = default_probe_runner()
        registry, needs = candidate_catalog.general_pressure_candidate_catalog(
            store,
            runner,
            case_id,
            clock=lambda: NOW,
        )
        record = registry.issue(case_id, EPOCH, needs[0])
        assert not isinstance(record, CandidateGap)
        _source(store, case_id, age_seconds=1)
        refreshed, _ = candidate_catalog.general_pressure_candidate_catalog(
            store,
            runner,
            case_id,
            clock=lambda: NOW,
        )
        result = refreshed.resolve(case_id, EPOCH, record.candidate_id)
        assert isinstance(result, CandidateGap)
        assert result.reason is CandidateGapReason.SOURCE_CHANGED


@pytest.mark.parametrize("windowed", (False, True))
def test_general_candidate_claims_once_and_links_sample(tmp_path: Path, windowed: bool) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        default_manifest = default_probe_runner().manifest("pressure.sample")
        assert default_manifest is not None
        observed: list[dict[str, JsonValue]] = []

        def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
            observed.append(parameters)
            at = datetime.now(UTC)
            return ProbeObservation(
                summary="Bounded host pressure",
                facts={"cpu_percent": 12.0},
                observed_at=at,
                captured_at=at,
            )

        runner = ProbeRunner(
            definitions=(
                ProbeDefinition(
                    manifest=default_manifest,
                    parameter_model=LiveSampleWindowParametersV1,
                    handler=collect,
                    isolated=False,
                    supports_window=True,
                ),
            )
        )
        service = CaseService(
            store,
            DeterministicPlanner(
                candidates=(
                    ProbeCandidate(
                        probe_id="pressure.sample", cost_ms=10_000, value=1.0, common=True
                    ),
                )
            ),
        )
        runtime = DiagnosticRuntime(store=store, case_service=service, probe_runner=runner)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="Host pressure",
            target_traits=frozenset(),
            created_at=NOW,
            budget_ms=20_000,
            max_probes=3,
        )
        case_id = opened.case.case_id
        store.connection.execute(
            "UPDATE cases SET state_version=? WHERE case_id=?", (EPOCH, str(case_id))
        )
        opened = opened.model_copy(
            update={
                "case": opened.case.model_copy(update={"state_version": EPOCH}),
            }
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
            (
                str(case_id),
                json.dumps(
                    {
                        "case_id": str(case_id),
                        "state_version": EPOCH,
                        "status": "running",
                        "deadline_at": opened.deadline_at.isoformat(),
                        "budget_ms": 20_000,
                        "spent_cost_ms": 0,
                        "max_probes": 3,
                        "completed_probe_ids": [],
                        "pending_probe_ids": [],
                        "interrupted_probe_ids": [],
                        "unrecorded_attempt_count": 0,
                    }
                ),
            ),
        )
        _source(store, case_id, age_seconds=1)
        window = (
            MeasurementWindow(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=11))
            if windowed
            else None
        )
        registry, needs = runtime.general_candidate_catalog(case_id, observation_window=window)
        candidate = registry.issue(case_id, EPOCH, needs[0])
        assert not isinstance(candidate, CandidateGap)
        resolved = registry.resolve(case_id, EPOCH, candidate.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        assert resolved.invocation.window == window
        snapshot_id = _snapshot_for_candidate(store, case_id, candidate, opened.deadline_at)
        results = runtime.execute_candidate_measurement(
            opened,
            candidate.candidate_id,
            snapshot_id,
        )
        assert isinstance(results, tuple)
        assert len(results) == 1
        assert results[0].status is TaskStatus.SUCCEEDED, results[0].value
        expected_parameters: dict[str, JsonValue] = (
            {}
            if window is None
            else {
                "window_start": window.start.isoformat(),
                "window_end": window.end.isoformat(),
            }
        )
        assert observed == [expected_parameters]
        counts = store.connection.execute(
            "SELECT (SELECT COUNT(*) FROM candidate_dispatch_admissions),"
            "(SELECT COUNT(*) FROM candidate_dispatch_claims),"
            "(SELECT COUNT(*) FROM candidate_decision_execution_links)"
        ).fetchone()
        assert counts == (1, 1, 1)
        persisted = store.connection.execute(
            "SELECT parameters_json,status FROM probe_executions WHERE case_id=? "
            "AND probe_id='pressure.sample'",
            (str(case_id),),
        ).fetchone()
        assert persisted is not None
        assert json.loads(str(persisted[0])) == expected_parameters
        assert persisted[1] == "ok"
        link = store.connection.execute(
            "SELECT candidate_id,executed_invocation_json FROM candidate_decision_execution_links"
        ).fetchone()
        assert link is not None and link[0] == candidate.candidate_id
        assert ProbeInvocation.model_validate_json(str(link[1])) == resolved.invocation
