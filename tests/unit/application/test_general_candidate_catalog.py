"""General measurements are bound to exact current-case baseline evidence."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from systemsense.application import candidate_catalog
from systemsense.application.case_service import CaseService
from systemsense.application.runtime import DiagnosticRuntime
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
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import TaskStatus
from systemsense.packs.runtime import NoParameters, default_probe_runner
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.case_candidates import CandidateGap, CandidateGapReason
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime.now(UTC)
EPOCH = 2


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
) -> EvidenceId:
    evidence_id, execution_id = EvidenceId.new(), ExecutionId.new()
    observed = NOW - timedelta(seconds=age_seconds)
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "core.resources", "probe_version": 1}
    )
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed,
        captured_at=observed,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "core.resources"},
        ),
        collector=CollectorReference(id="core.resources", version=1, execution_id=execution_id),
        summary="Resource baseline",
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="core.resources",
            probe_version=1,
            status=status,
            parameters_json="{}",
            started_at=(observed - timedelta(seconds=1)).isoformat(),
            finished_at=observed.isoformat(),
            state_version=EPOCH,
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
        assert manifest.input_model == "NoParametersV1"
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


def test_general_catalog_skips_successful_sample_after_baseline(tmp_path: Path) -> None:
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
                "ok",
                "{}",
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


def test_general_candidate_claims_once_and_links_sample(tmp_path: Path) -> None:
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
                    parameter_model=NoParameters,
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
        registry, needs = runtime.general_candidate_catalog(case_id)
        candidate = registry.issue(case_id, EPOCH, needs[0])
        assert not isinstance(candidate, CandidateGap)
        reference = AdmittedCandidateRefV1(**candidate.model_dump(exclude={"schema_version"}))
        request = CandidateDecisionRequestV1(
            case_id=case_id,
            state_version=EPOCH,
            correlation_id="general:pressure",
            deadline_at=opened.deadline_at,
            symptom="Host pressure",
            available_candidates=(reference,),
            budget_ms=20_000,
            max_candidates=1,
        )
        response = CandidateDecisionResponseV1(
            provider=ProviderIdentity(
                provider_id="fixture-fast",
                provider_version="1",
                role="fast_decision",
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
        snapshot = CandidateDecisionSnapshotRepository(store).capture(
            request,
            response,
            request_frozen_at=datetime.now(UTC),
        )
        results = runtime.execute_candidate_measurement(
            opened,
            candidate.candidate_id,
            snapshot.snapshot_id,
        )
        assert isinstance(results, tuple)
        assert len(results) == 1
        assert results[0].status is TaskStatus.SUCCEEDED
        assert observed == [{}]
        counts = store.connection.execute(
            "SELECT (SELECT COUNT(*) FROM candidate_dispatch_admissions),"
            "(SELECT COUNT(*) FROM candidate_dispatch_claims),"
            "(SELECT COUNT(*) FROM candidate_decision_execution_links)"
        ).fetchone()
        assert counts == (1, 1, 1)
