"""Trusted current-case machine edges to registered probe routing."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from systemsense.application.graph_routing import bind_trusted_machine_probe_targets
from systemsense.decision.contracts import ProbeCapability, ResourceClass
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
    CaseId,
    EntityId,
    EvidenceId,
    ExecutionId,
    JsonValue,
    stable_source_id,
)
from systemsense.evidence.graph import EvidenceRelation, RelationKind
from systemsense.evidence.projection import ExplicitRelationProjector
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def _series_fact() -> dict[str, object]:
    samples = [
        {
            "sample_started_at": (NOW + timedelta(milliseconds=450 * index)).isoformat(),
            "captured_at": (NOW + timedelta(milliseconds=450 * index + 100)).isoformat(),
            "status": "available",
            "limitation": "nvidia-smi sample instant is unknown within the bounded query interval",
            "gpus": [
                {
                    "index": 0,
                    "uuid": "GPU-fixture",
                    "name": "RTX Fixture",
                    "driver_version": "600.1",
                }
            ],
        }
        for index in range(3)
    ]
    return {
        "captured_at": (NOW + timedelta(seconds=1)).isoformat(),
        "window_started_at": NOW.isoformat(),
        "window_ended_at": (NOW + timedelta(seconds=1)).isoformat(),
        "inter_sample_delay_seconds": 0.5,
        "samples": samples,
        "status": "available",
        "limitations": ["nvidia-smi sample instant is unknown within the bounded query interval"],
    }


def _probe(probe_id: str) -> ProbeCapability:
    return ProbeCapability(
        probe_id=probe_id,
        description="Registered read-only snapshot",
        cost_ms=100,
        resource_class=ResourceClass.CPU,
    )


def _setup(
    store: SQLiteStore,
) -> tuple[CaseId, EvidenceContext, EvidenceRelation, tuple[ProbeCapability, ...]]:
    case_id = CaseId.new()
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "gpu.telemetry.sample", "probe_version": 1}
    )
    fact = _series_fact()
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW + timedelta(seconds=1),
        captured_at=NOW + timedelta(seconds=1, milliseconds=10),
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "gpu.telemetry.sample"},
        ),
        collector=CollectorReference(
            id="gpu.telemetry.sample", version=1, execution_id=execution_id
        ),
        summary="Three passive GPU samples",
        facts=(EvidenceFact(name="gpu_telemetry_sample", value=fact),),  # type: ignore[arg-type]
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    store.create_case(
        case_id=str(case_id),
        kind="incident",
        symptom="Game runs at 12 FPS",
        created_at=NOW.isoformat(),
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="gpu.telemetry.sample",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=NOW.isoformat(),
            finished_at=(NOW + timedelta(seconds=1, milliseconds=10)).isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )
    context = EvidenceContext(
        evidence_id=evidence_id,
        observed_at=record.observed_at,
        captured_at=record.captured_at,
        probe_id="local_ai",  # packet category, not collector identity
        summary=record.summary,
        facts={"gpu_telemetry_sample": fact},  # type: ignore[dict-item]
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    relation = ExplicitRelationProjector().project(record).relations[0]
    capabilities = (
        _probe("gpu.telemetry.sample"),
        _probe("devices.snapshot"),
        _probe("core.system"),
    )
    return case_id, context, relation, capabilities


def _bind(
    store: SQLiteStore,
    case_id: CaseId,
    context: EvidenceContext,
    relation: EvidenceRelation,
    capabilities: tuple[ProbeCapability, ...],
    *,
    completed: frozenset[str] = frozenset({"gpu.telemetry.sample"}),
    incident_start: datetime = NOW - timedelta(minutes=1),
    incident_end: datetime = NOW + timedelta(minutes=2),
    now: datetime = NOW + timedelta(seconds=2),
    symptom: str = "Game runs at 12 FPS",
) -> tuple[ProbeCapability, ...]:
    return bind_trusted_machine_probe_targets(
        store=store,
        case_id=case_id,
        incident_start=incident_start,
        incident_end=incident_end,
        context=(context,),
        relationships=(relation,),
        capabilities=capabilities,
        completed_probe_ids=completed,
        symptom=symptom,
        now=now,
    )


def test_authentic_current_gpu_edge_binds_only_registered_unused_driver_probe(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        bound = _bind(store, case_id, context, relation, capabilities)
        assert bound[0] == capabilities[0]
        assert bound[1].related_entity_hint_ids == (relation.target_entity_id,)
        assert bound[2] == capabilities[2]


def test_tampered_edge_cannot_create_catalog_binding(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        forged = relation.model_copy(update={"target_entity_id": EntityId.new()})
        assert _bind(store, case_id, context, forged, capabilities) == capabilities


def test_historical_or_out_of_window_gpu_evidence_cannot_route(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        historical = context.model_copy(update={"case_scope": "historical"})
        assert _bind(store, case_id, historical, relation, capabilities) == capabilities
        assert (
            _bind(
                store,
                case_id,
                context,
                relation,
                capabilities,
                incident_end=NOW,
            )
            == capabilities
        )
        assert (
            _bind(
                store,
                case_id,
                context,
                relation,
                capabilities,
                incident_start=NOW + timedelta(milliseconds=100),
            )
            == capabilities
        )


def test_resumed_case_does_not_reuse_stale_gpu_graph_hint(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        assert _bind(store, case_id, context, relation, capabilities) != capabilities
        assert (
            _bind(
                store,
                case_id,
                context,
                relation,
                capabilities,
                now=NOW + timedelta(minutes=6),
            )
            == capabilities
        )


def test_missing_source_completion_or_used_target_cannot_route(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        assert (
            _bind(store, case_id, context, relation, capabilities, completed=frozenset())
            == capabilities
        )
        assert (
            _bind(
                store,
                case_id,
                context,
                relation,
                capabilities,
                completed=frozenset({"gpu.telemetry.sample", "devices.snapshot"}),
            )
            == capabilities
        )


def test_unrelated_relation_or_modified_context_fact_cannot_route(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        unrelated = relation.model_copy(update={"relationship": RelationKind.CORRELATED_WITH})
        assert _bind(store, case_id, context, unrelated, capabilities) == capabilities
        changed = context.model_copy(update={"facts": {"gpu_telemetry_sample": {}}})
        assert _bind(store, case_id, changed, relation, capabilities) == capabilities


def test_evidence_row_must_match_owned_probe_execution_identity(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        store.connection.execute(
            "UPDATE evidence SET dedupe_key = ? WHERE case_id = ? AND evidence_id = ?",
            ("forged", str(case_id), str(context.evidence_id)),
        )
        assert _bind(store, case_id, context, relation, capabilities) == capabilities


def test_legacy_exact_time_claim_cannot_route_bounded_gpu_sample(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "graph.db") as store:
        case_id, context, relation, capabilities = _setup(store)
        store.connection.execute(
            "UPDATE evidence SET time_basis = ?, time_quality = ? "
            "WHERE case_id = ? AND evidence_id = ?",
            ("collector_observed", "exact", str(case_id), str(context.evidence_id)),
        )
        assert _bind(store, case_id, context, relation, capabilities) == capabilities


def test_observed_service_dependency_routes_registered_event_coverage(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "service-graph.db") as store:
        case_id = CaseId.new()
        evidence_id = EvidenceId.new()
        execution_id = ExecutionId.new()
        probe_id = "application.snapshot"
        source_id = stable_source_id(
            "systemsense.probe", {"probe_id": probe_id, "probe_version": 1}
        )
        facts = {"services": [{"name": "PrintSpooler", "dependencies": ["RPCSS"]}]}
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=NOW + timedelta(seconds=1),
            captured_at=NOW + timedelta(seconds=1, milliseconds=10),
            source=EvidenceSource(
                type="systemsense.probe",
                source_id=source_id,
                locator={"probe_id": probe_id},
            ),
            collector=CollectorReference(id=probe_id, version=1, execution_id=execution_id),
            summary="Registered services",
            facts=(EvidenceFact(name="services", value=facts["services"]),),  # type: ignore[arg-type]
            extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        store.create_case(
            case_id=str(case_id),
            kind="incident",
            symptom="Printing fails",
            created_at=NOW.isoformat(),
        )
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id=probe_id,
                probe_version=1,
                status="ok",
                parameters_json="{}",
                started_at=NOW.isoformat(),
                finished_at=record.captured_at.isoformat(),
                state_version=0,
            )
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=source_id,
                record_json=record.model_dump_json(),
                observed_at=record.observed_at.isoformat(),
                captured_at=record.captured_at.isoformat(),
                execution_id=str(execution_id),
                dedupe_key=f"execution:{execution_id}",
                time_basis="collector_upper_bound",
                time_quality="bounded_interval",
            )
        relation = next(
            edge
            for edge in ExplicitRelationProjector().project(record).relations
            if edge.relationship is RelationKind.DEPENDS_ON
        )
        context = EvidenceContext(
            evidence_id=evidence_id,
            observed_at=record.observed_at,
            captured_at=record.captured_at,
            probe_id="application",
            summary=record.summary,
            facts=facts,  # type: ignore[arg-type]
            status=EvidenceContextStatus.OBSERVED,
            case_scope="current_case",
            incident_relevant=True,
        )
        capabilities = (_probe(probe_id), _probe("incident.events"), _probe("devices.snapshot"))
        bound = _bind(
            store,
            case_id,
            context,
            relation,
            capabilities,
            completed=frozenset({probe_id}),
            symptom="PrintSpooler fails",
        )
        assert bound[1].related_entity_hint_ids == (relation.target_entity_id,)
        assert bound[2] == capabilities[2]
        inferred = relation.model_copy(update={"assertion_status": "inferred"})
        assert (
            _bind(
                store,
                case_id,
                context,
                inferred,
                capabilities,
                completed=frozenset({probe_id}),
                symptom="PrintSpooler fails",
            )
            == capabilities
        )
        assert (
            _bind(
                store,
                case_id,
                context,
                relation,
                capabilities,
                completed=frozenset({probe_id}),
                symptom="PDF page turns slowly",
            )
            == capabilities
        )


def test_named_volume_to_disk_routes_storage_event_coverage(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "storage-graph.db") as store:
        case_id = CaseId.new()
        evidence_id = EvidenceId.new()
        execution_id = ExecutionId.new()
        probe_id = "storage.snapshot"
        source_id = stable_source_id(
            "systemsense.probe", {"probe_id": probe_id, "probe_version": 1}
        )
        observed_at = NOW + timedelta(seconds=1)
        facts = {
            "collection_started_at": NOW.isoformat(),
            "collection_completed_at": observed_at.isoformat(),
            "collection_status": "partial",
            "volumes": [{"volume_id": "C:"}],
            "volume_mappings": [
                {"volume_id": "C:", "partition_id": "Disk #0, Partition #2", "disk_index": 0}
            ],
            "physical_disks": [{"disk_index": 0, "device_id": r"\\.\PHYSICALDRIVE0"}],
        }
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=observed_at,
            captured_at=observed_at + timedelta(milliseconds=10),
            source=EvidenceSource(
                type="systemsense.probe",
                source_id=source_id,
                locator={"probe_id": probe_id},
            ),
            collector=CollectorReference(id=probe_id, version=1, execution_id=execution_id),
            summary="Observed one volume to physical disk mapping",
            facts=tuple(
                EvidenceFact(name=name, value=cast("JsonValue", value))
                for name, value in facts.items()
            ),
            extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        store.create_case(
            case_id=str(case_id),
            kind="incident",
            symptom="C: drive is slow",
            created_at=NOW.isoformat(),
        )
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id=probe_id,
                probe_version=1,
                status="ok",
                parameters_json="{}",
                started_at=NOW.isoformat(),
                finished_at=record.captured_at.isoformat(),
                state_version=0,
            )
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=source_id,
                record_json=record.model_dump_json(),
                observed_at=record.observed_at.isoformat(),
                captured_at=record.captured_at.isoformat(),
                execution_id=str(execution_id),
                dedupe_key=f"execution:{execution_id}",
                time_basis="collector_upper_bound",
                time_quality="bounded_interval",
            )
        relation = next(
            edge
            for edge in ExplicitRelationProjector().project(record).relations
            if edge.relationship is RelationKind.STORED_ON
        )
        context = EvidenceContext(
            evidence_id=evidence_id,
            observed_at=record.observed_at,
            captured_at=record.captured_at,
            probe_id="storage",
            summary=record.summary,
            facts=facts,  # type: ignore[arg-type]
            status=EvidenceContextStatus.OBSERVED,
            case_scope="current_case",
            incident_relevant=True,
        )
        capabilities = (_probe(probe_id), _probe("incident.events"), _probe("core.system"))
        bound = _bind(
            store,
            case_id,
            context,
            relation,
            capabilities,
            completed=frozenset({probe_id}),
            symptom="C: drive is slow",
        )
        assert bound[1].related_entity_hint_ids == (relation.target_entity_id,)
        assert bound[2] == capabilities[2]
        assert (
            _bind(
                store,
                case_id,
                context,
                relation,
                capabilities,
                completed=frozenset({probe_id}),
                symptom="D: drive is slow",
            )
            == capabilities
        )
        assert (
            _bind(
                store,
                case_id,
                context,
                relation,
                capabilities,
                completed=frozenset({probe_id}),
                symptom="C: drive is slow",
                incident_start=NOW + timedelta(milliseconds=100),
            )
            == capabilities
        )
        for topology_loss in (
            "volume-to-disk mappings were capped at 128 associations",
            "1 volume-to-partition associations could not be resolved",
            "omitted 1 partitions beyond the 128-record cap",
            "omitted 1 physical disks with invalid indices",
        ):
            incomplete_record = record.model_copy(update={"limitations": (topology_loss,)})
            store.connection.execute(
                "UPDATE evidence SET record_json = ? WHERE case_id = ? AND evidence_id = ?",
                (incomplete_record.model_dump_json(), str(case_id), str(evidence_id)),
            )
            assert (
                _bind(
                    store,
                    case_id,
                    context,
                    relation,
                    capabilities,
                    completed=frozenset({probe_id}),
                    symptom="C: drive is slow",
                )
                == capabilities
            )
        store.connection.execute(
            "UPDATE evidence SET record_json = ? WHERE case_id = ? AND evidence_id = ?",
            (record.model_dump_json(), str(case_id), str(evidence_id)),
        )
        incomplete_facts = {
            **facts,
            "volumes": [{"volume_id": "C:"}, {"volume_id": "D:"}],
        }
        incomplete_record = record.model_copy(
            update={
                "facts": tuple(
                    EvidenceFact(name=name, value=cast("JsonValue", value))
                    for name, value in incomplete_facts.items()
                )
            }
        )
        store.connection.execute(
            "UPDATE evidence SET record_json = ? WHERE case_id = ? AND evidence_id = ?",
            (incomplete_record.model_dump_json(), str(case_id), str(evidence_id)),
        )
        assert (
            _bind(
                store,
                case_id,
                context.model_copy(update={"facts": incomplete_facts}),
                relation,
                capabilities,
                completed=frozenset({probe_id}),
                symptom="C: drive is slow",
            )
            == capabilities
        )
        ambiguous_facts = {
            **facts,
            "volume_mappings": [
                *facts["volume_mappings"],
                {"volume_id": "C:", "partition_id": "Disk #1, Partition #1", "disk_index": 1},
            ],
            "physical_disks": [
                *facts["physical_disks"],
                {"disk_index": 1, "device_id": r"\\.\PHYSICALDRIVE1"},
            ],
        }
        ambiguous_record = record.model_copy(
            update={
                "facts": tuple(
                    EvidenceFact(name=name, value=cast("JsonValue", value))
                    for name, value in ambiguous_facts.items()
                )
            }
        )
        store.connection.execute(
            "UPDATE evidence SET record_json = ? WHERE case_id = ? AND evidence_id = ?",
            (ambiguous_record.model_dump_json(), str(case_id), str(evidence_id)),
        )
        ambiguous_context = context.model_copy(update={"facts": ambiguous_facts})
        assert (
            _bind(
                store,
                case_id,
                ambiguous_context,
                relation,
                capabilities,
                completed=frozenset({probe_id}),
                symptom="C: drive is slow",
            )
            == capabilities
        )
