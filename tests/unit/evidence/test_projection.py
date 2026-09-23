from datetime import UTC, datetime, timedelta
from typing import cast

from pytest import MonkeyPatch

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
from systemsense.evidence import projection as projection_module
from systemsense.evidence.graph import AssertionStatus, MemoryLayer, RelationKind
from systemsense.evidence.projection import ExplicitRelationProjector

_OBSERVED = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _record(
    *facts: EvidenceFact,
    evidence_id: str = "ev_11111111111111111111111111111111",
    observed_at: datetime = _OBSERVED,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=EvidenceId(root=evidence_id),
        case_id=CaseId(root="case_11111111111111111111111111111111"),
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at + timedelta(seconds=1),
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=f"src_{'a' * 64}",
            locator={"probe_id": "fixture.snapshot"},
        ),
        collector=CollectorReference(
            id="fixture.snapshot",
            version=1,
            execution_id=ExecutionId(root="exec_11111111111111111111111111111111"),
        ),
        summary="explicit relation fixture",
        facts=facts,
        extraction=Extraction(confidence=1.0, parser="fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )


def test_projects_explicit_service_process_ownership_with_stable_process_identity() -> None:
    facts = (
        EvidenceFact(
            name="processes",
            value=[
                {
                    "pid": 42,
                    "creation_time": "2026-07-30T11:59:00+00:00",
                    "name": "service-host.exe",
                }
            ],
        ),
        EvidenceFact(
            name="services",
            value=[{"name": "AudioSrv", "process_id": 42}],
        ),
    )

    first = ExplicitRelationProjector().project(_record(*facts))
    second = ExplicitRelationProjector().project(
        _record(
            *facts,
            evidence_id="ev_22222222222222222222222222222222",
            observed_at=_OBSERVED + timedelta(minutes=1),
        )
    )

    assert len(first.relations) == 1
    relation = first.relations[0]
    assert relation.relationship is RelationKind.RUNS_IN_PROCESS
    assert relation.memory_layer is MemoryLayer.MACHINE
    assert relation.assertion_status is AssertionStatus.OBSERVED
    assert relation.valid_from == _OBSERVED
    assert relation.valid_until == _OBSERVED
    assert relation.evidence_ids == (EvidenceId(root="ev_11111111111111111111111111111111"),)
    assert relation.source_ids == (f"src_{'a' * 64}",)
    assert relation.version_metadata["source_service"] == "AudioSrv"
    assert relation.version_metadata["target_process_name"] == "service-host.exe"
    assert relation.target_entity_id == second.relations[0].target_entity_id


def test_projects_only_declared_service_dependencies() -> None:
    result = ExplicitRelationProjector().project(
        _record(
            EvidenceFact(
                name="services",
                value=[
                    {"name": "AudioSrv", "dependencies": ["RpcSs", "AudioEndpointBuilder"]},
                    {"name": "RpcSs", "dependencies": []},
                ],
            )
        )
    )

    dependencies = [
        edge for edge in result.relations if edge.relationship is RelationKind.DEPENDS_ON
    ]
    assert len(dependencies) == 2
    assert all(
        edge.conditions == ("service dependency explicitly reported",) for edge in dependencies
    )


def test_process_without_creation_time_never_gets_a_reusable_entity() -> None:
    result = ExplicitRelationProjector().project(
        _record(
            EvidenceFact(name="processes", value=[{"pid": 42, "name": "host.exe"}]),
            EvidenceFact(name="services", value=[{"name": "AudioSrv", "pid": 42}]),
        )
    )

    assert result.relations == ()
    assert result.skipped_count == 1
    assert "creation time" in result.limitations[0]


def test_projects_device_driver_only_on_real_normalized_device_id_match() -> None:
    result = ExplicitRelationProjector().project(
        _record(
            EvidenceFact(
                name="devices",
                value=[{"instance_id": r"PCI\VEN_1234", "name": "Fixture device"}],
            ),
            EvidenceFact(
                name="drivers",
                value=[
                    {
                        "device_id": r"pci\ven_1234",
                        "name": "Fixture driver",
                        "version": "1.2.3",
                        "inf_name": "fixture.inf",
                    },
                    {"device_id": r"PCI\VEN_OTHER", "name": "Other driver"},
                ],
            ),
        )
    )

    assert len(result.relations) == 1
    assert result.relations[0].relationship is RelationKind.USES_DRIVER


def test_category_cooccurrence_and_unmatched_ids_do_not_create_edges() -> None:
    result = ExplicitRelationProjector().project(
        _record(
            EvidenceFact(
                name="processes",
                value=[{"pid": 42, "creation_time": "2026-07-30T11:59:00+00:00"}],
            ),
            EvidenceFact(name="devices", value=[{"instance_id": "DEVICE-A"}]),
            EvidenceFact(name="drivers", value=[{"device_id": "DEVICE-B"}]),
        )
    )

    assert result.relations == ()


def test_projection_enforces_relation_limit_and_reports_drops() -> None:
    processes = [
        {"pid": index, "creation_time": f"2026-07-30T11:{index:02d}:00+00:00"}
        for index in range(1, 4)
    ]
    services = [{"name": f"service-{index}", "pid": index} for index in range(1, 4)]

    result = ExplicitRelationProjector(max_relations=2).project(
        _record(
            EvidenceFact(name="processes", value=cast("JsonValue", processes)),
            EvidenceFact(name="services", value=cast("JsonValue", services)),
        )
    )

    assert len(result.relations) == 2
    assert result.skipped_count == 1
    assert "limit" in result.limitations[-1]


def test_default_projection_budget_keeps_broad_service_dependency_inventory() -> None:
    services = [
        {"name": f"service-{index}", "dependencies": [f"dependency-{index}"]}
        for index in range(300)
    ]

    result = ExplicitRelationProjector().project(
        _record(EvidenceFact(name="services", value=cast("JsonValue", services)))
    )

    assert len(result.relations) == 300
    assert result.skipped_count == 0


def test_projects_volume_storage_edge_without_inventing_process_parent_causality() -> None:
    result = ExplicitRelationProjector().project(
        _record(
            EvidenceFact(
                name="processes",
                value=[
                    {
                        "pid": 4,
                        "creation_time": "2026-07-30T11:58:00+00:00",
                        "name": "parent.exe",
                    },
                    {
                        "pid": 42,
                        "ppid": 4,
                        "creation_time": "2026-07-30T11:59:00+00:00",
                        "name": "child.exe",
                    },
                ],
            ),
            EvidenceFact(
                name="volume_mappings",
                value=[{"volume_id": "C:", "disk_index": 0}],
            ),
            EvidenceFact(
                name="physical_disks",
                value=[{"disk_index": 0, "device_id": r"\\.\PHYSICALDRIVE0"}],
            ),
        )
    )

    assert {edge.relationship for edge in result.relations} == {RelationKind.STORED_ON}


def test_projects_nvidia_gpu_to_reported_driver_without_inventing_performance_cause() -> None:
    result = ExplicitRelationProjector().project(
        _record(
            EvidenceFact(
                name="nvidia_telemetry",
                value={
                    "status": "available",
                    "gpus": [
                        {
                            "uuid": "GPU-fixture",
                            "name": "RTX Fixture",
                            "driver_version": "600.1",
                            "graphics_clock_mhz": 2550.0,
                            "temperature_c": 61.0,
                            "power_draw_w": 320.5,
                            "utilization_percent": 72,
                        }
                    ],
                },
            )
        )
    )

    assert len(result.relations) == 1
    relation = result.relations[0]
    assert relation.relationship is RelationKind.USES_DRIVER
    assert relation.version_metadata["gpu_uuid"] == "GPU-fixture"
    assert relation.version_metadata["driver_version"] == "600.1"


def _gpu_sample_record(
    *,
    second_driver: str = "600.1",
    include_query_bounds: bool = True,
    runtime_capture_lag: timedelta = timedelta(),
) -> EvidenceRecord:
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "gpu.telemetry.sample", "probe_version": 1}
    )
    samples = [
        {
            **(
                {"sample_started_at": (_OBSERVED + timedelta(milliseconds=450 * index)).isoformat()}
                if include_query_bounds
                else {}
            ),
            "captured_at": (_OBSERVED + timedelta(milliseconds=450 * index + 100)).isoformat(),
            "status": "available",
            "limitation": "nvidia-smi sample instant is unknown within the bounded query interval",
            "gpus": [
                {
                    "index": 0,
                    "uuid": "GPU-fixture",
                    "name": "RTX Fixture",
                    "driver_version": version,
                }
            ],
        }
        for index, version in enumerate(("600.1", second_driver, "600.1"))
    ]
    return _record(
        EvidenceFact(
            name="gpu_telemetry_sample",
            value=cast(
                "JsonValue",
                {
                    "captured_at": (_OBSERVED + timedelta(seconds=1)).isoformat(),
                    "window_started_at": _OBSERVED.isoformat(),
                    "window_ended_at": (_OBSERVED + timedelta(seconds=1)).isoformat(),
                    "inter_sample_delay_seconds": 0.5,
                    "samples": samples,
                    "status": "available",
                    "limitations": [
                        "nvidia-smi sample instant is unknown within the bounded query interval"
                    ],
                },
            ),
        ),
        observed_at=_OBSERVED + timedelta(seconds=1),
    ).model_copy(
        update={
            "captured_at": _OBSERVED + timedelta(seconds=1) + runtime_capture_lag,
            "source": EvidenceSource(
                type="systemsense.probe",
                source_id=source_id,
                locator={"probe_id": "gpu.telemetry.sample"},
            ),
            "collector": CollectorReference(
                id="gpu.telemetry.sample",
                version=1,
                execution_id=ExecutionId.new(),
            ),
            "extraction": Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        }
    )


def test_projects_authentic_stable_gpu_sample_series_to_driver_edge() -> None:
    record = _gpu_sample_record()
    result = ExplicitRelationProjector().project(record)
    assert len(result.relations) == 1
    edge = result.relations[0]
    assert edge.relationship is RelationKind.USES_DRIVER
    assert edge.relation_version == 2
    assert edge.applicability == ("gpu.telemetry.sample",)
    assert edge.source_ids == (record.source.source_id,)
    assert edge.version_metadata["driver_version"] == "600.1"
    assert edge.version_metadata["window_started_at"] == _OBSERVED.isoformat()
    assert (
        edge.version_metadata["window_ended_at"] == (_OBSERVED + timedelta(seconds=1)).isoformat()
    )


def test_conflicting_gpu_sample_driver_versions_produce_no_edge() -> None:
    assert (
        ExplicitRelationProjector().project(_gpu_sample_record(second_driver="600.2")).relations
        == ()
    )


def test_gpu_series_without_each_query_start_cannot_claim_bounded_provenance() -> None:
    assert (
        ExplicitRelationProjector()
        .project(_gpu_sample_record(include_query_bounds=False))
        .relations
        == ()
    )


def test_gpu_projection_accepts_bounded_worker_transport_lag_not_long_delay() -> None:
    projector = ExplicitRelationProjector()
    assert projector.project(
        _gpu_sample_record(runtime_capture_lag=timedelta(milliseconds=10))
    ).relations
    assert (
        projector.project(_gpu_sample_record(runtime_capture_lag=timedelta(seconds=16))).relations
        == ()
    )


def test_gpu_projection_without_registered_probe_fails_closed(monkeypatch: MonkeyPatch) -> None:
    from systemsense.packs import runtime

    try:
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "default_probe_definitions", lambda: ())
            projection_module._gpu_registered_timeout.cache_clear()  # pyright: ignore[reportPrivateUsage]
            assert ExplicitRelationProjector().project(_gpu_sample_record()).relations == ()
    finally:
        projection_module._gpu_registered_timeout.cache_clear()  # pyright: ignore[reportPrivateUsage]
