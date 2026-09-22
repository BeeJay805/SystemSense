"""Conservative projections from explicit collector facts into graph edges."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable

from pydantic import Field

from systemsense.domain.evidence import EvidenceRecord, FrozenModel
from systemsense.domain.ids import EntityId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)


class ProjectionResult(FrozenModel):
    relations: tuple[EvidenceRelation, ...]
    skipped_count: int = Field(ge=0)
    limitations: tuple[str, ...] = ()


class ExplicitRelationProjector:
    """Project only relationships directly represented by one observation."""

    def __init__(self, *, max_relations: int = 512) -> None:
        if max_relations < 1 or max_relations > 1000:
            raise ValueError("max_relations must be between 1 and 1000")
        self._max_relations = max_relations

    def project(self, record: EvidenceRecord) -> ProjectionResult:
        facts = {fact.name: fact.value for fact in record.facts}
        candidates: dict[str, EvidenceRelation] = {}
        skipped = 0
        limitations: list[str] = []

        process_relations, process_skipped, process_limitations = self._service_process_relations(
            record, facts
        )
        service_dependency_relations = self._service_dependency_relations(record, facts)
        device_relations = self._device_driver_relations(record, facts)
        storage_relations = self._volume_disk_relations(record, facts)
        gpu_relations = self._gpu_driver_relations(record, facts)
        skipped += process_skipped
        limitations.extend(process_limitations)
        for relation in (
            *process_relations,
            *service_dependency_relations,
            *device_relations,
            *storage_relations,
            *gpu_relations,
        ):
            candidates[relation.relation_id] = relation

        ordered = sorted(
            candidates.values(),
            key=lambda item: (
                item.relationship.value,
                str(item.source_entity_id),
                str(item.target_entity_id),
                item.relation_id,
            ),
        )
        if len(ordered) > self._max_relations:
            skipped += len(ordered) - self._max_relations
            limitations.append("explicit relationship projection limit reached")
            ordered = ordered[: self._max_relations]
        return ProjectionResult(
            relations=tuple(ordered),
            skipped_count=skipped,
            limitations=tuple(dict.fromkeys(limitations)),
        )

    def _service_process_relations(
        self,
        record: EvidenceRecord,
        facts: dict[str, JsonValue],
    ) -> tuple[list[EvidenceRelation], int, list[str]]:
        processes = _records(facts.get("processes"))
        services = _records(facts.get("services"))
        process_by_pid: dict[int, dict[str, JsonValue]] = {}
        for process in processes:
            pid = _positive_int(process.get("pid"))
            if pid is not None:
                process_by_pid[pid] = process

        relations: list[EvidenceRelation] = []
        skipped = 0
        limitations: list[str] = []
        for service in services:
            pid = _positive_int(service.get("process_id"))
            if pid is None:
                pid = _positive_int(service.get("pid"))
            service_name = service.get("name")
            if pid is None or not isinstance(service_name, str) or not service_name.strip():
                continue
            process = process_by_pid.get(pid)
            if process is None:
                skipped += 1
                limitations.append("service process ID had no matching process observation")
                continue
            creation_time = process.get("creation_time")
            if not _stable_creation_time(creation_time):
                skipped += 1
                limitations.append("matching process creation time was unavailable")
                continue
            service_entity = _entity_id("service", service_name.casefold())
            process_entity = _entity_id("process", pid, creation_time)
            relations.append(
                _relation(
                    record,
                    source_entity=service_entity,
                    target_entity=process_entity,
                    kind=RelationKind.RUNS_IN_PROCESS,
                    identity=(service_name.casefold(), pid, creation_time),
                    conditions=("service process ownership explicitly reported",),
                    metadata={
                        "source_service": service_name,
                        "pid": pid,
                        "creation_time": creation_time,
                        "target_process_name": process.get("name"),
                    },
                )
            )
        return relations, skipped, limitations

    def _device_driver_relations(
        self,
        record: EvidenceRecord,
        facts: dict[str, JsonValue],
    ) -> list[EvidenceRelation]:
        devices = _records(facts.get("devices"))
        drivers = _records(facts.get("drivers"))
        drivers_by_device: dict[str, list[dict[str, JsonValue]]] = {}
        for driver in drivers:
            device_id = _normalized_device_id(driver.get("device_id"))
            if device_id is not None:
                drivers_by_device.setdefault(device_id, []).append(driver)

        relations: list[EvidenceRelation] = []
        for device in devices:
            device_id = _normalized_device_id(device.get("instance_id"))
            if device_id is None:
                continue
            for driver in drivers_by_device.get(device_id, ()):  # exact normalized match only
                driver_identity = (
                    device_id,
                    driver.get("version"),
                    driver.get("inf_name"),
                    driver.get("provider"),
                    driver.get("name"),
                )
                relations.append(
                    _relation(
                        record,
                        source_entity=_entity_id("device", device_id),
                        target_entity=_entity_id("driver", *driver_identity),
                        kind=RelationKind.USES_DRIVER,
                        identity=driver_identity,
                        conditions=("device and signed driver IDs matched",),
                        metadata={
                            "device_id": device_id,
                            "driver_version": driver.get("version"),
                            "inf_name": driver.get("inf_name"),
                        },
                    )
                )
        return relations

    def _gpu_driver_relations(
        self,
        record: EvidenceRecord,
        facts: dict[str, JsonValue],
    ) -> list[EvidenceRelation]:
        telemetry = facts.get("nvidia_telemetry")
        if not isinstance(telemetry, dict):
            return []
        gpus = _records(telemetry.get("gpus"))
        relations: list[EvidenceRelation] = []
        for gpu in gpus:
            gpu_uuid = gpu.get("uuid")
            driver_version = gpu.get("driver_version")
            if not isinstance(gpu_uuid, str) or not gpu_uuid.strip():
                continue
            if not isinstance(driver_version, str) or not driver_version.strip():
                continue
            normalized_uuid = gpu_uuid.strip().casefold()
            normalized_driver = driver_version.strip().casefold()
            relations.append(
                _relation(
                    record,
                    source_entity=_entity_id("gpu", normalized_uuid),
                    target_entity=_entity_id("gpu_driver", "nvidia", normalized_driver),
                    kind=RelationKind.USES_DRIVER,
                    identity=(normalized_uuid, "nvidia", normalized_driver),
                    conditions=("GPU telemetry explicitly reported driver version",),
                    metadata={
                        "gpu_uuid": gpu_uuid,
                        "gpu_name": gpu.get("name"),
                        "driver_version": driver_version,
                    },
                )
            )
        return relations

    def _service_dependency_relations(
        self,
        record: EvidenceRecord,
        facts: dict[str, JsonValue],
    ) -> list[EvidenceRelation]:
        relations: list[EvidenceRelation] = []
        for service in _records(facts.get("services")):
            service_name = service.get("name")
            dependencies = service.get("dependencies")
            if not isinstance(service_name, str) or not service_name.strip():
                continue
            if not isinstance(dependencies, list):
                continue
            normalized_service = service_name.strip().casefold()
            for dependency in dependencies[:32]:
                if not isinstance(dependency, str) or not dependency.strip():
                    continue
                normalized_dependency = dependency.strip().casefold()
                relations.append(
                    _relation(
                        record,
                        source_entity=_entity_id("service", normalized_service),
                        target_entity=_entity_id("service", normalized_dependency),
                        kind=RelationKind.DEPENDS_ON,
                        identity=(normalized_service, normalized_dependency),
                        conditions=("service dependency explicitly reported",),
                        metadata={
                            "source_service": service_name,
                            "target_service": dependency,
                        },
                    )
                )
        return relations

    def _volume_disk_relations(
        self,
        record: EvidenceRecord,
        facts: dict[str, JsonValue],
    ) -> list[EvidenceRelation]:
        mappings = _records(facts.get("volume_mappings"))
        disks = _records(facts.get("physical_disks"))
        disk_by_index: dict[int, dict[str, JsonValue]] = {}
        for disk in disks:
            index = _nonnegative_int(disk.get("disk_index"))
            if index is not None:
                disk_by_index[index] = disk

        relations: list[EvidenceRelation] = []
        for mapping in mappings:
            volume_id = mapping.get("volume_id")
            disk_index = _nonnegative_int(mapping.get("disk_index"))
            if not isinstance(volume_id, str) or not volume_id.strip() or disk_index is None:
                continue
            disk = disk_by_index.get(disk_index)
            if disk is None:
                continue
            device_id = disk.get("device_id")
            if not isinstance(device_id, str) or not device_id.strip():
                continue
            normalized_volume = volume_id.strip().casefold()
            normalized_device = device_id.strip().casefold()
            relations.append(
                _relation(
                    record,
                    source_entity=_entity_id("volume", normalized_volume),
                    target_entity=_entity_id("physical_disk", disk_index, normalized_device),
                    kind=RelationKind.STORED_ON,
                    identity=(normalized_volume, disk_index, normalized_device),
                    conditions=("volume-to-partition-to-disk mapping explicitly reported",),
                    metadata={
                        "volume_id": volume_id,
                        "partition_id": mapping.get("partition_id"),
                        "disk_index": disk_index,
                        "device_id": device_id,
                    },
                )
            )
        return relations


def _records(value: JsonValue | None) -> tuple[dict[str, JsonValue], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _positive_int(value: JsonValue | None) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _nonnegative_int(value: JsonValue | None) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _stable_creation_time(value: JsonValue | None) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _normalized_device_id(value: JsonValue | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().casefold()


def _entity_id(kind: str, *identity: JsonValue) -> EntityId:
    digest = _digest({"identity": list(identity), "kind": kind})
    return EntityId(root=f"entity_{digest[:32]}")


def _relation(
    record: EvidenceRecord,
    *,
    source_entity: EntityId,
    target_entity: EntityId,
    kind: RelationKind,
    identity: Iterable[JsonValue],
    conditions: tuple[str, ...],
    metadata: dict[str, JsonValue],
) -> EvidenceRelation:
    relation_digest = _digest(
        {
            "evidence_id": str(record.evidence_id),
            "identity": list(identity),
            "kind": kind.value,
            "source_entity_id": str(source_entity),
            "target_entity_id": str(target_entity),
        }
    )
    return EvidenceRelation(
        relation_id=f"rel_{relation_digest[:32]}",
        source_entity_id=source_entity,
        target_entity_id=target_entity,
        relationship=kind,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        valid_from=record.observed_at,
        valid_until=record.observed_at,
        evidence_ids=(record.evidence_id,),
        source_ids=(record.source.source_id,),
        conditions=conditions,
        applicability=(record.collector.id,),
        version_metadata=metadata,
    )


def _digest(value: dict[str, JsonValue]) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
