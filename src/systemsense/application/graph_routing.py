"""Trusted, bounded machine-edge to broad registered-probe hints.

This is deterministic attention routing, not a claim that a driver caused a
symptom or that a bounded inventory will enumerate that exact driver. No model
text or arbitrary stored relationship can mint a hint.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from systemsense.decision.contracts import PermissionClass, ProbeCapability
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId, EntityId, JsonValue, stable_source_id
from systemsense.domain.probes import SafetyClass
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.projection import ExplicitRelationProjector
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.storage.sqlite_store import SQLiteStore

# This allowlist maps an observed machine relationship to *coverage*, not a
# cause or a command. A new mapping requires an explicit projector and test.
_ROUTES: tuple[tuple[str, RelationKind, str], ...] = (
    ("gpu.telemetry.sample", RelationKind.USES_DRIVER, "devices.snapshot"),
    ("application.snapshot", RelationKind.DEPENDS_ON, "incident.events"),
    ("storage.snapshot", RelationKind.STORED_ON, "incident.events"),
)
_MAX_INPUTS = 128
_MAX_GRAPH_SOURCE_AGE = timedelta(minutes=5)
_STORAGE_NON_TOPOLOGY_LIMITATIONS = (
    re.compile(r"omitted [1-9][0-9]* reliability rows with invalid device identifiers"),
    re.compile(
        r"[1-9][0-9]* storage reliability rows remain unbound: provider DeviceId "
        r"was not verified against Win32 disk identity"
    ),
    re.compile(r"storage reliability unavailable: [A-Za-z_][A-Za-z0-9_]*"),
)


def bind_trusted_machine_probe_targets(
    *,
    store: SQLiteStore,
    case_id: CaseId,
    incident_start: datetime,
    incident_end: datetime,
    context: tuple[EvidenceContext, ...],
    relationships: tuple[EvidenceRelation, ...],
    capabilities: tuple[ProbeCapability, ...],
    completed_probe_ids: frozenset[str],
    symptom: str,
    now: datetime | None = None,
) -> tuple[ProbeCapability, ...]:
    """Return possible related coverage from reprojected current-case facts."""

    try:
        decision_at = ensure_utc(now or utc_now())
    except ValueError:
        return capabilities
    if (
        incident_start > incident_end
        or len(context) > _MAX_INPUTS
        or len(relationships) > _MAX_INPUTS
        or len(capabilities) > _MAX_INPUTS
    ):
        return capabilities
    catalog = {capability.probe_id: capability for capability in capabilities}
    by_id = {item.evidence_id: item for item in context}
    if len(by_id) != len(context):
        return capabilities
    confirmed: dict[str, dict[str, EntityId]] = {}
    with store.read_snapshot():
        for relation in relationships:
            route = next(
                (
                    (source_id, target_id)
                    for source_id, kind, target_id in _ROUTES
                    if relation.relationship is kind
                    and relation.applicability == (source_id,)
                    and source_id in completed_probe_ids
                    and target_id not in completed_probe_ids
                    and source_id in catalog
                    and target_id in catalog
                    and _safe_read_only(catalog[source_id])
                    and _safe_read_only(catalog[target_id])
                ),
                None,
            )
            if (
                route is None
                or relation.memory_layer is not MemoryLayer.MACHINE
                or relation.assertion_status is not AssertionStatus.OBSERVED
                or len(relation.evidence_ids) != 1
            ):
                continue
            source_id, target_id = route
            if source_id == "application.snapshot" and not _named_service_in_symptom(
                relation, symptom
            ):
                continue
            if source_id == "storage.snapshot" and not _named_volume_in_symptom(relation, symptom):
                continue
            excerpt = by_id.get(relation.evidence_ids[0])
            if excerpt is None:
                continue
            record = _trusted_record(
                store=store,
                case_id=case_id,
                incident_start=incident_start,
                incident_end=incident_end,
                excerpt=excerpt,
                decision_at=decision_at,
                source_probe_id=source_id,
            )
            if record is None:
                continue
            if source_id == "storage.snapshot" and not _storage_interval_within_incident(
                record, incident_start, incident_end
            ):
                continue
            if source_id == "storage.snapshot" and not _single_storage_disk(record, relation):
                continue
            if relation not in ExplicitRelationProjector().project(record).relations:
                continue
            if not _window_within_incident(relation, incident_start, incident_end):
                continue
            confirmed.setdefault(target_id, {})[str(relation.target_entity_id)] = (
                relation.target_entity_id
            )
    if not confirmed:
        return capabilities
    updated: dict[str, ProbeCapability] = {}
    for target_id, entities in confirmed.items():
        target = catalog[target_id]
        entity_ids = tuple(entities[key] for key in sorted(entities))[:64]
        updated[target_id] = ProbeCapability.model_validate(
            {
                **target.model_dump(mode="json"),
                "related_entity_hint_ids": [str(item) for item in entity_ids],
            }
        )
    return tuple(updated.get(item.probe_id, item) for item in capabilities)


def _named_service_in_symptom(relation: EvidenceRelation, symptom: str) -> bool:
    """Require exact named service binding before machine-wide edges affect routing."""

    name = relation.version_metadata.get("source_service")
    if not isinstance(name, str) or not 1 <= len(name) <= 120 or len(symptom) > 2000:
        return False
    normalized_name = name.strip().casefold()
    if not normalized_name:
        return False
    return (
        re.search(
            r"(?<![a-z0-9_.-])" + re.escape(normalized_name) + r"(?![a-z0-9_.-])",
            symptom.casefold(),
        )
        is not None
    )


def _named_volume_in_symptom(relation: EvidenceRelation, symptom: str) -> bool:
    """Tie broad storage-event coverage to the specific reported drive."""

    volume_id = relation.version_metadata.get("volume_id")
    if not isinstance(volume_id, str) or re.fullmatch(r"[a-zA-Z]:", volume_id) is None:
        return False
    if len(symptom) > 2000:
        return False
    return (
        re.search(
            r"(?<![a-z0-9])" + re.escape(volume_id.casefold()) + r"(?![a-z0-9])",
            symptom.casefold(),
        )
        is not None
    )


def _safe_read_only(capability: ProbeCapability) -> bool:
    return (
        capability.permission_class is PermissionClass.READ_ONLY
        and capability.safety_class in {SafetyClass.R0, SafetyClass.R1}
        and capability.target_state_effect == "none"
        and not capability.outbound_network
    )


def _storage_interval_within_incident(
    record: EvidenceRecord, incident_start: datetime, incident_end: datetime
) -> bool:
    """A storage topology read spans WMI calls; its entire interval must qualify."""

    facts = {fact.name: fact.value for fact in record.facts}
    raw_start = facts.get("collection_started_at")
    raw_end = facts.get("collection_completed_at")
    if not isinstance(raw_start, str) or not isinstance(raw_end, str):
        return False
    if facts.get("collection_status") not in {"available", "partial"}:
        return False
    try:
        started_at = ensure_utc(datetime.fromisoformat(raw_start))
        ended_at = ensure_utc(datetime.fromisoformat(raw_end))
    except ValueError:
        return False
    return (
        incident_start <= started_at <= ended_at <= incident_end
        and ended_at == record.observed_at
        and ended_at <= record.captured_at
    )


def _single_storage_disk(record: EvidenceRecord, relation: EvidenceRelation) -> bool:
    """A spanned volume is not a hint for one physical-disk identity."""

    facts = {fact.name: fact.value for fact in record.facts}
    mappings = facts.get("volume_mappings")
    volumes = facts.get("volumes")
    disks = facts.get("physical_disks")
    volume_id = relation.version_metadata.get("volume_id")
    disk_index = relation.version_metadata.get("disk_index")
    if (
        not isinstance(mappings, list)
        or not isinstance(volumes, list)
        or not isinstance(disks, list)
        or len(mappings) >= 128
        or len(volumes) >= 64
        or len(disks) >= 64
        or not isinstance(volume_id, str)
        or not isinstance(disk_index, int)
        or isinstance(disk_index, bool)
        or any(not _storage_limitation_is_non_topology(item) for item in record.limitations)
    ):
        return False
    volume_ids: set[str] = set()
    for item in volumes:
        if not isinstance(item, dict):
            return False
        observed_id = item.get("volume_id")
        if not isinstance(observed_id, str) or not observed_id.strip():
            return False
        volume_ids.add(observed_id.casefold())
    if not volume_ids or len(volume_ids) != len(volumes):
        return False
    mapped_ids: set[str] = set()
    matches: list[dict[str, JsonValue]] = []
    for item in mappings:
        if not isinstance(item, dict):
            return False
        observed_volume = item.get("volume_id")
        if not isinstance(observed_volume, str):
            return False
        mapped_ids.add(observed_volume.casefold())
        if observed_volume.casefold() == volume_id.casefold():
            matches.append(item)
    return (
        volume_ids == mapped_ids
        and bool(matches)
        and all(
            isinstance(item.get("disk_index"), int)
            and not isinstance(item["disk_index"], bool)
            and item["disk_index"] == disk_index
            for item in matches
        )
    )


def _storage_limitation_is_non_topology(note: str) -> bool:
    if note == "Storage fields were read over the collection interval":
        return True
    return any(pattern.fullmatch(note) is not None for pattern in _STORAGE_NON_TOPOLOGY_LIMITATIONS)


def _window_within_incident(
    relation: EvidenceRelation, incident_start: datetime, incident_end: datetime
) -> bool:
    """The full query interval, not just its upper bound, must fit the incident."""

    raw_start = relation.version_metadata.get("window_started_at")
    raw_end = relation.version_metadata.get("window_ended_at")
    if not isinstance(raw_start, str) or not isinstance(raw_end, str):
        return (
            relation.applicability != ("gpu.telemetry.sample",)
            and relation.valid_from is not None
            and relation.valid_until is not None
            and incident_start <= relation.valid_from <= relation.valid_until <= incident_end
        )
    try:
        started_at = ensure_utc(datetime.fromisoformat(raw_start))
        ended_at = ensure_utc(datetime.fromisoformat(raw_end))
    except ValueError:
        return False
    return incident_start <= started_at <= ended_at <= incident_end


def _trusted_record(
    *,
    store: SQLiteStore,
    case_id: CaseId,
    incident_start: datetime,
    incident_end: datetime,
    excerpt: EvidenceContext,
    decision_at: datetime,
    source_probe_id: str,
) -> EvidenceRecord | None:
    if (
        excerpt.status is not EvidenceContextStatus.OBSERVED
        or excerpt.case_scope != "current_case"
        or excerpt.incident_relevant is not True
        or not incident_start <= excerpt.observed_at <= incident_end
        or excerpt.observed_at > excerpt.captured_at
        or excerpt.captured_at > decision_at
        or decision_at - excerpt.captured_at > _MAX_GRAPH_SOURCE_AGE
    ):
        return None
    row = store.evidence(case_id=str(case_id), evidence_id=str(excerpt.evidence_id))
    if (
        row is None
        or row.time_basis != "collector_upper_bound"
        or row.time_quality != "bounded_interval"
    ):
        return None
    try:
        record = EvidenceRecord.model_validate_json(row.record_json)
    except ValueError:
        return None
    if (
        record.case_id != case_id
        or record.evidence_id != excerpt.evidence_id
        or record.observed_at != excerpt.observed_at
        or record.captured_at != excerpt.captured_at
        or row.observed_at != record.observed_at.isoformat()
        or row.captured_at != record.captured_at.isoformat()
        or record.statement_kind is not StatementKind.OBSERVED_FACT
        or record.source.type != "systemsense.probe"
        or record.source.locator != {"probe_id": source_probe_id}
        or record.collector.id != source_probe_id
        or record.extraction.parser != "builtin.probe"
        or record.extraction.parser_version != 1
        or record.extraction.confidence != 1.0
        or row.execution_id != str(record.collector.execution_id)
        or row.dedupe_key != f"execution:{record.collector.execution_id}"
    ):
        return None
    expected_source_id = stable_source_id(
        "systemsense.probe",
        {"probe_id": source_probe_id, "probe_version": record.collector.version},
    )
    source_row = store.connection.execute(
        "SELECT source_id FROM evidence WHERE case_id = ? AND evidence_id = ?",
        (str(case_id), str(excerpt.evidence_id)),
    ).fetchone()
    if (
        source_row is None
        or source_row[0] != expected_source_id
        or record.source.source_id != expected_source_id
    ):
        return None
    facts = {fact.name: fact.value for fact in record.facts}
    if len(facts) != len(record.facts) or facts != excerpt.facts:
        return None
    execution = store.probe_execution(str(record.collector.execution_id))
    if (
        execution is None
        or execution.case_id != str(case_id)
        or execution.probe_id != source_probe_id
        or execution.probe_version != record.collector.version
        or execution.status != "ok"
        or execution.parameters_json != "{}"
        or execution.finished_at is None
    ):
        return None
    try:
        started_at = ensure_utc(datetime.fromisoformat(execution.started_at))
        finished_at = ensure_utc(datetime.fromisoformat(execution.finished_at))
    except ValueError:
        return None
    if started_at > record.observed_at or finished_at < record.captured_at:
        return None
    return record
