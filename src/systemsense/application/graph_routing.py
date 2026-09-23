"""Trusted, bounded machine-edge to broad registered-probe hints.

This is deterministic attention routing, not a claim that a driver caused a
symptom or that a bounded inventory will enumerate that exact driver. No model
text or arbitrary stored relationship can mint a hint.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from systemsense.decision.contracts import PermissionClass, ProbeCapability
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId, EntityId, stable_source_id
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

_SOURCE_PROBE = "gpu.telemetry.sample"
_TARGET_PROBE = "devices.snapshot"
_MAX_INPUTS = 128
_MAX_GRAPH_SOURCE_AGE = timedelta(minutes=5)


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
        or _SOURCE_PROBE not in completed_probe_ids
        or _TARGET_PROBE in completed_probe_ids
    ):
        return capabilities
    catalog = {capability.probe_id: capability for capability in capabilities}
    source = catalog.get(_SOURCE_PROBE)
    target = catalog.get(_TARGET_PROBE)
    if (
        source is None
        or target is None
        or not _safe_read_only(source)
        or not _safe_read_only(target)
    ):
        return capabilities
    by_id = {item.evidence_id: item for item in context}
    if len(by_id) != len(context):
        return capabilities
    confirmed: dict[str, EntityId] = {}
    with store.read_snapshot():
        for relation in relationships:
            if (
                relation.memory_layer is not MemoryLayer.MACHINE
                or relation.assertion_status is not AssertionStatus.OBSERVED
                or relation.relationship is not RelationKind.USES_DRIVER
                or relation.applicability != (_SOURCE_PROBE,)
                or len(relation.evidence_ids) != 1
            ):
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
            )
            if record is None:
                continue
            if relation not in ExplicitRelationProjector().project(record).relations:
                continue
            if not _window_within_incident(relation, incident_start, incident_end):
                continue
            confirmed[str(relation.target_entity_id)] = relation.target_entity_id
    if not confirmed:
        return capabilities
    entity_ids = tuple(confirmed[key] for key in sorted(confirmed))[:64]
    updated = ProbeCapability.model_validate(
        {
            **target.model_dump(mode="json"),
            "related_entity_hint_ids": [str(item) for item in entity_ids],
        }
    )
    return tuple(updated if item.probe_id == _TARGET_PROBE else item for item in capabilities)


def _safe_read_only(capability: ProbeCapability) -> bool:
    return (
        capability.permission_class is PermissionClass.READ_ONLY
        and capability.safety_class in {SafetyClass.R0, SafetyClass.R1}
        and capability.target_state_effect == "none"
        and not capability.outbound_network
    )


def _window_within_incident(
    relation: EvidenceRelation, incident_start: datetime, incident_end: datetime
) -> bool:
    """The full query interval, not just its upper bound, must fit the incident."""

    raw_start = relation.version_metadata.get("window_started_at")
    raw_end = relation.version_metadata.get("window_ended_at")
    if not isinstance(raw_start, str) or not isinstance(raw_end, str):
        return False
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
        or record.source.locator != {"probe_id": _SOURCE_PROBE}
        or record.collector.id != _SOURCE_PROBE
        or record.extraction.parser != "builtin.probe"
        or record.extraction.parser_version != 1
        or record.extraction.confidence != 1.0
        or row.execution_id != str(record.collector.execution_id)
        or row.dedupe_key != f"execution:{record.collector.execution_id}"
    ):
        return None
    expected_source_id = stable_source_id(
        "systemsense.probe",
        {"probe_id": _SOURCE_PROBE, "probe_version": record.collector.version},
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
        or execution.probe_id != _SOURCE_PROBE
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
