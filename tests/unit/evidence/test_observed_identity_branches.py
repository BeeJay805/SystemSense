from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.evidence.graph import AssertionStatus, MemoryLayer, RelationKind
from systemsense.evidence.projection import ExplicitRelationProjector
from systemsense.evidence.retrieval import EvidenceRelationRepository
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
CASE = CaseId(root="case_" + "a" * 32)


def _insert_service_observation(
    store: SQLiteStore,
    *,
    ordinal: int,
    observed_at: datetime,
    service: str = "AudioSrv",
    pid: int = 42,
    case_id: CaseId = CASE,
) -> tuple[EvidenceId, str, int]:
    evidence_id = EvidenceId(root=f"ev_{ordinal:032x}")
    source_id = "src_" + f"{ordinal:064x}"
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at + timedelta(seconds=1),
        source=EvidenceSource(type="test.fixture", source_id=source_id, locator={}),
        collector=CollectorReference(
            id="services.snapshot",
            version=1,
            execution_id=ExecutionId(root=f"exec_{ordinal:032x}"),
        ),
        summary="Observed service and exact process identity",
        facts=(
            EvidenceFact(
                name="processes",
                value=[{"pid": pid, "creation_time": "2026-09-23T11:59:00+00:00"}],
            ),
            EvidenceFact(name="services", value=[{"name": service, "process_id": pid}]),
        ),
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
        )
    relation = ExplicitRelationProjector().project(record).relations[0]
    assert EvidenceRelationRepository(store).append(relation)
    return evidence_id, relation.relation_id, relation.relation_version


def test_exact_shared_entity_yields_noncausal_cross_record_navigation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "identity.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow", created_at=NOW.isoformat()
        )
        visible, relation_id, version = _insert_service_observation(
            store, ordinal=1, observed_at=NOW
        )
        unseen, _, _ = _insert_service_observation(
            store, ordinal=2, observed_at=NOW + timedelta(minutes=1)
        )

        repository = EvidenceRelationRepository(store)
        with store.read_snapshot():
            bridges = repository.observed_identity_bridges(
                case_id=CASE,
                visible_evidence_ids=(visible,),
                anchor_relations=((relation_id, version),),
                limit=4,
            )

        assert len(bridges) == 1
        bridge = bridges[0]
        assert bridge.evidence_ids == (visible, unseen)
        assert bridge.memory_layer is MemoryLayer.MACHINE
        assert bridge.assertion_status is AssertionStatus.OBSERVED
        assert bridge.relationship is RelationKind.OBSERVED_AFTER
        assert bridge.source_entity_id == bridge.target_entity_id
        assert bridge.version_metadata["navigation_only"] is True
        assert repository.read_latest(bridge.relation_id) is None
        assert repository.observed_identity_bridges(
            case_id=CASE,
            visible_evidence_ids=(visible,),
            anchor_relations=((relation_id, version),),
            limit=4,
        ) == (bridge,)


def test_identity_navigation_rejects_wrong_target_case_and_stale_window(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "identity-negative.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow", created_at=NOW.isoformat()
        )
        foreign = CaseId(root="case_" + "b" * 32)
        store.create_case(
            case_id=str(foreign), kind="incident", symptom="slow", created_at=NOW.isoformat()
        )
        visible, relation_id, version = _insert_service_observation(
            store, ordinal=1, observed_at=NOW
        )
        _insert_service_observation(
            store, ordinal=2, observed_at=NOW + timedelta(minutes=1), service="OtherService", pid=43
        )
        _insert_service_observation(store, ordinal=3, observed_at=NOW + timedelta(minutes=10))
        _insert_service_observation(
            store, ordinal=4, observed_at=NOW + timedelta(minutes=1), case_id=foreign
        )
        _insert_service_observation(store, ordinal=5, observed_at=NOW)

        assert (
            EvidenceRelationRepository(store).observed_identity_bridges(
                case_id=CASE,
                visible_evidence_ids=(visible,),
                anchor_relations=((relation_id, version),),
                limit=4,
            )
            == ()
        )
