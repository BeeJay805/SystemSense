from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, ExecutionId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.retrieval import (
    EvidenceRelationRepository,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
    RelationProvenanceError,
)
from systemsense.storage.sqlite_store import SQLiteStore

_CASE_ID = "case_11111111111111111111111111111111"
_EVIDENCE_ID = EvidenceId(root="ev_11111111111111111111111111111111")
_SOURCE_ID = f"src_{'a' * 64}"
_PROCESS = EntityId(root="entity_11111111111111111111111111111111")
_MODULE = EntityId(root="entity_22222222222222222222222222222222")
_DEVICE = EntityId(root="entity_33333333333333333333333333333333")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _seed_evidence(store: SQLiteStore) -> None:
    store.create_case(
        case_id=_CASE_ID,
        kind="incident",
        symptom="graph fixture",
        created_at=_NOW.isoformat(),
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=_CASE_ID,
            evidence_id=str(_EVIDENCE_ID),
            source_id=_SOURCE_ID,
            record_json='{"summary":"process loaded module"}',
            observed_at=_NOW.isoformat(),
            captured_at=_NOW.isoformat(),
        )


def _relation(
    relation_id: str = "rel_11111111111111111111111111111111",
    *,
    source: EntityId = _PROCESS,
    target: EntityId = _MODULE,
    version: int = 1,
    valid_from: datetime = _NOW,
) -> EvidenceRelation:
    return EvidenceRelation(
        relation_id=relation_id,
        source_entity_id=source,
        target_entity_id=target,
        relationship=RelationKind.DEPENDS_ON,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=version,
        valid_from=valid_from,
        evidence_ids=(_EVIDENCE_ID,),
        source_ids=(_SOURCE_ID,),
    )


def test_relation_versions_survive_reopen_and_exact_append_is_idempotent(
    tmp_path: Path,
) -> None:
    database = tmp_path / "systemsense.db"
    first = _relation()
    second = _relation(version=2, valid_from=_NOW + timedelta(hours=1))

    with SQLiteStore(database) as store:
        _seed_evidence(store)
        repository = EvidenceRelationRepository(store)
        assert repository.append(first) is True
        assert repository.append(first) is False
        assert repository.append(second) is True

    with SQLiteStore(database) as store:
        assert EvidenceRelationRepository(store).relations() == (first, second)


def test_relation_scope_is_applied_before_global_page_limit(tmp_path: Path) -> None:
    target_id = EvidenceId(root="ev_22222222222222222222222222222222")
    with SQLiteStore(tmp_path / "scoped.db") as store:
        _seed_evidence(store)
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=_CASE_ID,
                evidence_id=str(target_id),
                source_id=_SOURCE_ID,
                record_json='{"summary":"second scoped observation"}',
                dedupe_key=str(target_id),
                observed_at=_NOW.isoformat(),
                captured_at=_NOW.isoformat(),
            )
        repository = EvidenceRelationRepository(store)
        repository.append(_relation())
        target = _relation("rel_ffffffffffffffffffffffffffffffff").model_copy(
            update={"evidence_ids": (target_id,)}
        )
        repository.append(target)
        assert repository.relations(limit=1, evidence_ids=(target_id,)) == (target,)
        assert repository.relations(limit=1, evidence_ids=()) == ()


def test_seed_relation_page_follows_evidence_priority_before_relation_id(
    tmp_path: Path,
) -> None:
    lower_priority = EvidenceId(root="ev_22222222222222222222222222222222")
    with SQLiteStore(tmp_path / "seed-priority.db") as store:
        _seed_evidence(store)
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=_CASE_ID,
                evidence_id=str(lower_priority),
                source_id=_SOURCE_ID,
                record_json='{"summary":"lower-priority observation"}',
                dedupe_key=str(lower_priority),
                observed_at=_NOW.isoformat(),
                captured_at=_NOW.isoformat(),
            )
        repository = EvidenceRelationRepository(store)
        lower = _relation("rel_11111111111111111111111111111111").model_copy(
            update={"evidence_ids": (lower_priority,)}
        )
        higher = _relation("rel_ffffffffffffffffffffffffffffffff")
        repository.append(lower)
        repository.append(higher)

        assert repository.prioritized_relations(
            evidence_ids=(_EVIDENCE_ID, lower_priority), limit=1
        ) == (higher,)


def test_relation_append_requires_real_evidence_and_source_provenance(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        store.create_case(
            case_id=_CASE_ID,
            kind="incident",
            symptom="graph fixture",
            created_at=_NOW.isoformat(),
        )
        repository = EvidenceRelationRepository(store)

        with pytest.raises(RelationProvenanceError, match="evidence"):
            repository.append(_relation())

        assert repository.relations() == ()


def test_relation_append_rejects_conflicting_same_version(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_evidence(store)
        repository = EvidenceRelationRepository(store)
        relation = _relation()
        repository.append(relation)

        with pytest.raises(ValueError, match="conflicting"):
            repository.append(relation.model_copy(update={"target_entity_id": _DEVICE}))


def test_persisted_graph_traversal_delegates_temporal_and_hard_bounds(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_evidence(store)
        repository = EvidenceRelationRepository(store)
        repository.append(_relation(target=_MODULE))
        repository.append(
            _relation(
                "rel_22222222222222222222222222222222",
                source=_MODULE,
                target=_DEVICE,
                valid_from=_NOW + timedelta(days=1),
            )
        )

        traversed = repository.traverse(
            start_entity_id=_PROCESS,
            as_of=_NOW,
            max_depth=8,
            max_nodes=8,
            max_edges=1,
        )

        assert traversed == (_relation(target=_MODULE),)


def test_outgoing_relation_lookup_is_directional_and_bounded(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "outgoing.db") as store:
        _seed_evidence(store)
        repository = EvidenceRelationRepository(store)
        first = _relation("rel_11111111111111111111111111111111", source=_MODULE)
        second = _relation("rel_22222222222222222222222222222222", source=_MODULE)
        reverse = _relation("rel_33333333333333333333333333333333", source=_PROCESS)
        for relation in (second, reverse, first):
            repository.append(relation)

        assert repository.outgoing(source_entity_ids=(_MODULE,), limit=1) == (first,)
        assert repository.outgoing(source_entity_ids=(_DEVICE,), limit=10) == ()


def test_retention_removes_relations_whose_provenance_was_deleted(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_evidence(store)
        repository = EvidenceRelationRepository(store)
        repository.append(_relation())

        assert (
            store.delete_expired_raw_evidence(
                captured_before=(_NOW + timedelta(seconds=1)).isoformat(),
                limit=10,
            )
            == 1
        )

        assert repository.relations() == ()


def test_retention_removes_source_only_relation_after_last_source_record(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_evidence(store)
        repository = EvidenceRelationRepository(store)
        repository.append(_relation().model_copy(update={"evidence_ids": ()}))

        store.delete_expired_raw_evidence(
            captured_before=(_NOW + timedelta(seconds=1)).isoformat(),
            limit=10,
        )

        assert repository.relations() == ()


def _insert_record(
    store: SQLiteStore,
    *,
    case_id: str,
    evidence_id: str,
    collector_id: str,
    summary: str,
    observed_at: datetime,
    facts: tuple[EvidenceFact, ...] = (),
) -> None:
    source_id = f"src_{evidence_id.removeprefix('ev_') * 2}"
    record = EvidenceRecord(
        evidence_id=EvidenceId(root=evidence_id),
        case_id=CaseId(root=case_id),
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at + timedelta(seconds=1),
        source=EvidenceSource(type="test.fixture", source_id=source_id, locator={}),
        collector=CollectorReference(
            id=collector_id,
            version=1,
            execution_id=ExecutionId(root=f"exec_{evidence_id.removeprefix('ev_')}"),
        ),
        summary=summary,
        facts=facts,
        extraction=Extraction(confidence=1.0, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
        )


def _insert_coverage(
    store: SQLiteStore,
    *,
    case_id: str,
    evidence_id: str,
    category: str,
    reason: str,
    status: CoverageStatus = CoverageStatus.MISSING,
) -> None:
    record = CoverageRecord(
        evidence_id=EvidenceId(root=evidence_id),
        case_id=CaseId(root=case_id),
        category=category,
        status=status,
        captured_at=_NOW,
        reason=reason,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            source_id=f"src_{evidence_id.removeprefix('ev_') * 2}",
            record_json=record.model_dump_json(),
            captured_at=record.captured_at.isoformat(),
        )


def _create_case(store: SQLiteStore, case_id: str, *, kind: str = "incident") -> None:
    store.create_case(
        case_id=case_id,
        kind=kind,
        symptom="retrieval fixture",
        created_at=_NOW.isoformat(),
    )


def test_retrieval_defaults_to_current_case_and_includes_explicit_coverage(
    tmp_path: Path,
) -> None:
    current = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    historical = "case_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, current)
        _create_case(store, historical, kind="passive")
        _insert_record(
            store,
            case_id=current,
            evidence_id="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            collector_id="devices.audio",
            summary="current endpoint observation",
            observed_at=_NOW,
            facts=(EvidenceFact(name="endpoint_count", value=0),),
        )
        _insert_coverage(
            store,
            case_id=current,
            evidence_id="ev_cccccccccccccccccccccccccccccccc",
            category="devices",
            reason="access denied",
        )
        _insert_record(
            store,
            case_id=historical,
            evidence_id="ev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            collector_id="devices.audio",
            summary="historical endpoint observation",
            observed_at=_NOW - timedelta(days=1),
        )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(current_case_id=CaseId(root=current))
        )

        assert tuple(str(item.case_id) for item in packet.evidence) == (current,)
        assert packet.evidence[0].facts == (EvidenceFact(name="endpoint_count", value=0),)
        assert packet.evidence[0].collector_id == "devices.audio"
        assert packet.evidence[0].execution_id == ExecutionId(root=f"exec_{'a' * 32}")
        assert len(packet.coverage) == 1
        assert packet.coverage[0].status is CoverageStatus.MISSING
        assert packet.coverage[0].reason == "access denied"
        assert packet.considered_case_ids == (CaseId(root=current),)


def test_priority_evidence_can_enter_bounded_packet_beyond_candidate_page(tmp_path: Path) -> None:
    current = CaseId(root="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    target = EvidenceId(root="ev_ffffffffffffffffffffffffffffffff")
    with SQLiteStore(tmp_path / "priority.db") as store:
        _create_case(store, str(current))
        _insert_record(
            store,
            case_id=str(current),
            evidence_id=str(target),
            collector_id="fixture.rows",
            summary="graph-linked older observation",
            observed_at=_NOW - timedelta(minutes=2),
        )
        for index in range(3):
            _insert_record(
                store,
                case_id=str(current),
                evidence_id=f"ev_{index + 1:032x}",
                collector_id="fixture.rows",
                summary=f"newer observation {index}",
                observed_at=_NOW - timedelta(seconds=index),
            )
        query = EvidenceRetrievalQuery(
            current_case_id=current,
            candidate_limit=2,
            evidence_limit=1,
            coverage_limit=1,
            priority_evidence_ids=(target,),
        )
        packet = EvidenceRetriever(store).retrieve(query)

        assert tuple(item.evidence_id for item in packet.evidence) == (target,)
        assert packet.omitted_evidence_count == 3


def test_historical_retrieval_requires_opt_in_and_exact_case_ids(tmp_path: Path) -> None:
    current = CaseId(root="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    selected = CaseId(root="case_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    unselected = CaseId(root="case_cccccccccccccccccccccccccccccccc")
    with pytest.raises(ValidationError, match="include_historical"):
        EvidenceRetrievalQuery(current_case_id=current, historical_case_ids=(selected,))

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        for case_id in (current, selected, unselected):
            _create_case(store, str(case_id), kind="passive")
            _insert_record(
                store,
                case_id=str(case_id),
                evidence_id=f"ev_{case_id.root[-1] * 32}",
                collector_id="core.system",
                summary=f"record for {case_id}",
                observed_at=_NOW,
            )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=current,
                include_historical=True,
                historical_case_ids=(selected,),
            )
        )

        assert {str(item.case_id) for item in packet.evidence} == {
            str(current),
            str(selected),
        }
        assert unselected not in packet.considered_case_ids


def test_historical_retrieval_rejects_non_passive_case(tmp_path: Path) -> None:
    current = CaseId(root="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    other_investigation = CaseId(root="case_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, str(current))
        _create_case(store, str(other_investigation))

        with pytest.raises(ValueError, match="passive"):
            EvidenceRetriever(store).retrieve(
                EvidenceRetrievalQuery(
                    current_case_id=current,
                    include_historical=True,
                    historical_case_ids=(other_investigation,),
                )
            )


def test_retrieval_intersects_time_category_exact_id_and_keyword_filters(
    tmp_path: Path,
) -> None:
    case_id = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    wanted_id = EvidenceId(root="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, case_id)
        _insert_record(
            store,
            case_id=case_id,
            evidence_id=str(wanted_id),
            collector_id="network.dns",
            summary="DNS cache contains target.example",
            observed_at=_NOW,
        )
        _insert_record(
            store,
            case_id=case_id,
            evidence_id="ev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            collector_id="core.system",
            summary="target.example appears elsewhere",
            observed_at=_NOW,
        )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=CaseId(root=case_id),
                observed_from=_NOW - timedelta(minutes=1),
                observed_until=_NOW + timedelta(minutes=1),
                categories=("network",),
                evidence_ids=(wanted_id,),
                keyword="target.example",
            )
        )

        assert tuple(item.evidence_id for item in packet.evidence) == (wanted_id,)


def test_retrieval_enforces_fact_and_packet_budgets_with_visible_truncation(
    tmp_path: Path,
) -> None:
    case_id = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, case_id)
        _insert_record(
            store,
            case_id=case_id,
            evidence_id="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            collector_id="core.system",
            summary="bounded record",
            observed_at=_NOW,
            facts=(
                EvidenceFact(name="small", value="ok"),
                EvidenceFact(name="large", value="x" * 1000),
            ),
        )
        _insert_record(
            store,
            case_id=case_id,
            evidence_id="ev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            collector_id="core.system",
            summary="second bounded record",
            observed_at=_NOW - timedelta(seconds=1),
        )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=CaseId(root=case_id),
                evidence_limit=1,
                max_fact_chars=128,
                max_chars=2048,
            )
        )

        assert len(packet.model_dump_json()) <= 2048
        assert len(packet.evidence) == 1
        assert packet.evidence[0].facts == (EvidenceFact(name="small", value="ok"),)
        assert packet.evidence[0].facts_truncated is True
        assert "retrieval budget" in packet.evidence[0].limitations[-1]
        assert packet.truncated is True
        assert packet.omitted_evidence_count == 1


def test_retrieval_compacts_structured_fact_to_an_unchanged_prefix(tmp_path: Path) -> None:
    case_id = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    processes = [{"pid": index, "name": f"process-{index}"} for index in range(10)]
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, case_id)
        _insert_record(
            store,
            case_id=case_id,
            evidence_id="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            collector_id="application.snapshot",
            summary="bounded processes",
            observed_at=_NOW,
            facts=(EvidenceFact(name="processes", value=cast("JsonValue", processes)),),
        )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=CaseId(root=case_id),
                max_fact_chars=180,
                max_chars=4096,
            )
        )

        fact = packet.evidence[0].facts[0]
        assert isinstance(fact.value, list)
        assert 0 < len(fact.value) < len(processes)
        for compacted, original in zip(fact.value, processes, strict=False):
            assert isinstance(compacted, dict)
            assert all(original[key] == value for key, value in compacted.items())
        assert packet.evidence[0].facts_truncated is True


def test_retrieval_reserves_current_failure_coverage_before_large_evidence(
    tmp_path: Path,
) -> None:
    case_id = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, case_id)
        _insert_record(
            store,
            case_id=case_id,
            evidence_id="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            collector_id="core.system",
            summary="x" * 600,
            observed_at=_NOW,
        )
        _insert_coverage(
            store,
            case_id=case_id,
            evidence_id="ev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            category="security.snapshot",
            reason="y" * 600,
            status=CoverageStatus.DENIED,
        )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=CaseId(root=case_id),
                max_chars=1400,
            )
        )

        assert [item.status for item in packet.coverage] == [CoverageStatus.DENIED]
        assert packet.omitted_coverage_count == 0


def test_retrieval_uses_spare_packet_budget_for_exact_fact_prefix(tmp_path: Path) -> None:
    case_id = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    facts = tuple(EvidenceFact(name=f"fact_{index}", value="x" * 1000) for index in range(20))
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, case_id)
        _insert_record(
            store,
            case_id=case_id,
            evidence_id="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            collector_id="core.system",
            summary="many exact facts",
            observed_at=_NOW,
            facts=facts,
        )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=CaseId(root=case_id),
                max_chars=16_000,
                max_fact_chars=4096,
            )
        )

        retained = packet.evidence[0].facts
        assert 0 < len(retained) < len(facts)
        assert retained == facts[: len(retained)]
        assert packet.evidence[0].facts_truncated is True
        assert len(packet.model_dump_json()) <= 16_000


def test_retrieval_reserves_bounded_space_for_opted_in_history(tmp_path: Path) -> None:
    current = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    historical = "case_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _create_case(store, current)
        _create_case(store, historical, kind="passive")
        for index in range(48):
            suffix = f"{index + 1:032x}"
            _insert_record(
                store,
                case_id=current,
                evidence_id=f"ev_{suffix}",
                collector_id=f"domain.{index}",
                summary=f"current record {index}",
                observed_at=_NOW,
            )
        historical_id = EvidenceId(root="ev_ffffffffffffffffffffffffffffffff")
        _insert_record(
            store,
            case_id=historical,
            evidence_id=str(historical_id),
            collector_id="pressure.sample",
            summary="historical pressure sample",
            observed_at=_NOW,
        )

        packet = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=CaseId(root=current),
                include_historical=True,
                historical_case_ids=(CaseId(root=historical),),
                evidence_limit=48,
                max_chars=100_000,
            )
        )

        assert str(historical_id) in {str(item.evidence_id) for item in packet.evidence}
        assert sum(str(item.case_id) == historical for item in packet.evidence) <= 12
        assert sum(str(item.case_id) == current for item in packet.evidence) >= 36
