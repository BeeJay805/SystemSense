"""A selected graph branch can reveal stored facts, never invent measurements."""

from datetime import datetime, timedelta
from pathlib import Path

from systemsense.application.frontier_branch import process_claimed_branch
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, ExecutionId
from systemsense.domain.time import utc_now
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.retrieval import (
    EvidenceCatalogQuery,
    EvidenceRelationRepository,
    EvidenceRetriever,
)
from systemsense.storage.search_frontier import (
    FrontierBranchReferenceV2,
    FrontierItemV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _insert_record(
    store: SQLiteStore,
    *,
    case_id: str,
    evidence_id: str,
    collector_id: str,
    summary: str,
    observed_at: datetime,
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
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
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


def _case_with_branch(
    store: SQLiteStore,
) -> tuple[CaseId, EvidenceId, EvidenceId, EvidenceRelation]:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind="incident",
        symptom="Investigate network adapter",
        created_at=utc_now().isoformat(),
    )
    source = EvidenceId(root=f"ev_{'1' * 32}")
    neighbor = EvidenceId(root=f"ev_{'2' * 32}")
    for evidence_id in (source, neighbor):
        _insert_record(
            store,
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            collector_id="network.adapter",
            summary=f"Stored observation {evidence_id}",
            observed_at=utc_now() - timedelta(seconds=2),
        )
    relation = EvidenceRelation(
        relation_id=f"rel_{'a' * 32}",
        source_entity_id=EntityId(root=f"entity_{'1' * 32}"),
        target_entity_id=EntityId(root=f"entity_{'2' * 32}"),
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(source, neighbor),
    )
    assert EvidenceRelationRepository(store).append(relation)
    return case_id, source, neighbor, relation


def _claim(
    store: SQLiteStore, case_id: CaseId, relation: EvidenceRelation
) -> tuple[SearchFrontierRepository, RelevantVersionsV1, FrontierItemV1]:
    retriever = EvidenceRetriever(store)
    generation = retriever.discover(
        EvidenceCatalogQuery(case_id=case_id, limit=1)
    ).case_evidence_generation
    versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
    frontier = SearchFrontierRepository(store)
    item = frontier.upsert_item(
        case_id, FrontierBranchReferenceV2.from_relation(relation), versions
    )
    return frontier, versions, frontier.claim_ready(item.item_id, versions)


def test_single_record_relation_is_not_traversable(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "single-branch.db") as store:
        case_id, source, _, relation = _case_with_branch(store)
        singleton = relation.model_copy(
            update={"relation_id": "rel_" + "b" * 32, "evidence_ids": (source,)}
        )
        assert EvidenceRelationRepository(store).append(singleton)
        frontier, versions, selected = _claim(store, case_id, singleton)

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=singleton,
            current_packet_evidence_ids=(source,),
            expected_versions=versions,
            store=store,
            retriever=EvidenceRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert result.limitations == ("branch_source_changed",)


def test_claimed_branch_returns_one_exact_omitted_current_case_observation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch-success.db") as store:
        case_id, source, neighbor, relation = _case_with_branch(store)
        frontier, versions, selected = _claim(store, case_id, relation)

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(source,),
            expected_versions=versions,
            store=store,
            retriever=EvidenceRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.RUNNING
        assert result.evidence is not None
        assert result.evidence.evidence_id == neighbor
        assert result.evidence.case_id == case_id
        assert frontier.readback(selected.item_id).status is FrontierStatus.RUNNING
        # Only the coordinator can assert that this exact ID survived into the
        # focused packet before acknowledging completed delivery.
        frontier.transition(
            selected.item_id, FrontierStatus.RUNNING, FrontierStatus.SATISFIED, "delivered"
        )
        assert frontier.readback(selected.item_id).status is FrontierStatus.SATISFIED
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0


def test_claimed_branch_without_unseen_provenance_closes_obsolete(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch-empty.db") as store:
        case_id, source, neighbor, relation = _case_with_branch(store)
        frontier, versions, selected = _claim(store, case_id, relation)

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(source, neighbor),
            expected_versions=versions,
            store=store,
            retriever=EvidenceRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert result.evidence is None
        assert "no_unseen_neighbor" in result.limitations
        assert frontier.readback(selected.item_id).status is FrontierStatus.OBSOLETE


def test_claimed_branch_requires_a_visible_provenance_anchor(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch-unanchored.db") as store:
        case_id, _source, _neighbor, relation = _case_with_branch(store)
        frontier, versions, selected = _claim(store, case_id, relation)

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(),
            expected_versions=versions,
            store=store,
            retriever=EvidenceRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert result.evidence is None
        assert "branch_not_anchored_in_packet" in result.limitations


def test_claimed_branch_fails_closed_if_relation_version_is_superseded(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch-new-version.db") as store:
        case_id, source, _neighbor, relation = _case_with_branch(store)
        frontier, versions, selected = _claim(store, case_id, relation)
        assert EvidenceRelationRepository(store).append(
            relation.model_copy(
                update={"relation_version": 2, "relationship": RelationKind.DEPENDS_ON}
            )
        )

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(source,),
            expected_versions=versions,
            store=store,
            retriever=EvidenceRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert result.evidence is None
        assert frontier.readback(selected.item_id).status is FrontierStatus.OBSOLETE


def test_claimed_branch_rejects_foreign_case_source_provenance(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch-foreign-source.db") as store:
        case_id, source, _neighbor, relation = _case_with_branch(store)
        foreign_case = CaseId.new()
        store.create_case(
            case_id=str(foreign_case),
            kind="incident",
            symptom="Unrelated case",
            created_at=utc_now().isoformat(),
        )
        foreign_evidence = f"ev_{'f' * 32}"
        _insert_record(
            store,
            case_id=str(foreign_case),
            evidence_id=foreign_evidence,
            collector_id="network.adapter",
            summary="Foreign observation",
            observed_at=utc_now() - timedelta(seconds=2),
        )
        foreign_source = f"src_{'f' * 64}"
        relation = relation.model_copy(
            update={"relation_version": 2, "source_ids": (foreign_source,)}
        )
        assert EvidenceRelationRepository(store).append(relation)
        frontier, versions, selected = _claim(store, case_id, relation)

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(source,),
            expected_versions=versions,
            store=store,
            retriever=EvidenceRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert "branch_source_changed" in result.limitations
        assert result.evidence is None


def test_claimed_branch_does_not_deliver_across_generation_race(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch-generation.db") as store:
        case_id, source, _neighbor, relation = _case_with_branch(store)
        frontier, versions, selected = _claim(store, case_id, relation)

        class ChangingRetriever(EvidenceRetriever):
            def retrieve(self, query):  # type: ignore[override]
                packet = super().retrieve(query)
                _insert_record(
                    store,
                    case_id=str(case_id),
                    evidence_id=f"ev_{'3' * 32}",
                    collector_id="network.adapter",
                    summary="Concurrent stored observation",
                    observed_at=utc_now() - timedelta(seconds=1),
                )
                return packet

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(source,),
            expected_versions=versions,
            store=store,
            retriever=ChangingRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert result.evidence is None
        assert "catalog_generation_changed" in result.limitations
        assert frontier.readback(selected.item_id).status is FrontierStatus.OBSOLETE


def test_claimed_branch_does_not_deliver_after_relation_revision_during_read(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "branch-relation-race.db") as store:
        case_id, source, _neighbor, relation = _case_with_branch(store)
        frontier, versions, selected = _claim(store, case_id, relation)

        class ChangingRetriever(EvidenceRetriever):
            def retrieve(self, query):  # type: ignore[override]
                packet = super().retrieve(query)
                revised = relation.model_copy(
                    update={"relation_version": 2, "relationship": RelationKind.DEPENDS_ON}
                )
                assert EvidenceRelationRepository(store).append(revised)
                return packet

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(source,),
            expected_versions=versions,
            store=store,
            retriever=ChangingRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert result.evidence is None
        assert "branch_source_changed" in result.limitations
        assert frontier.readback(selected.item_id).status is FrontierStatus.OBSOLETE


def test_claimed_branch_closes_when_catalog_readback_fails(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch-catalog-error.db") as store:
        case_id, source, _neighbor, relation = _case_with_branch(store)
        frontier, versions, selected = _claim(store, case_id, relation)

        class FailingRetriever(EvidenceRetriever):
            def discover(self, query):  # type: ignore[override]
                raise RuntimeError("catalog unavailable")

        result = process_claimed_branch(
            case_id=case_id,
            selected=selected,
            branch_relation=relation,
            current_packet_evidence_ids=(source,),
            expected_versions=versions,
            store=store,
            retriever=FailingRetriever(store),
            frontier=frontier,
        )

        assert result.status is FrontierStatus.OBSOLETE
        assert result.evidence is None
        assert "branch_catalog_error" in result.limitations
        assert frontier.readback(selected.item_id).status is FrontierStatus.OBSOLETE
