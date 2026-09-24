"""Discovery adds advisory work; only exact stored evidence retrieval is processed here."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application.frontier_discovery import (
    process_claimed_retrieval,
    seed_frontier_discovery,
)
from systemsense.decision.candidates import AdmittedCandidateRefV1
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import SafetyClass
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.knowledge.models import (
    KnowledgeNode,
    KnowledgeNodeKind,
    KnowledgePacket,
    KnowledgeProbeRoles,
    KnowledgeRelation,
    KnowledgeRelationKind,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.search_frontier import (
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
CASE = CaseId(root="case_" + "a" * 32)


def _record(store: SQLiteStore, number: int, collector: str, age_s: int) -> EvidenceId:
    evidence_id = EvidenceId(root=f"ev_{number:032x}")
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=CASE,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW - timedelta(seconds=age_s),
        captured_at=NOW - timedelta(seconds=age_s) + timedelta(milliseconds=1),
        source=EvidenceSource(type="test.fixture", source_id="src_" + f"{number:064x}", locator={}),
        collector=CollectorReference(
            id=collector,
            version=1,
            execution_id=ExecutionId(root=f"exec_{number:032x}"),
        ),
        summary=f"stored {collector} observation {number}",
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(CASE),
            evidence_id=str(evidence_id),
            source_id=record.source.source_id,
            record_json=record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
        )
    return evidence_id


def _candidate(number: int, probe_id: str) -> AdmittedCandidateRefV1:
    return AdmittedCandidateRefV1(
        candidate_id=f"cand_v1_{number:032x}",
        probe_id=probe_id,
        description=f"Read {probe_id}",
        manifest_sha256="a" * 64,
        invocation_sha256="b" * 64,
        cost_ms=25,
        resource_class=ResourceClass.CPU,
        safety_class=SafetyClass.R0,
    )


def _knowledge() -> KnowledgePacket:
    nodes = (
        KnowledgeNode(
            node_id="kn_storage",
            label="storage",
            category="storage",
            kind=KnowledgeNodeKind.SUBSYSTEM,
        ),
        KnowledgeNode(
            node_id="kn_disk", label="disk", category="storage", kind=KnowledgeNodeKind.MECHANISM
        ),
        KnowledgeNode(
            node_id="kn_network",
            label="network",
            category="network",
            kind=KnowledgeNodeKind.SUBSYSTEM,
        ),
    )
    relations = (
        KnowledgeRelation(
            relation_id="kr_disk_path",
            source_node_id="kn_storage",
            target_node_id="kn_disk",
            relationship=KnowledgeRelationKind.DEPENDS_ON,
            mechanism="Storage depends on disk health",
            conditions=("Disk present",),
            probe_roles=KnowledgeProbeRoles(
                screening_probe_ids=("disk.health",),
                discriminating_probe_ids=(),
                unavailable_measurements=(),
            ),
            counterevidence=("Disk healthy",),
            limitations=("Reference edge does not prove cause",),
            applicability=("Windows storage",),
            source_ids=("ks_test",),
        ),
        KnowledgeRelation(
            relation_id="kr_network_path",
            source_node_id="kn_network",
            target_node_id="kn_storage",
            relationship=KnowledgeRelationKind.INTERACTS_WITH,
            mechanism="Network paths can affect storage-facing applications",
            conditions=("Remote resource",),
            probe_roles=KnowledgeProbeRoles(
                screening_probe_ids=("network.dns",),
                discriminating_probe_ids=(),
                unavailable_measurements=(),
            ),
            counterevidence=("No remote access",),
            limitations=("Reference edge does not prove cause",),
            applicability=("Windows network",),
            source_ids=("ks_test",),
        ),
    )
    return KnowledgePacket(
        schema_version=3,
        pack_id="test",
        pack_version=1,
        nodes=nodes,
        relations=relations,
        sources=(),
        truncated=False,
        omitted_relation_count=0,
        limitations=(),
        disclaimer="Reference relationships are not proof of a case cause.",
    )


def _versions(store: SQLiteStore) -> RelevantVersionsV1:
    generation = (
        EvidenceRetriever(store)
        .discover(EvidenceCatalogQuery(case_id=CASE, limit=1))
        .case_evidence_generation
    )
    return RelevantVersionsV1(objective=1, evidence=generation, graph=1, capabilities=1)


def test_graph_branches_get_fair_retrieval_and_measure_seeds_beyond_packet(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow PDF", created_at=NOW.isoformat()
        )
        visible = _record(store, 1, "disk.health", 0)
        _record(store, 2, "disk.health", 1)
        _record(store, 3, "disk.health", 2)
        network = _record(store, 4, "network.dns", 3)
        _record(store, 5, "disk.health", 4)
        repo = SearchFrontierRepository(store)
        result = seed_frontier_discovery(
            case_id=CASE,
            retriever=EvidenceRetriever(store),
            frontier=repo,
            versions=_versions(store),
            candidates=(_candidate(1, "disk.health"), _candidate(2, "network.dns")),
            knowledge=_knowledge(),
            packet_evidence_ids=(visible,),
            page_limit=1,
            max_pages=5,
            max_items=4,
        )

        assert result.catalog_entries_scanned == 5
        assert result.catalog_has_more is False
        assert result.omitted_reference_count == 2
        assert [item.reference.kind for item in result.items] == [
            "retrieve_evidence",
            "retrieve_evidence",
            "measure",
            "measure",
        ]
        assert result.items[0].reference.evidence_id != visible
        assert result.items[1].reference.evidence_id == network
        assert {item.reference.candidate_id for item in result.items[2:]} == {
            _candidate(1, "disk.health").candidate_id,
            _candidate(2, "network.dns").candidate_id,
        }
        assert all(item.status is FrontierStatus.REQUESTED for item in result.items)
        assert (
            seed_frontier_discovery(
                case_id=CASE,
                retriever=EvidenceRetriever(store),
                frontier=repo,
                versions=_versions(store),
                candidates=(_candidate(1, "disk.health"), _candidate(2, "network.dns")),
                knowledge=_knowledge(),
                packet_evidence_ids=(visible,),
                page_limit=1,
                max_pages=5,
                max_items=4,
            ).items
            == result.items
        )


def test_catalog_page_cap_is_visible_and_never_claims_exhaustive_discovery(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow PDF", created_at=NOW.isoformat()
        )
        for number in range(1, 4):
            _record(store, number, "disk.health", number)
        result = seed_frontier_discovery(
            case_id=CASE,
            retriever=EvidenceRetriever(store),
            frontier=SearchFrontierRepository(store),
            versions=_versions(store),
            candidates=(),
            knowledge=_knowledge(),
            page_limit=1,
            max_pages=1,
            max_items=4,
        )
        assert result.catalog_entries_scanned == 1
        assert result.catalog_has_more is True
        assert result.next_cursor is not None
        assert "catalog_more_pages_unscanned" in result.limitations
        assert result.items[0].reference.kind == "retrieve_evidence"
        next_page = seed_frontier_discovery(
            case_id=CASE,
            retriever=EvidenceRetriever(store),
            frontier=SearchFrontierRepository(store),
            versions=_versions(store),
            candidates=(),
            knowledge=_knowledge(),
            start_cursor=result.next_cursor,
            page_limit=1,
            max_pages=1,
            max_items=4,
        )
        assert next_page.items[0].reference.evidence_id != result.items[0].reference.evidence_id


def test_catalog_generation_change_between_pages_seeds_nothing(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow PDF", created_at=NOW.isoformat()
        )
        _record(store, 1, "disk.health", 1)
        _record(store, 2, "disk.health", 2)
        versions = _versions(store)

        class MutatingRetriever(EvidenceRetriever):
            def __init__(self, data: SQLiteStore) -> None:
                super().__init__(data)
                self.calls = 0

            def discover(self, query: EvidenceCatalogQuery):  # type: ignore[override]
                page = super().discover(query)
                self.calls += 1
                if self.calls == 1:
                    _record(store, 3, "network.dns", 0)
                return page

        repo = SearchFrontierRepository(store)
        with pytest.raises(ValueError, match="generation changed"):
            seed_frontier_discovery(
                case_id=CASE,
                retriever=MutatingRetriever(store),
                frontier=repo,
                versions=versions,
                candidates=(_candidate(1, "disk.health"),),
                knowledge=_knowledge(),
                page_limit=1,
                max_pages=2,
            )
        assert (
            store.connection.execute("SELECT COUNT(*) FROM search_frontier_items").fetchone()[0]
            == 0
        )


def test_claimed_retrieval_reads_exact_stored_id_and_commits_outcome(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow PDF", created_at=NOW.isoformat()
        )
        target = _record(store, 1, "disk.health", 1)
        _record(store, 2, "disk.health", 0)
        repo = SearchFrontierRepository(store)
        versions = _versions(store)
        item = repo.upsert_item(
            CASE, FrontierReferenceV1(kind="retrieve_evidence", evidence_id=target), versions
        )
        repo.claim_ready(item.item_id, versions)
        before = store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0]
        outcome = process_claimed_retrieval(
            item_id=item.item_id,
            case_id=CASE,
            retriever=EvidenceRetriever(store),
            frontier=repo,
            expected_versions=versions,
        )
        after = store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0]
        assert outcome.status is FrontierStatus.SATISFIED
        assert outcome.evidence is not None and outcome.evidence.evidence_id == target
        assert repo.readback(item.item_id).status is FrontierStatus.SATISFIED
        assert before == after == 0
        with pytest.raises(ValueError, match="claimed"):
            process_claimed_retrieval(
                item_id=item.item_id,
                case_id=CASE,
                retriever=EvidenceRetriever(store),
                frontier=repo,
                expected_versions=versions,
            )


def test_claimed_retrieval_goes_obsolete_if_catalog_changed_before_processing(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow PDF", created_at=NOW.isoformat()
        )
        target = _record(store, 1, "disk.health", 1)
        versions = _versions(store)
        repo = SearchFrontierRepository(store)
        item = repo.upsert_item(
            CASE, FrontierReferenceV1(kind="retrieve_evidence", evidence_id=target), versions
        )
        repo.claim_ready(item.item_id, versions)
        _record(store, 2, "network.dns", 0)
        outcome = process_claimed_retrieval(
            item_id=item.item_id,
            case_id=CASE,
            retriever=EvidenceRetriever(store),
            frontier=repo,
            expected_versions=versions,
        )
        assert outcome.status is FrontierStatus.OBSOLETE
        assert outcome.evidence is None
        assert "catalog_generation_changed" in outcome.limitations
        assert repo.readback(item.item_id).status is FrontierStatus.OBSOLETE


def test_missing_stored_id_is_failed_not_a_new_probe_or_fabricated_fact(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        store.create_case(
            case_id=str(CASE), kind="incident", symptom="slow PDF", created_at=NOW.isoformat()
        )
        versions = _versions(store)
        repo = SearchFrontierRepository(store)
        item = repo.upsert_item(
            CASE,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=EvidenceId.new()),
            versions,
        )
        repo.claim_ready(item.item_id, versions)
        outcome = process_claimed_retrieval(
            item_id=item.item_id,
            case_id=CASE,
            retriever=EvidenceRetriever(store),
            frontier=repo,
            expected_versions=versions,
        )
        assert outcome.status is FrontierStatus.FAILED
        assert outcome.evidence is None
        assert "stored_evidence_not_found" in outcome.limitations
        assert repo.readback(item.item_id).status is FrontierStatus.FAILED
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0
