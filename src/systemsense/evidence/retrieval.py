"""Bounded durable evidence-graph and case-evidence retrieval."""

import re
from collections import deque
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from systemsense.domain.cases import CaseKind
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    EvidenceFact,
    EvidenceRecord,
    FrozenModel,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, ExecutionId, JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.graph import (
    EvidenceGraph,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.storage.sqlite_store import SQLiteStore


class RelationProvenanceError(ValueError):
    """A relation cites evidence or sources absent from the durable repository."""


class EvidenceRelationRepository:
    """Persist typed graph edges and traverse them through ``EvidenceGraph``."""

    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    def append(self, relation: EvidenceRelation) -> bool:
        """Append one immutable identity/version after checking real provenance."""

        connection = self._store.connection
        connection.execute("SAVEPOINT append_evidence_relation")
        try:
            existing = connection.execute(
                """
                SELECT record_json
                FROM evidence_relations
                WHERE relation_id = ? AND relation_version = ?
                """,
                (relation.relation_id, relation.relation_version),
            ).fetchone()
            if existing is not None:
                persisted = EvidenceRelation.model_validate_json(str(existing[0]))
                if persisted != relation:
                    raise ValueError("conflicting relation for the same identity and version")
                connection.execute("RELEASE append_evidence_relation")
                return False

            self._require_provenance(relation)
            connection.execute(
                """
                INSERT INTO evidence_relations (relation_id, relation_version, record_json)
                VALUES (?, ?, ?)
                """,
                (
                    relation.relation_id,
                    relation.relation_version,
                    relation.model_dump_json(),
                ),
            )
            connection.executemany(
                """
                INSERT INTO evidence_relation_evidence (
                    relation_id, relation_version, evidence_id
                ) VALUES (?, ?, ?)
                """,
                (
                    (relation.relation_id, relation.relation_version, str(evidence_id))
                    for evidence_id in relation.evidence_ids
                ),
            )
            connection.executemany(
                """
                INSERT INTO evidence_relation_sources (
                    relation_id, relation_version, source_id
                ) VALUES (?, ?, ?)
                """,
                (
                    (relation.relation_id, relation.relation_version, source_id)
                    for source_id in relation.source_ids
                ),
            )
        except BaseException:
            connection.execute("ROLLBACK TO append_evidence_relation")
            connection.execute("RELEASE append_evidence_relation")
            raise
        else:
            connection.execute("RELEASE append_evidence_relation")
            return True

    def relations(
        self,
        *,
        limit: int = 1000,
        evidence_ids: tuple[EvidenceId, ...] | None = None,
    ) -> tuple[EvidenceRelation, ...]:
        """Read a bounded, stable relation/version page and recheck provenance."""

        if limit < 1 or limit > 5000:
            raise ValueError("relation limit must be between 1 and 5000")
        if evidence_ids is not None and len(evidence_ids) > 256:
            raise ValueError("relation evidence scope must not exceed 256 records")
        if evidence_ids == ():
            return ()
        where = ""
        parameters: list[str | int] = []
        if evidence_ids is not None:
            where = (
                "WHERE EXISTS (SELECT 1 FROM evidence_relation_evidence AS provenance "
                "WHERE provenance.relation_id = evidence_relations.relation_id "
                "AND provenance.relation_version = evidence_relations.relation_version "
                f"AND provenance.evidence_id IN ({','.join('?' for _ in evidence_ids)}))"
            )
            parameters.extend(str(item) for item in evidence_ids)
        parameters.append(limit)
        rows = self._store.connection.execute(
            f"""
            SELECT record_json
            FROM evidence_relations
            {where}
            ORDER BY relation_id, relation_version
            LIMIT ?
            """,
            parameters,
        )
        result: list[EvidenceRelation] = []
        for row in rows:
            relation = EvidenceRelation.model_validate_json(str(row[0]))
            self._require_provenance(relation)
            result.append(relation)
        return tuple(result)

    def outgoing(
        self,
        *,
        source_entity_ids: tuple[EntityId, ...],
        limit: int = 64,
    ) -> tuple[EvidenceRelation, ...]:
        """Read a small, directed adjacency page without loading the whole graph."""

        if not 1 <= limit <= 128:
            raise ValueError("outgoing relation limit must be between 1 and 128")
        if len(source_entity_ids) > 8:
            raise ValueError("outgoing source scope must not exceed 8 entities")
        if not source_entity_ids:
            return ()
        rows = self._store.connection.execute(
            f"""
            SELECT record_json FROM evidence_relations
            WHERE json_extract(record_json, '$.source_entity_id')
                IN ({",".join("?" for _ in source_entity_ids)})
            ORDER BY relation_id, relation_version
            LIMIT ?
            """,
            (*map(str, source_entity_ids), limit),
        )
        relations: list[EvidenceRelation] = []
        for row in rows:
            relation = EvidenceRelation.model_validate_json(str(row[0]))
            self._require_provenance(relation)
            relations.append(relation)
        return tuple(relations)

    def prioritized_relations(
        self,
        *,
        evidence_ids: tuple[EvidenceId, ...],
        limit: int = 64,
    ) -> tuple[EvidenceRelation, ...]:
        """Prefer edges supported by the earliest evidence in a bounded packet."""

        if not 1 <= limit <= 128:
            raise ValueError("prioritized relation limit must be between 1 and 128")
        if len(evidence_ids) > 64:
            raise ValueError("prioritized evidence scope must not exceed 64 records")
        if not evidence_ids:
            return ()
        values = ",".join("(?, ?)" for _ in evidence_ids)
        parameters: list[str | int] = []
        for rank, evidence_id in enumerate(evidence_ids):
            parameters.extend((str(evidence_id), rank))
        rows = self._store.connection.execute(
            f"""
            WITH priority(evidence_id, rank) AS (VALUES {values})
            SELECT relation.record_json
            FROM priority
            JOIN evidence_relation_evidence AS provenance
                ON provenance.evidence_id = priority.evidence_id
            JOIN evidence_relations AS relation
                ON relation.relation_id = provenance.relation_id
                AND relation.relation_version = provenance.relation_version
            GROUP BY relation.relation_id, relation.relation_version
            ORDER BY MIN(priority.rank), relation.relation_id, relation.relation_version
            LIMIT ?
            """,
            (*parameters, limit),
        )
        relations: list[EvidenceRelation] = []
        for row in rows:
            relation = EvidenceRelation.model_validate_json(str(row[0]))
            self._require_provenance(relation)
            relations.append(relation)
        return tuple(relations)

    def traverse(
        self,
        *,
        start_entity_id: EntityId,
        relation_kinds: Iterable[RelationKind | str] | None = None,
        memory_layers: Iterable[MemoryLayer | str] | None = None,
        as_of: UtcDateTime | None = None,
        max_depth: int = 8,
        max_nodes: int = 256,
        max_edges: int = 512,
        relation_limit: int = 5000,
    ) -> tuple[EvidenceRelation, ...]:
        """Load a bounded durable snapshot and use the graph's temporal traversal."""

        graph = EvidenceGraph()
        for relation in self.relations(limit=relation_limit):
            graph.add_relation(relation)
        return graph.traverse(
            start_entity_id=start_entity_id,
            relation_kinds=relation_kinds,
            memory_layers=memory_layers,
            as_of=as_of,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )

    def _require_provenance(self, relation: EvidenceRelation) -> None:
        connection = self._store.connection
        missing_evidence = tuple(
            evidence_id
            for evidence_id in relation.evidence_ids
            if connection.execute(
                "SELECT 1 FROM evidence WHERE evidence_id = ?",
                (str(evidence_id),),
            ).fetchone()
            is None
        )
        if missing_evidence:
            raise RelationProvenanceError(
                f"relation evidence provenance is missing: {missing_evidence[0]}"
            )
        missing_sources = tuple(
            source_id
            for source_id in relation.source_ids
            if connection.execute(
                "SELECT 1 FROM evidence WHERE source_id = ? LIMIT 1",
                (source_id,),
            ).fetchone()
            is None
        )
        if missing_sources:
            raise RelationProvenanceError(
                f"relation source provenance is missing: {missing_sources[0]}"
            )


class EvidenceRetrievalQuery(FrozenModel):
    """Explicit, bounded scope for current-case and opted-in passive history."""

    current_case_id: CaseId
    include_historical: bool = False
    historical_case_ids: tuple[CaseId, ...] = Field(default=(), max_length=32)
    observed_from: UtcDateTime | None = None
    observed_until: UtcDateTime | None = None
    # Optional current-case collection scope, separate from the historical
    # incident window. It never broadens another case's observation window.
    current_collection_start: UtcDateTime | None = None
    categories: tuple[str, ...] = Field(default=(), max_length=32)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=100)
    priority_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    keyword: str | None = Field(default=None, min_length=1, max_length=128)
    evidence_limit: int = Field(default=40, ge=1, le=100)
    coverage_limit: int = Field(default=20, ge=1, le=100)
    candidate_limit: int = Field(default=500, ge=1, le=1000)
    max_chars: int = Field(default=32_000, ge=1024, le=100_000)
    max_facts_per_record: int = Field(default=32, ge=0, le=64)
    max_fact_chars: int = Field(default=2048, ge=64, le=4096)

    @field_validator("categories")
    @classmethod
    def categories_are_typed_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"[a-z][a-z0-9_.-]*", value) is None for value in values):
            raise ValueError("categories must be typed category names")
        return values

    @field_validator("keyword")
    @classmethod
    def normalize_keyword(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("keyword must not be blank")
        return normalized

    @model_validator(mode="after")
    def validate_scope(self) -> "EvidenceRetrievalQuery":
        if self.historical_case_ids and not self.include_historical:
            raise ValueError("historical case IDs require include_historical opt-in")
        if self.current_case_id in self.historical_case_ids:
            raise ValueError("current case must not be repeated as historical")
        if len(set(self.historical_case_ids)) != len(self.historical_case_ids):
            raise ValueError("historical case IDs must be unique")
        if (
            self.observed_from is not None
            and self.observed_until is not None
            and self.observed_until < self.observed_from
        ):
            raise ValueError("retrieval time window must be ordered")
        if self.candidate_limit < max(self.evidence_limit, self.coverage_limit):
            raise ValueError("candidate_limit must cover each result limit")
        if len({str(item) for item in self.priority_evidence_ids}) != len(
            self.priority_evidence_ids
        ):
            raise ValueError("priority evidence IDs must be unique")
        return self


class RetrievedEvidence(FrozenModel):
    evidence_id: EvidenceId
    case_id: CaseId
    category: str
    collector_id: str
    execution_id: ExecutionId
    statement_kind: StatementKind
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    summary: str
    facts: tuple[EvidenceFact, ...]
    facts_truncated: bool
    limitations: tuple[str, ...]
    source_id: str
    source_type: str


class RetrievedCoverage(FrozenModel):
    evidence_id: EvidenceId
    case_id: CaseId
    category: str
    status: CoverageStatus
    captured_at: UtcDateTime
    reason: str | None
    limitations: tuple[str, ...]
    execution_id: ExecutionId | None
    source_id: str
    source_type: str = "systemsense.coverage"


class EvidencePacket(FrozenModel):
    """Compact retrieval result with visible omission and truncation accounting."""

    evidence: tuple[RetrievedEvidence, ...]
    coverage: tuple[RetrievedCoverage, ...]
    considered_case_ids: tuple[CaseId, ...]
    truncated: bool
    omitted_evidence_count: int = Field(ge=0)
    omitted_coverage_count: int = Field(ge=0)


class EvidenceCatalogCursor(FrozenModel):
    """Last persisted sort key; case and filters are reapplied on every page."""

    observed_at: UtcDateTime
    evidence_id: EvidenceId


class EvidenceCatalogQuery(FrozenModel):
    """Bounded discovery within one authorized case, independent of packet limits."""

    schema_version: Literal[1] = 1
    case_id: CaseId
    observed_from: UtcDateTime | None = None
    observed_until: UtcDateTime | None = None
    current_collection_start: UtcDateTime | None = None
    collector_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]*$")
    source_id: str | None = Field(default=None, min_length=1, max_length=128)
    cursor: EvidenceCatalogCursor | None = None
    limit: int = Field(default=32, ge=1, le=64)

    @model_validator(mode="after")
    def validate_window(self) -> "EvidenceCatalogQuery":
        if (
            self.observed_from is not None
            and self.observed_until is not None
            and self.observed_until < self.observed_from
        ):
            raise ValueError("catalog time window must be ordered")
        return self


class EvidenceCatalogEntry(FrozenModel):
    evidence_id: EvidenceId
    case_id: CaseId
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    collector_id: str
    source_id: str
    summary: str


class EvidenceCatalogPage(FrozenModel):
    schema_version: Literal[2] = 2
    entries: tuple[EvidenceCatalogEntry, ...]
    next_cursor: EvidenceCatalogCursor | None = None
    case_evidence_generation: int = Field(ge=0)


class EvidenceRetriever:
    """Retrieve bounded typed context without exposing a general SQL surface."""

    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    def retrieve(self, query: EvidenceRetrievalQuery) -> EvidencePacket:
        with self._store.read_snapshot():
            return self._retrieve(query)

    def discover(self, query: EvidenceCatalogQuery) -> EvidenceCatalogPage:
        """Page metadata from the whole case; retrieve exact IDs for full detail."""
        with self._store.read_snapshot():
            if self._store.case(str(query.case_id)) is None:
                raise ValueError("catalog case does not exist")
            generation_row = self._store.connection.execute(
                "SELECT generation FROM evidence_case_generations WHERE case_id = ?",
                (str(query.case_id),),
            ).fetchone()
            assert generation_row is not None
            generation = int(generation_row[0])
            clauses = ["case_id = ?", "json_type(record_json, '$.statement_kind') IS NOT NULL"]
            parameters: list[str | int] = [str(query.case_id)]
            if query.observed_from is not None:
                lower = "julianday(observed_at) >= julianday(?)"
                if query.current_collection_start is not None:
                    lower = f"(julianday(captured_at) >= julianday(?) OR {lower})"
                    parameters.append(query.current_collection_start.isoformat())
                clauses.append(lower)
                parameters.append(query.observed_from.isoformat())
            if query.observed_until is not None:
                upper = "julianday(observed_at) <= julianday(?)"
                if query.current_collection_start is not None:
                    upper = f"(julianday(captured_at) >= julianday(?) OR {upper})"
                    parameters.append(query.current_collection_start.isoformat())
                clauses.append(upper)
                parameters.append(query.observed_until.isoformat())
            if query.collector_id is not None:
                clauses.append("json_extract(record_json, '$.collector.id') = ?")
                parameters.append(query.collector_id)
            if query.source_id is not None:
                clauses.append("source_id = ?")
                parameters.append(query.source_id)
            if query.cursor is not None:
                clauses.append(
                    "(julianday(observed_at) < julianday(?) OR "
                    "(julianday(observed_at) = julianday(?) AND evidence_id > ?))"
                )
                parameters.extend(
                    (
                        query.cursor.observed_at.isoformat(),
                        query.cursor.observed_at.isoformat(),
                        str(query.cursor.evidence_id),
                    )
                )
            rows = self._store.connection.execute(
                f"""
                SELECT evidence_id, case_id, observed_at, captured_at, source_id,
                    json_extract(record_json, '$.collector.id'),
                    substr(json_extract(record_json, '$.summary'), 1, 240)
                FROM evidence
                WHERE {" AND ".join(clauses)}
                ORDER BY julianday(observed_at) DESC, evidence_id
                LIMIT ?
                """,
                (*parameters, query.limit + 1),
            ).fetchall()
            entries = tuple(
                EvidenceCatalogEntry(
                    evidence_id=EvidenceId(root=str(row[0])),
                    case_id=CaseId(root=str(row[1])),
                    observed_at=datetime.fromisoformat(str(row[2])),
                    captured_at=datetime.fromisoformat(str(row[3])),
                    source_id=str(row[4]),
                    collector_id=str(row[5]),
                    summary=str(row[6]),
                )
                for row in rows[: query.limit]
            )
            cursor = None
            if len(rows) > query.limit:
                last = entries[-1]
                cursor = EvidenceCatalogCursor(
                    observed_at=last.observed_at, evidence_id=last.evidence_id
                )
            return EvidenceCatalogPage(
                entries=entries,
                next_cursor=cursor,
                case_evidence_generation=generation,
            )

    def _retrieve(self, query: EvidenceRetrievalQuery) -> EvidencePacket:
        case_ids = self._case_scope(query)
        evidence_records, evidence_total = self._evidence_candidates(query, case_ids)
        coverage_records, coverage_total = self._coverage_candidates(query, case_ids)

        selected_coverage: list[RetrievedCoverage] = []
        for candidate in self._prioritized_coverage(coverage_records, query.current_case_id):
            if len(selected_coverage) >= query.coverage_limit:
                break
            attempted = (*selected_coverage, candidate)
            packet = self._packet(
                evidence=(),
                coverage=attempted,
                case_ids=case_ids,
                evidence_total=evidence_total,
                coverage_total=coverage_total,
            )
            if len(packet.model_dump_json()) <= query.max_chars:
                selected_coverage.append(candidate)

        selected_evidence: list[RetrievedEvidence] = []
        for candidate in self._hybrid_evidence_order(evidence_records, query):
            if len(selected_evidence) >= query.evidence_limit:
                break
            fitted = self._fit_evidence_candidate(
                candidate,
                selected=tuple(selected_evidence),
                coverage=tuple(selected_coverage),
                case_ids=case_ids,
                evidence_total=evidence_total,
                coverage_total=coverage_total,
                max_chars=query.max_chars,
            )
            if fitted is not None:
                selected_evidence.append(fitted)

        packet = self._packet(
            evidence=tuple(selected_evidence),
            coverage=tuple(selected_coverage),
            case_ids=case_ids,
            evidence_total=evidence_total,
            coverage_total=coverage_total,
        )
        if len(packet.model_dump_json()) > query.max_chars:
            raise ValueError("max_chars is too small for the retrieval envelope")
        return packet

    @staticmethod
    def _prioritized_coverage(
        records: tuple[RetrievedCoverage, ...], current_case_id: CaseId
    ) -> tuple[RetrievedCoverage, ...]:
        severity = {
            CoverageStatus.DENIED: 0,
            CoverageStatus.FAILED: 0,
            CoverageStatus.UNAVAILABLE: 1,
            CoverageStatus.UNSUPPORTED: 1,
            CoverageStatus.TRUNCATED: 2,
            CoverageStatus.PARTIAL: 2,
            CoverageStatus.MISSING: 3,
            CoverageStatus.STALE: 3,
            CoverageStatus.COVERED: 4,
        }
        indexed = enumerate(records)
        return tuple(
            item
            for _index, item in sorted(
                indexed,
                key=lambda pair: (
                    int(pair[1].case_id != current_case_id),
                    severity[pair[1].status],
                    pair[0],
                ),
            )
        )

    @staticmethod
    def _hybrid_evidence_order(
        records: tuple[RetrievedEvidence, ...], query: EvidenceRetrievalQuery
    ) -> tuple[RetrievedEvidence, ...]:
        current = deque(item for item in records if item.case_id == query.current_case_id)
        historical_by_case = {
            case_id: deque(item for item in records if item.case_id == case_id)
            for case_id in query.historical_case_ids
        }
        historical_quota = max(1, query.evidence_limit // 4) if query.include_historical else 0
        ordered: list[RetrievedEvidence] = []
        history_used = 0
        historical_cases = deque(case_id for case_id, items in historical_by_case.items() if items)
        while current or (historical_cases and history_used < historical_quota):
            for _ in range(3):
                if current:
                    ordered.append(current.popleft())
            if historical_cases and history_used < historical_quota:
                case_id = historical_cases.popleft()
                items = historical_by_case[case_id]
                ordered.append(items.popleft())
                history_used += 1
                if items:
                    historical_cases.append(case_id)
        ordered.extend(current)
        return tuple(ordered)

    @classmethod
    def _fit_evidence_candidate(
        cls,
        candidate: RetrievedEvidence,
        *,
        selected: tuple[RetrievedEvidence, ...],
        coverage: tuple[RetrievedCoverage, ...],
        case_ids: tuple[CaseId, ...],
        evidence_total: int,
        coverage_total: int,
        max_chars: int,
    ) -> RetrievedEvidence | None:
        def fits(item: RetrievedEvidence) -> bool:
            packet = cls._packet(
                evidence=(*selected, item),
                coverage=coverage,
                case_ids=case_ids,
                evidence_total=evidence_total,
                coverage_total=coverage_total,
            )
            return len(packet.model_dump_json()) <= max_chars

        if fits(candidate):
            return candidate
        limitation = "Fact prefix deferred by packet budget; full observation remains stored."
        compacted = candidate.model_copy(
            update={
                "facts": (),
                "facts_truncated": True,
                "limitations": tuple(dict.fromkeys((*candidate.limitations, limitation))),
            }
        )
        if not fits(compacted):
            return None
        retained: list[EvidenceFact] = []
        for fact in candidate.facts:
            trial = compacted.model_copy(update={"facts": (*retained, fact)})
            if not fits(trial):
                break
            retained.append(fact)
            compacted = trial
        return compacted

    def _case_scope(self, query: EvidenceRetrievalQuery) -> tuple[CaseId, ...]:
        if self._store.case(str(query.current_case_id)) is None:
            raise ValueError("current retrieval case does not exist")
        historical = query.historical_case_ids if query.include_historical else ()
        for case_id in historical:
            historical_case = self._store.case(str(case_id))
            if historical_case is None:
                raise ValueError(f"historical retrieval case does not exist: {case_id}")
            if historical_case.kind != CaseKind.PASSIVE.value:
                raise ValueError(f"historical retrieval case is not passive: {case_id}")
        return (query.current_case_id, *historical)

    def _evidence_candidates(
        self,
        query: EvidenceRetrievalQuery,
        case_ids: tuple[CaseId, ...],
    ) -> tuple[tuple[RetrievedEvidence, ...], int]:
        clauses, parameters = self._common_clauses(query, case_ids, coverage=False)
        total = self._count(clauses, parameters)

        def scoped_rows(scope: tuple[CaseId, ...], limit: int) -> list[tuple[object, ...]]:
            scoped_clauses, scoped_parameters = self._common_clauses(query, scope, coverage=False)
            return list(
                self._store.connection.execute(
                    f"""
                    SELECT record_json FROM (
                        SELECT record_json, case_id, observed_at, evidence_id,
                            ROW_NUMBER() OVER (
                                PARTITION BY case_id,
                                    json_extract(record_json, '$.collector.id')
                                ORDER BY datetime(observed_at) DESC, evidence_id
                            ) AS category_rank
                        FROM evidence WHERE {" AND ".join(scoped_clauses)}
                    )
                    ORDER BY category_rank, datetime(observed_at) DESC, evidence_id
                    LIMIT ?
                    """,
                    (*scoped_parameters, limit),
                )
            )

        priority_rows: list[tuple[object, ...]] = []
        if query.priority_evidence_ids:
            priority_clauses, priority_parameters = self._common_clauses(
                query, (query.current_case_id,), coverage=False
            )
            priority_clauses.append(
                f"evidence_id IN ({','.join('?' for _ in query.priority_evidence_ids)})"
            )
            priority_parameters.extend(str(item) for item in query.priority_evidence_ids)
            priority_rows = list(
                self._store.connection.execute(
                    f"SELECT record_json FROM evidence WHERE {' AND '.join(priority_clauses)}",
                    priority_parameters,
                )
            )
        rows = scoped_rows((query.current_case_id,), query.candidate_limit)
        if len(case_ids) > 1:
            historical_fetch_limit = min(
                query.candidate_limit,
                max(len(query.historical_case_ids), query.evidence_limit),
            )
            rows.extend(scoped_rows(case_ids[1:], historical_fetch_limit))
        priority_records: dict[str, EvidenceRecord] = {}
        for row in priority_rows:
            record = EvidenceRecord.model_validate_json(str(row[0]))
            priority_records[str(record.evidence_id)] = record
        ordered_records = [
            priority_records[str(evidence_id)]
            for evidence_id in query.priority_evidence_ids
            if str(evidence_id) in priority_records
        ]
        for row in rows:
            record = EvidenceRecord.model_validate_json(str(row[0]))
            if str(record.evidence_id) not in priority_records:
                ordered_records.append(record)
        records: list[RetrievedEvidence] = []
        for record in ordered_records:
            facts: list[EvidenceFact] = []
            facts_truncated = False
            for fact in record.facts:
                if len(facts) >= query.max_facts_per_record:
                    facts_truncated = True
                    continue
                compacted, truncated = _compact_fact(fact, max_chars=query.max_fact_chars)
                facts_truncated = facts_truncated or truncated
                if compacted is not None:
                    facts.append(compacted)
            limitations = record.limitations
            if facts_truncated:
                limitations = (*limitations, "fact content compacted by retrieval budget")
            records.append(
                RetrievedEvidence(
                    evidence_id=record.evidence_id,
                    case_id=record.case_id,
                    category=record.collector.id,
                    collector_id=record.collector.id,
                    execution_id=record.collector.execution_id,
                    statement_kind=record.statement_kind,
                    observed_at=record.observed_at,
                    captured_at=record.captured_at,
                    summary=record.summary,
                    facts=tuple(facts),
                    facts_truncated=facts_truncated,
                    limitations=limitations,
                    source_id=record.source.source_id,
                    source_type=record.source.type,
                )
            )
        return tuple(records), total

    def _coverage_candidates(
        self,
        query: EvidenceRetrievalQuery,
        case_ids: tuple[CaseId, ...],
    ) -> tuple[tuple[RetrievedCoverage, ...], int]:
        clauses, parameters = self._common_clauses(query, case_ids, coverage=True)
        total = self._count(clauses, parameters)
        rows = self._store.connection.execute(
            f"""
            SELECT source_id, record_json
            FROM evidence
            WHERE {" AND ".join(clauses)}
            ORDER BY
                CASE WHEN case_id = ? THEN 0 ELSE 1 END,
                datetime(captured_at) DESC,
                evidence_id
            LIMIT ?
            """,
            (*parameters, str(query.current_case_id), query.candidate_limit),
        )
        return (
            tuple(
                self._compact_coverage(
                    CoverageRecord.model_validate_json(str(row[1])),
                    source_id=str(row[0]),
                )
                for row in rows
            ),
            total,
        )

    @staticmethod
    def _compact_coverage(record: CoverageRecord, *, source_id: str) -> RetrievedCoverage:
        return RetrievedCoverage(
            evidence_id=record.evidence_id,
            case_id=record.case_id,
            category=record.category,
            status=record.status,
            captured_at=record.captured_at,
            reason=record.reason,
            limitations=record.limitations,
            execution_id=record.execution_id,
            source_id=source_id,
        )

    def _common_clauses(
        self,
        query: EvidenceRetrievalQuery,
        case_ids: tuple[CaseId, ...],
        *,
        coverage: bool,
    ) -> tuple[list[str], list[str]]:
        placeholders = ",".join("?" for _ in case_ids)
        clauses = [f"case_id IN ({placeholders})"]
        parameters = [str(case_id) for case_id in case_ids]
        if coverage:
            clauses.extend(
                (
                    "json_type(record_json, '$.status') IS NOT NULL",
                    "json_type(record_json, '$.category') IS NOT NULL",
                )
            )
            timestamp_column = "captured_at"
            category_expression = "json_extract(record_json, '$.category')"
            keyword_expressions = ("json_extract(record_json, '$.reason')",)
        else:
            clauses.append("json_type(record_json, '$.statement_kind') IS NOT NULL")
            timestamp_column = "observed_at"
            category_expression = "json_extract(record_json, '$.collector.id')"
            keyword_expressions = (
                "json_extract(record_json, '$.summary')",
                "json_extract(record_json, '$.facts')",
            )
        if query.observed_from is not None:
            lower = f"datetime({timestamp_column}) >= datetime(?)"
            if query.current_collection_start is not None:
                lower = f"((case_id = ? AND datetime(captured_at) >= datetime(?)) OR {lower})"
                parameters.extend(
                    (str(query.current_case_id), query.current_collection_start.isoformat())
                )
            clauses.append(lower)
            parameters.append(query.observed_from.isoformat())
        if query.observed_until is not None:
            upper = f"datetime({timestamp_column}) <= datetime(?)"
            if query.current_collection_start is not None:
                upper = f"((case_id = ? AND datetime(captured_at) >= datetime(?)) OR {upper})"
                parameters.extend(
                    (str(query.current_case_id), query.current_collection_start.isoformat())
                )
            clauses.append(upper)
            parameters.append(query.observed_until.isoformat())
        if query.categories:
            category_clauses: list[str] = []
            for category in query.categories:
                category_clauses.append(
                    f"({category_expression} = ? OR {category_expression} LIKE ?)"
                )
                parameters.extend((category, f"{category}.%"))
            clauses.append(f"({' OR '.join(category_clauses)})")
        if query.evidence_ids:
            clauses.append(f"evidence_id IN ({','.join('?' for _ in query.evidence_ids)})")
            parameters.extend(str(evidence_id) for evidence_id in query.evidence_ids)
        if query.keyword is not None:
            clauses.append(
                "("
                + " OR ".join(
                    f"instr(lower(COALESCE({expression}, '')), lower(?)) > 0"
                    for expression in keyword_expressions
                )
                + ")"
            )
            parameters.extend(query.keyword for _ in keyword_expressions)
        return clauses, parameters

    def _count(self, clauses: list[str], parameters: list[str]) -> int:
        row = self._store.connection.execute(
            f"SELECT COUNT(*) FROM evidence WHERE {' AND '.join(clauses)}",
            parameters,
        ).fetchone()
        assert row is not None
        return int(row[0])

    @staticmethod
    def _packet(
        *,
        evidence: tuple[RetrievedEvidence, ...],
        coverage: tuple[RetrievedCoverage, ...],
        case_ids: tuple[CaseId, ...],
        evidence_total: int,
        coverage_total: int,
    ) -> EvidencePacket:
        omitted_evidence = evidence_total - len(evidence)
        omitted_coverage = coverage_total - len(coverage)
        return EvidencePacket(
            evidence=evidence,
            coverage=coverage,
            considered_case_ids=case_ids,
            truncated=(
                omitted_evidence > 0
                or omitted_coverage > 0
                or any(item.facts_truncated for item in evidence)
            ),
            omitted_evidence_count=omitted_evidence,
            omitted_coverage_count=omitted_coverage,
        )


def _compact_fact(
    fact: EvidenceFact,
    *,
    max_chars: int,
) -> tuple[EvidenceFact | None, bool]:
    if len(fact.model_dump_json()) <= max_chars:
        return fact, False

    def fits(value: JsonValue) -> bool:
        candidate = EvidenceFact(name=fact.name, value=value, unit=fact.unit)
        return len(candidate.model_dump_json()) <= max_chars

    compacted = _compact_json_value(fact.value, fits=fits)
    if compacted is None:
        return None, True
    return EvidenceFact(name=fact.name, value=compacted, unit=fact.unit), True


def _compact_json_value(
    value: JsonValue,
    *,
    fits: Callable[[JsonValue], bool],
) -> JsonValue | None:
    """Retain only exact list prefixes or dict entries that fit the caller budget."""

    if fits(value):
        return value
    if isinstance(value, list):
        result: list[JsonValue] = []
        for item in value:
            candidate = [*result, item]
            if fits(candidate):
                result.append(item)
                continue
            if isinstance(item, (list, dict)):
                nested = _compact_json_value(
                    item,
                    fits=lambda nested_value: fits([*result, nested_value]),
                )
                if nested is not None:
                    result.append(nested)
            break
        return result or None
    if isinstance(value, dict):
        result_dict: dict[str, JsonValue] = {}
        for key, item in value.items():
            candidate_dict = {**result_dict, key: item}
            if fits(candidate_dict):
                result_dict[key] = item
                continue
            if isinstance(item, (list, dict)):
                current_key = key
                nested = _compact_json_value(
                    item,
                    fits=_dict_entry_fits(fits, result_dict, current_key),
                )
                if nested is not None:
                    result_dict[current_key] = nested
        return result_dict or None
    # Scalar values are indivisible. Omitting them is honest; clipping would alter meaning.
    return None


def _dict_entry_fits(
    fits: Callable[[JsonValue], bool],
    current: dict[str, JsonValue],
    key: str,
) -> Callable[[JsonValue], bool]:
    return lambda value: fits({**current, key: value})
