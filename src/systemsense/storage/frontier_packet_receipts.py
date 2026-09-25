"""Source-owned semantic packet receipts for mixed frontier requests.

Only exact, typed evidence rows in the active case or explicitly opted-in
passive history can create packets. A receipt is frozen before model inference;
revalidation rebuilds the same projection from current stored rows.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import Field, model_validator

from systemsense.application.investigation_state import InvestigationState
from systemsense.decision.frontier_ranker import FrontierRankRequestV1, SemanticPacketRefV1
from systemsense.decision.semantic_packets import SERIALIZER_ID, evidence_packets
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import EvidenceRecord, FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.redaction import Redactor
from systemsense.evidence.retrieval import EvidenceRetrievalQuery, EvidenceRetriever
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

_PROJECTION = "frontier_typed_row_context_v1_p24"
_REDACTOR = "systemsense_redactor_v1"
_ROW_COLUMNS = (
    "case_id,source_id,record_json,observed_at,captured_at,execution_id,"
    "dedupe_key,time_basis,time_quality"
)


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class FrontierPacketSourceV1(FrozenModel):
    evidence_id: EvidenceId
    owner_case_id: CaseId
    scope: Literal["current_case", "historical"]
    row_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FrontierPacketReceiptV1(FrozenModel):
    schema_version: Literal[1] = 1
    receipt_id: str = Field(pattern=r"^frontier_packet_receipt_[0-9a-f]{32}$")
    case_id: CaseId
    epoch_state_version: int = Field(ge=0)
    case_generation: int = Field(ge=1)
    incident_start: UtcDateTime
    incident_end: UtcDateTime
    historical_case_ids: tuple[CaseId, ...] = Field(max_length=32)
    source_projection: Literal["frontier_typed_row_context_v1_p24"] = _PROJECTION
    max_packets: Literal[24] = 24
    semantic_serializer: Literal["semantic_fact_packets_v1"] = SERIALIZER_ID
    redactor_version: Literal["systemsense_redactor_v1"] = _REDACTOR
    sources: tuple[FrontierPacketSourceV1, ...] = Field(min_length=1, max_length=16)
    packets: tuple[SemanticPacketRefV1, ...] = Field(min_length=1, max_length=24)
    frozen_at: UtcDateTime

    @model_validator(mode="after")
    def validate_sources(self) -> FrontierPacketReceiptV1:
        if len({str(item.evidence_id) for item in self.sources}) != len(self.sources):
            raise ValueError("frontier receipt repeats a source")
        if any(
            (item.owner_case_id == self.case_id) != (item.scope == "current_case")
            or (item.scope == "historical" and item.owner_case_id not in self.historical_case_ids)
            for item in self.sources
        ):
            raise ValueError("frontier receipt source ownership is inconsistent")
        return self


def _redact(value: JsonValue, redactor: Redactor, key: str = "") -> JsonValue:
    if isinstance(value, str):
        return redactor.redact_field(key, value)
    if isinstance(value, list):
        return [_redact(item, redactor, key) for item in value]
    if isinstance(value, dict):
        return {name: _redact(item, redactor, name) for name, item in value.items()}
    return value


class FrontierPacketReceiptRepository:
    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    def projectable_optional_sources(
        self,
        *,
        case_id: CaseId,
        epoch_state_version: int,
        evidence_ids: tuple[EvidenceId, ...],
    ) -> tuple[EvidenceId, ...]:
        """Preflight optional current-case rows with the exact receipt projector.

        This only filters advisory context. A later freeze still validates every
        selected source together against its own snapshot and generation.
        """

        if len(evidence_ids) > 128:
            raise ValueError("frontier optional packet sources are unbounded")
        with self._store.read_snapshot():
            state = self._state(case_id, epoch_state_version)
            accepted: list[EvidenceId] = []
            for evidence_id in dict.fromkeys(evidence_ids):
                row = self._store.connection.execute(
                    "SELECT case_id FROM evidence WHERE evidence_id=?", (str(evidence_id),)
                ).fetchone()
                if row is None or str(row[0]) != str(case_id):
                    continue
                try:
                    self._project(state, (evidence_id,))
                except (TypeError, ValueError):
                    # Invalid optional context is omitted, never counted as a
                    # negative finding or used as a source for model packets.
                    continue
                accepted.append(evidence_id)
            return tuple(accepted)

    def freeze(
        self,
        *,
        case_id: CaseId,
        epoch_state_version: int,
        evidence_ids: tuple[EvidenceId, ...],
        expected_generation: int,
    ) -> FrontierPacketReceiptV1:
        """Derive exact packet bytes from one SQLite snapshot, then persist before rank."""

        if not 1 <= len(evidence_ids) <= 16 or len({str(item) for item in evidence_ids}) != len(
            evidence_ids
        ):
            raise ValueError("frontier packet source IDs are empty, repeated, or unbounded")
        with self._store.read_snapshot():
            state = self._state(case_id, epoch_state_version)
            generation = self._generation(case_id)
            if generation != expected_generation:
                raise ValueError("frontier context generation changed before freeze")
            sources, packets = self._project(state, evidence_ids)
            receipt = FrontierPacketReceiptV1(
                receipt_id=f"frontier_packet_receipt_{uuid4().hex}",
                case_id=case_id,
                epoch_state_version=epoch_state_version,
                case_generation=generation,
                incident_start=state.incident_start,
                incident_end=state.incident_end,
                historical_case_ids=state.historical_case_ids,
                sources=sources,
                packets=packets,
                frozen_at=utc_now(),
            )
        # The source read lock has ended. Recheck before durable insertion;
        # unrelated appends do not invalidate exact source rows.
        with self._store.transaction():
            self._validate_locked(receipt)
            raw = _canonical(receipt.model_dump(mode="json"))
            self._store.connection.execute(
                "INSERT INTO frontier_packet_receipts "
                "(receipt_id,schema_version,case_id,epoch_state_version,"
                "receipt_json,receipt_sha256,frozen_at) "
                "VALUES (?,1,?,?,?,?,?)",
                (
                    receipt.receipt_id,
                    str(case_id),
                    epoch_state_version,
                    raw,
                    _sha(receipt.model_dump(mode="json")),
                    receipt.frozen_at.isoformat(),
                ),
            )
        return receipt

    def readback(self, receipt_id: str) -> FrontierPacketReceiptV1:
        with self._store.read_snapshot():
            return self._readback_locked(receipt_id)

    def _readback_locked(self, receipt_id: str) -> FrontierPacketReceiptV1:
        row = self._store.connection.execute(
            "SELECT schema_version,case_id,epoch_state_version,"
            "receipt_json,receipt_sha256,frozen_at "
            "FROM frontier_packet_receipts WHERE receipt_id=?",
            (receipt_id,),
        ).fetchone()
        if row is None or int(row[0]) != 1 or _sha(json.loads(str(row[3]))) != str(row[4]):
            raise ValueError("frontier packet receipt is unavailable or corrupt")
        receipt = FrontierPacketReceiptV1.model_validate_json(str(row[3]))
        if (
            receipt.receipt_id != receipt_id
            or str(receipt.case_id) != str(row[1])
            or receipt.epoch_state_version != int(row[2])
            or receipt.frozen_at.isoformat() != str(row[5])
            or _canonical(receipt.model_dump(mode="json")) != str(row[3])
        ):
            raise ValueError("frontier packet receipt binding is invalid")
        self._validate_locked(receipt)
        return receipt

    def bind_snapshot(self, receipt_id: str, snapshot_id: str) -> None:
        if not self._store.connection.in_transaction:
            raise ValueError("frontier packet binding requires caller transaction")
        receipt = self.readback(receipt_id)
        row = self._store.connection.execute(
            "SELECT schema_version,case_id,epoch_state_version,request_json,request_frozen_at "
            "FROM candidate_decision_snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        if row is None or int(row[0]) != 2:
            raise ValueError("frontier packet binding needs a v2 snapshot")
        request = FrontierRankRequestV1.model_validate_json(str(row[3]))
        if (
            str(row[1]) != str(receipt.case_id)
            or int(row[2]) != receipt.epoch_state_version
            or request.case_id != receipt.case_id
            or request.evidence_packets != receipt.packets
            or request.items[0].versions.evidence != receipt.case_generation
            or receipt.frozen_at > datetime.fromisoformat(str(row[4]))
        ):
            raise ValueError("frontier packet binding differs from source and snapshot")
        try:
            self._store.connection.execute(
                "INSERT INTO frontier_packet_snapshot_bindings (snapshot_id,receipt_id,bound_at) "
                "VALUES (?,?,?)",
                (snapshot_id, receipt_id, utc_now().isoformat()),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("frontier packet receipt was already bound") from error

    def bound_receipt(self, snapshot_id: str) -> FrontierPacketReceiptV1 | None:
        row = self._store.connection.execute(
            "SELECT receipt_id FROM frontier_packet_snapshot_bindings WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        return None if row is None else self.readback(str(row[0]))

    def _state(
        self, case_id: CaseId, epoch: int, *, require_current: bool = True
    ) -> InvestigationState:
        state = InvestigationRepository(self._store).load(str(case_id))
        case = self._store.case(str(case_id))
        if (
            case is None
            or state.state_version < epoch
            or case.state_version < epoch
            or (
                require_current
                and (
                    state.state_version != epoch
                    or case.state_version != epoch
                    or case.status != "collecting"
                )
            )
        ):
            raise ValueError("frontier packet case epoch is stale")
        return state

    def _generation(self, case_id: CaseId) -> int:
        row = self._store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()
        if row is None:
            raise ValueError("frontier packet case generation is unavailable")
        return int(row[0])

    def _validate_locked(self, receipt: FrontierPacketReceiptV1) -> None:
        state = self._state(receipt.case_id, receipt.epoch_state_version, require_current=False)
        if (
            state.incident_start != receipt.incident_start
            or state.incident_end != receipt.incident_end
            or state.historical_case_ids != receipt.historical_case_ids
            or self._generation(receipt.case_id) < receipt.case_generation
        ):
            raise ValueError("frontier packet case context changed")
        sources, packets = self._project(state, tuple(item.evidence_id for item in receipt.sources))
        if sources != receipt.sources or packets != receipt.packets:
            raise ValueError("frontier packet source projection changed")

    def _project(
        self, state: InvestigationState, evidence_ids: tuple[EvidenceId, ...]
    ) -> tuple[tuple[FrontierPacketSourceV1, ...], tuple[SemanticPacketRefV1, ...]]:
        retriever = EvidenceRetriever(self._store)
        redactor = Redactor()
        sources: list[FrontierPacketSourceV1] = []
        contexts: list[EvidenceContext] = []
        for evidence_id in evidence_ids:
            row = self._store.connection.execute(
                f"SELECT {_ROW_COLUMNS} FROM evidence WHERE evidence_id=?", (str(evidence_id),)
            ).fetchone()
            if row is None:
                raise ValueError("frontier packet source is missing")
            owner = CaseId(root=str(row[0]))
            if owner != state.case_id and owner not in state.historical_case_ids:
                raise ValueError("frontier packet source is outside authorized case scope")
            scope: Literal["current_case", "historical"] = (
                "current_case" if owner == state.case_id else "historical"
            )
            if scope == "historical":
                historical = self._store.case(str(owner))
                if historical is None or historical.kind != "passive":
                    raise ValueError("frontier packet historical source is not passive")
            raw = str(row[2])
            query = EvidenceRetrievalQuery(
                current_case_id=owner,
                evidence_ids=(evidence_id,),
                priority_evidence_ids=(evidence_id,),
                evidence_limit=1,
                coverage_limit=1,
                candidate_limit=1,
                max_chars=100_000,
                max_fact_chars=4096,
            )
            packet = retriever.retrieve(query)
            if packet.evidence and packet.evidence[0].evidence_id == evidence_id:
                typed = EvidenceRecord.model_validate_json(raw)
                if (
                    typed.evidence_id != evidence_id
                    or typed.case_id != owner
                    or typed.source.source_id != str(row[1])
                    or typed.observed_at.isoformat() != str(row[3])
                    or typed.captured_at.isoformat() != str(row[4])
                    or str(typed.collector.execution_id) != str(row[5])
                ):
                    raise ValueError("frontier packet evidence row identity differs")
                item = packet.evidence[0]
                limitations = list(item.limitations)
                if item.statement_kind is not StatementKind.OBSERVED_FACT:
                    limitations.insert(0, f"statement_kind={item.statement_kind.value}")
                observed_at = item.observed_at
                probe_id = item.category
                summary = item.summary
                facts: dict[str, JsonValue] = {}
                for fact in item.facts:
                    candidate = {**facts, fact.name: _redact(fact.value, redactor, fact.name)}
                    if len(candidate) > 32 or len(_canonical(candidate).encode("utf-8")) > 8000:
                        limitations.append(
                            "Evidence facts exceeded the inference context byte budget."
                        )
                        continue
                    facts = candidate
                if item.facts_truncated:
                    limitations.append("Evidence facts were truncated for this compact packet.")
                status = {
                    StatementKind.MISSING: EvidenceContextStatus.MISSING,
                    StatementKind.UNAVAILABLE: EvidenceContextStatus.UNAVAILABLE,
                }.get(item.statement_kind, EvidenceContextStatus.OBSERVED)
            elif packet.coverage and packet.coverage[0].evidence_id == evidence_id:
                typed_coverage = CoverageRecord.model_validate_json(raw)
                if (
                    typed_coverage.evidence_id != evidence_id
                    or typed_coverage.case_id != owner
                    or typed_coverage.captured_at.isoformat() != str(row[4])
                    or (
                        None
                        if typed_coverage.execution_id is None
                        else str(typed_coverage.execution_id)
                    )
                    != (None if row[5] is None else str(row[5]))
                ):
                    raise ValueError("frontier packet coverage row identity differs")
                item_coverage = packet.coverage[0]
                limitations = list(item_coverage.limitations)
                observed_at = item_coverage.captured_at
                probe_id = f"{item_coverage.category}.coverage"
                summary = item_coverage.reason or "Coverage recorded."
                facts = {}
                status = (
                    EvidenceContextStatus.OBSERVED
                    if item_coverage.status is CoverageStatus.COVERED
                    else EvidenceContextStatus(item_coverage.status.value)
                )
            else:
                raise ValueError("frontier packet source is not retrievable as typed evidence")
            relevant = state.incident_start <= observed_at <= state.incident_end
            if scope == "current_case" and not relevant:
                limitations.insert(
                    0,
                    "Current collection is outside the incident window; "
                    "it does not establish conditions during that incident.",
                )
            if scope == "historical":
                limitations.append(
                    f"Historical observation from {owner}; freshness requires review."
                )
            time_basis, time_quality = str(row[7]), str(row[8])
            if (
                re.fullmatch(r"[a-z0-9_]{1,48}", time_basis) is None
                or re.fullmatch(r"[a-z0-9_]{1,32}", time_quality) is None
            ):
                raise ValueError("frontier packet source time metadata is invalid")
            trusted_exact_basis = {
                "source_event",
                "source_observed",
                "collector_observed",
                "collector_captured",
                "probe_attempt_finish",
            }
            reliable_time = time_quality == "exact" and time_basis in trusted_exact_basis
            if not reliable_time:
                temporal_caveat = (
                    "is an upper bound" if time_quality == "bounded_interval" else "is unverified"
                )
                limitations.insert(
                    0,
                    f"Source time {time_quality}/{time_basis} {temporal_caveat}; "
                    "incident relevance unverified.",
                )
            contexts.append(
                EvidenceContext(
                    evidence_id=evidence_id,
                    observed_at=observed_at,
                    captured_at=datetime.fromisoformat(str(row[4])),
                    probe_id=probe_id,
                    summary=redactor.redact_text(summary[:1000]).text,
                    facts=facts,
                    status=status,
                    case_scope=scope,
                    incident_relevant=relevant if reliable_time else None,
                    limitations=tuple(
                        redactor.redact_text(item[:240]).text for item in limitations[:16]
                    ),
                )
            )
            sources.append(
                FrontierPacketSourceV1(
                    evidence_id=evidence_id,
                    owner_case_id=owner,
                    scope=scope,
                    row_sha256=_sha({"evidence_id": str(evidence_id), "row": tuple(row)}),
                )
            )
        packets = tuple(
            SemanticPacketRefV1.model_validate(item)
            for item in evidence_packets(contexts, max_packets=24)
        )
        if not packets:
            raise ValueError("frontier packet projection is empty")
        return tuple(sources), packets
