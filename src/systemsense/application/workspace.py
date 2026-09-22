"""Neutral case/evidence workspace services shared by local adapters."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import cast

from pydantic import Field

from systemsense.application.case_service import CaseService, OpenedCase
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    CaseTimeWindowBasis,
    DiagnosticCase,
)
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import EvidenceRecord, FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.brief import BriefEvidence, BriefGenerator, CaseBrief
from systemsense.evidence.ranking import RankableEvidence, rank_evidence
from systemsense.storage.sqlite_store import EvidenceRow, SQLiteStore


class WorkspaceAccessError(ValueError):
    """A requested case-scoped object or cursor is unavailable."""


class EvidenceSummary(FrozenModel):
    evidence_id: EvidenceId
    statement_kind: StatementKind
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    source_type: str
    collector_id: str
    summary: str
    limitation_count: int = Field(ge=0)


class EvidencePage(FrozenModel):
    case_id: CaseId
    items: tuple[EvidenceSummary, ...]
    next_cursor: str | None = Field(default=None, max_length=512)


class BoundedFact(FrozenModel):
    name: str
    value: JsonValue
    unit: str | None = None
    truncated: bool = False


class EvidenceDetail(FrozenModel):
    case_id: CaseId
    evidence_id: EvidenceId
    statement_kind: StatementKind
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    source_type: str
    source_id: str
    collector_id: str
    collector_version: int
    summary: str
    facts: tuple[BoundedFact, ...]
    limitations: tuple[str, ...]
    next_cursor: str | None = Field(default=None, max_length=512)


class EvidenceFactPage(FrozenModel):
    case_id: CaseId
    evidence_id: EvidenceId
    facts: tuple[BoundedFact, ...]
    next_cursor: str | None = Field(default=None, max_length=512)


class CoverageSummary(FrozenModel):
    evidence_id: EvidenceId
    category: str
    status: CoverageStatus
    captured_at: UtcDateTime
    reason: str | None
    limitations: tuple[str, ...]


class CoveragePage(FrozenModel):
    case_id: CaseId
    items: tuple[CoverageSummary, ...]
    next_cursor: str | None = Field(default=None, max_length=512)


class _CursorCodec:
    def __init__(self, secret: bytes | None = None) -> None:
        self._secret = secret or os.urandom(32)

    def encode(self, *, kind: str, offset: int, bindings: dict[str, str]) -> str:
        payload = json.dumps(
            {"bindings": bindings, "kind": kind, "offset": offset},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")

    def decode(self, cursor: str, *, kind: str, bindings: dict[str, str]) -> int:
        try:
            padding = "=" * (-len(cursor) % 4)
            encoded = base64.urlsafe_b64decode(cursor + padding)
            payload, signature = encoded[:-32], encoded[-32:]
            expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            raw_decoded: object = json.loads(payload)
            if not isinstance(raw_decoded, dict):
                raise ValueError
            decoded = cast("dict[str, object]", raw_decoded)
            if decoded.get("kind") != kind or decoded.get("bindings") != bindings:
                raise ValueError
            offset = decoded.get("offset")
            if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
                raise ValueError
            return offset
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            raise WorkspaceAccessError("cursor is invalid for this request") from error


class EvidenceWorkspace:
    """Case-scoped application service independent of any transport."""

    def __init__(
        self,
        *,
        store: SQLiteStore,
        case_service: CaseService,
        case_runtime: DiagnosticRuntime | None = None,
        cursor_secret: bytes | None = None,
    ) -> None:
        self._store = store
        self._case_service = case_service
        self._case_runtime = case_runtime
        self._cursor = _CursorCodec(cursor_secret)
        self._briefs: dict[str, CaseBrief] = {}
        self._pending_probes: dict[str, tuple[str, ...]] = {}

    def open_case(
        self,
        *,
        kind: CaseKind,
        symptom: str,
        target_traits: Iterable[str],
        budget_ms: int,
        max_probes: int,
        created_at: UtcDateTime,
    ) -> OpenedCase:
        traits = tuple(target_traits)
        opened = (
            self._case_service.open_case(
                kind=kind,
                symptom=symptom,
                target_traits=frozenset(traits),
                created_at=created_at,
                budget_ms=budget_ms,
                max_probes=max_probes,
            )
            if self._case_runtime is None
            else self._case_runtime.open_case(
                kind=kind,
                symptom=symptom,
                target_traits=traits,
                created_at=created_at,
                budget_ms=budget_ms,
                max_probes=max_probes,
            )
        )
        self._pending_probes[str(opened.case.case_id)] = (
            opened.plan.probe_ids if opened.case.status is CaseStatus.COLLECTING else ()
        )
        return opened

    def query_case_evidence(
        self,
        *,
        case_id: CaseId,
        category: str | None,
        statement_kind: StatementKind | None,
        limit: int,
        cursor: str | None,
    ) -> EvidencePage:
        self._require_case(case_id)
        bindings = {
            "case_id": str(case_id),
            "category": category or "",
            "statement_kind": statement_kind.value if statement_kind is not None else "",
        }
        offset = (
            0 if cursor is None else self._cursor.decode(cursor, kind="evidence", bindings=bindings)
        )
        rows = self._store.evidence_page(
            case_id=str(case_id),
            offset=offset,
            limit=limit + 1,
            category=category,
            statement_kind=statement_kind.value if statement_kind is not None else None,
        )
        records = tuple(_parse_evidence(row) for row in rows[:limit])
        next_cursor = None
        if len(rows) > limit:
            next_cursor = self._cursor.encode(
                kind="evidence", offset=offset + limit, bindings=bindings
            )
        return EvidencePage(
            case_id=case_id,
            items=tuple(_summary(record) for record in records),
            next_cursor=next_cursor,
        )

    def get_evidence(self, *, case_id: CaseId, evidence_id: EvidenceId) -> EvidenceDetail:
        self._require_case(case_id)
        row = self._store.evidence(case_id=str(case_id), evidence_id=str(evidence_id))
        if row is None:
            raise WorkspaceAccessError("evidence is unavailable for this case")
        record = _parse_evidence(row)
        facts = tuple(_bounded_fact(fact) for fact in record.facts[:12])
        bindings = {"case_id": str(case_id), "evidence_id": str(evidence_id)}
        next_cursor = None
        if len(record.facts) > 12:
            next_cursor = self._cursor.encode(kind="facts", offset=12, bindings=bindings)
        return EvidenceDetail(
            case_id=case_id,
            evidence_id=record.evidence_id,
            statement_kind=record.statement_kind,
            observed_at=record.observed_at,
            captured_at=record.captured_at,
            source_type=record.source.type,
            source_id=record.source.source_id,
            collector_id=record.collector.id,
            collector_version=record.collector.version,
            summary=record.summary,
            facts=facts,
            limitations=tuple(_clip(item, 240) for item in record.limitations[:8]),
            next_cursor=next_cursor,
        )

    def inspect_more(
        self,
        *,
        case_id: CaseId,
        evidence_id: EvidenceId,
        limit: int,
        cursor: str | None,
    ) -> EvidenceFactPage:
        self._require_case(case_id)
        row = self._store.evidence(case_id=str(case_id), evidence_id=str(evidence_id))
        if row is None:
            raise WorkspaceAccessError("evidence is unavailable for this case")
        record = _parse_evidence(row)
        bindings = {"case_id": str(case_id), "evidence_id": str(evidence_id)}
        offset = (
            12 if cursor is None else self._cursor.decode(cursor, kind="facts", bindings=bindings)
        )
        selected = record.facts[offset : offset + limit]
        next_cursor = None
        if offset + limit < len(record.facts):
            next_cursor = self._cursor.encode(
                kind="facts", offset=offset + limit, bindings=bindings
            )
        return EvidenceFactPage(
            case_id=case_id,
            evidence_id=evidence_id,
            facts=tuple(_bounded_fact(fact) for fact in selected),
            next_cursor=next_cursor,
        )

    def get_coverage_map(
        self,
        *,
        case_id: CaseId,
        limit: int,
        cursor: str | None,
    ) -> CoveragePage:
        self._require_case(case_id)
        bindings = {"case_id": str(case_id)}
        offset = (
            0 if cursor is None else self._cursor.decode(cursor, kind="coverage", bindings=bindings)
        )
        rows = self._store.coverage_page(case_id=str(case_id), offset=offset, limit=limit + 1)
        records = tuple(_parse_coverage(row) for row in rows[:limit])
        next_cursor = None
        if len(rows) > limit:
            next_cursor = self._cursor.encode(
                kind="coverage", offset=offset + limit, bindings=bindings
            )
        return CoveragePage(
            case_id=case_id,
            items=tuple(_coverage_summary(record) for record in records),
            next_cursor=next_cursor,
        )

    def get_case_brief(self, *, case_id: CaseId, max_chars: int) -> CaseBrief:
        diagnostic_case = self._load_case(case_id)
        rows = self._store.evidence_page(case_id=str(case_id), offset=0, limit=256)
        records = tuple(_parse_evidence(row) for row in rows)
        coverage_rows = self._store.coverage_page(case_id=str(case_id), offset=0, limit=128)
        coverage = tuple(_parse_coverage(row) for row in coverage_rows)
        diagnostic_case = diagnostic_case.model_copy(update={"coverage": coverage})
        by_id = {record.evidence_id: record for record in records}
        ranked = rank_evidence(
            (_rankable_evidence(record, diagnostic_case) for record in records),
            limit=256,
            max_per_category=256,
        )
        brief_evidence = tuple(
            BriefEvidence(
                evidence_id=record.evidence_id,
                category=record.collector.id,
                statement_kind=record.statement_kind,
                observed_at=record.observed_at,
                captured_at=record.captured_at,
                summary=record.summary,
                score=1.0 - (index / max(1, len(ranked))),
            )
            for index, item in enumerate(ranked)
            for record in (by_id[item.evidence.evidence_id],)
        )
        key = str(case_id)
        brief = BriefGenerator(max_chars=max_chars).generate(
            case=diagnostic_case,
            evidence=brief_evidence,
            pending_probe_ids=self._pending_probes.get(key, ()),
            generated_at=utc_now(),
            previous=self._briefs.get(key),
        )
        self._briefs[key] = brief
        return brief

    def get_case(self, case_id: CaseId) -> DiagnosticCase:
        """Return the persisted typed case state without re-deriving its time window."""

        return self._load_case(case_id)

    def _require_case(self, case_id: CaseId) -> None:
        if self._store.case(str(case_id)) is None:
            raise WorkspaceAccessError("case is unavailable")

    def _load_case(self, case_id: CaseId) -> DiagnosticCase:
        row = self._store.case(str(case_id))
        if row is None:
            raise WorkspaceAccessError("case is unavailable")
        created_at = datetime.fromisoformat(row.created_at)
        try:
            status = CaseStatus(row.status)
            window_basis = CaseTimeWindowBasis(row.time_window_basis)
        except ValueError as error:
            raise WorkspaceAccessError("stored case metadata is invalid") from error
        if row.time_window_start is not None and row.time_window_end is not None:
            window_start = datetime.fromisoformat(row.time_window_start)
            window_end = datetime.fromisoformat(row.time_window_end)
        else:
            # Legacy cases did not persist a window. Keep the compatibility
            # fallback explicitly unknown rather than calling it evidence time.
            window_start = created_at - timedelta(minutes=15)
            window_end = created_at + timedelta(minutes=5)
            window_basis = CaseTimeWindowBasis.UNKNOWN
        return DiagnosticCase(
            case_id=case_id,
            kind=CaseKind(row.kind),
            status=status,
            symptom=row.symptom,
            created_at=created_at,
            time_window=CaseTimeWindow(
                start=window_start,
                end=window_end,
                basis=window_basis,
            ),
            state_version=row.state_version,
        )


def _parse_evidence(row: EvidenceRow) -> EvidenceRecord:
    try:
        return EvidenceRecord.model_validate_json(row.record_json)
    except ValueError as error:
        raise WorkspaceAccessError("stored evidence record is invalid") from error


def _parse_coverage(row: EvidenceRow) -> CoverageRecord:
    try:
        return CoverageRecord.model_validate_json(row.record_json)
    except ValueError as error:
        raise WorkspaceAccessError("stored coverage record is invalid") from error


def _summary(record: EvidenceRecord) -> EvidenceSummary:
    return EvidenceSummary(
        evidence_id=record.evidence_id,
        statement_kind=record.statement_kind,
        observed_at=record.observed_at,
        captured_at=record.captured_at,
        source_type=record.source.type,
        collector_id=record.collector.id,
        summary=record.summary,
        limitation_count=len(record.limitations),
    )


def _coverage_summary(record: CoverageRecord) -> CoverageSummary:
    return CoverageSummary(
        evidence_id=record.evidence_id,
        category=record.category,
        status=record.status,
        captured_at=record.captured_at,
        reason=None if record.reason is None else _clip(record.reason, 240),
        limitations=tuple(_clip(item, 240) for item in record.limitations[:8]),
    )


def _bounded_fact(fact: object) -> BoundedFact:
    from systemsense.domain.evidence import EvidenceFact

    if not isinstance(fact, EvidenceFact):
        raise TypeError("fact must be normalized evidence")
    serialized = json.dumps(
        fact.value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized) <= 800:
        value = fact.value
        truncated = False
    else:
        value = _clip(serialized, 800)
        truncated = True
    return BoundedFact(
        name=fact.name,
        value=value,
        unit=fact.unit,
        truncated=truncated,
    )


def _brief_score(kind: StatementKind) -> float:
    if kind in {StatementKind.CHANGE, StatementKind.CONTRADICTION}:
        return 1.0
    if kind in {StatementKind.MISSING, StatementKind.UNAVAILABLE}:
        return 0.8
    return 0.5


def _rankable_evidence(record: EvidenceRecord, diagnostic_case: DiagnosticCase) -> RankableEvidence:
    category = record.collector.id.split(".", maxsplit=1)[0]
    case_category = (
        "devices" if diagnostic_case.kind is CaseKind.DEVICES_AUDIO else diagnostic_case.kind.value
    )
    relevance = (
        0.8
        if diagnostic_case.kind is CaseKind.GENERAL
        else (1.0 if category == case_category else 0.5)
    )
    in_window = (
        diagnostic_case.time_window.start <= record.observed_at <= diagnostic_case.time_window.end
    )
    is_change = record.statement_kind is StatementKind.CHANGE
    is_contradiction = record.statement_kind is StatementKind.CONTRADICTION
    return RankableEvidence(
        evidence_id=record.evidence_id,
        category=category,
        relevance=relevance,
        severity=_brief_score(record.statement_kind),
        proximity=1.0 if in_window else 0.4,
        novelty=1.0 if is_change or is_contradiction else 0.5,
        coverage=1.0,
        is_change=is_change,
        is_contradiction=is_contradiction,
    )


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"
