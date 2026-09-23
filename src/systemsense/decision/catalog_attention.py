"""Metadata-only attention over a bounded case evidence catalog page.

This lane may suggest exact IDs for retrieval. It cannot supply observations,
diagnoses, citations, probe proposals, or permission to act.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.retrieval import EvidenceCatalogPage
from systemsense.inference.laya_runtime import LayaRuntimeError


class CatalogAttentionValidationError(ValueError):
    """An advisory result is not bound to the supplied catalog page."""


class CatalogMetadata(FrozenModel):
    """Untrusted lookup hints, never full observations or evidence facts."""

    evidence_id: EvidenceId
    case_id: CaseId
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    collector_id: str = Field(min_length=1, max_length=80)
    source_id: str = Field(min_length=1, max_length=128)
    summary_hint: str = Field(max_length=160)


class CatalogAttentionRequest(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    case_evidence_generation: int = Field(ge=0)
    deadline_at: UtcDateTime
    attention_goal: str = Field(default="", max_length=240)
    entries: tuple[CatalogMetadata, ...] = Field(max_length=20)
    visible_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    max_requests: int = Field(default=8, ge=1, le=8)

    @model_validator(mode="after")
    def validate_page(self) -> CatalogAttentionRequest:
        if any(item.case_id != self.case_id for item in self.entries):
            raise ValueError("catalog attention entry has a different case")
        if len({str(item.evidence_id) for item in self.entries}) != len(self.entries):
            raise ValueError("catalog attention page repeats an evidence ID")
        if len({str(item) for item in self.visible_evidence_ids}) != len(self.visible_evidence_ids):
            raise ValueError("visible evidence IDs must be unique")
        if len(self.model_dump_json().encode("utf-8")) > 8192:
            raise ValueError("catalog attention metadata exceeds 8192 bytes")
        return self

    @classmethod
    def from_page(
        cls,
        *,
        case_id: CaseId,
        page: EvidenceCatalogPage,
        visible_evidence_ids: tuple[EvidenceId, ...],
        deadline_at: datetime,
        attention_goal: str = "",
        max_requests: int = 8,
    ) -> CatalogAttentionRequest:
        if len(page.entries) > 20:
            raise ValueError("catalog attention page cannot exceed 20 entries")
        return cls(
            case_id=case_id,
            case_evidence_generation=page.case_evidence_generation,
            deadline_at=deadline_at,
            attention_goal=attention_goal,
            entries=tuple(
                CatalogMetadata(
                    evidence_id=item.evidence_id,
                    case_id=item.case_id,
                    observed_at=item.observed_at,
                    captured_at=item.captured_at,
                    collector_id=item.collector_id,
                    source_id=item.source_id,
                    summary_hint=" ".join(item.summary.split())[:160],
                )
                for item in page.entries
            ),
            visible_evidence_ids=visible_evidence_ids,
            max_requests=max_requests,
        )

    @property
    def page_digest(self) -> str:
        payload = {
            "case_id": str(self.case_id),
            "generation": self.case_evidence_generation,
            "attention_goal": self.attention_goal,
            "entries": [item.model_dump(mode="json") for item in self.entries],
            "visible_evidence_ids": [str(item) for item in self.visible_evidence_ids],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


class CatalogAttentionResponse(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    case_evidence_generation: int = Field(ge=0)
    page_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    deadline_at: UtcDateTime
    ranked_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    degraded: bool = False

    def validate_against(self, request: CatalogAttentionRequest) -> CatalogAttentionResponse:
        if datetime.now(UTC) >= request.deadline_at and not (
            self.degraded and not self.ranked_evidence_ids
        ):
            raise CatalogAttentionValidationError("catalog attention deadline elapsed")
        if (
            self.case_id != request.case_id
            or self.case_evidence_generation != request.case_evidence_generation
            or self.page_digest != request.page_digest
            or self.deadline_at != request.deadline_at
        ):
            raise CatalogAttentionValidationError("catalog attention page binding mismatch")
        allowed = {str(item.evidence_id) for item in request.entries} - {
            str(item) for item in request.visible_evidence_ids
        }
        if len({str(item) for item in self.ranked_evidence_ids}) != len(self.ranked_evidence_ids):
            raise CatalogAttentionValidationError("catalog attention repeats evidence")
        if len(self.ranked_evidence_ids) > request.max_requests or not {
            str(item) for item in self.ranked_evidence_ids
        }.issubset(allowed):
            raise CatalogAttentionValidationError("catalog attention references unavailable ID")
        if self.degraded and self.ranked_evidence_ids:
            raise CatalogAttentionValidationError("degraded attention cannot request evidence")
        return self


class CatalogAttentionProvider(Protocol):
    """Replaceable ranker; the coordinator remains owner of exact retrieval."""

    def rank_catalog(self, request: CatalogAttentionRequest) -> CatalogAttentionResponse: ...


class DeterministicCatalogFallback:
    """Fail closed when no qualified metadata ranker is available."""

    def rank_catalog(self, request: CatalogAttentionRequest) -> CatalogAttentionResponse:
        return CatalogAttentionResponse(
            case_id=request.case_id,
            case_evidence_generation=request.case_evidence_generation,
            page_digest=request.page_digest,
            deadline_at=request.deadline_at,
            degraded=True,
        ).validate_against(request)


class CatalogMetadataRanker(Protocol):
    """The narrow `LayaSubprocessRuntime.rank` call needed by this adapter."""

    def rank(
        self,
        *,
        state: dict[str, object],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> tuple[str, ...]: ...


def _exact_permutation(value: object, expected: tuple[str, ...]) -> bool:
    if not isinstance(value, tuple):
        return False
    items = cast(tuple[object, ...], value)
    return (
        all(isinstance(item, str) for item in items)
        and len(items) == len(expected)
        and set(items) == set(expected)
    )


class LayaCatalogAttentionProvider:
    """Rank lookup hints only; output is an exact-ID retrieval suggestion."""

    def __init__(
        self,
        *,
        ranker: CatalogMetadataRanker,
        timeout_seconds: float = 1.5,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("catalog attention timeout must be positive")
        self._ranker = ranker
        self._timeout_seconds = timeout_seconds
        self._fallback = DeterministicCatalogFallback()

    def rank_catalog(self, request: CatalogAttentionRequest) -> CatalogAttentionResponse:
        visible = {str(item) for item in request.visible_evidence_ids}
        omitted = tuple(item for item in request.entries if str(item.evidence_id) not in visible)
        remaining = (request.deadline_at - datetime.now(UTC)).total_seconds()
        timeout = min(self._timeout_seconds, remaining)
        if not omitted or timeout <= 0:
            return self._fallback.rank_catalog(request)
        candidates = tuple(
            {
                "probe_id": str(item.evidence_id),
                "description": json.dumps(
                    {
                        "kind": "catalog_metadata_only_not_evidence_fact",
                        "case_id": str(item.case_id),
                        "collector_id": item.collector_id,
                        "source_id": item.source_id,
                        "observed_at": item.observed_at.isoformat(),
                        "captured_at": item.captured_at.isoformat(),
                        "untrusted_summary_hint": item.summary_hint,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            }
            for item in omitted
        )
        state: dict[str, object] = {
            "attention_kind": "evidence_relevance",
            "attention_goal": request.attention_goal,
            "symptom": request.attention_goal,
            "catalog_metadata_only": True,
            "case_id": str(request.case_id),
        }
        expected = tuple(str(item.evidence_id) for item in omitted)
        try:
            ranked_raw: object = self._ranker.rank(
                state=state,
                candidates=candidates,
                timeout_seconds=timeout,
            )
            if not _exact_permutation(ranked_raw, expected):
                raise CatalogAttentionValidationError("worker returned an incomplete catalog rank")
            ranked = tuple(str(item) for item in ranked_raw)
            by_id = {str(item.evidence_id): item.evidence_id for item in omitted}
            return CatalogAttentionResponse(
                case_id=request.case_id,
                case_evidence_generation=request.case_evidence_generation,
                page_digest=request.page_digest,
                deadline_at=request.deadline_at,
                ranked_evidence_ids=tuple(by_id[item] for item in ranked[: request.max_requests]),
            ).validate_against(request)
        except (LayaRuntimeError, TimeoutError, OSError, ValueError):
            return self._fallback.rank_catalog(request)
