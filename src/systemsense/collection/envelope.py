"""Normalized envelopes for bounded evidence ingestion."""

import hashlib
import json
from collections.abc import Mapping
from enum import IntEnum
from typing import Literal

from pydantic import Field

from systemsense.domain.coverage import CoverageStatus
from systemsense.domain.evidence import FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, JsonValue
from systemsense.domain.time import UtcDateTime


class EnvelopePriority(IntEnum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


def normalized_fingerprint(payload: Mapping[str, JsonValue]) -> str:
    canonical = json.dumps(
        dict(payload),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class EnvelopeBase(FrozenModel):
    case_id: CaseId
    category: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    source_id: str = Field(pattern=r"^src_[0-9a-f]{64}$")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    captured_at: UtcDateTime
    priority: EnvelopePriority


class EvidenceEnvelope(EnvelopeBase):
    kind: Literal["evidence"] = "evidence"
    statement_kind: StatementKind
    observed_at: UtcDateTime
    payload: dict[str, JsonValue]

    @classmethod
    def create(
        cls,
        *,
        case_id: CaseId,
        category: str,
        source_id: str,
        statement_kind: StatementKind,
        observed_at: UtcDateTime,
        captured_at: UtcDateTime,
        payload: Mapping[str, JsonValue],
    ) -> "EvidenceEnvelope":
        normalized_payload = dict(payload)
        priority = (
            EnvelopePriority.HIGH
            if statement_kind in {StatementKind.CHANGE, StatementKind.CONTRADICTION}
            else EnvelopePriority.CRITICAL
            if statement_kind in {StatementKind.MISSING, StatementKind.UNAVAILABLE}
            else EnvelopePriority.NORMAL
        )
        return cls(
            case_id=case_id,
            category=category,
            source_id=source_id,
            fingerprint=normalized_fingerprint(normalized_payload),
            captured_at=captured_at,
            priority=priority,
            statement_kind=statement_kind,
            observed_at=observed_at,
            payload=normalized_payload,
        )


class CoverageEnvelope(EnvelopeBase):
    kind: Literal["coverage"] = "coverage"
    status: CoverageStatus
    reason: str = Field(min_length=1, max_length=1000)

    @classmethod
    def create(
        cls,
        *,
        case_id: CaseId,
        category: str,
        source_id: str,
        status: CoverageStatus,
        captured_at: UtcDateTime,
        reason: str,
    ) -> "CoverageEnvelope":
        fingerprint_payload: dict[str, JsonValue] = {
            "category": category,
            "status": status.value,
            "reason": reason,
        }
        return cls(
            case_id=case_id,
            category=category,
            source_id=source_id,
            fingerprint=normalized_fingerprint(fingerprint_payload),
            captured_at=captured_at,
            priority=EnvelopePriority.CRITICAL,
            status=status,
            reason=reason,
        )


type CollectionEnvelope = EvidenceEnvelope | CoverageEnvelope
