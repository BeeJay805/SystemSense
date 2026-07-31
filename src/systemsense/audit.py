"""Hash-linked, redacted probe execution audit records."""

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Literal, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, JsonValue
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.redaction import Redactor

_GENESIS_HASH = "0" * 64
_LIMITATION = "tamper-evident only; not forensic integrity"


class AuditOutcome(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    TRUNCATED = "truncated"


class AuditEntry(FrozenModel):
    schema_version: Literal[1] = 1
    sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1, max_length=255)
    case_id: CaseId | None
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    outcome: AuditOutcome
    occurred_at: UtcDateTime
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    error: str | None = None
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditCheckpoint(FrozenModel):
    entry_count: int = Field(ge=0)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditVerification(FrozenModel):
    valid: bool
    failure_index: int | None = Field(default=None, ge=0)
    reason: str | None = None
    limitation: Literal["tamper-evident only; not forensic integrity"] = _LIMITATION


class AuditChain:
    def __init__(self, *, redactor: Redactor | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._redactor = redactor or Redactor()

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def append(
        self,
        *,
        event_id: str,
        case_id: CaseId | None,
        probe_id: str,
        outcome: AuditOutcome,
        occurred_at: UtcDateTime | None = None,
        parameters: Mapping[str, JsonValue] | None = None,
        error: str | None = None,
    ) -> AuditEntry:
        redacted_parameters = {
            name: self._redact_json(name, value) for name, value in (parameters or {}).items()
        }
        candidate = AuditEntry(
            sequence=len(self._entries) + 1,
            event_id=event_id,
            case_id=case_id,
            probe_id=probe_id,
            outcome=outcome,
            occurred_at=occurred_at or utc_now(),
            parameters=redacted_parameters,
            error=None if error is None else self._redactor.redact_text(error).text,
            previous_hash=self._entries[-1].event_hash if self._entries else _GENESIS_HASH,
            event_hash=_GENESIS_HASH,
        )
        entry = candidate.model_copy(update={"event_hash": self._hash_entry(candidate)})
        self._entries.append(entry)
        return entry

    def checkpoint(self) -> AuditCheckpoint:
        return AuditCheckpoint(
            entry_count=len(self._entries),
            head_hash=self._entries[-1].event_hash if self._entries else _GENESIS_HASH,
        )

    @classmethod
    def verify(
        cls,
        entries: tuple[AuditEntry, ...],
        *,
        checkpoint: AuditCheckpoint,
    ) -> AuditVerification:
        if len(entries) != checkpoint.entry_count:
            return AuditVerification(valid=False, reason="entry count mismatch")

        previous_hash = _GENESIS_HASH
        for index, entry in enumerate(entries):
            if entry.sequence != index + 1:
                return AuditVerification(
                    valid=False,
                    failure_index=index,
                    reason="sequence mismatch",
                )
            if entry.previous_hash != previous_hash:
                return AuditVerification(
                    valid=False,
                    failure_index=index,
                    reason="previous hash mismatch",
                )
            if entry.event_hash != cls._hash_entry(entry):
                return AuditVerification(
                    valid=False,
                    failure_index=index,
                    reason="event hash mismatch",
                )
            previous_hash = entry.event_hash

        if previous_hash != checkpoint.head_hash:
            return AuditVerification(valid=False, reason="checkpoint head mismatch")
        return AuditVerification(valid=True)

    @staticmethod
    def _hash_entry(entry: AuditEntry) -> str:
        payload = entry.model_dump(mode="json", exclude={"event_hash"})
        canonical = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _redact_json(self, field_name: str, value: JsonValue) -> JsonValue:
        if isinstance(value, str):
            return self._redactor.redact_field(field_name, value)
        if isinstance(value, list):
            return [self._redact_json(field_name, item) for item in value]
        if isinstance(value, dict):
            return {
                name: self._redact_json(name, nested_value) for name, nested_value in value.items()
            }
        return cast("JsonValue", value)
