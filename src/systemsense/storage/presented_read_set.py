"""Versioned read-set fingerprints for evidence actually shown to a decision model.

This is a read-only content-integrity check, not a MAC or proof of causality. It
queries only caller-supplied opaque IDs, never searches arbitrary SQL. Unrelated
case appends may advance the catalog generation without changing this read set.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.coverage import CoverageRecord
from systemsense.domain.evidence import EvidenceRecord, FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.storage.sqlite_store import SQLiteStore

_MAX_VISIBLE_IDS = 256
_ROW_COLUMNS = (
    "case_id,source_id,record_json,observed_at,captured_at,execution_id,"
    "dedupe_key,time_basis,time_quality"
)


def _digest(payload: object) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class PresentedReadSetEntryV1(FrozenModel):
    schema_version: Literal[1] = 1
    evidence_id: EvidenceId
    kind: Literal["evidence", "coverage", "missing", "outside_case"]
    owner_case_id: CaseId | None = None
    row_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_owner_and_digest(self) -> PresentedReadSetEntryV1:
        present = self.kind in {"evidence", "coverage"}
        if (self.owner_case_id is not None) != present or (self.row_sha256 is not None) != present:
            raise ValueError("presented read-set entry owner/digest does not match state")
        return self


class PresentedReadSetV1(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    case_generation: int = Field(ge=1)
    entries: tuple[PresentedReadSetEntryV1, ...] = Field(max_length=_MAX_VISIBLE_IDS)
    read_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_binding(self) -> PresentedReadSetV1:
        ids = tuple(item.evidence_id for item in self.entries)
        if len(set(ids)) != len(ids):
            raise ValueError("presented read set repeats an evidence ID")
        if any(
            item.owner_case_id is not None and item.owner_case_id != self.case_id
            for item in self.entries
        ):
            raise ValueError("presented read set contains another case's row")
        if self.read_set_sha256 != _snapshot_digest(
            self.case_id, self.case_generation, self.entries
        ):
            raise ValueError("presented read-set digest mismatch")
        return self


class PresentedReadSetCheckV1(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    frozen_generation: int = Field(ge=1)
    current_generation: int = Field(ge=1)
    consistent: bool
    generation_advanced: bool
    generation_regressed: bool
    modified_ids: tuple[EvidenceId, ...] = ()
    missing_or_retained_away_ids: tuple[EvidenceId, ...] = ()
    missing_at_freeze_ids: tuple[EvidenceId, ...] = ()
    outside_case_ids: tuple[EvidenceId, ...] = ()


def _snapshot_digest(
    case_id: CaseId, generation: int, entries: tuple[PresentedReadSetEntryV1, ...]
) -> str:
    return _digest(
        {
            "schema_version": 1,
            "case_id": str(case_id),
            "case_generation": generation,
            "entries": [item.model_dump(mode="json") for item in entries],
        }
    )


def _case_generation(store: SQLiteStore, case_id: CaseId) -> int:
    if store.case(str(case_id)) is None:
        raise ValueError("presented read-set case does not exist")
    row = store.connection.execute(
        "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
    ).fetchone()
    if row is None:
        raise ValueError("presented read-set case generation is unavailable")
    return int(row[0])


def _entry(
    store: SQLiteStore,
    case_id: CaseId,
    evidence_id: EvidenceId,
    *,
    validate_payload: bool,
) -> PresentedReadSetEntryV1:
    # An exact primary-key lookup determines ownership without returning any
    # foreign case payload or owner identifier to the caller.
    owner = store.connection.execute(
        "SELECT case_id FROM evidence WHERE evidence_id=?", (str(evidence_id),)
    ).fetchone()
    if owner is None:
        return PresentedReadSetEntryV1(evidence_id=evidence_id, kind="missing")
    if str(owner[0]) != str(case_id):
        return PresentedReadSetEntryV1(evidence_id=evidence_id, kind="outside_case")
    row = store.connection.execute(
        f"SELECT {_ROW_COLUMNS} FROM evidence WHERE evidence_id=? AND case_id=?",
        (str(evidence_id), str(case_id)),
    ).fetchone()
    if row is None:
        raise ValueError("presented evidence changed inside the read snapshot")
    raw_payload = str(row[2])
    kind: Literal["evidence", "coverage"] = "evidence"
    if validate_payload:
        try:
            evidence = EvidenceRecord.model_validate_json(raw_payload)
        except ValueError:
            try:
                coverage = CoverageRecord.model_validate_json(raw_payload)
            except ValueError as error:
                raise ValueError(
                    "presented evidence payload is not typed evidence/coverage"
                ) from error
            if coverage.evidence_id != evidence_id or coverage.case_id != case_id:
                raise ValueError(
                    "presented coverage payload identity differs from owner row"
                ) from None
            kind = "coverage"
        else:
            if (
                evidence.evidence_id != evidence_id
                or evidence.case_id != case_id
                or evidence.source.source_id != str(row[1])
            ):
                raise ValueError("presented evidence payload identity differs from owner row")
    else:
        try:
            CoverageRecord.model_validate_json(raw_payload)
        except ValueError:
            pass
        else:
            kind = "coverage"
    return PresentedReadSetEntryV1(
        evidence_id=evidence_id,
        kind=kind,
        owner_case_id=case_id,
        row_sha256=_digest(
            {
                "schema_version": 1,
                "evidence_id": str(evidence_id),
                "case_id": str(row[0]),
                "source_id": str(row[1]),
                "record_json": raw_payload,
                "observed_at": str(row[3]),
                "captured_at": str(row[4]),
                "execution_id": None if row[5] is None else str(row[5]),
                "dedupe_key": str(row[6]),
                "time_basis": str(row[7]),
                "time_quality": str(row[8]),
            }
        ),
    )


def capture_presented_read_set(
    store: SQLiteStore, case_id: CaseId, visible_evidence_ids: tuple[EvidenceId, ...]
) -> PresentedReadSetV1:
    """Bind the exact ordered IDs presented by a frozen request, at one DB snapshot."""

    if len(visible_evidence_ids) > _MAX_VISIBLE_IDS:
        raise ValueError("presented evidence ID bound exceeded")
    if len(set(visible_evidence_ids)) != len(visible_evidence_ids):
        raise ValueError("presented evidence IDs repeat")
    with store.read_snapshot():
        generation = _case_generation(store, case_id)
        entries = tuple(
            _entry(store, case_id, evidence_id, validate_payload=True)
            for evidence_id in visible_evidence_ids
        )
    return PresentedReadSetV1(
        case_id=case_id,
        case_generation=generation,
        entries=entries,
        read_set_sha256=_snapshot_digest(case_id, generation, entries),
    )


def revalidate_presented_read_set(
    store: SQLiteStore, snapshot: PresentedReadSetV1
) -> PresentedReadSetCheckV1:
    """Compare only presented rows; a newer catalog is not automatically stale."""

    validated = PresentedReadSetV1.model_validate(snapshot.model_dump(mode="json"))
    with store.read_snapshot():
        generation = _case_generation(store, validated.case_id)
        current = tuple(
            _entry(store, validated.case_id, item.evidence_id, validate_payload=False)
            for item in validated.entries
        )
    modified: list[EvidenceId] = []
    missing_now: list[EvidenceId] = []
    missing_at_freeze: list[EvidenceId] = []
    outside_case: list[EvidenceId] = []
    for before, after in zip(validated.entries, current, strict=True):
        if before.kind == "missing":
            missing_at_freeze.append(before.evidence_id)
        elif before.kind == "outside_case":
            outside_case.append(before.evidence_id)
        elif after.kind == "missing":
            missing_now.append(before.evidence_id)
        elif before != after:
            modified.append(before.evidence_id)
    regressed = generation < validated.case_generation
    return PresentedReadSetCheckV1(
        case_id=validated.case_id,
        frozen_generation=validated.case_generation,
        current_generation=generation,
        consistent=not (modified or missing_now or missing_at_freeze or outside_case or regressed),
        generation_advanced=generation > validated.case_generation,
        generation_regressed=regressed,
        modified_ids=tuple(modified),
        missing_or_retained_away_ids=tuple(missing_now),
        missing_at_freeze_ids=tuple(missing_at_freeze),
        outside_case_ids=tuple(outside_case),
    )
