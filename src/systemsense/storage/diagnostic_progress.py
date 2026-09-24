"""Append-only branch progress derived from verified diagnostic custody.

Projection is a durable receipt. Readback revalidates the admission, terminal,
and source citations before exposing any diagnostic Boolean to a coordinator.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evaluation.progress import (
    ProgressEvent,
    ProgressLedger,
    VerifiedPredicateObservation,
    record_progress,
)
from systemsense.storage.diagnostic_intents import (
    DiagnosticIntentAdmissionV2,
    DiagnosticIntentRepository,
    DiagnosticIntentTerminalV1,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DiagnosticProgressProjectionV1(FrozenModel):
    """One terminal's bounded result, explicitly not a root-cause conclusion."""

    schema_version: Literal[1] = 1
    admission_id: str = Field(pattern=r"^diagnostic_intent_[0-9a-f]{32}$")
    case_id: CaseId
    question_id: str
    branch_id: str
    uncertainty_id: str
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_status: Literal["evaluated", "unknown", "failed", "interrupted"]
    terminal_reason: str
    event: ProgressEvent
    projected_at: UtcDateTime


def _event(
    admission: DiagnosticIntentAdmissionV2, terminal: DiagnosticIntentTerminalV1
) -> ProgressEvent:
    observation = None
    evaluation = terminal.evaluation
    if terminal.status == "evaluated":
        if (
            evaluation is None
            or evaluation.observed is None
            or not evaluation.evidence_ids
            or evaluation.scope != admission.question.scope
        ):
            raise ValueError("evaluated diagnostic terminal has no cited scoped observation")
        observation = VerifiedPredicateObservation(
            predicate_id=evaluation.predicate_id,
            observed=evaluation.observed,
            evidence_ids=evaluation.evidence_ids,
            scope=evaluation.scope,
        )
    elif evaluation is not None and evaluation.observed is not None:
        raise ValueError("non-evaluated diagnostic terminal carries an observed Boolean")
    event = record_progress(
        ProgressLedger(),
        intent=admission.question.to_intent(),
        observation=observation,
    ).events[0]
    if evaluation is not None:
        event = event.model_copy(
            update={"evaluation": evaluation, "evidence_ids": evaluation.evidence_ids}
        )
    return event


class DiagnosticProgressRepository:
    def __init__(self, store: SQLiteStore) -> None:
        self._store = store
        self._intents = DiagnosticIntentRepository(store)

    def project_terminal(self, admission_id: str) -> DiagnosticProgressProjectionV1:
        """Idempotently project one trusted terminal in the caller's transaction."""

        if not self._store.connection.in_transaction:
            raise ValueError("diagnostic progress write requires caller-owned transaction")
        previous = self._raw_record(admission_id)
        if previous is not None:
            return self.readback(admission_id)
        admission = self._intents.admission_record(admission_id)
        if not isinstance(admission, DiagnosticIntentAdmissionV2):
            raise ValueError("diagnostic progress requires a versioned question")
        terminal = self._intents.terminal(admission_id)
        if terminal is None:
            raise ValueError("diagnostic progress requires a terminal")
        record = DiagnosticProgressProjectionV1(
            admission_id=admission_id,
            case_id=admission.case_id,
            question_id=admission.question.question_id,
            branch_id=admission.question.branch_id,
            uncertainty_id=admission.question.uncertainty_id,
            admission_sha256=_digest(_canonical(admission.model_dump(mode="json"))),
            terminal_sha256=_digest(_canonical(terminal.model_dump(mode="json"))),
            terminal_status=terminal.status,
            terminal_reason=terminal.reason,
            event=_event(admission, terminal),
            projected_at=utc_now(),
        )
        raw = _canonical(record.model_dump(mode="json"))
        self._store.connection.execute(
            "INSERT INTO diagnostic_progress "
            "(admission_id,case_id,branch_id,terminal_sha256,admission_sha256,"
            "record_json,record_sha256,projected_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                record.admission_id,
                str(record.case_id),
                record.branch_id,
                record.terminal_sha256,
                record.admission_sha256,
                raw,
                _digest(raw),
                record.projected_at.isoformat(),
            ),
        )
        return record

    def _raw_record(self, admission_id: str) -> tuple[object, ...] | None:
        row = self._store.connection.execute(
            "SELECT case_id,branch_id,terminal_sha256,admission_sha256,record_json,"
            "record_sha256,projected_at FROM diagnostic_progress WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        return None if row is None else tuple(row)

    def readback(self, admission_id: str) -> DiagnosticProgressProjectionV1:
        row = self._raw_record(admission_id)
        if row is None or _digest(str(row[4])) != row[5]:
            raise ValueError("diagnostic progress is unavailable or corrupt")
        result = DiagnosticProgressProjectionV1.model_validate_json(str(row[4]))
        admission = self._intents.admission_record(admission_id)
        if not isinstance(admission, DiagnosticIntentAdmissionV2):
            raise ValueError("diagnostic progress has no versioned question")
        terminal = self._intents.terminal(admission_id)
        if terminal is None:
            raise ValueError("diagnostic progress terminal is unavailable")
        if (
            result.admission_id != admission_id
            or result.case_id != admission.case_id
            or result.question_id != admission.question.question_id
            or result.branch_id != admission.question.branch_id
            or result.uncertainty_id != admission.question.uncertainty_id
            or result.admission_sha256 != _digest(_canonical(admission.model_dump(mode="json")))
            or result.terminal_sha256 != _digest(_canonical(terminal.model_dump(mode="json")))
            or result.terminal_status != terminal.status
            or result.terminal_reason != terminal.reason
            or result.event != _event(admission, terminal)
            or result.projected_at < terminal.evaluated_at
            or result.projected_at > utc_now()
            or row
            != (
                str(result.case_id),
                result.branch_id,
                result.terminal_sha256,
                result.admission_sha256,
                str(row[4]),
                str(row[5]),
                result.projected_at.isoformat(),
            )
            or _canonical(result.model_dump(mode="json")) != row[4]
        ):
            raise ValueError("diagnostic progress binding is invalid")
        return result

    def for_case(self, case_id: CaseId) -> tuple[DiagnosticProgressProjectionV1, ...]:
        rows = self._store.connection.execute(
            "SELECT admission_id FROM diagnostic_progress WHERE case_id=? "
            "ORDER BY projected_at,admission_id LIMIT 513",
            (str(case_id),),
        ).fetchall()
        if len(rows) > 512:
            raise ValueError("diagnostic progress case bound exceeded")
        results = tuple(self.readback(str(row[0])) for row in rows)
        if any(result.case_id != case_id for result in results):
            raise ValueError("diagnostic progress case binding is invalid")
        return results

    def project_unprojected(self, case_id: CaseId) -> tuple[DiagnosticProgressProjectionV1, ...]:
        """Recover terminal receipts under exclusive case ownership, without dispatch."""

        if not self._store.connection.in_transaction:
            raise ValueError("diagnostic progress write requires caller-owned transaction")
        rows = self._store.connection.execute(
            "SELECT a.admission_id FROM diagnostic_intent_admissions a "
            "JOIN diagnostic_intent_terminals t ON t.admission_id=a.admission_id "
            "LEFT JOIN diagnostic_progress p ON p.admission_id=a.admission_id "
            "WHERE a.case_id=? AND p.admission_id IS NULL "
            "ORDER BY a.admitted_at,a.admission_id LIMIT 513",
            (str(case_id),),
        ).fetchall()
        if len(rows) > 512:
            raise ValueError("diagnostic unprojected terminal bound exceeded")
        results: list[DiagnosticProgressProjectionV1] = []
        for row in rows:
            admission = self._intents.admission_record(str(row[0]))
            if isinstance(admission, DiagnosticIntentAdmissionV2):
                results.append(self.project_terminal(admission.admission_id))
        return tuple(results)
