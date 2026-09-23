"""Transactional checkpoint and append-only hypothesis/timeline history."""

from systemsense.application.investigation_state import (
    InvestigationState,
    InvestigationStatus,
    InvestigationStep,
)
from systemsense.domain.cases import CaseKind, CaseStatus
from systemsense.domain.time import utc_now
from systemsense.storage.sqlite_store import SQLiteStore, StaleCaseStateError


class InvestigationRepository:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def create(self, state: InvestigationState) -> None:
        with self.store.transaction():
            self.store.create_case(
                case_id=str(state.case_id),
                kind=CaseKind.GENERAL.value,
                symptom=state.objective,
                created_at=state.created_at.isoformat(),
                status=CaseStatus.OPEN.value,
                state_version=state.state_version,
                time_window_start=state.incident_start.isoformat(),
                time_window_end=state.incident_end.isoformat(),
                time_window_basis="case_open_derived",
            )
            self.store.connection.execute(
                "INSERT INTO investigation_checkpoints (case_id, record_json) VALUES (?, ?)",
                (str(state.case_id), state.model_dump_json()),
            )
            self._step(state, "created", state.summary)

    def load(self, case_id: str) -> InvestigationState:
        row = self.store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id = ?", (case_id,)
        ).fetchone()
        if row is None:
            raise ValueError("investigation is unavailable")
        state = InvestigationState.model_validate_json(str(row[0]))
        if str(state.case_id) != case_id:
            raise ValueError("investigation checkpoint belongs to another case")
        return state

    def save(
        self, state: InvestigationState, *, expected_version: int, event: str, detail: str
    ) -> InvestigationState:
        if state.state_version != expected_version:
            raise StaleCaseStateError("checkpoint was prepared from a stale version")
        updated = state.model_copy(
            update={
                "schema_version": 5,
                "state_version": expected_version + 1,
                "updated_at": utc_now(),
            }
        )
        with self.store.transaction() as transaction:
            transaction.transition_case(
                case_id=str(state.case_id),
                expected_state_version=expected_version,
                status=(
                    CaseStatus.COLLECTING.value
                    if state.status in {InvestigationStatus.RUNNING, InvestigationStatus.QUEUED}
                    else CaseStatus.READY.value
                ),
            )
            cursor = self.store.connection.execute(
                "UPDATE investigation_checkpoints SET record_json = ? WHERE case_id = ?",
                (updated.model_dump_json(), str(state.case_id)),
            )
            if cursor.rowcount != 1:
                raise ValueError("investigation checkpoint is unavailable")
            self._step(updated, event, detail)
            if (
                updated.status
                in {
                    InvestigationStatus.COMPLETE,
                    InvestigationStatus.CANCELLED,
                    InvestigationStatus.FAILED,
                    InvestigationStatus.INTERRUPTED,
                }
                and self.store.connection.execute(
                    "SELECT 1 FROM coordinator_events WHERE case_id = ? AND kind = 'terminal'",
                    (str(updated.case_id),),
                ).fetchone()
                is None
            ):
                transaction.append_coordinator_event(
                    case_id=str(updated.case_id),
                    kind="terminal",
                    fields={"status": updated.status.value, "outcome": updated.outcome.value},
                    source_record_id=str(updated.state_version),
                    source_observed_at=updated.updated_at.isoformat(),
                )
        return updated

    def steps(self, case_id: str, *, limit: int = 200) -> tuple[InvestigationStep, ...]:
        if not 1 <= limit <= 500:
            raise ValueError("timeline limit must be between 1 and 500")
        rows = self.store.connection.execute(
            "SELECT record_json FROM investigation_steps WHERE case_id = ? "
            "ORDER BY state_version DESC LIMIT ?",
            (case_id, limit),
        ).fetchall()
        return tuple(InvestigationStep.model_validate_json(str(row[0])) for row in reversed(rows))

    def _step(self, state: InvestigationState, event: str, detail: str) -> None:
        step = InvestigationStep(
            case_id=state.case_id,
            state_version=state.state_version,
            occurred_at=state.updated_at,
            event=event,
            detail=detail[:4000],
            # Starting a provider is progress, not a new hypothesis revision.
            hypotheses=() if event in {"attention", "reasoning"} else state.hypotheses,
            probe_ids=state.pending_probe_ids,
        )
        self.store.connection.execute(
            "INSERT INTO investigation_steps (case_id, state_version, record_json) "
            "VALUES (?, ?, ?)",
            (str(state.case_id), state.state_version, step.model_dump_json()),
        )
