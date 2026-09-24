"""Transactional checkpoint and append-only hypothesis/timeline history."""

from systemsense.application.deep_worker import DeepMailboxCompletionV1, DeepMailboxRepository
from systemsense.application.investigation_state import (
    InvestigationState,
    InvestigationStatus,
    InvestigationStep,
)
from systemsense.domain.cases import CaseKind, CaseStatus
from systemsense.domain.time import utc_now
from systemsense.storage.search_frontier import (
    FrontierInvestigatorItemTransitionV1,
    FrontierInvestigatorTurnClosureIntentV1,
    FrontierInvestigatorTurnCompletionV1,
    FrontierStatus,
    SearchFrontierRepository,
)
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
        self,
        state: InvestigationState,
        *,
        expected_version: int,
        event: str,
        detail: str,
        deep_completion: DeepMailboxCompletionV1 | None = None,
        frontier_turn_completion: FrontierInvestigatorTurnCompletionV1 | None = None,
        frontier_item_transition: FrontierInvestigatorItemTransitionV1 | None = None,
        frontier_session_closure: FrontierInvestigatorTurnClosureIntentV1 | None = None,
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
            if frontier_turn_completion is not None:
                if frontier_turn_completion.case_id != updated.case_id:
                    raise ValueError("frontier turn completion belongs to another case")
                frontier = SearchFrontierRepository(self.store)
                reserved = frontier.read_investigator_turn(frontier_turn_completion.turn_id)
                if reserved.case_id != updated.case_id:
                    raise ValueError("frontier turn reservation belongs to another case")
                if frontier_turn_completion.outcome == "focused_delivery":
                    if (
                        frontier_item_transition is None
                        or frontier_item_transition.item_id
                        != frontier_turn_completion.frontier_item_ids[0]
                        or frontier_item_transition.expected_status is not FrontierStatus.RUNNING
                        or frontier_item_transition.terminal_status is not FrontierStatus.SATISFIED
                    ):
                        raise ValueError("focused delivery requires an atomic frontier transition")
                    selected_item = frontier.readback(frontier_item_transition.item_id)
                    selected_evidence_id = selected_item.reference.evidence_id
                    if (
                        selected_item.reference.kind != "retrieve_evidence"
                        or selected_evidence_id is None
                        or selected_evidence_id not in updated.fast_catalog_selected_ids
                        or updated.fast_catalog_generation != reserved.catalog_generation
                    ):
                        raise ValueError("focused delivery selected evidence is not in checkpoint")
                elif frontier_item_transition is not None and (
                    frontier_item_transition.terminal_status is not FrontierStatus.OBSOLETE
                ):
                    raise ValueError("non-delivery frontier transition must be obsolete")
                if frontier_item_transition is not None:
                    if frontier_item_transition.item_id not in (
                        *reserved.offered_item_ids,
                        *reserved.pending_item_ids,
                    ):
                        raise ValueError("frontier transition was not frozen in reserved turn")
                    frontier.transition_in_transaction(
                        frontier_item_transition.item_id,
                        frontier_item_transition.expected_status,
                        frontier_item_transition.terminal_status,
                        frontier_item_transition.reason,
                    )
                frontier.complete_investigator_turn_in_transaction(
                    frontier_turn_completion,
                    expected_checkpoint_version=updated.state_version,
                )
                if frontier_session_closure is not None:
                    if (
                        frontier_session_closure.case_id != updated.case_id
                        or frontier_session_closure.event_id != reserved.event_id
                        or frontier_session_closure.final_turn_id
                        != frontier_turn_completion.turn_id
                    ):
                        raise ValueError("frontier session closure is not bound to completed turn")
                    frontier.close_investigator_session_in_transaction(frontier_session_closure)
            elif frontier_item_transition is not None:
                raise ValueError("frontier item transition requires turn completion")
            elif frontier_session_closure is not None:
                if (
                    frontier_session_closure.case_id != updated.case_id
                    or frontier_session_closure.outcome != "gap"
                    or frontier_session_closure.reason_code
                    not in {"case_stopped", "source_unverifiable"}
                    or updated.status
                    not in {
                        InvestigationStatus.COMPLETE,
                        InvestigationStatus.CANCELLED,
                        InvestigationStatus.FAILED,
                        InvestigationStatus.INTERRUPTED,
                    }
                ):
                    raise ValueError("frontier session closure requires turn completion")
                SearchFrontierRepository(self.store).close_investigator_session_in_transaction(
                    frontier_session_closure
                )
            if deep_completion is not None:
                if deep_completion.task.request.case_id != state.case_id:
                    raise ValueError("deep completion belongs to another case")
                # A typed SQL-only transition, atomic with the case checkpoint.
                # No executable callbacks, inference or external I/O run here.
                if not DeepMailboxRepository(self.store).finish_in_transaction(
                    deep_completion.task,
                    deep_completion.status,
                    result=deep_completion.result,
                    reason=deep_completion.reason,
                ):
                    raise ValueError("deep completion was already consumed or interrupted")
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
