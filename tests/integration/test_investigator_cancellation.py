import threading
from pathlib import Path

from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationStatus,
)
from systemsense.decision.contracts import ProviderIdentity
from systemsense.reasoning.contracts import (
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator


class _BlockingReasoningProvider:
    def __init__(self, entered: threading.Event, release: threading.Event) -> None:
        self._entered = entered
        self._release = release

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="blocking-reasoning",
            provider_version="1",
            role="reasoning",
        )

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        self._entered.set()
        if not self._release.wait(3):
            raise TimeoutError("test did not release reasoning provider")
        return ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=ReasoningStatus.UNRESOLVED,
            summary="Reasoning completed after cancellation was requested.",
        )


def test_final_round_cancellation_is_not_replaced_by_budget_outcome(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    cancellation = threading.Event()

    def cancel_during_reasoning() -> None:
        if not entered.wait(3):
            return
        cancellation.set()
        release.set()

    with SQLiteStore(tmp_path / "cancel.db") as store:
        app = investigator(store)
        app.reasoning = _BlockingReasoningProvider(entered, release)
        initial = app.create(objective="slow computer", budget_ms=10_000, max_rounds=1)
        helper = threading.Thread(target=cancel_during_reasoning)
        helper.start()
        try:
            result = app.run(str(initial.case_id), cancel_event=cancellation)
        finally:
            release.set()
            helper.join(timeout=3)

    assert not helper.is_alive()
    assert cancellation.is_set()
    assert result.status is InvestigationStatus.CANCELLED
    assert result.outcome is InvestigationOutcome.CANCELLED
    assert result.stop_reason == "Cancelled by the user."
