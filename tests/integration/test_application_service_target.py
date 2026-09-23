"""Case-facing process selection never accepts a caller-supplied PID."""

from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationStatus,
)
from systemsense.application.investigator import Investigator
from systemsense.application.service import ApplicationService
from systemsense.application.targets import TargetSelectionError
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator
from tests.unit.application.test_process_target_binding import (
    _process,  # pyright: ignore[reportPrivateUsage]
    _snapshot,  # pyright: ignore[reportPrivateUsage]
)


def _candidate_id(report: dict[str, object]) -> str:
    inventory = cast("dict[str, object]", report["process_target_inventory"])
    candidates = cast("list[dict[str, object]]", inventory["candidates"])
    return str(candidates[0]["candidate_id"])


def _waiting_case(app: ApplicationService, *, at: datetime) -> str:
    with SQLiteStore(app.database) as store:
        state = investigator(store).create(objective="PDF editor is slow", budget_ms=5_000)
        InvestigationRepository(store).save(
            state.model_copy(
                update={
                    "status": InvestigationStatus.AWAITING_TARGET,
                    "outcome": InvestigationOutcome.AWAITING_TARGET,
                }
            ),
            expected_version=state.state_version,
            event="awaiting_target",
            detail="Choose a process from this case snapshot.",
        )
        _snapshot(
            store,
            state.case_id,
            processes=[_process(42, at - timedelta(minutes=1))],
            at=at,
            omitted=2,
        )
    return str(state.case_id)


def test_waiting_case_exposes_fresh_candidates_and_selection_launches_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resumed: list[str] = []
    launched: list[str] = []

    def resume_after_target(self: Investigator, case_id: str) -> None:
        resumed.append(case_id)
        repo = InvestigationRepository(self.store)
        state = repo.load(case_id)
        repo.save(
            state.model_copy(update={"status": InvestigationStatus.QUEUED}),
            expected_version=state.state_version,
            event="target_selected",
            detail="Selected case process.",
        )

    def launch(_self: ApplicationService, case_id: str) -> None:
        launched.append(case_id)

    monkeypatch.setattr(Investigator, "resume_after_target", resume_after_target, raising=False)
    monkeypatch.setattr(ApplicationService, "_launch", launch)
    app = ApplicationService(tmp_path / "cases.db", factory=investigator)
    try:
        case_id = _waiting_case(app, at=datetime.now(UTC))
        waiting = app.get_case(case_id)
        next_action = cast("list[dict[str, object]]", waiting["next_action"])
        assert "Choose one process" in str(next_action[0]["summary"])
        inventory = waiting["process_target_inventory"]
        assert isinstance(inventory, dict)
        assert inventory["inventory_complete"] is False
        assert inventory["omitted_process_count"] == 2
        assert len(cast("list[object]", inventory["candidates"])) == 1
        candidate_id = _candidate_id(waiting)

        recorder_future: Future[None] = Future()
        app._passive_future = recorder_future  # pyright: ignore[reportPrivateUsage]
        assert app.recorder_status()["active"] is True

        with pytest.raises(TargetSelectionError, match="Select a process target"):
            app.resume_case(case_id)
        result = app.select_process_target(case_id, candidate_id)
        assert result["status"] == "queued"
        assert "process_target_inventory" not in result
        assert app.select_process_target(case_id, candidate_id)["status"] == "queued"
        assert resumed == [case_id]
        assert launched == [case_id]
        assert app.recorder_status()["active"] is True
        recorder_future.set_result(None)
        with pytest.raises(TargetSelectionError, match="not awaiting"):
            app.select_process_target(case_id, "proc_" + "0" * 32)
    finally:
        app.close()


def test_selection_rejects_stale_or_busy_case_without_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched: list[str] = []

    def launch(_self: ApplicationService, case_id: str) -> None:
        launched.append(case_id)

    monkeypatch.setattr(ApplicationService, "_launch", launch)
    app = ApplicationService(tmp_path / "cases.db", factory=investigator)
    try:
        case_id = _waiting_case(app, at=datetime.now(UTC) - timedelta(minutes=6))
        report = app.get_case(case_id)
        inventory = cast("dict[str, object]", report["process_target_inventory"])
        assert inventory["candidates"] == []
        assert "stale" in str(inventory["unavailable_reason"])
        assert "Start a new investigation" in str(report["next_action"])
        with pytest.raises(TargetSelectionError, match="stale"):
            app.select_process_target(case_id, "proc_" + "0" * 32)

        future: Future[None] = Future()
        app._future = future  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(RuntimeError, match="already active"):
            app.select_process_target(case_id, "proc_" + "0" * 32)
        future.set_result(None)
        assert launched == []
    finally:
        app.close()


def test_selection_retry_after_resume_failure_uses_same_binding_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0
    launched: list[str] = []

    def resume_after_target(self: Investigator, case_id: str) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected resume failure")
        repo = InvestigationRepository(self.store)
        state = repo.load(case_id)
        repo.save(
            state.model_copy(update={"status": InvestigationStatus.QUEUED}),
            expected_version=state.state_version,
            event="target_selected",
            detail="Selected case process.",
        )

    def launch(_self: ApplicationService, case_id: str) -> None:
        launched.append(case_id)

    monkeypatch.setattr(Investigator, "resume_after_target", resume_after_target)
    monkeypatch.setattr(ApplicationService, "_launch", launch)
    app = ApplicationService(tmp_path / "cases.db", factory=investigator)
    try:
        case_id = _waiting_case(app, at=datetime.now(UTC))
        inventory = app.get_case(case_id)["process_target_inventory"]
        assert isinstance(inventory, dict)
        candidate_id = _candidate_id(app.get_case(case_id))
        with pytest.raises(RuntimeError, match="injected"):
            app.select_process_target(case_id, candidate_id)
        with SQLiteStore(app.database) as store:
            assert store.connection.execute(
                "SELECT COUNT(*) FROM case_process_targets WHERE case_id = ?", (case_id,)
            ).fetchone() == (1,)
        assert launched == []
        assert app.select_process_target(case_id, candidate_id)["status"] == "queued"
        assert attempts == 2
        assert launched == [case_id]
    finally:
        app.close()


def test_cross_case_candidate_and_terminal_case_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched: list[str] = []

    def launch(_self: ApplicationService, case_id: str) -> None:
        launched.append(case_id)

    monkeypatch.setattr(ApplicationService, "_launch", launch)
    app = ApplicationService(tmp_path / "cases.db", factory=investigator)
    try:
        first = _waiting_case(app, at=datetime.now(UTC))
        second = _waiting_case(app, at=datetime.now(UTC))
        inventory = app.get_case(first)["process_target_inventory"]
        assert isinstance(inventory, dict)
        candidate_id = _candidate_id(app.get_case(first))
        with pytest.raises(TargetSelectionError, match="unavailable"):
            app.select_process_target(second, candidate_id)
        with SQLiteStore(app.database) as store:
            repo = InvestigationRepository(store)
            state = repo.load(first)
            repo.save(
                state.model_copy(update={"status": InvestigationStatus.COMPLETE}),
                expected_version=state.state_version,
                event="complete",
                detail="Terminal case.",
            )
        with pytest.raises(TargetSelectionError, match="not awaiting"):
            app.select_process_target(first, candidate_id)
        assert launched == []
    finally:
        app.close()
