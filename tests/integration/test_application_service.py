import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.passive import PassiveRecorder, PassiveRecorderConfig
from systemsense.application.service import ApplicationService
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.inference.settings import ProviderStatus
from systemsense.knowledge.windows_errors import (
    WindowsErrorCatalog,
    WindowsErrorReference,
    WindowsErrorSource,
)
from systemsense.orchestration.executor import CancellationSignal
from systemsense.orchestration.probes import ProbeObservation, ProbeRun, ProbeRunStatus
from systemsense.platform.windows.eventlog import EventQuery, QueryStatus
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator


class _RecorderManifest:
    version = 1


class _RecorderRunner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def manifest(self, probe_id: str) -> _RecorderManifest:
        del probe_id
        return _RecorderManifest()

    def run(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> ProbeRun:
        del parameters
        assert deadline_at is not None
        assert cancellation is not None
        self.calls.append(probe_id)
        now = datetime.now(UTC)
        return ProbeRun(
            execution_id=ExecutionId.new(),
            probe_id=probe_id,
            status=ProbeRunStatus.OK,
            started_at=now,
            finished_at=now,
            elapsed_ms=0,
            observation=ProbeObservation(
                summary=f"{probe_id} service integration sample",
                facts={"probe_id": probe_id},
                observed_at=now,
                captured_at=now,
            ),
        )


class _NoEvents:
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> EventQuery:
        del channel, after_record_id, limit
        assert deadline_at is not None
        assert cancellation is not None
        return EventQuery(status=QueryStatus.OK)


def test_application_runs_exports_and_reopens_durable_case(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    app = ApplicationService(database, factory=investigator)
    try:
        started = app.start_case("Investigate network failure", 2000, 4)
        app.wait(timeout=5)
        result = app.get_case(str(started["case_id"]))
        assert result["status"] == "complete"
        assert result["evidence_count"] == 3
        assert app.export_case(str(started["case_id"]))["format"] == "systemsense-case-report-v1"
        assert app.capabilities()["read_only"] is True
    finally:
        app.close()
    reopened = ApplicationService(database, factory=investigator)
    try:
        assert len(reopened.list_cases()["cases"]) == 1  # type: ignore[arg-type]
        assert reopened.get_case(str(started["case_id"]))["status"] == "complete"
    finally:
        reopened.close()


def test_case_report_includes_explicit_error_references_as_reference_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog = WindowsErrorCatalog.from_constants(
        {"ERROR_ACCESS_DENIED": 5},
        message_resolver=lambda _code: "Access is denied.",
        source=WindowsErrorSource(
            catalog_provider="fixture",
            catalog_version="1",
            message_provider="fixture",
            os_version="fixture Windows",
            runtime_observed=False,
        ),
    )
    reference = catalog.lookup_win32(5)
    assert reference is not None

    def references(_text: str, max_items: int = 4) -> tuple[WindowsErrorReference, ...]:
        return (reference,) if max_items == 4 else ()

    monkeypatch.setattr("systemsense.application.investigator.reference_for_text", references)
    app = ApplicationService(tmp_path / "app.db", factory=investigator)
    try:
        started = app.start_case("The API returned Win32 error 5", 2000, 4)
        app.wait(timeout=5)

        report = app.get_case(str(started["case_id"]))

        error_references = report["error_references"]
        assert isinstance(error_references, list)
        assert error_references[0]["reference_id"] == "windows-error:win32:5"
        assert error_references[0]["namespace"] == "win32"
        assert error_references[0]["source"]["catalog_provider"] == "fixture"
        assert "evidence_id" not in error_references[0]
    finally:
        app.close()


def test_one_application_owns_workspace_and_recovery_marks_interruption(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    with SQLiteStore(database) as store:
        state = investigator(store).create(objective="interrupted case", budget_ms=2000)
    app = ApplicationService(database, factory=investigator)
    try:
        with pytest.raises(RuntimeError, match="already has an active"):
            ApplicationService(database, factory=investigator)
        with SQLiteStore(database) as store:
            state = InvestigationRepository(store).load(str(state.case_id))
            assert state.status is InvestigationStatus.INTERRUPTED
            assert store.probe_execution_count(case_id=str(state.case_id)) == 0
        app.resume_case(str(state.case_id))
        app.wait(timeout=5)
        assert app.get_case(str(state.case_id))["status"] == "complete"
    finally:
        app.close()


def test_application_service_runs_one_bounded_passive_cycle(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    runner = _RecorderRunner()

    def passive_factory(store: SQLiteStore, config: PassiveRecorderConfig) -> PassiveRecorder:
        return PassiveRecorder(
            store=store,
            runner=runner,
            event_log=_NoEvents(),
            config=config,
        )

    app = ApplicationService(
        database,
        factory=investigator,
        passive_factory=passive_factory,
    )
    try:
        started = app.start_recorder(interval_seconds=5, max_cycles=1)
        assert started["available"] is True
        app.wait_recorder(timeout=5)

        status = app.recorder_status()
        assert status["active"] is False
        assert status["cycles_completed"] == 1
        assert status["error"] is None
        assert runner.calls == ["core.system", "core.resources"]
        with SQLiteStore(database) as store:
            passive = store.cases(kinds=("passive",), limit=10)
            assert len(passive) == 1
            assert passive[0].status == "complete"
            assert store.probe_execution_count(case_id=passive[0].case_id) == 4
    finally:
        app.close()


def test_capabilities_reports_live_shared_provider_status(tmp_path: Path) -> None:
    class StatusDecision(KeywordBaselineDecisionProvider):
        status = ProviderStatus(
            provider_id="laya-local-decision",
            enabled=True,
            available=False,
            detail="not_checked",
        )

    class StatusReasoning(DeterministicReasoningProvider):
        status = ProviderStatus(
            provider_id="ollama-local-reasoning",
            enabled=True,
            available=False,
            detail="not_checked",
        )

    decision = StatusDecision()
    reasoning = StatusReasoning()

    def factory(store: SQLiteStore):  # type: ignore[no-untyped-def]
        instance = investigator(store)
        instance.decision = decision
        instance.reasoning = reasoning
        return instance

    app = ApplicationService(
        tmp_path / "status.db",
        factory=factory,
        inference_status={
            "enabled": True,
            "mode": "local-dual-brain",
            "decision_status": "not_checked",
            "reasoning_status": "not_checked",
        },
    )
    try:
        initial = app.capabilities()["inference"]
        assert isinstance(initial, dict)
        assert initial["decision_status"] == "not_checked"
        assert initial["reasoning_status"] == "not_checked"

        decision.status = decision.status.model_copy(update={"available": True, "detail": "ready"})
        reasoning.status = reasoning.status.model_copy(
            update={"available": False, "detail": "context budget unavailable"}
        )
        live = app.capabilities()["inference"]
        assert isinstance(live, dict)
        assert live["decision_status"] == "ready"
        assert live["decision_detail"] == "ready"
        assert live["reasoning_status"] == "unavailable"
        assert live["reasoning_detail"] == "context budget unavailable"
    finally:
        app.close()


def test_capabilities_does_not_treat_historical_prewarm_as_live_provider_readiness(
    tmp_path: Path,
) -> None:
    class StatusDecision(KeywordBaselineDecisionProvider):
        status = ProviderStatus(
            provider_id="laya-local-decision",
            enabled=True,
            available=False,
            detail="not_checked",
        )

    class StatusReasoning(DeterministicReasoningProvider):
        status = ProviderStatus(
            provider_id="ollama-local-reasoning",
            enabled=True,
            available=False,
            detail="not_checked",
        )

    def factory(store: SQLiteStore):  # type: ignore[no-untyped-def]
        instance = investigator(store)
        instance.decision = StatusDecision()
        instance.reasoning = StatusReasoning()
        return instance

    app = ApplicationService(
        tmp_path / "prewarm-status.db",
        factory=factory,
        inference_status={
            "enabled": True,
            "mode": "local-dual-brain",
            "decision_status": "ready",
            "reasoning_status": "unavailable",
            "decision_prewarm": {"status": "ready"},
            "reasoning_prewarm": {"status": "degraded", "reason": "timeout"},
        },
    )
    try:
        initial = app.capabilities()["inference"]
        assert isinstance(initial, dict)
        assert initial["decision_status"] == "not_checked"
        assert initial["reasoning_status"] == "not_checked"
        assert initial["decision_prewarm"] == {"status": "ready"}
        assert initial["reasoning_prewarm"] == {"status": "degraded", "reason": "timeout"}
    finally:
        app.close()


def test_worker_failure_logs_safe_stack_without_exception_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fail_run(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.OperationalError("private host path and secret access_token=abc")

    monkeypatch.setattr(Investigator, "run", fail_run)
    with caplog.at_level(logging.ERROR, logger="systemsense.application.service"):
        app = ApplicationService(tmp_path / "failure.db", factory=investigator)
        try:
            started = app.start_case("test failure boundary", 2000, 1)
            app.wait(timeout=5)
            report = app.get_case(str(started["case_id"]))
            assert report["status"] == "failed"
        finally:
            app.close()
    assert "OperationalError" in caplog.text
    assert "fail_run" in caplog.text
    assert "private host path" not in caplog.text
    assert "access_token" not in caplog.text


def test_case_history_returns_summaries_not_full_evidence_checkpoints(tmp_path: Path) -> None:
    app = ApplicationService(tmp_path / "history.db", factory=investigator)
    try:
        started = app.start_case("Investigate network failure", 2000, 4)
        app.wait(timeout=5)
        history = cast(list[dict[str, object]], app.list_cases()["cases"])
        assert len(history) == 1
        assert history[0]["case_id"] == started["case_id"]
        assert history[0]["status"] == "complete"
        assert set(history[0]) == {
            "case_id",
            "objective",
            "status",
            "outcome",
            "created_at",
            "updated_at",
        }
    finally:
        app.close()
