"""Deep task custody remains bounded, immutable and atomic with case state."""

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from systemsense.application.deep_worker import (
    DeepMailboxCompletionV1,
    DeepMailboxRepository,
    freeze_deep_task,
    run_deep_worker,
)
from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.time import utc_now
from systemsense.reasoning.contracts import ReasoningRequest
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.presented_read_set import capture_presented_read_set
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator


def test_mailbox_recovery_never_replays_and_basis_is_immutable(tmp_path: Path) -> None:
    path = tmp_path / "custody.db"
    with SQLiteStore(path) as store:
        app = investigator(store)
        state = app.create(objective="network issue")
        request = ReasoningRequest(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id="deep:test",
            deadline_at=utc_now() + timedelta(seconds=30),
            objective=state.objective,
            available_probes=app.capabilities,
            budget_ms=3000,
            max_probes=1,
        )
        task = freeze_deep_task(
            request,
            capture_presented_read_set(store, state.case_id, ()),
            provider_identity=app.reasoning.identity,
            hypothesis_revision=0,
        )
        mailbox = DeepMailboxRepository(store)
        assert mailbox.admit(task)
        assert not mailbox.admit(task)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            with store.transaction():
                store.connection.execute("UPDATE deep_mailbox SET task_json='{}'")
    with SQLiteStore(path) as store:
        mailbox = DeepMailboxRepository(store)
        assert mailbox.recover(state.case_id) == 1
        assert mailbox.recover(state.case_id) == 0
        assert not mailbox.admit(task)
        assert (
            store.connection.execute("SELECT status FROM deep_mailbox").fetchone()[0]
            == "interrupted"
        )


def test_checkpoint_and_mailbox_completion_roll_back_together(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "atomic.db") as store:
        app = investigator(store)
        state = app.create(objective="network issue")
        provider = UnavailableReasoningProvider()
        request = ReasoningRequest(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id="deep:test",
            deadline_at=utc_now() + timedelta(seconds=30),
            objective=state.objective,
            available_probes=app.capabilities,
            budget_ms=3000,
            max_probes=1,
        )
        task = freeze_deep_task(
            request,
            capture_presented_read_set(store, state.case_id, ()),
            provider_identity=provider.identity,
            hypothesis_revision=0,
        )
        mailbox = DeepMailboxRepository(store)
        assert mailbox.admit(task)
        result = run_deep_worker(provider, task, cancel_event=None)
        completion = DeepMailboxCompletionV1(task=task, result=result, status="rejected")
        store.connection.execute(
            "CREATE TEMP TRIGGER fail_deep_completion BEFORE UPDATE ON deep_mailbox "
            "BEGIN SELECT RAISE(ABORT,'injected mailbox failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="injected"):
            app.repository.save(
                state,
                expected_version=state.state_version,
                event="deep_rejected",
                detail="test",
                deep_completion=completion,
            )
        assert app.repository.load(str(state.case_id)).state_version == state.state_version
        assert (
            store.connection.execute("SELECT status FROM deep_mailbox").fetchone()[0] == "running"
        )
        store.connection.execute("DROP TRIGGER fail_deep_completion")
        saved = app.repository.save(
            state,
            expected_version=state.state_version,
            event="deep_rejected",
            detail="test",
            deep_completion=completion,
        )
        with pytest.raises(ValueError, match="already consumed"):
            app.repository.save(
                saved,
                expected_version=saved.state_version,
                event="deep_rejected",
                detail="test",
                deep_completion=completion,
            )
        assert app.repository.load(str(state.case_id)).state_version == saved.state_version


def test_completion_rejects_same_request_with_different_provider_basis(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "binding.db") as store:
        app = investigator(store)
        state = app.create(objective="network issue")
        request = ReasoningRequest(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id="deep:test",
            deadline_at=utc_now() + timedelta(seconds=30),
            objective=state.objective,
            available_probes=app.capabilities,
            budget_ms=3000,
            max_probes=1,
        )
        task = freeze_deep_task(
            request,
            capture_presented_read_set(store, state.case_id, ()),
            provider_identity=app.reasoning.identity,
            hypothesis_revision=0,
        )
        mailbox = DeepMailboxRepository(store)
        assert mailbox.admit(task)
        changed = task.model_copy(
            update={
                "provider_identity": ProviderIdentity(
                    provider_id="another", provider_version="1", role="reasoning"
                )
            }
        )
        with pytest.raises(ValueError, match="basis mismatch"):
            mailbox.finish(changed, "rejected")
        assert (
            store.connection.execute("SELECT status FROM deep_mailbox").fetchone()[0] == "running"
        )


def test_large_request_is_rejected_before_custody(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "bounded.db") as store:
        app = investigator(store)
        state = app.create(objective="network issue")
        request = ReasoningRequest(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id="deep:test",
            deadline_at=utc_now() + timedelta(seconds=30),
            objective=state.objective,
            available_probes=app.capabilities,
            budget_ms=3000,
            max_probes=1,
            reference_context=({"unbounded": "x" * 270_000},),
        )
        task = freeze_deep_task(
            request,
            capture_presented_read_set(store, state.case_id, ()),
            provider_identity=app.reasoning.identity,
            hypothesis_revision=0,
        )
        with pytest.raises(ValueError, match="byte bound"):
            DeepMailboxRepository(store).admit(task)
        assert store.connection.execute("SELECT COUNT(*) FROM deep_mailbox").fetchone()[0] == 0
