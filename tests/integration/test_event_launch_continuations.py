"""Launch permits separate timely decisions from bounded worker handoffs."""

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

import pytest

from systemsense.application import runtime as runtime_module
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
)
from systemsense.domain.ids import CaseId, ExecutionId
from systemsense.domain.time import utc_now
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.orchestration.probes import ProbeRun, ProbeRunStatus
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import (
    CandidateDispatchAdmissionRepository,
    CandidateLaunchContinuation,
)
from systemsense.storage.search_frontier import FrontierStatus, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration import test_event_frontier_loop as event_loop
from tests.integration.test_event_frontier_loop import (
    MeasurementFirstRanker,
    _app_with_registered_host_probes,  # pyright: ignore[reportPrivateUsage]
    _omit_until_selected,  # pyright: ignore[reportPrivateUsage]
    _source,  # pyright: ignore[reportPrivateUsage]
    _started_with_event,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.application import test_general_candidate_catalog as catalog_fixtures


@pytest.fixture(autouse=True)
def _refresh_imported_catalog_clock(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    # Imported event-loop helpers do not inherit their defining module's fixture.
    monkeypatch.setattr(catalog_fixtures, "NOW", utc_now())


def _short_rank_seconds(_default: float) -> float:
    return 2.5


def test_mixed_frontier_reserves_time_to_commit_selected_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timely local choice survives bounded work to save its one-shot permit."""
    with SQLiteStore(tmp_path / "event-mixed-dispatch-reserve.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        monkeypatch.setattr(app, "_frontier_rank_seconds", lambda _default: 2.0)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)

        original_rank = ranker.rank

        def rank_with_local_latency(
            request: FrontierRankRequestV1,
            *,
            capture_worker_batch: Callable[
                [str, int, dict[str, object], LayaWorkerPresentation], None
            ]
            | None = None,
        ) -> FrontierRankResponseV1:
            time.sleep(1.0)
            return original_rank(request, capture_worker_batch=capture_worker_batch)

        monkeypatch.setattr(ranker, "rank", rank_with_local_latency)
        original_continuation = (
            CandidateDispatchAdmissionRepository.create_launch_continuation_in_transaction
        )

        def commit_after_bounded_delay(
            repository: CandidateDispatchAdmissionRepository,
            admission_id: str,
            *,
            turn_id: str,
            owner_started_version: int,
            resulting_checkpoint_version: int,
            deadline_at: datetime | None = None,
        ) -> CandidateLaunchContinuation:
            time.sleep(1.4)
            return original_continuation(
                repository,
                admission_id,
                turn_id=turn_id,
                owner_started_version=owner_started_version,
                resulting_checkpoint_version=resulting_checkpoint_version,
                deadline_at=deadline_at,
            )

        monkeypatch.setattr(
            CandidateDispatchAdmissionRepository,
            "create_launch_continuation_in_transaction",
            commit_after_bounded_delay,
        )
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        turn = SearchFrontierRepository(store).investigator_turns(state.case_id, event.event_id)[0]
        outcome = SearchFrontierRepository(store).read_investigator_turn_outcome(turn.turn_id)
        assert handled and outcome is not None
        assert outcome.outcome == "measurement_admitted"
        assert updated.state_version > state.state_version


def test_timely_event_admission_continues_after_rank_deadline_v2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timely frozen Laya choice may cross its rank turn only under its fresh V2 permit."""
    with SQLiteStore(tmp_path / "event-continuation-v2-cross-rank.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        # Keep the case deadline generous; shorten only this synthetic rank turn.
        monkeypatch.setattr(app, "_frontier_rank_seconds", _short_rank_seconds)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)

        rank = ranker.rank

        def rank_near_turn_deadline(
            request: FrontierRankRequestV1,
            *,
            capture_worker_batch: Callable[
                [str, int, dict[str, object], LayaWorkerPresentation], None
            ]
            | None = None,
        ) -> FrontierRankResponseV1:
            delay = (request.deadline_at - utc_now()).total_seconds() - 0.9
            if delay > 0:
                time.sleep(delay)
            assert utc_now() < request.deadline_at
            return rank(request, capture_worker_batch=capture_worker_batch)

        monkeypatch.setattr(ranker, "rank", rank_near_turn_deadline)
        consume = CandidateDispatchAdmissionRepository.consume_launch_continuation
        consumed_ids: list[str] = []

        def consume_after_turn_deadline(
            repository: CandidateDispatchAdmissionRepository,
            continuation_id: str,
            *,
            case_id: CaseId,
            task_id: str,
            invocation_sha256: str,
        ) -> CandidateLaunchContinuation:
            continuation = repository.readback_launch_continuation(continuation_id)
            turn = SearchFrontierRepository(repository._store).read_investigator_turn(  # pyright: ignore[reportPrivateUsage]
                continuation.turn_id
            )
            assert continuation.created_at < turn.deadline_at
            delay = (turn.deadline_at + timedelta(milliseconds=50) - utc_now()).total_seconds()
            if delay > 0:
                time.sleep(delay)
            assert utc_now() > turn.deadline_at
            result = consume(
                repository,
                continuation_id,
                case_id=case_id,
                task_id=task_id,
                invocation_sha256=invocation_sha256,
            )
            consumed_ids.append(continuation_id)
            return result

        monkeypatch.setattr(
            CandidateDispatchAdmissionRepository,
            "consume_launch_continuation",
            consume_after_turn_deadline,
        )
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert handled and outcome is not None
        assert updated.state_version > state.state_version
        assert outcome.outcome == "measurement_admitted"
        assert ranker.requests and utc_now() > turn.deadline_at
        assert outcome.launch_continuation_id is not None
        assert consumed_ids == [outcome.launch_continuation_id]

        continuation = CandidateDispatchAdmissionRepository(store).readback_launch_continuation(
            outcome.launch_continuation_id
        )
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(
            outcome.candidate_snapshot_id or ""
        )
        assert continuation.schema_version == 2
        assert continuation.continuation_id.startswith("candidate_launch_v2_")
        assert continuation.created_at < turn.deadline_at
        assert continuation.created_at < snapshot.request.deadline_at
        assert continuation.deadline_at == min(
            state.deadline_at, continuation.created_at + timedelta(seconds=2)
        )
        assert continuation.deadline_at > turn.deadline_at
        assert continuation.consumed_at is not None
        assert turn.deadline_at < continuation.consumed_at < continuation.deadline_at

        admission = CandidateDispatchAdmissionRepository(store).readback(
            outcome.dispatch_admission_id or ""
        )
        assert admission.outcome_status == "linked"
        assert admission.execution_id is not None
        assert store.connection.execute(
            "SELECT status FROM probe_executions WHERE execution_id=?",
            (admission.execution_id,),
        ).fetchone() == ("ok",)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_launch_consumptions WHERE continuation_id=?",
            (continuation.continuation_id,),
        ).fetchone() == (1,)


def test_v2_expiry_during_source_validation_is_not_consumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Time is rechecked after expensive source validation, before the consume insert."""
    with SQLiteStore(tmp_path / "event-continuation-v2-validation-expiry.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        monkeypatch.setattr(app, "_frontier_rank_seconds", _short_rank_seconds)
        state, _, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)

        original_consume = CandidateDispatchAdmissionRepository.consume_launch_continuation
        observed_ids: list[str] = []

        def expire_during_validation(
            repository: CandidateDispatchAdmissionRepository,
            continuation_id: str,
            *,
            case_id: CaseId,
            task_id: str,
            invocation_sha256: str,
        ) -> CandidateLaunchContinuation:
            continuation = repository.readback_launch_continuation(continuation_id)
            moments = iter(
                (
                    continuation.deadline_at - timedelta(milliseconds=1),
                    continuation.deadline_at + timedelta(milliseconds=1),
                )
            )

            def controlled_clock() -> datetime:
                return next(moments)

            saved_clock = repository._clock  # pyright: ignore[reportPrivateUsage]
            repository._clock = controlled_clock  # pyright: ignore[reportPrivateUsage]
            try:
                result = original_consume(
                    repository,
                    continuation_id,
                    case_id=case_id,
                    task_id=task_id,
                    invocation_sha256=invocation_sha256,
                )
            finally:
                repository._clock = saved_clock  # pyright: ignore[reportPrivateUsage]
            observed_ids.append(result.continuation_id)
            return result

        monkeypatch.setattr(
            CandidateDispatchAdmissionRepository,
            "consume_launch_continuation",
            expire_during_validation,
        )
        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        assert handled
        continuation_rows = store.connection.execute(
            "SELECT continuation_id,admission_id FROM candidate_launch_continuations"
        ).fetchall()
        assert len(continuation_rows) == 1
        continuation_id = str(continuation_rows[0][0])
        admission_id = str(continuation_rows[0][1])
        assert observed_ids == []
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_launch_consumptions WHERE continuation_id=?",
            (continuation_id,),
        ).fetchone() == (0,)
        admission = CandidateDispatchAdmissionRepository(store).readback(admission_id)
        assert admission.execution_id is None


class _ExpiryClock(datetime):
    expiry: datetime | None = None

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> datetime:
        value = cls.expiry
        if value is None:
            return datetime.now(tz)
        return value.replace(tzinfo=None) if tz is None else value.astimezone(tz)


def test_worker_never_reaches_runner_after_consumed_permit_expires(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_fixtures.NOW = utc_now()
    _ExpiryClock.expiry = None
    with SQLiteStore(tmp_path / "expired-after-consume.db") as store:
        ranker = event_loop.MeasurementFirstRanker()
        app = event_loop._app_with_registered_host_probes(store, ranker)  # pyright: ignore[reportPrivateUsage]
        state, event, target = event_loop._started_with_event(  # pyright: ignore[reportPrivateUsage]
            app, store, count=1, budget_ms=30_000
        )
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        event_loop._omit_until_selected(  # pyright: ignore[reportPrivateUsage]
            app, str(state.case_id), target, monkeypatch
        )

        consumed_deadlines: list[datetime] = []
        original_consume = CandidateDispatchAdmissionRepository.consume_launch_continuation

        def consume_then_expire(
            repository: CandidateDispatchAdmissionRepository,
            continuation_id: str,
            *,
            case_id: CaseId,
            task_id: str,
            invocation_sha256: str,
        ) -> CandidateLaunchContinuation:
            continuation = original_consume(
                repository,
                continuation_id,
                case_id=case_id,
                task_id=task_id,
                invocation_sha256=invocation_sha256,
            )
            consumed_deadlines.append(continuation.deadline_at)
            _ExpiryClock.expiry = continuation.deadline_at + timedelta(milliseconds=1)
            monkeypatch.setattr(runtime_module, "datetime", _ExpiryClock)
            return continuation

        monkeypatch.setattr(
            CandidateDispatchAdmissionRepository,
            "consume_launch_continuation",
            consume_then_expire,
        )
        runner_calls: list[str] = []

        def forbidden_runner(
            probe_id: str,
            _parameters: dict[str, object],
            **_kwargs: object,
        ) -> ProbeRun:
            runner_calls.append(probe_id)
            now = datetime.now(UTC)
            return ProbeRun(
                execution_id=ExecutionId.new(),
                probe_id=probe_id,
                status=ProbeRunStatus.UNAVAILABLE,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                error="test spy: no host access",
            )

        monkeypatch.setattr(app.runtime._probe_runner, "run", forbidden_runner)  # pyright: ignore[reportPrivateUsage]
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state,
            app.context(str(state.case_id), state=state),
            state.state_version,
        )

        assert handled
        assert len(consumed_deadlines) == 1
        assert runner_calls == [], "expired one-shot permit reached the host probe runner"
        frontier = SearchFrontierRepository(store)
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert outcome is not None and outcome.outcome == "measurement_admitted"
        admission_row = store.connection.execute(
            "SELECT admission_id FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert admission_row is not None
        dispatch = CandidateDispatchAdmissionRepository(store).readback(str(admission_row[0]))
        assert dispatch.outcome_status == "claimed_unlinked"
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_launch_consumptions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (1,)
        assert dispatch.execution_id is None
        assert outcome.frontier_item_ids
        assert frontier.readback(outcome.frontier_item_ids[0]).status is FrontierStatus.INTERRUPTED
        assert any(
            "measurement" in warning.lower() or "worker" in warning.lower()
            for warning in updated.warnings
        )
