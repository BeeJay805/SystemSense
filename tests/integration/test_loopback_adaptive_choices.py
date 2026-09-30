"""Real observed task custody admits competing recurrence and listener checks."""

# pyright: reportPrivateUsage=false

from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.candidate_catalog import general_measurement_candidate_catalog
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.loopback_task_observation import (
    TestOwnedLoopbackTaskV1,
    observe_test_owned_loopback_task,
)
from systemsense.application.task_observation import resolve_task_observation
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_loopback_owner_review_closure import _persist_listener


@pytest.mark.parametrize("initial_success", [False, True])
def test_exact_task_offers_distinct_useful_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, initial_success: bool
) -> None:
    class Response:
        status = 200

        def read(self, _limit: int) -> bytes:
            return ("b" * 32 + "\n").encode("ascii")

    class ControlledConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            if not initial_success:
                raise ConnectionRefusedError()

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "systemsense.application.loopback_task_observation.http.client.HTTPConnection",
        ControlledConnection,
    )
    with SQLiteStore(tmp_path / "case.db") as store:
        state = default_investigator(store).create(objective="Check this exact local health task")
        observe_test_owned_loopback_task(
            store,
            case_id=state.case_id,
            scope=TestOwnedLoopbackTaskV1(port=59152, nonce="b" * 32),
        )
        registry, needs = general_measurement_candidate_catalog(
            store, default_probe_runner(), state.case_id
        )
        assert {need.capability_id for need in needs} == {
            "network.listeners",
            "network.loopback_replay",
        }
        replay = next(need for need in needs if need.capability_id == "network.loopback_replay")
        repository = InvestigationRepository(store)
        bound = repository.load(str(state.case_id))
        running = repository.save(
            bound.model_copy(update={"status": InvestigationStatus.RUNNING}),
            expected_version=bound.state_version,
            event="started",
            detail="Testing source-bound competing checks.",
        )
        candidate = registry.issue(state.case_id, running.state_version, replay)
        assert not isinstance(candidate, CandidateGap)
        resolved = registry.resolve(state.case_id, running.state_version, candidate.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        assert resolved.invocation.parameters == {"port": 59152, "nonce": "b" * 32}


def test_healthy_first_listener_does_not_close_before_model_can_consider_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Response:
        status = 200

        def read(self, _limit: int) -> bytes:
            return ("b" * 32 + "\n").encode("ascii")

    class ControlledConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            pass

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "systemsense.application.loopback_task_observation.http.client.HTTPConnection",
        ControlledConnection,
    )
    with SQLiteStore(tmp_path / "case.db") as store:
        investigator = default_investigator(store)
        case = investigator.create(objective="Check this exact local health task")
        observe_test_owned_loopback_task(
            store,
            case_id=case.case_id,
            scope=TestOwnedLoopbackTaskV1(port=59152, nonce="b" * 32),
        )
        repository = InvestigationRepository(store)
        bound = repository.load(str(case.case_id))
        assert bound.task_observation_reference is not None
        task = resolve_task_observation(
            store, case_id=case.case_id, reference=bound.task_observation_reference
        )
        listener = _persist_listener(store, task, task.window_end)
        running = repository.save(
            bound.model_copy(
                update={
                    "status": InvestigationStatus.RUNNING,
                    "completed_probe_ids": ("network.listeners",),
                }
            ),
            expected_version=bound.state_version,
            event="started",
            detail="Listener returned before the model reconsidered exact replay.",
        )
        # This unit uses the real catalog and custody records. The ranker
        # marker only enables the model-route scheduling branch; no model is called.
        investigator.frontier_ranker = object()  # type: ignore[assignment]
        assert investigator._initial_success_replay_opportunity_pending(
            running, task, listener.captured_at
        )
        assert investigator._loopback_check_precedes_deep_review(running)

        # A terminal exact replay means this opportunity was spent. Closure
        # then depends on the separate applied-Sol evidence review.
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id="terminal-replay-fixture",
                case_id=str(case.case_id),
                probe_id="network.loopback_replay",
                probe_version=1,
                status="failed",
                parameters_json="{}",
                started_at=listener.captured_at.isoformat(),
                finished_at=listener.captured_at.isoformat(),
                state_version=running.state_version,
            )
        assert not investigator._initial_success_replay_opportunity_pending(
            running, task, listener.captured_at
        )
