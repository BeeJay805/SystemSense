"""Real observed task custody admits competing recurrence and listener checks."""

from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.candidate_catalog import general_measurement_candidate_catalog
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.loopback_task_observation import (
    TestOwnedLoopbackTaskV1,
    observe_test_owned_loopback_task,
)
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


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
