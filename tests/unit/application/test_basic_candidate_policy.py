"""Synthetic registered menus verify deterministic choice, not diagnostic utility."""

from datetime import UTC, datetime, timedelta

import pytest

from systemsense.application.basic_candidate_policy import (
    select_basic_loopback_candidate,
    select_basic_process_candidate,
)
from systemsense.domain.affected_task import TaskObservationContextV1
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import SafetyClass
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.case_candidates import CandidateRecord

LISTENER = "network.listeners"
OWNER = "network.listener_owner_pressure"
REPLAY = "network.loopback_replay"
PROCESS = "application.target_pressure"


@pytest.fixture
def task() -> TaskObservationContextV1:
    now = datetime(2026, 9, 29, tzinfo=UTC)
    return TaskObservationContextV1(
        case_id=CaseId.new(),
        evidence_id=EvidenceId.new(),
        source_id="src_" + "a" * 64,
        collector_id="task.loopback_http",
        collector_version=1,
        execution_id=ExecutionId.new(),
        record_sha256="a" * 64,
        target_handle="127.0.0.1:59152",
        action="GET /health/" + "a" * 32,
        expected="HTTP 200 with matching nonce",
        observed="timeout",
        window_start=now,
        window_end=now + timedelta(seconds=1),
        sample_window_ms=1000,
        observed_at=now + timedelta(seconds=1),
        captured_at=now + timedelta(seconds=1),
        limitation="Synthetic policy fixture",
        scope="test_owned_loopback",
        reported_task_relation="exact_action_replayed",
    )


def _candidate(probe: str, index: int, cost: int) -> CandidateRecord:
    return CandidateRecord(
        candidate_id="cand_v1_" + str(index) * 32,
        probe_id=probe,
        description="Registered test choice",
        manifest_sha256="a" * 64,
        invocation_sha256="b" * 64,
        cost_ms=cost,
        resource_class=ResourceClass.CPU,
        safety_class=SafetyClass.R1,
    )


MENU = (_candidate(LISTENER, 1, 1500), _candidate(OWNER, 2, 10000), _candidate(REPLAY, 3, 3000))


@pytest.mark.parametrize("observed", ["timeout", "connection_refused", "request_error"])
def test_transport_failures_start_with_listener(
    task: TaskObservationContextV1, observed: str
) -> None:
    choice = select_basic_loopback_candidate(
        task.model_copy(update={"observed": observed}),
        MENU,
        frozenset(),
        verified_owner_available=False,
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.candidate_id == MENU[0].candidate_id
    assert choice.probe_id == LISTENER
    assert choice.reason_code == "listener_state"


def test_timeout_owner_is_source_bound_and_budgeted(task: TaskObservationContextV1) -> None:
    choice = select_basic_loopback_candidate(
        task,
        MENU,
        frozenset({LISTENER}),
        verified_owner_available=True,
        remaining_ms=90_000,
        remaining_probe_calls=5,
    )
    assert choice.candidate_id == MENU[1].candidate_id
    assert choice.probe_id == OWNER
    assert "handler" in choice.reason


@pytest.mark.parametrize("observed", ["http_503", "http_other_status", "wrong_response"])
def test_response_failures_choose_recurrence_without_unrelated_listener(
    task: TaskObservationContextV1, observed: str
) -> None:
    choice = select_basic_loopback_candidate(
        task.model_copy(update={"observed": observed}),
        MENU,
        frozenset(),
        verified_owner_available=True,
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.probe_id == REPLAY


@pytest.mark.parametrize("owner,budget", [(False, 90000), (True, 3000)])
def test_replay_remains_useful_without_owner_or_owner_budget(
    task: TaskObservationContextV1, owner: bool, budget: int
) -> None:
    choice = select_basic_loopback_candidate(
        task,
        MENU,
        frozenset({LISTENER}),
        verified_owner_available=owner,
        remaining_ms=budget,
        remaining_probe_calls=1,
    )
    assert choice.probe_id == REPLAY
    assert choice.reason_code == "recurrence"


@pytest.mark.parametrize(
    "initial,later",
    [("http_200_nonce_match", "http_200_nonce_match"), ("timeout", "http_200_nonce_match")],
)
def test_verified_later_success_stops_without_cause_claim(
    task: TaskObservationContextV1, initial: str, later: str | None
) -> None:
    choice = select_basic_loopback_candidate(
        task.model_copy(update={"observed": initial}),
        MENU,
        frozenset(),
        verified_owner_available=True,
        verified_later_outcome=later,
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.candidate_id is None
    assert choice.reason_code == "observed_success"
    assert "earlier cause remains unverified" in choice.reason


def test_initial_success_allows_only_one_budgeted_recurrence(
    task: TaskObservationContextV1,
) -> None:
    for attempted, budget, slots, expected in [
        (frozenset[str](), 3000, 1, REPLAY),
        (frozenset({REPLAY}), 3000, 1, None),
        (frozenset[str](), 2999, 1, None),
        (frozenset[str](), 3000, 0, None),
    ]:
        choice = select_basic_loopback_candidate(
            task.model_copy(update={"observed": "http_200_nonce_match"}),
            MENU,
            attempted,
            verified_owner_available=False,
            remaining_ms=budget,
            remaining_probe_calls=slots,
        )
        assert choice.probe_id == expected


def test_attempted_replay_does_not_hide_still_useful_owner_check(
    task: TaskObservationContextV1,
) -> None:
    choice = select_basic_loopback_candidate(
        task,
        MENU,
        frozenset({LISTENER, REPLAY}),
        verified_owner_available=True,
        verified_later_outcome="timeout",
        remaining_ms=90_000,
        remaining_probe_calls=1,
    )
    assert choice.probe_id == OWNER


def test_no_repeated_or_unrelated_work_when_useful_candidates_are_spent(
    task: TaskObservationContextV1,
) -> None:
    choice = select_basic_loopback_candidate(
        task,
        (*MENU, _candidate("storage.snapshot", 4, 10)),
        frozenset({LISTENER, OWNER, REPLAY}),
        verified_owner_available=True,
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.candidate_id is None
    assert choice.reason_code == "no_useful_candidate"


def test_missing_listener_can_fall_back_only_to_registered_exact_replay(
    task: TaskObservationContextV1,
) -> None:
    choice = select_basic_loopback_candidate(
        task,
        (MENU[2],),
        frozenset(),
        verified_owner_available=False,
        remaining_ms=3000,
        remaining_probe_calls=1,
    )
    assert choice.candidate_id == MENU[2].candidate_id


def test_ambiguous_owner_does_not_silently_select_a_target(task: TaskObservationContextV1) -> None:
    choice = select_basic_loopback_candidate(
        task,
        (*MENU, _candidate(OWNER, 4, 10000)),
        frozenset({LISTENER}),
        verified_owner_available=True,
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.candidate_id is None
    assert choice.reason_code == "ambiguous_candidate"


@pytest.mark.parametrize("remaining_ms,slots", [(2999, 1), (90000, 0), (-1, 6)])
def test_original_budget_is_never_expanded(
    task: TaskObservationContextV1, remaining_ms: int, slots: int
) -> None:
    choice = select_basic_loopback_candidate(
        task,
        MENU,
        frozenset({LISTENER}),
        verified_owner_available=False,
        remaining_ms=remaining_ms,
        remaining_probe_calls=slots,
    )
    assert choice.candidate_id is None
    assert choice.reason_code == "budget_exhausted"


def test_unbound_task_does_not_gain_authority(task: TaskObservationContextV1) -> None:
    choice = select_basic_loopback_candidate(
        task.model_copy(update={"reported_task_relation": "unbound"}),
        MENU,
        frozenset(),
        verified_owner_available=True,
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.candidate_id is None
    assert choice.reason_code == "unbound_task"


@pytest.mark.parametrize(
    "question,bound,decisive,expected",
    [
        ("presence", True, False, None),
        ("cpu", False, False, None),
        ("cpu", True, True, None),
        ("cpu", True, False, PROCESS),
    ],
)
def test_process_policy_only_samples_unresolved_source_bound_cpu_question(
    question: str, bound: bool, decisive: bool, expected: str | None
) -> None:
    choice = select_basic_process_candidate(
        (_candidate(PROCESS, 4, 4000),),
        frozenset(),
        question=question,
        verified_target_bound=bound,
        decisive=decisive,
        remaining_ms=4000,
        remaining_probe_calls=1,
    )
    assert choice.probe_id == expected


def test_process_target_ambiguity_and_exhausted_attempts_are_gaps() -> None:
    candidate = _candidate(PROCESS, 4, 4000)
    for menu, attempts, reason in (
        ((candidate, _candidate(PROCESS, 5, 4000)), frozenset[str](), "ambiguous_candidate"),
        ((candidate,), frozenset({PROCESS}), "no_useful_candidate"),
        ((), frozenset[str](), "candidate_unavailable"),
    ):
        choice = select_basic_process_candidate(
            menu,
            attempts,
            question="cpu",
            verified_target_bound=True,
            decisive=False,
            remaining_ms=90000,
            remaining_probe_calls=6,
        )
        assert choice.candidate_id is None
        assert choice.reason_code == reason


def test_unsafe_candidate_is_rejected_without_fallback(task: TaskObservationContextV1) -> None:
    unsafe = MENU[0].model_copy(update={"safety_class": SafetyClass.R2})
    choice = select_basic_loopback_candidate(
        task,
        (unsafe, *MENU[1:]),
        frozenset(),
        verified_owner_available=False,
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.candidate_id is None
    assert choice.reason_code == "scope_denied"


def test_later_failure_does_not_become_success_from_initial_control(
    task: TaskObservationContextV1,
) -> None:
    choice = select_basic_loopback_candidate(
        task.model_copy(update={"observed": "http_200_nonce_match"}),
        MENU,
        frozenset({REPLAY}),
        verified_owner_available=False,
        verified_later_outcome="timeout",
        remaining_ms=90_000,
        remaining_probe_calls=6,
    )
    assert choice.probe_id == LISTENER
