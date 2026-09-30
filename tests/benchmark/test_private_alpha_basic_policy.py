"""Synthetic menu mechanics, never a measured Basic/model outcome comparison."""

from datetime import UTC, datetime, timedelta

import pytest

from benchmarks.private_alpha_basic_policy import select_loopback_baseline
from systemsense.domain.affected_task import TaskObservationContextV1
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import SafetyClass
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.case_candidates import CandidateRecord


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
        limitation="Synthetic menu fixture",
        scope="test_owned_loopback",
        reported_task_relation="exact_action_replayed",
    )


def _menu() -> tuple[CandidateRecord, ...]:
    return tuple(
        CandidateRecord(
            candidate_id="cand_v1_" + str(index) * 32,
            probe_id=probe,
            description="Synthetic source-bound choice",
            manifest_sha256="a" * 64,
            invocation_sha256="b" * 64,
            cost_ms=cost,
            resource_class=ResourceClass.NETWORK,
            safety_class=SafetyClass.R1,
        )
        for index, probe, cost in (
            (1, "network.listeners", 1500),
            (2, "network.listener_owner_pressure", 10000),
            (3, "network.loopback_replay", 3000),
        )
    )


@pytest.mark.parametrize(
    "attempted,owner,selected",
    [
        (frozenset[str](), False, 1),
        (frozenset({"network.listeners"}), True, 2),
        (frozenset({"network.listeners"}), False, 3),
    ],
)
def test_same_menu_fixed_sequence(
    task: TaskObservationContextV1, attempted: frozenset[str], owner: bool, selected: int
) -> None:
    result = select_loopback_baseline(
        task,
        _menu(),
        attempted,
        verified_owner_available=owner,
        remaining_ms=90000,
        remaining_probe_calls=6,
    )
    assert result.candidate_id == "cand_v1_" + str(selected) * 32


@pytest.mark.parametrize("probe", ["network.loopback_replay", "network.listener_owner_pressure"])
def test_failed_discriminator_is_not_retried(task: TaskObservationContextV1, probe: str) -> None:
    result = select_loopback_baseline(
        task,
        _menu(),
        frozenset({"network.listeners", probe}),
        verified_owner_available=True,
        remaining_ms=90000,
        remaining_probe_calls=6,
    )
    assert result.candidate_id is None
    assert "already attempted" in result.reason


@pytest.mark.parametrize("milliseconds,calls", [(9999, 6), (90000, 0)])
def test_original_budget_cannot_be_expanded(
    task: TaskObservationContextV1, milliseconds: int, calls: int
) -> None:
    result = select_loopback_baseline(
        task,
        _menu(),
        frozenset({"network.listeners"}),
        verified_owner_available=True,
        remaining_ms=milliseconds,
        remaining_probe_calls=calls,
    )
    assert result.candidate_id is None
    assert "budget" in result.reason


def test_missing_or_ambiguous_source_bound_choice_is_a_gap(task: TaskObservationContextV1) -> None:
    for menu in ((), (*_menu(), _menu()[0])):
        result = select_loopback_baseline(
            task,
            menu,
            frozenset(),
            verified_owner_available=False,
            remaining_ms=90000,
            remaining_probe_calls=6,
        )
        assert result.candidate_id is None
        assert "absent or ambiguous" in result.reason


def test_successful_task_needs_no_extra_probe(task: TaskObservationContextV1) -> None:
    result = select_loopback_baseline(
        task.model_copy(update={"observed": "http_200_nonce_match"}),
        _menu(),
        frozenset(),
        verified_owner_available=False,
        remaining_ms=90000,
        remaining_probe_calls=6,
    )
    assert result.candidate_id is None


def test_unbound_task_never_authorizes_a_candidate(task: TaskObservationContextV1) -> None:
    result = select_loopback_baseline(
        task.model_copy(update={"reported_task_relation": "unbound"}),
        _menu(),
        frozenset(),
        verified_owner_available=False,
        remaining_ms=90000,
        remaining_probe_calls=6,
    )
    assert result.candidate_id is None
    assert "verified exact" in result.reason
