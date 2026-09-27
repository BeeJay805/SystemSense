"""A fixed advisory provider cannot see evaluator recipes or assert a winner."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from benchmarks.fixed_rival_provider import FixedRivalReasoningProvider
from benchmarks.sequential_hypothesis_episodes import run_hypothesis_suite, verify_hypothesis_suite
from systemsense.decision.contracts import ProbeCapability
from systemsense.domain.ids import CaseId
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import HypothesisStatus, ReasoningRequest, ReasoningStatus


def _request(probe_ids: tuple[str, ...]) -> ReasoningRequest:
    return ReasoningRequest(
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="fixed_rival_test",
        deadline_at=datetime.now(UTC) + timedelta(minutes=1),
        objective="Browser cannot reliably open the requested site",
        available_probes=tuple(
            ProbeCapability(
                probe_id=probe_id,
                description=f"Read {probe_id}",
                cost_ms=25,
                resource_class=ResourceClass.CPU,
            )
            for probe_id in probe_ids
        ),
        budget_ms=30_000,
        max_probes=5,
    )


def test_fixed_provider_emits_only_unresolved_registered_rivals() -> None:
    ids = (
        "core.system",
        "browser.route_attempt",
        "browser.proxy_settings",
        "browser.direct_control",
        "browser.external_control",
    )
    provider = FixedRivalReasoningProvider()
    response = provider.investigate(_request(ids))
    assert response.status is ReasoningStatus.UNRESOLVED
    assert len(response.hypotheses) == 2
    assert all(item.status is HypothesisStatus.UNRESOLVED for item in response.hypotheses)
    assert all(set(item.distinguishing_probe_ids).issubset(ids) for item in response.hypotheses)
    assert response.distinguishing_probes == ()
    assert response.hypotheses == provider.investigate(_request(ids)).hypotheses


def test_fixed_provider_does_not_invent_missing_probe() -> None:
    response = FixedRivalReasoningProvider().investigate(_request(("core.system",)))
    assert response.status is ReasoningStatus.INSUFFICIENT_OBSERVABILITY
    assert response.hypotheses == ()


def test_application_menu_gets_two_unresolved_alternatives() -> None:
    ids = (
        "core.system",
        "application.task_timing",
        "application.storage_latency",
        "application.renderer_mode",
        "application.external_control",
    )
    response = FixedRivalReasoningProvider().investigate(_request(ids))
    assert len(response.hypotheses) == 2
    assert all(item.status is HypothesisStatus.UNRESOLVED for item in response.hypotheses)
    assert all(set(item.distinguishing_probe_ids).issubset(ids) for item in response.hypotheses)


def test_one_case_replay_is_hashed_and_hypothesis_bearing(tmp_path: Path) -> None:
    output = tmp_path / "hypothesis-replay"
    report = run_hypothesis_suite(output, case_ids=("toy-network-002",))
    assert report["runs"][0]["runtime_complete"] is True
    assert len(report["runs"][0]["hypotheses"]) == 2
    assert verify_hypothesis_suite(output)["integrity_verified"] is True
