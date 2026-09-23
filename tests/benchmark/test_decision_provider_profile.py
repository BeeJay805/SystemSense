from __future__ import annotations

import json
import socket
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime, timedelta

import pytest

from benchmarks.decision_provider_profile import (
    catalog_sha256,
    demo_keyword_profile,
    main,
    profile_decision_provider,
    request_sha256,
    synthetic_broad_request,
)
from systemsense.application import bootstrap
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProbeCapability
from systemsense.domain.ids import CaseId
from systemsense.orchestration.scheduler import ResourceClass


def _request(*, probe_id: str = "network.snapshot") -> DecisionRequest:
    return DecisionRequest(
        case_id=CaseId(root="case_" + "1" * 32),
        state_version=2,
        correlation_id="profile_1",
        deadline_at=datetime.now(UTC) + timedelta(minutes=5),
        symptom="Wi-Fi is unavailable",
        target_traits=frozenset({"wifi", "laptop"}),
        available_probes=(
            ProbeCapability(
                probe_id=probe_id,
                description="Read bounded network state",
                keywords=frozenset({"wifi", "network"}),
                cost_ms=10,
                resource_class=ResourceClass.NETWORK,
            ),
        ),
        budget_ms=100,
        max_probes=1,
    )


def test_profile_pins_each_request_and_catalog_and_separates_cold_from_warm() -> None:
    first = _request()
    second = _request(probe_id="network.adapters")
    report = profile_decision_provider(
        KeywordBaselineDecisionProvider(), (first, second), warm_repeats=2
    )

    assert report.schema_version == 1
    assert report.measurement_scope == "provider_component_only"
    assert report.request_hashes == (request_sha256(first), request_sha256(second))
    assert report.catalog_hashes == (catalog_sha256(first), catalog_sha256(second))
    assert [(call.phase, call.request_index) for call in report.calls] == [
        ("cold", 0),
        ("warm", 0),
        ("warm", 1),
        ("warm", 0),
        ("warm", 1),
    ]
    assert report.cold.attempts == 1
    assert report.warm.attempts == 4
    assert report.cold.valid_responses == 1
    assert report.warm.valid_responses == 4
    assert all(call.status == "valid" for call in report.calls)
    assert all(call.wall_ms >= 0 for call in report.calls)
    assert all(call.process_rss_before_bytes > 0 for call in report.calls)
    assert all(call.process_rss_after_bytes > 0 for call in report.calls)
    assert report.warm.wall_p50_ms is not None
    assert report.warm.wall_p95_ms is not None
    assert report.warm.wall_p95_ms >= report.warm.wall_p50_ms >= 0


def test_catalog_hash_is_independent_of_set_insertion_order_and_changes_with_catalog() -> None:
    request = _request()
    same = request.model_copy(update={"target_traits": frozenset({"laptop", "wifi"})})
    different = _request(probe_id="network.adapters")
    assert request_sha256(request) == request_sha256(same)
    assert catalog_sha256(request) == catalog_sha256(same)
    assert catalog_sha256(request) != catalog_sha256(different)


class _ScriptedProvider(KeywordBaselineDecisionProvider):
    def __init__(self) -> None:
        self.calls = 0

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        self.calls += 1
        if self.calls == 1:
            return super().decide(request).model_copy(update={"correlation_id": "wrong"})
        if self.calls == 2:
            raise TimeoutError("scripted timeout")
        return super().decide(request)


def test_invalid_response_and_timeout_remain_in_sample_denominator() -> None:
    provider = _ScriptedProvider()
    report = profile_decision_provider(provider, (_request(),), warm_repeats=2)
    assert provider.calls == 3
    assert [call.status for call in report.calls] == ["invalid_response", "timeout", "valid"]
    assert report.cold.attempts == 1
    assert report.cold.valid_responses == 0
    assert report.warm.attempts == 2
    assert report.warm.valid_responses == 1
    assert report.warm.timeouts == 1
    assert report.warm.wall_p50_ms is not None
    assert report.warm.wall_p95_ms is not None


def test_malformed_response_object_is_recorded_without_aborting_profile() -> None:
    class MalformedProvider(KeywordBaselineDecisionProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return super().decide(request).model_copy(update={"provider": None})

    report = profile_decision_provider(MalformedProvider(), (_request(),), warm_repeats=1)
    assert [call.status for call in report.calls] == ["invalid_response", "invalid_response"]
    assert report.cold.attempts == 1
    assert report.warm.attempts == 1


def test_soft_timeout_marks_slow_result_but_does_not_discard_timing() -> None:
    from time import sleep

    class SlowProvider(KeywordBaselineDecisionProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            sleep(0.005)
            return super().decide(request)

    report = profile_decision_provider(
        SlowProvider(), (_request(),), warm_repeats=0, soft_timeout_ms=1
    )
    assert report.cold.attempts == 1
    assert report.cold.timeouts == 1
    assert report.calls[0].status == "timeout"
    assert report.calls[0].wall_ms >= 1


def test_demo_uses_keyword_only_and_disclaims_diagnostic_quality() -> None:
    report = demo_keyword_profile(warm_repeats=1)
    assert report.provider.provider_id == "keyword-baseline"
    assert report.workload_kind == "synthetic_contract_smoke"
    assert report.diagnostic_quality_measured is False
    assert report.warm.attempts == 1


def test_synthetic_broad_fixture_is_stable_bounded_and_uses_registered_catalog() -> None:
    request = synthetic_broad_request()
    again = synthetic_broad_request()
    assert len(request.evidence_context) == 54
    assert len(request.evidence_ids) == 54
    assert len(set(request.evidence_ids)) == 54
    assert request.available_probes == bootstrap.default_capabilities()
    assert len(request.available_probes) == 17
    assert request_sha256(request) == request_sha256(again)
    assert catalog_sha256(request) == catalog_sha256(again)
    assert all(context.redaction_applied for context in request.evidence_context)
    assert all(
        "Synthetic bounded preview" in context.summary for context in request.evidence_context
    )
    assert all(len(context.facts) <= 2 for context in request.evidence_context)


@pytest.mark.parametrize("provider_name", ["keyword", "typed-feature"])
def test_synthetic_broad_cli_profiles_pure_provider_without_external_actions(
    provider_name: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external operation launched")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(bootstrap, "default_probe_runner", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "decision_provider_profile",
            "--synthetic-broad",
            "--provider",
            provider_name,
            "--warm-repeats",
            "1",
        ],
    )
    main()
    report = json.loads(capsys.readouterr().out)
    assert report["workload_kind"] == "synthetic_broad_contract_smoke"
    assert report["measurement_scope"] == "provider_component_only"
    assert report["diagnostic_quality_measured"] is False
    assert report["provider"]["provider_id"] == (
        "keyword-baseline" if provider_name == "keyword" else "typed-feature-challenger"
    )
    assert report["cold"]["valid_responses"] == 1
    assert report["warm"]["valid_responses"] == 1
    assert report["request_hashes"] == [request_sha256(synthetic_broad_request())]
    assert report["request_hashes"] != list(demo_keyword_profile(warm_repeats=0).request_hashes)
