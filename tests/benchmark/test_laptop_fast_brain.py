"""Contract tests for opt-in, same-request laptop fast-brain profiling."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    ProviderIdentity,
)


def _requests() -> tuple[DecisionRequest, ...]:
    from benchmarks.decision_provider_profile import synthetic_broad_request

    base = synthetic_broad_request()
    return tuple(
        base.model_copy(
            update={
                "correlation_id": f"laptop_fixture_{index}",
                "symptom": symptom,
            }
        )
        for index, symptom in enumerate(("Wi-Fi disconnects", "PDF turns slowly", "Game stutters"))
    )


class _CompleteProvider:
    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="fake-complete", provider_version="1", role="fast_decision"
        )

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        pages = request.attention_context or request.evidence_context
        return DecisionResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            ranked_attention_page_ids=tuple(
                f"{page.evidence_id}:{index}" for index, page in enumerate(pages)
            ),
            considered_evidence_count=len({str(page.evidence_id) for page in pages}),
        )


def test_same_hashed_requests_cold_construction_and_distinct_warm_calls() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    constructions: list[str] = []

    def factory() -> ProviderSession:
        constructions.append("constructed")
        return ProviderSession(_CompleteProvider())

    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan("first", factory, attention_required=True),
            ProviderPlan("second", factory, attention_required=True),
        ),
        deadline_ms=5_000,
        redaction_attested=True,
    )
    assert constructions == ["constructed", "constructed"]
    assert [sample["phase"] for sample in report["providers"]["first"]["samples"]] == [
        "cold",
        "warm",
        "warm",
    ]
    assert (
        report["providers"]["first"]["request_hashes"]
        == report["providers"]["second"]["request_hashes"]
    )
    assert len(set(report["providers"]["first"]["request_hashes"])) == 3
    assert report["providers"]["first"]["summary"]["complete"] == 3
    for sample in report["providers"]["first"]["samples"]:
        baseline = sample["baseline_owned_process_tree_rss_bytes"]
        peak = sample["peak_owned_process_tree_rss_bytes"]
        cpu_seconds = sample["owned_process_tree_cpu_seconds"]
        assert baseline is not None and peak is not None and peak >= baseline
        assert cpu_seconds is not None and cpu_seconds >= 0
    assert "Wi-Fi disconnects" not in str(report)


def test_deadline_coverage_and_construction_failures_remain_in_denominator() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    class _Incomplete(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return super().decide(request).model_copy(update={"ranked_attention_page_ids": ()})

    def unavailable() -> ProviderSession:
        raise RuntimeError("unavailable")

    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan(
                "coverage", lambda: ProviderSession(_Incomplete()), attention_required=True
            ),
            ProviderPlan("missing", unavailable, attention_required=True),
        ),
        deadline_ms=1,
        redaction_attested=True,
    )
    coverage = report["providers"]["coverage"]
    missing = report["providers"]["missing"]
    assert coverage["summary"]["planned"] == 3
    assert coverage["summary"]["complete"] == 0
    assert all(
        sample["status"] in {"coverage_failure", "deadline_miss"} for sample in coverage["samples"]
    )
    assert coverage["summary"]["coverage_failure"] == 3
    assert missing["summary"]["planned"] == 3
    assert [item["status"] for item in missing["samples"]] == [
        "construction_error",
        "not_run",
        "not_run",
    ]


def test_late_incomplete_response_counts_both_deadline_and_coverage() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    class _Incomplete(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return super().decide(request).model_copy(update={"ranked_attention_page_ids": ()})

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("late", lambda: ProviderSession(_Incomplete()), attention_required=True),),
        deadline_ms=0.001,
        redaction_attested=True,
    )
    result = report["providers"]["late"]
    assert result["summary"]["deadline_miss"] == 3
    assert result["summary"]["coverage_failure"] == 3
    assert all(
        sample["deadline_exceeded"] is True and sample["coverage_complete"] is False
        for sample in result["samples"]
    )


def test_none_response_is_invalid_not_unexplained_call_error() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    class _NoneProvider(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return None  # type: ignore[return-value]

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("none", lambda: ProviderSession(_NoneProvider())),),
        redaction_attested=True,
    )
    assert all(
        sample["status"] == "invalid_response" and sample["failure_type"] == "UnexpectedType"
        for sample in report["providers"]["none"]["samples"]
    )


def test_declared_laya_keyword_fallback_is_degraded_not_complete_or_invalid() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains
    from systemsense.decision.baseline import KeywordBaselineDecisionProvider

    baseline = KeywordBaselineDecisionProvider()

    class _Fallback(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return baseline.decide(request).model_copy(update={"degraded": True})

    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan(
                "laya-like",
                lambda: ProviderSession(_Fallback()),
                attention_required=True,
                fallback_identity=baseline.identity,
            ),
        ),
        deadline_ms=0.001,
        redaction_attested=True,
    )
    assert report["providers"]["laya-like"]["summary"]["degraded"] == 3
    assert report["providers"]["laya-like"]["summary"]["deadline_miss"] == 3
    assert report["providers"]["laya-like"]["summary"]["complete"] == 0


def test_refuses_unattested_or_repeated_warm_workload() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    plan = (ProviderPlan("fake", lambda: ProviderSession(_CompleteProvider())),)
    with pytest.raises(ValueError, match="redaction attestation"):
        compare_fast_brains(_requests(), plan, redaction_attested=False)
    with pytest.raises(ValueError, match="distinct"):
        compare_fast_brains((_requests()[0], _requests()[0]), plan, redaction_attested=True)


def test_laya_ram_refusal_does_not_construct_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from benchmarks import laptop_fast_brain
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    monkeypatch.setattr(
        laptop_fast_brain.psutil, "virtual_memory", lambda: type("Memory", (), {"available": 0})()
    )

    def forbidden() -> ProviderSession:
        raise AssertionError("provider should not be constructed")

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("laya", forbidden, attention_required=True, cpu_laya=True),),
        redaction_attested=True,
    )
    assert [sample["status"] for sample in report["providers"]["laya"]["samples"]] == [
        "admission_refused",
        "not_run",
        "not_run",
    ]


def test_laya_requires_explicit_untruncated_attention_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from benchmarks import laptop_fast_brain
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    monkeypatch.setattr(
        laptop_fast_brain.psutil,
        "virtual_memory",
        lambda: type("Memory", (), {"available": 16 * 1024**3})(),
    )
    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan(
                "laya-like",
                lambda: ProviderSession(_CompleteProvider()),
                attention_required=True,
                cpu_laya=True,
            ),
        ),
        redaction_attested=True,
    )
    assert report["providers"]["laya-like"]["summary"]["coverage_failure"] == 3


def test_fast_failures_have_no_successful_latency_summary() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    def unavailable() -> ProviderSession:
        raise RuntimeError("unavailable")

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("missing", unavailable),),
        redaction_attested=True,
    )
    summary = report["providers"]["missing"]["summary"]
    assert summary["complete"] == 0
    assert summary["complete_wall_p95_ms"] is None
    assert summary["wall_p95_ms"] is not None
    assert report["resource_scope"] == "whole_harness_process_tree_order_confounded"


def test_cli_defaults_to_deterministic_providers_without_loading_laya(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain
    from benchmarks.laptop_fast_brain import ProviderSession

    files: list[str] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        files.extend(("--request-json", str(path)))
    output = tmp_path / "profile.json"

    def forbidden_laya(_profile: Path) -> ProviderSession:
        pytest.fail("CPU Laya must be explicit")

    monkeypatch.setattr(
        laptop_fast_brain,
        "_laya_session",
        forbidden_laya,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["laptop_fast_brain", *files, "--redaction-attested", "--output", str(output)],
    )
    laptop_fast_brain.main()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert set(report["providers"]) == {"keyword", "typed-feature"}
    assert all(item["summary"]["planned"] == 3 for item in report["providers"].values())
    assert report["ordinary_laptop_qualified"] is False
