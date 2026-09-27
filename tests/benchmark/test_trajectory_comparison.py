"""The comparison runner executes available arms and retains every planned cell."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from benchmarks import trajectory_comparison as comparison
from benchmarks.sequential_investigator_episodes import (
    _score_after_run,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.sequential_visible_matrix import _WORLDS  # pyright: ignore[reportPrivateUsage]
from benchmarks.trajectory_comparison import (
    ArmAdapter,
    compare_replays,
    freeze_sequential_comparison,
    run_comparison,
    verify_comparison,
)
from benchmarks.trajectory_protocol import Arm
from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import MixedFrontierRanker
from systemsense.inference.factory import load_advisory_providers
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.reasoning.ollama import OllamaReasoningProvider


def _deterministic() -> ArmAdapter:
    return ArmAdapter(
        provider_factory=lambda: load_advisory_providers(LocalInferenceConfig()),
        expected_mode="deterministic",
        scout_prefetch=False,
    )


def test_frozen_matrix_reserves_all_toy_cases_without_leaking_labels() -> None:
    protocol = freeze_sequential_comparison()
    assert len(protocol.cases) == 14
    assert {case.source for case in protocol.cases} == {"synthetic"}
    assert {case.split for case in protocol.cases} == {"development"}
    assert len({case.visible_input_sha256 for case in protocol.cases[:7]}) == 1
    assert len({case.ordered_tools_sha256 for case in protocol.cases[7:]}) == 1
    assert "wrong_browser_proxy" not in protocol.model_dump_json()
    assert "storage_saturation" not in protocol.model_dump_json()


def test_missing_arms_are_explicitly_unavailable_not_completed(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    protocol = freeze_sequential_comparison(("toy-network-002",))
    result = run_comparison(output, protocol=protocol, adapters={})
    assert len(result["attempts"]) == 4
    assert {item["status"] for item in result["attempts"]} == {"unavailable"}
    assert all(item["reason"] == "no_admitted_arm_adapter" for item in result["attempts"])
    assert result["score"]["complete_paired_cases"] == 0
    assert all(arm["unrun"] == 1 for arm in result["score"]["arms"].values())
    assert json.loads((output / "trajectories.json").read_text(encoding="utf-8")) == []


def test_deterministic_arm_runs_real_investigator_with_private_review(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    protocol = freeze_sequential_comparison(("toy-network-002", "toy-network-007"))
    result = run_comparison(
        output, protocol=protocol, adapters={Arm.DETERMINISTIC: _deterministic()}
    )
    attempts = result["attempts"]
    deterministic = [item for item in attempts if item["arm"] == Arm.DETERMINISTIC.value]
    assert len(attempts) == 8 and len(deterministic) == 2
    assert all(item["status"] == "completed" for item in deterministic)
    assert all(item["coverage"]["executions"] for item in deterministic)
    assert all(item["provider_identities"] for item in deterministic)
    assert all(item["raw_state_provider_calls"] for item in deterministic)
    assert all(
        item["advisory_call_count"] == len(item["provider_identities"]) for item in deterministic
    )
    assert all(
        item["provider_configuration"]["effective_mode"] == "deterministic"
        for item in deterministic
    )
    assert all(item["model_cost_usd"] == 0.0 for item in deterministic)
    assert all(item["host_impact_ms"] is None for item in deterministic)
    assert all(item["affected_task_bound"] is False for item in attempts)
    assert all(item["independent_task_outcome_verified"] is False for item in attempts)
    assert all(item["policy_realization"]["status"] == "demonstrated" for item in deterministic)
    assert all(
        item["policy_realization"]["status"] == "unavailable"
        for item in attempts
        if item["arm"] != Arm.DETERMINISTIC
    )
    assert result["policy_comparison"]["realized_paired_cases"] == 0
    assert result["policy_comparison"]["admissible_paired_cases"] == 0
    assert all(
        case["search_policy_fixture_suitable"] is False
        for case in result["policy_comparison"]["cases"].values()
    )
    assert result["affected_task_outcome"]["status"] == "unavailable"
    assert result["affected_task_outcome"]["bound_cases"] == 0
    assert result["affected_task_outcome"]["verified_cases"] == 0
    assert result["score"]["arms"][Arm.DETERMINISTIC.value]["completed"] == 2
    assert result["score"]["complete_paired_cases"] == 0
    assert result["by_family"]["toy_network_sequential"]["planned_cases"] == 2
    assert result["provider_pin_parity"]["toy-network-002"]["status"] == "unknown"
    assert result["first_request_parity"]["toy-network-002"]["status"] == "unknown"
    assert all(len(item["first_request_content_sha256"]) == 64 for item in deterministic)
    assert all(len(item["first_request_raw_sha256"]) == 64 for item in deterministic)
    assert all(0 < item["first_request_budget_ms"] <= item["budget_ms"] for item in deterministic)
    assert result["runtime_parity_admissible"] is False
    assert all(
        item["status"] == "unavailable" for item in attempts if item["arm"] != Arm.DETERMINISTIC
    )
    public = (output / "attempts.json").read_text(encoding="utf-8")
    private = (output / "evaluator-only" / "reviews.json").read_text(encoding="utf-8")
    assert "wrong_browser_proxy" not in public
    assert "wrong_browser_proxy" in private
    assert verify_comparison(output)["integrity_verified"] is True
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["toy_reviewer_sha256"]) == 64
    assert len(manifest["cause_scorer_sha256"]) == 64
    reviews = json.loads(private)
    assert reviews[0]["review"]["cause_equivalence"]["supported_answer_inferred"] is False


def test_verifier_rejects_tampered_attempts(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    run_comparison(output, protocol=freeze_sequential_comparison(("toy-network-001",)))
    report = output / "attempts.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        verify_comparison(output)


def test_exact_revision_pair_preserves_unknown_arms(tmp_path: Path) -> None:
    protocol = freeze_sequential_comparison(("toy-network-002",))
    left = tmp_path / "left"
    right = tmp_path / "right"
    run_comparison(left, protocol=protocol)
    run_comparison(right, protocol=protocol)
    result = compare_replays(left, right)
    rows = cast(list[dict[str, object]], result["rows"])
    assert len(rows) == 4
    deterministic = next(item for item in rows if item["arm"] == "deterministic")
    assert deterministic["statuses"] == ["completed", "completed"]
    assert deterministic["selection_set_equal"] is True
    assert deterministic["usefulness_equal"] is True
    assert deterministic["provider_events_equal"] is True
    assert deterministic["cause_labels_equal"] is True
    assert deterministic["cause_reduction_credit_equal"] is True
    unavailable = next(item for item in rows if item["arm"] == "deep_only")
    assert unavailable["statuses"] == ["unavailable", "unavailable"]
    assert unavailable["usefulness_equal"] is None
    assert unavailable["selection_set_equal"] is None
    assert unavailable["cause_reduction_credit_equal"] is None


def test_bad_provider_mode_is_failure_not_false_arm_result(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    protocol = freeze_sequential_comparison(("toy-application-002",))
    wrong = ArmAdapter(
        provider_factory=lambda: load_advisory_providers(LocalInferenceConfig()),
        expected_mode="deep-only",
        scout_prefetch=False,
    )
    result = run_comparison(output, protocol=protocol, adapters={Arm.DEEP_ONLY: wrong})
    deep = next(item for item in result["attempts"] if item["arm"] == Arm.DEEP_ONLY)
    assert deep["status"] == "failed"
    assert deep["reason"] == "provider_factory:ValueError"
    assert deep["answer"] == {"hypotheses": [], "assessment": None}
    assert result["score"]["arms"][Arm.DEEP_ONLY.value]["failed"] == 1


def test_deep_only_rejects_claimed_mode_without_a_deep_ranker() -> None:
    providers = load_advisory_providers(LocalInferenceConfig())
    providers.effective_mode = "deep-only"
    adapter = ArmAdapter(
        provider_factory=lambda: providers,
        expected_mode="deep-only",
        scout_prefetch=False,
    )

    with pytest.raises(ValueError, match="deep ranker"):
        comparison._validate_adapter(  # pyright: ignore[reportPrivateUsage]
            Arm.DEEP_ONLY, adapter, providers
        )


def test_deep_only_rejects_identity_spoof_without_actual_ranker() -> None:
    digest = "f" * 64
    config = LocalInferenceConfig(
        enabled=True, reasoning_model="test-local-model", reasoning_digest=digest
    )
    providers = load_advisory_providers(LocalInferenceConfig())
    providers.reasoning = OllamaReasoningProvider(config)
    providers.effective_mode = "deep-only"

    def fake_rank(_request: object) -> None:
        return None

    providers.frontier_ranker = cast(
        MixedFrontierRanker,
        SimpleNamespace(
            provider=ProviderIdentity(
                provider_id="local-deep-frontier", provider_version="1", role="fast_decision"
            ),
            model_digest=digest,
            rank=fake_rank,
        ),
    )
    adapter = ArmAdapter(
        provider_factory=lambda: providers,
        expected_mode="deep-only",
        scout_prefetch=False,
    )

    with pytest.raises(ValueError):
        comparison._validate_adapter(  # pyright: ignore[reportPrivateUsage]
            Arm.DEEP_ONLY, adapter, providers
        )


def test_frontier_ranker_state_call_is_counted_without_coordinator_event() -> None:
    run = {
        "provider_events": [
            {
                "role": "decision",
                "attempted_provider_id": "keyword-baseline",
                "effective_provider_id": "keyword-baseline",
                "failed": False,
            }
        ],
        "provider_calls": [
            {
                "role": "fast_decision",
                "provider_id": "keyword-baseline",
                "degraded": False,
                "detail": None,
            },
            {
                "role": "fast_decision",
                "provider_id": "local-deep-frontier",
                "degraded": False,
                "detail": "frontier_local_deep",
            },
        ],
    }
    calls = comparison._provider_calls(run)  # pyright: ignore[reportPrivateUsage]
    assert [call.attempted_provider_id for call in calls] == [
        "keyword-baseline",
        "local-deep-frontier",
    ]
    assert calls[1].role == "fast"
    assert calls[1].cost_usd is None


def test_same_provider_frontier_failure_is_not_hidden_by_decision_event() -> None:
    run = {
        "provider_events": [
            {
                "role": "decision",
                "attempted_provider_id": "laya-local-decision",
                "effective_provider_id": "laya-local-decision",
                "failed": False,
            }
        ],
        "provider_calls": [
            {
                "role": "fast_decision",
                "provider_id": "laya-local-decision",
                "degraded": True,
                "detail": "frontier_deadline_expired",
            },
            {
                "role": "fast_decision",
                "provider_id": "laya-local-decision",
                "degraded": False,
                "detail": "ready",
            },
        ],
    }
    calls = comparison._provider_calls(run)  # pyright: ignore[reportPrivateUsage]
    assert len(calls) == 2
    assert [call.failed for call in calls] == [False, True]


def test_deep_only_advisory_count_includes_decision_frontier_and_reasoning() -> None:
    run = {
        "provider_events": [
            {
                "role": role,
                "attempted_provider_id": provider_id,
                "effective_provider_id": provider_id,
                "failed": False,
            }
            for role, provider_id in (
                ("decision", "ollama-local-decision"),
                ("reasoning", "ollama-local-reasoning"),
            )
        ],
        "provider_calls": [
            {"role": role, "provider_id": provider_id, "degraded": False}
            for role, provider_id in (
                ("fast_decision", "ollama-local-decision"),
                ("catalog_attention", "local-deep-frontier"),
                ("reasoning", "ollama-local-reasoning"),
            )
        ],
    }
    calls = comparison._provider_calls(run)  # pyright: ignore[reportPrivateUsage]
    assert len(calls) == 3
    assert {call.attempted_provider_id for call in calls} == {
        "ollama-local-decision",
        "local-deep-frontier",
        "ollama-local-reasoning",
    }
    assert [call.role for call in calls].count("deep") == 1
    assert all(call.cost_usd is None for call in calls)


def test_realized_policy_gate_requires_durable_non_degraded_neural_roles() -> None:
    run: dict[str, Any] = {
        "provider_calls": [
            {"role": "fast_decision", "provider_id": "keyword-baseline", "degraded": False},
            {"role": "reasoning", "provider_id": "ollama-local-reasoning", "degraded": False},
        ],
        "frontier_offer_counts": {
            "source_offer_state_versions": [],
        },
    }
    deep = comparison._policy_realization(Arm.DEEP_ONLY, run, "completed")  # pyright: ignore[reportPrivateUsage]
    assert deep["status"] == "not_demonstrated"
    assert deep["missing_provider_ids"] == [
        "fast_decision:ollama-local-decision",
        "catalog_attention:local-deep-frontier",
    ]
    assert deep["frontier_offer_observed"] is False
    mixed = comparison._policy_realization(Arm.FAST_DEEP_SCOUT_OFF, run, "completed")  # pyright: ignore[reportPrivateUsage]
    assert mixed["status"] == "not_demonstrated"
    assert mixed["missing_provider_ids"] == [
        "fast_decision:laya-local-decision",
        "catalog_attention:laya-local-decision",
    ]
    run["provider_calls"] = [
        {"role": "fast_decision", "provider_id": "ollama-local-decision", "degraded": False},
        {
            "role": "catalog_attention",
            "provider_id": "local-deep-frontier",
            "detail": "event_frontier_retrieval",
            "degraded": False,
            "state_version": 3,
        },
        {"role": "reasoning", "provider_id": "ollama-local-reasoning", "degraded": False},
    ]
    run["frontier_offer_counts"] = {
        "source_offer_state_versions": [3],
    }
    assert (
        comparison._policy_realization(Arm.DEEP_ONLY, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "demonstrated"
    )
    run["frontier_offer_counts"] = {
        "source_offer_state_versions": [],
    }
    assert (
        comparison._policy_realization(Arm.DEEP_ONLY, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "not_demonstrated"
    )
    run["frontier_offer_counts"] = {
        "source_offer_state_versions": [3],
    }
    run["provider_calls"][1]["detail"] = "ordinary_catalog"
    assert (
        comparison._policy_realization(Arm.DEEP_ONLY, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "not_demonstrated"
    )
    run["provider_calls"][1]["detail"] = "frontier_laya"
    assert (
        comparison._policy_realization(Arm.DEEP_ONLY, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "demonstrated"
    )
    run["frontier_offer_counts"] = {"source_offer_state_versions": [4]}
    assert (
        comparison._policy_realization(Arm.DEEP_ONLY, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "not_demonstrated"
    )
    run["frontier_offer_counts"] = {"source_offer_state_versions": [3]}
    run["provider_calls"][1]["degraded"] = True
    assert (
        comparison._policy_realization(Arm.DEEP_ONLY, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "not_demonstrated"
    )
    run["provider_calls"] = [
        {"role": "fast_decision", "provider_id": "laya-local-decision", "degraded": False},
        {"role": "reasoning", "provider_id": "ollama-local-reasoning", "degraded": False},
    ]
    assert (
        comparison._policy_realization(Arm.FAST_DEEP_SCOUT_ON, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "not_demonstrated"
    )
    cast(list[dict[str, Any]], run["provider_calls"]).append(
        {
            "role": "catalog_attention",
            "provider_id": "laya-local-decision",
            "detail": "frontier_laya",
            "degraded": False,
            "state_version": 3,
        }
    )
    assert (
        comparison._policy_realization(Arm.FAST_DEEP_SCOUT_ON, run, "completed")["status"]  # pyright: ignore[reportPrivateUsage]
        == "demonstrated"
    )


def test_persisted_model_fallback_is_one_advisory_attempt(tmp_path: Path) -> None:
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse
    from systemsense.evaluation.recorder import EpisodeRecorder
    from systemsense.evaluation.tracking import TrackedDecisionProvider
    from systemsense.storage.investigations import InvestigationRepository
    from systemsense.storage.sqlite_store import SQLiteStore
    from tests.integration.test_runtime_trace import (
        _investigator,  # pyright: ignore[reportPrivateUsage]
        _spec,  # pyright: ignore[reportPrivateUsage]
    )

    class FailingDecision:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-failing-decision", provider_version="1", role="fast_decision"
            )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            raise RuntimeError("fixture unavailable")

    database = tmp_path / "fallback.db"
    with SQLiteStore(database) as store:
        investigator, _, reasoning = _investigator(store)
        decision = TrackedDecisionProvider(FailingDecision())
        investigator.decision = decision
        artifact = EpisodeRecorder().record(
            investigator=investigator, decision=decision, reasoning=reasoning, spec=_spec()
        )
    with SQLiteStore(database) as store:
        state = InvestigationRepository(store).load(str(artifact.case_id))
        events = [
            json.loads(str(row[0]))
            for row in store.connection.execute(
                "SELECT event_json FROM coordinator_events "
                "WHERE case_id=? AND kind='provider' ORDER BY sequence",
                (str(artifact.case_id),),
            )
        ]
    calls = comparison._provider_calls(  # pyright: ignore[reportPrivateUsage]
        {
            "provider_events": events,
            "provider_calls": [item.model_dump(mode="json") for item in state.provider_calls],
        }
    )
    fallback = [call for call in calls if call.role == "fast"]
    assert len(fallback) == 1
    assert fallback[0].attempted_provider_id == "fixture-failing-decision"
    assert fallback[0].effective_provider_id == "keyword-baseline"
    assert fallback[0].failed is True


def test_hidden_review_labels_stay_out_of_policy_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "private-oracle-label-never-policy-visible"
    original = comparison._score_after_run  # pyright: ignore[reportPrivateUsage]

    def private_review(run: dict[str, Any], world: Any) -> dict[str, Any]:
        review = original(run, world)
        review["private_oracle_sentinel"] = secret
        return review

    monkeypatch.setattr(comparison, "_score_after_run", private_review)
    output = tmp_path / "comparison"
    run_comparison(
        output,
        protocol=freeze_sequential_comparison(("toy-network-002",)),
        adapters={Arm.DETERMINISTIC: _deterministic()},
    )

    assert secret in (output / "evaluator-only" / "reviews.json").read_text(encoding="utf-8")
    for name in ("protocol.json", "attempts.json", "trajectories.json"):
        assert secret not in (output / name).read_text(encoding="utf-8")


def test_first_request_signature_keeps_semantics_and_actual_budget_separate() -> None:
    request: dict[str, Any] = {
        "schema_version": 2,
        "case_id": "case_" + "a" * 32,
        "correlation_id": "first",
        "deadline_at": "2026-09-27T08:00:00+00:00",
        "state_version": 4,
        "symptom": "page did not load",
        "budget_ms": 30000,
        "max_probes": 5,
        "available_probes": [{"probe_id": "browser.route_attempt", "description": "route"}],
        "evidence_ids": ["ev_" + "b" * 32],
        "evidence_context": [
            {
                "evidence_id": "ev_" + "b" * 32,
                "observed_at": "2026-09-27T07:00:00+00:00",
                "captured_at": "2026-09-27T07:00:01+00:00",
                "probe_id": "core.system",
                "summary": "observed baseline",
                "facts": {"status": "ok"},
                "status": "observed",
            }
        ],
        "attention_context": [],
        "completed_probe_ids": ["core.system"],
        "relationships": [],
    }
    original = comparison._first_request_signature(request)  # pyright: ignore[reportPrivateUsage]
    regenerated = deepcopy(request)
    regenerated["case_id"] = "case_" + "c" * 32
    regenerated["correlation_id"] = "second"
    regenerated["deadline_at"] = "2026-09-27T09:00:00+00:00"
    regenerated["evidence_ids"] = ["ev_" + "d" * 32]
    regenerated["evidence_context"][0]["evidence_id"] = "ev_" + "d" * 32
    regenerated["evidence_context"][0]["observed_at"] = "2026-09-27T08:00:00+00:00"
    regenerated["evidence_context"][0]["captured_at"] = "2026-09-27T08:00:01+00:00"

    assert comparison._first_request_signature(regenerated) == original  # pyright: ignore[reportPrivateUsage]
    changed_fact = deepcopy(regenerated)
    changed_fact["evidence_context"][0]["facts"]["status"] = "failed"
    assert comparison._first_request_signature(changed_fact)[0] != original[0]  # pyright: ignore[reportPrivateUsage]
    changed_budget = deepcopy(regenerated)
    changed_budget["budget_ms"] = 29999
    changed_signature = comparison._first_request_signature(changed_budget)  # pyright: ignore[reportPrivateUsage]
    assert changed_signature[0] == original[0]
    assert changed_signature[1] != original[1]
    extra_unexpanded_evidence = deepcopy(regenerated)
    extra_unexpanded_evidence["evidence_ids"].append("ev_" + "e" * 32)
    assert comparison._first_request_signature(extra_unexpanded_evidence)[0] != original[0]  # pyright: ignore[reportPrivateUsage]


def test_first_request_pairing_rejects_remaining_budget_drift() -> None:
    attempts = [
        {
            "status": "completed",
            "first_request_content_sha256": "a" * 64,
            "first_request_raw_sha256": "b" * 64,
            "first_request_budget_ms": 30000,
        }
        for _ in Arm
    ]
    assert comparison._first_request_parity(attempts)["status"] == "matched"  # pyright: ignore[reportPrivateUsage]
    attempts[-1] = {**attempts[-1], "first_request_raw_sha256": "c" * 64}
    raw_drift = comparison._first_request_parity(attempts)  # pyright: ignore[reportPrivateUsage]
    assert raw_drift["status"] == "mismatched"
    assert raw_drift["strict_request_bytes_equal"] is False
    assert raw_drift["content_equal_excluding_evidence_times"] is True
    assert raw_drift["evidence_timestamp_parity"] == "unknown"
    assert raw_drift["actual_remaining_budget_equal"] is True
    attempts[-1] = {**attempts[-1], "first_request_budget_ms": 29999}
    drift = comparison._first_request_parity(attempts)  # pyright: ignore[reportPrivateUsage]
    assert drift == {
        "status": "mismatched",
        "content_equal_excluding_evidence_times": True,
        "evidence_timestamp_parity": "unknown",
        "actual_remaining_budget_equal": False,
        "strict_request_bytes_equal": False,
    }
    assert comparison._first_request_parity(attempts[:-1])["status"] == "unknown"  # pyright: ignore[reportPrivateUsage]


def test_unavailable_measurement_is_observed_without_causal_guess(tmp_path: Path) -> None:
    result = run_comparison(
        tmp_path / "comparison",
        protocol=freeze_sequential_comparison(("toy-network-006",)),
    )
    run = result["attempts"][0]
    assert run["status"] == "completed"
    attribution = run["failure_attribution"]
    assert attribution["observation_unavailable"]["observed"] is True
    assert attribution["decisive_evidence_omitted"] == "unknown"
    assert attribution["deep_failure_given_sufficient_evidence"] == "unknown"
    assert attribution["policy_missed_useful_offered_action"] == "unknown"


def test_overlapping_probe_completions_keep_a_valid_time_series() -> None:
    run = {
        "executions": [
            {"execution_id": "first", "probe_id": "browser.route_attempt", "status": "ok"},
            {"execution_id": "second", "probe_id": "browser.direct_control", "status": "ok"},
        ]
    }
    review = {
        "observed_effects": [
            {"execution_id": "first", "utility": "useful", "finished_ms": 9},
            {"execution_id": "second", "utility": "negative", "finished_ms": 3},
        ]
    }
    choices = comparison._choices(run, review, 12)  # pyright: ignore[reportPrivateUsage]
    assert [item.item_id for item in choices] == [
        "browser.direct_control",
        "browser.route_attempt",
    ]
    assert [item.elapsed_ms for item in choices] == [3, 9]
    assert run["executions"][0]["execution_id"] == "first"


def test_joint_batch_utility_uses_frozen_menu_tie_order() -> None:
    world = next(item for item in _WORLDS if item.case_id == "toy-application-007")
    probe_ids = (
        "application.task_timing",
        "application.storage_latency",
        "application.renderer_mode",
        "application.external_control",
    )
    executions = [
        {
            "execution_id": f"exec-{index}",
            "probe_id": probe_id,
            "status": "ok",
            "state_version": 7,
            "finished_at": f"2026-09-27T00:00:00.{(10 - index) * 1000:06d}+00:00",
        }
        for index, probe_id in enumerate(probe_ids)
    ]
    evidence = [
        {
            "execution_id": f"exec-{index}",
            "statement_kind": "observed_fact",
            "facts": [
                {"name": "observation", "value": world.observations[index]},
                {"name": "measurement_status", "value": "observed"},
            ],
        }
        for index in range(len(probe_ids))
    ]
    run = {
        "case_id": world.case_id,
        "executions": executions,
        "evidence": evidence,
        "created_at": "2026-09-27T00:00:00+00:00",
        "registered_probe_ids": ["core.system", *probe_ids, "system.battery_wear"],
        "hypotheses": [],
        "assessment": None,
    }
    first = _score_after_run(run, world)
    reversed_run = {**run, "executions": list(reversed(executions))}
    second = _score_after_run(reversed_run, world)
    assert first["observed_effects"] == second["observed_effects"]
    assert [item["probe_id"] for item in first["observed_effects"]] == list(probe_ids)
    assert first["first_useful_evidence_ms"] == min(
        item["finished_ms"] for item in first["observed_effects"] if item["utility"] == "useful"
    )


def test_changed_protocol_is_rejected_before_output(tmp_path: Path) -> None:
    protocol = freeze_sequential_comparison(("toy-network-002",))
    altered = protocol.model_copy(update={"digest": "0" * 64})
    output = tmp_path / "comparison"
    with pytest.raises(ValueError, match="unchanged frozen"):
        run_comparison(output, protocol=altered)
    assert not output.exists()
