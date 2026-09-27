"""Run frozen toy cases through fresh Investigator databases for each available arm.

Only the deterministic arm is available without an explicitly supplied provider
factory. Other arms remain unavailable until their real routing is supplied and
reviewed. The toy oracle is read only after each run. These mechanics records
cannot establish Windows diagnostic performance or model cost savings.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from benchmarks.score_cause_equivalence import score_case_cause_equivalence
from benchmarks.sequential_investigator_episodes import (
    _BASELINE_ID,  # pyright: ignore[reportPrivateUsage]
    _file_digest,  # pyright: ignore[reportPrivateUsage]
    _git_head,  # pyright: ignore[reportPrivateUsage]
    _readback,  # pyright: ignore[reportPrivateUsage]
    _registered_case,  # pyright: ignore[reportPrivateUsage]
    _score_after_run,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.sequential_visible_matrix import (
    _WORLDS,  # pyright: ignore[reportPrivateUsage]
    build_matrix,
)
from benchmarks.trajectory_protocol import (
    REQUIRED_ARMS,
    Arm,
    CasePlan,
    Choice,
    Claim,
    FrozenProtocol,
    ProviderCall,
    Trajectory,
    freeze_protocol,
    score_trajectories,
)
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.decision.frontier_ranker import LocalDeepFrontierRanker
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.inference.factory import AdvisoryProviders, load_advisory_providers
from systemsense.inference.sequential_providers import SequentialAdvisoryRuntime
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _first_request_signature(request: dict[str, Any]) -> tuple[str, int]:
    """Hash first request content with case IDs and evidence clocks normalized.

    Fresh cases necessarily change opaque IDs and evidence observation/capture
    times. This hash does not establish full model-visible request parity;
    exact bytes and actual remaining budget are recorded separately.
    """
    budget = request.get("budget_ms")
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 0:
        raise ValueError("first decision request has invalid remaining budget")
    evidence = cast(list[dict[str, Any]], request.get("evidence_context", []))
    evidence_ids = cast(list[str], request.get("evidence_ids", []))
    if len(evidence_ids) != len(set(evidence_ids)) or not {
        str(item["evidence_id"]) for item in evidence
    }.issubset(evidence_ids):
        raise ValueError("first decision request has unmapped evidence IDs")
    identities = {
        evidence_id: f"evidence_{index}" for index, evidence_id in enumerate(evidence_ids)
    }
    identities[str(request.get("case_id"))] = "current_case"

    def canonical_id(value: Any) -> Any:
        if isinstance(value, str):
            return identities.get(value, value)
        if isinstance(value, list):
            return [canonical_id(item) for item in cast(list[Any], value)]
        if isinstance(value, dict):
            return {key: canonical_id(item) for key, item in cast(dict[str, Any], value).items()}
        return value

    def without_capture_identity(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return canonical_id(
            [
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"observed_at", "captured_at"}
                }
                for item in items
            ]
        )

    semantic = {
        key: value
        for key, value in request.items()
        if key
        not in {
            "case_id",
            "correlation_id",
            "deadline_at",
            "budget_ms",
            "evidence_context",
            "attention_context",
        }
    }
    semantic["evidence_context"] = without_capture_identity(evidence)
    semantic["attention_context"] = without_capture_identity(
        cast(list[dict[str, Any]], request.get("attention_context", []))
    )
    return _digest(canonical_id(semantic)), budget


def _first_request_parity(attempts: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    if len(attempts) != len(REQUIRED_ARMS) or any(
        item.get("status") != "completed"
        or item.get("first_request_content_sha256") is None
        or item.get("first_request_raw_sha256") is None
        or item.get("first_request_budget_ms") is None
        for item in attempts
    ):
        return {"status": "unknown", "reason": "required_arm_or_first_request_missing"}
    content_equal = len({item["first_request_content_sha256"] for item in attempts}) == 1
    budget_equal = len({item["first_request_budget_ms"] for item in attempts}) == 1
    raw_equal = len({item["first_request_raw_sha256"] for item in attempts}) == 1
    return {
        "status": "matched" if content_equal and budget_equal and raw_equal else "mismatched",
        "content_equal_excluding_evidence_times": content_equal,
        "evidence_timestamp_parity": "unknown",
        "actual_remaining_budget_equal": budget_equal,
        "strict_request_bytes_equal": raw_equal,
    }


def freeze_sequential_comparison(case_ids: tuple[str, ...] | None = None) -> FrozenProtocol:
    """Pin visible inputs and the existing toy world's family grouping."""

    matrix = build_matrix()
    visible = {
        str(row["case_id"]): cast(dict[str, Any], row["initial_input"]) for row in matrix.visible
    }
    worlds = {world.case_id: world for world in _WORLDS}
    selected = tuple(worlds) if case_ids is None else case_ids
    if not selected or len(set(selected)) != len(selected) or not set(selected) <= set(worlds):
        raise ValueError("comparison selection must be unique frozen toy case IDs")
    plans: list[CasePlan] = []
    for case_id in selected:
        initial = visible[case_id]
        world = worlds[case_id]
        network = world.domain == "network_browser"
        plans.append(
            CasePlan(
                case_id=case_id,
                source="synthetic",
                split="development",
                family_group="toy_network_sequential" if network else "toy_app_sequential",
                scenario_role="network_sequential_toy" if network else "application_sequential_toy",
                objective=str(initial["symptom"]),
                visible_input_sha256=_digest(initial),
                initial_evidence_sha256=_digest(
                    {"symptom": initial["symptom"], "baseline_facts": initial["baseline_facts"]}
                ),
                ordered_tools_sha256=_digest(initial["ordered_probe_menu"]),
                budget_ms=int(initial["budget"]["budget_ms"]),
                max_probes=int(initial["budget"]["max_probes"]),
                max_model_calls=100,
            )
        )
    return freeze_protocol(tuple(plans))


@dataclass(frozen=True, slots=True)
class ArmAdapter:
    """No case, world, recipe, future result, or label reaches the factory."""

    provider_factory: Callable[[], AdvisoryProviders]
    expected_mode: str
    scout_prefetch: bool
    classification: str = "scripted_mechanics_only"


def _provider_calls(run: dict[str, Any]) -> tuple[ProviderCall, ...]:
    calls: list[ProviderCall] = []
    event_counts: Counter[tuple[str, str, bool]] = Counter()
    for item in run.get("provider_events", []):
        role = "deep" if item["role"] == "reasoning" else "fast"
        attempted = str(item["attempted_provider_id"])
        effective = str(item["effective_provider_id"])
        native_role = "fast_decision" if item["role"] == "decision" else str(item["role"])
        event_counts[
            (native_role, effective if effective != "none" else attempted, bool(item["failed"]))
        ] += 1
        calls.append(
            ProviderCall(
                role=role,
                attempted_provider_id=attempted,
                effective_provider_id=effective,
                model_id=None,  # Durable call rows do not carry a model pin.
                failed=bool(item["failed"]),
                invalid_advice=None,
                cost_usd=(
                    0.0 if attempted in {"keyword-baseline", "deterministic-reasoning"} else None
                ),
            )
        )
    # Frontier ranker calls are durable state calls, but currently have no
    # coordinator provider event. Reconcile by native role and provider before
    # adding state-only calls, so normal decision/reasoning calls are not doubled.
    for item in run.get("provider_calls", []):
        native_role = str(item["role"])
        provider_id = str(item["provider_id"])
        key = (native_role, provider_id, bool(item["degraded"]))
        if event_counts[key]:
            event_counts[key] -= 1
            continue
        calls.append(
            ProviderCall(
                role="deep" if native_role == "reasoning" else "fast",
                attempted_provider_id=provider_id,
                effective_provider_id=None if item["degraded"] else provider_id,
                model_id=None,
                failed=bool(item["degraded"]),
                invalid_advice=None,
                cost_usd=(
                    0.0 if provider_id in {"keyword-baseline", "deterministic-reasoning"} else None
                ),
            )
        )
    return tuple(calls)


def _choices(run: dict[str, Any], review: dict[str, Any], duration_ms: int) -> tuple[Choice, ...]:
    effects = {item["execution_id"]: item for item in review["observed_effects"]}
    prefetch: dict[str, bool | None] = {}
    for step in run.get("steps", []):
        if step.get("event") == "scout_prefetch_accounted":
            detail = json.loads(str(step["detail"]))
            usage = detail.get("usage")
            prefetch[str(detail["probe_id"])] = (
                True if usage == "used" else False if usage == "wasted" else None
            )
    choices: list[Choice] = []
    for execution in run.get("executions", []):
        if execution["probe_id"] == _BASELINE_ID:
            continue
        effect = effects.get(execution["execution_id"])
        utility = None if effect is None else effect["utility"]
        outcome = (
            "failed"
            if execution["status"] != "ok"
            else "useful"
            if utility == "useful"
            else "uninformative"
            if utility == "negative"
            else "unknown"
        )
        elapsed = None if effect is None else effect["finished_ms"]
        probe_id = str(execution["probe_id"])
        is_prefetch = probe_id in prefetch
        choices.append(
            Choice(
                kind="probe",
                item_id=probe_id,
                outcome=outcome,
                elapsed_ms=max(0, int(duration_ms if elapsed is None else elapsed)),
                prefetch=is_prefetch,
                used=prefetch.get(probe_id) if is_prefetch else None,
            )
        )
    # Probe starts may overlap; the scorer's choice time series is completion ordered.
    # The raw execution/selection order remains in the per-attempt coverage record.
    return tuple(sorted(choices, key=lambda choice: cast(int, choice.elapsed_ms)))


def _claims(run: dict[str, Any], duration_ms: int) -> tuple[Claim, ...]:
    # Sourced support is an independent review; raw runtime support is advisory.
    result = [
        Claim(code=str(item.get("hypothesis_id") or item.get("code") or "advisory")[:120])
        for item in run.get("hypotheses", [])
    ]
    assessment = run.get("assessment")
    if isinstance(assessment, dict):
        assessment = cast(dict[str, object], assessment)
        result.append(
            Claim(
                code=f"assessment:{assessment.get('disposition', 'unknown')}"[:120],
                elapsed_ms=duration_ms,
            )
        )
    return tuple(result[:12])


def _record(
    plan: CasePlan,
    arm: Arm,
    run: dict[str, Any],
    review: dict[str, Any],
    duration_ms: int,
    status: str,
) -> Trajectory:
    calls = _provider_calls(run)
    choices = _choices(run, review, duration_ms)
    return Trajectory(
        case_id=plan.case_id,
        arm=arm,
        status=cast(Any, status),
        visible_input_sha256=plan.visible_input_sha256,
        initial_evidence_sha256=plan.initial_evidence_sha256,
        ordered_tools_sha256=plan.ordered_tools_sha256,
        budget_ms=plan.budget_ms,
        max_probes=plan.max_probes,
        max_model_calls=plan.max_model_calls,
        started_at_ms=0,
        finished_at_ms=duration_ms,
        capture_sha256=_digest(run),
        review_sha256=_digest(review),
        choices=choices,
        claims=_claims(run, duration_ms),
        provider_calls=calls,
        host_impact_ms=None,
        eligible_opportunities=len(
            {
                probe_id
                for snapshot in run.get("offered", [])
                for probe_id in snapshot["probe_ids"]
                if probe_id != _BASELINE_ID
            }
        )
        if run.get("offered")
        else None,
    )


def _validate_adapter(arm: Arm, adapter: ArmAdapter, providers: AdvisoryProviders) -> None:
    if providers.effective_mode != adapter.expected_mode or providers.degradation_reason:
        raise ValueError("arm effective mode or provider degradation mismatch")
    if arm is Arm.DETERMINISTIC:
        if (
            providers.decision.identity.provider_id != "keyword-baseline"
            or providers.reasoning.identity.provider_id != "deterministic-reasoning"
            or providers.frontier_ranker is not None
            or adapter.scout_prefetch
        ):
            raise ValueError("deterministic arm provider mismatch")
    elif arm is Arm.DEEP_ONLY:
        ranker = providers.frontier_ranker
        if type(ranker) is not LocalDeepFrontierRanker:
            raise ValueError("deep-only arm requires the actual local deep ranker")
        decision = providers.decision
        reasoning = providers.reasoning
        runtime = providers._sequential_runtime  # pyright: ignore[reportPrivateUsage]
        client = getattr(ranker, "_client", None)
        if (
            adapter.expected_mode != "deep-only"
            or providers.configured_mode != "deep-only"
            or adapter.scout_prefetch
            or type(decision) is not OllamaDecisionProvider
            or type(reasoning) is not OllamaReasoningProvider
            or type(runtime) is not SequentialAdvisoryRuntime
            or providers._ollama_reasoner is not reasoning  # pyright: ignore[reportPrivateUsage]
            or client is None
            or getattr(decision, "_client", None) is not client
            or getattr(reasoning, "_client", None) is not client
            or runtime.client is not client
            or ranker.model_weight_sha256 != providers._reasoning_digest  # pyright: ignore[reportPrivateUsage]
            or decision.model_weight_sha256 != ranker.model_weight_sha256
            or ranker.model != providers._reasoning_model  # pyright: ignore[reportPrivateUsage]
            or decision.model != ranker.model
            or getattr(reasoning, "_model", None) != ranker.model
        ):
            raise ValueError("deep-only arm provider, shared client, or model pin mismatch")
    elif (
        providers.frontier_ranker is None
        or providers.decision.identity.provider_id == "keyword-baseline"
        or providers.reasoning.identity.provider_id == "deterministic-reasoning"
        or adapter.scout_prefetch != (arm is Arm.FAST_DEEP_SCOUT_ON)
    ):
        raise ValueError("mixed arm provider or Scout mismatch")


def _attribution(run: dict[str, Any], attempt: dict[str, Any]) -> dict[str, object]:
    """Name observed blockers; leave causal counterfactuals unknown."""

    unavailable_ids = sorted(
        {
            str(item["source_id"])
            for item in run.get("evidence", [])
            if any(
                fact.get("name") == "measurement_status" and fact.get("value") == "unavailable"
                for fact in item.get("facts", [])
            )
        }
    )
    provider_failures = [
        str(item["event_id"])
        for item in run.get("provider_events", [])
        if item.get("failed") is True
    ]
    detail = f"{attempt.get('reason') or ''} {run.get('stop_reason') or ''}".casefold()
    deadline = "deadline" in detail or "timeout" in detail
    return {
        "observation_unavailable": {"observed": bool(unavailable_ids), "sources": unavailable_ids},
        "provider_failure": {"observed": bool(provider_failures), "events": provider_failures},
        "scheduling_or_deadline_failure": {"observed": deadline},
        "decisive_evidence_omitted": "unknown",
        "deep_failure_given_sufficient_evidence": "unknown",
        "policy_missed_useful_offered_action": "unknown",
        "unclassified_failure": (
            attempt["status"] == "failed"
            and not unavailable_ids
            and not provider_failures
            and not deadline
        ),
    }


def run_comparison(
    output_dir: Path,
    *,
    protocol: FrozenProtocol | None = None,
    adapters: Mapping[Arm, ArmAdapter] | None = None,
) -> dict[str, Any]:
    """Run every planned cell, preserving unavailable and failed attempts."""

    frozen = freeze_sequential_comparison() if protocol is None else protocol
    if (
        freeze_sequential_comparison(tuple(case.case_id for case in frozen.cases)).digest
        != frozen.digest
    ):
        raise ValueError("comparison requires the unchanged frozen sequential protocol")
    matrix = build_matrix()
    visible = {
        str(row["case_id"]): cast(dict[str, Any], row["initial_input"]) for row in matrix.visible
    }
    worlds = {world.case_id: world for world in _WORLDS}
    adapters = (
        {
            Arm.DETERMINISTIC: ArmAdapter(
                provider_factory=lambda: load_advisory_providers(LocalInferenceConfig()),
                expected_mode="deterministic",
                scout_prefetch=False,
            )
        }
        if adapters is None
        else adapters
    )
    if any(arm not in REQUIRED_ARMS for arm in adapters):
        raise ValueError("unsupported comparison arm")
    output_dir.mkdir(parents=False, exist_ok=False)
    (output_dir / "cases").mkdir()
    (output_dir / "evaluator-only").mkdir()
    attempts: list[dict[str, Any]] = []
    trajectories: list[Trajectory] = []
    reviews: list[dict[str, Any]] = []
    for plan in frozen.cases:
        initial = visible[plan.case_id]
        world = worlds[plan.case_id]
        for arm in REQUIRED_ARMS:
            adapter = adapters.get(arm)
            attempt: dict[str, Any] = {
                "case_id": plan.case_id,
                "arm": arm.value,
                "visible_input_sha256": plan.visible_input_sha256,
                "initial_evidence_sha256": plan.initial_evidence_sha256,
                "ordered_tools_sha256": plan.ordered_tools_sha256,
                "budget_ms": plan.budget_ms,
                "max_probes": plan.max_probes,
                "max_model_calls": plan.max_model_calls,
                "status": "unavailable" if adapter is None else "pending",
                "reason": "no_admitted_arm_adapter" if adapter is None else None,
                "classification": None if adapter is None else adapter.classification,
                "answer": None,
                "coverage": None,
                "latency_ms": None,
                "model_cost_usd": None,
                "host_impact_ms": None,
                "provider_identities": [],
                "raw_provider_events": [],
                "raw_state_provider_calls": [],
                "advisory_call_count": None,
                "provider_configuration": None,
                "invalid_advice": None,
                "model_budget_enforced": False,
                "first_request_content_sha256": None,
                "first_request_raw_sha256": None,
                "first_request_budget_ms": None,
            }
            if adapter is None:
                attempt["failure_attribution"] = {
                    "arm_unavailable": True,
                    "diagnostic_cause": "unknown",
                }
                attempts.append(attempt)
                continue
            started = time.monotonic()
            database = output_dir / "cases" / f"{plan.case_id}-{arm.value}.db"
            providers: AdvisoryProviders | None = None
            run: dict[str, Any] = {"executions": [], "offered": [], "hypotheses": []}
            review: dict[str, Any] = {"observed_effects": []}
            stage = "provider_factory"
            try:
                providers = adapter.provider_factory()
                _validate_adapter(arm, adapter, providers)
                attempt["provider_configuration"] = providers.runtime_status()
                stage = "case_setup"
                with SQLiteStore(database) as store:
                    app = _registered_case(store, initial=initial, world=world)
                    app.decision = providers.decision
                    app.reasoning = providers.reasoning
                    app.knowledge = providers.knowledge
                    app.catalog_attention = providers.catalog_attention
                    app.frontier_ranker = providers.frontier_ranker
                    app.enable_scout_prefetch = adapter.scout_prefetch
                    state = app.create(
                        objective=plan.objective,
                        budget_ms=plan.budget_ms,
                        max_rounds=int(initial["budget"]["max_rounds"]),
                        max_probes=plan.max_probes,
                    )
                    stage = "investigator_run"
                    try:
                        state = app.run(str(state.case_id))
                    except Exception as error:
                        attempt["reason"] = f"investigator_run:{type(error).__name__}"
                        state = app.repository.load(str(state.case_id))
                    stage = "readback"
                    run = _readback(store, state, initial)
                    first_request = store.connection.execute(
                        "SELECT request_json FROM decision_snapshots "
                        "WHERE case_id=? ORDER BY captured_at LIMIT 1",
                        (str(state.case_id),),
                    ).fetchone()
                    if first_request is not None:
                        attempt["first_request_raw_sha256"] = hashlib.sha256(
                            str(first_request[0]).encode("utf-8")
                        ).hexdigest()
                        signature, remaining_budget = _first_request_signature(
                            cast(dict[str, Any], json.loads(str(first_request[0])))
                        )
                        attempt["first_request_content_sha256"] = signature
                        attempt["first_request_budget_ms"] = remaining_budget
                    run["provider_events"] = [
                        json.loads(str(row[0]))
                        for row in store.connection.execute(
                            "SELECT event_json FROM coordinator_events "
                            "WHERE case_id=? AND kind='provider' ORDER BY sequence",
                            (str(state.case_id),),
                        )
                    ]
                    run["created_at"] = state.created_at.isoformat()
                    run["registered_probe_ids"] = [
                        _BASELINE_ID,
                        *(item["probe_id"] for item in initial["ordered_probe_menu"]),
                    ]
                    run["case_id"] = plan.case_id
                    run["unrun_probe_ids"] = [
                        item["probe_id"]
                        for item in initial["ordered_probe_menu"]
                        if item["probe_id"]
                        not in {entry["probe_id"] for entry in run["executions"]}
                    ]
                    stage = "independent_toy_review"
                    review = _score_after_run(run, world)
                    review["cause_equivalence"] = score_case_cause_equivalence(run)
                    attempt["status"] = (
                        "completed"
                        if state.status is InvestigationStatus.COMPLETE
                        and attempt["reason"] is None
                        else "failed"
                    )
            except Exception as error:
                attempt["status"] = "failed"
                attempt["reason"] = f"{stage}:{type(error).__name__}"
            finally:
                if providers is not None:
                    try:
                        providers.close()
                    except Exception as error:
                        attempt["status"] = "failed"
                        attempt["reason"] = f"provider_close:{type(error).__name__}"
            duration_ms = max(1, round((time.monotonic() - started) * 1000))
            try:
                record = _record(plan, arm, run, review, duration_ms, str(attempt["status"]))
            except Exception as error:
                attempt["status"] = "failed"
                attempt["reason"] = f"trajectory_validation:{type(error).__name__}"
                record = _record(plan, arm, {}, {"observed_effects": []}, duration_ms, "failed")
                attempt["trace_projection_incomplete"] = True
            trajectories.append(record)
            attempt.update(
                {
                    "answer": {
                        "hypotheses": run.get("hypotheses", []),
                        "assessment": run.get("assessment"),
                    },
                    "investigation_outcome": run.get("outcome"),
                    "coverage": {
                        "offered": run.get("offered", []),
                        "selected": run.get("selected", []),
                        "executions": run.get("executions", []),
                        "unrun_probe_ids": [
                            str(item["probe_id"])
                            for item in initial["ordered_probe_menu"]
                            if item["probe_id"]
                            not in {entry["probe_id"] for entry in run.get("executions", [])}
                        ],
                    },
                    "latency_ms": duration_ms,
                    "model_cost_usd": (
                        sum(call.cost_usd or 0 for call in record.provider_calls)
                        if record.provider_calls
                        and all(call.cost_usd is not None for call in record.provider_calls)
                        else None
                    ),
                    "provider_identities": [
                        call.model_dump(mode="json") for call in record.provider_calls
                    ],
                    "raw_provider_events": run.get("provider_events", []),
                    "raw_state_provider_calls": run.get("provider_calls", []),
                    "advisory_call_count": len(record.provider_calls),
                    "capture_sha256": record.capture_sha256,
                    "review_sha256": record.review_sha256,
                    "database_sha256": hashlib.sha256(database.read_bytes()).hexdigest()
                    if database.is_file()
                    else None,
                    "failure_attribution": _attribution(run, attempt),
                }
            )
            attempts.append(attempt)
            reviews.append({"case_id": plan.case_id, "arm": arm.value, "review": review})
    by_family: dict[str, dict[str, object]] = {}
    for family in dict.fromkeys(case.family_group for case in frozen.cases):
        cases = tuple(case for case in frozen.cases if case.family_group == family)
        family_ids = {case.case_id for case in cases}
        by_family[family] = {
            "planned_cases": len(cases),
            "split": cases[0].split,
            "score": score_trajectories(
                freeze_protocol(cases),
                tuple(item for item in trajectories if item.case_id in family_ids),
            ),
        }
    provider_pin_parity: dict[str, dict[str, object]] = {}
    first_request_parity: dict[str, dict[str, object]] = {}
    for plan in frozen.cases:
        case_attempts = [item for item in attempts if item["case_id"] == plan.case_id]
        first_request_parity[plan.case_id] = _first_request_parity(case_attempts)
        cells = {
            str(item["arm"]): item
            for item in attempts
            if item["case_id"] == plan.case_id and item["status"] == "completed"
        }
        required = (
            Arm.DEEP_ONLY.value,
            Arm.FAST_DEEP_SCOUT_OFF.value,
            Arm.FAST_DEEP_SCOUT_ON.value,
        )
        if not all(arm in cells for arm in required):
            provider_pin_parity[plan.case_id] = {
                "status": "unknown",
                "reason": "required_deep_arms_incomplete",
            }
            continue
        configurations = [
            cast(dict[str, object], cells[arm]["provider_configuration"]) for arm in required
        ]
        pins = [
            (
                item.get("reasoning_provider"),
                item.get("reasoning_model"),
                item.get("reasoning_digest"),
            )
            for item in configurations
        ]
        fast_pins = [
            (
                item.get("decision_provider"),
                item.get("decision_weight_sha256"),
            )
            for item in configurations[1:]
        ]
        provider_pin_parity[plan.case_id] = {
            "status": (
                "unknown"
                if any(pin[1] is None or pin[2] is None for pin in pins)
                or any(pin[1] is None for pin in fast_pins)
                else "matched"
                if len(set(pins)) == 1 and len(set(fast_pins)) == 1
                else "mismatched"
            ),
            "reason": "provider_runtime_status_pins_only",
        }
    report = {
        "schema_version": 1,
        "classification": "synthetic_investigator_comparison_mechanics_only",
        "runner_git_sha": _git_head(Path(__file__).resolve().parents[1]),
        "runner_sha256": _file_digest(Path(__file__)),
        "runtime_investigator_sha256": _file_digest(Path(inspect.getfile(Investigator))),
        "toy_reviewer_sha256": _file_digest(Path(inspect.getfile(_score_after_run))),
        "cause_scorer_sha256": _file_digest(Path(inspect.getfile(score_case_cause_equivalence))),
        "protocol_digest": frozen.digest,
        "matrix_contract_sha256": matrix.contract_sha256,
        "attempts": attempts,
        "score": score_trajectories(frozen, tuple(trajectories)),
        "by_family": by_family,
        "provider_pin_parity": provider_pin_parity,
        "first_request_parity": first_request_parity,
        "runtime_parity_admissible": False,
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
    }
    (output_dir / "protocol.json").write_text(frozen.model_dump_json(indent=2), encoding="utf-8")
    (output_dir / "attempts.json").write_text(
        json.dumps(report, sort_keys=True, indent=2), encoding="utf-8"
    )
    (output_dir / "trajectories.json").write_text(
        json.dumps(
            [item.model_dump(mode="json") for item in trajectories], sort_keys=True, indent=2
        ),
        encoding="utf-8",
    )
    (output_dir / "evaluator-only" / "reviews.json").write_text(
        json.dumps(reviews, sort_keys=True, indent=2), encoding="utf-8"
    )
    (output_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "protocol_digest": frozen.digest,
                "runner_sha256": _file_digest(Path(__file__)),
                "runtime_investigator_sha256": _file_digest(Path(inspect.getfile(Investigator))),
                "toy_reviewer_sha256": _file_digest(Path(inspect.getfile(_score_after_run))),
                "cause_scorer_sha256": _file_digest(
                    Path(inspect.getfile(score_case_cause_equivalence))
                ),
                "matrix_contract_sha256": matrix.contract_sha256,
                "files_sha256": {
                    name: _file_digest(output_dir / name)
                    for name in (
                        "protocol.json",
                        "attempts.json",
                        "trajectories.json",
                        "evaluator-only/reviews.json",
                    )
                },
                "database_sha256": {
                    f"{item['case_id']}-{item['arm']}": item.get("database_sha256")
                    for item in attempts
                    if item["status"] != "unavailable"
                },
            },
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    return report


def verify_comparison(output_dir: Path) -> dict[str, object]:
    """Check immutable input and result custody without executing an arm."""

    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    files = cast(dict[str, str], manifest["files_sha256"])
    if (
        manifest["runner_sha256"] != _file_digest(Path(__file__))
        or manifest["runtime_investigator_sha256"]
        != _file_digest(Path(inspect.getfile(Investigator)))
        or manifest["toy_reviewer_sha256"] != _file_digest(Path(inspect.getfile(_score_after_run)))
        or manifest["cause_scorer_sha256"]
        != _file_digest(Path(inspect.getfile(score_case_cause_equivalence)))
        or manifest["matrix_contract_sha256"] != build_matrix().contract_sha256
        or any(_file_digest(output_dir / name) != digest for name, digest in files.items())
    ):
        raise ValueError("comparison artifact integrity mismatch")
    protocol = FrozenProtocol.model_validate_json((output_dir / "protocol.json").read_text())
    expected = freeze_sequential_comparison(tuple(case.case_id for case in protocol.cases))
    if protocol.digest != expected.digest or protocol.digest != manifest["protocol_digest"]:
        raise ValueError("comparison frozen protocol mismatch")
    report = json.loads((output_dir / "attempts.json").read_text(encoding="utf-8"))
    trajectories = tuple(
        Trajectory.model_validate(item)
        for item in json.loads((output_dir / "trajectories.json").read_text(encoding="utf-8"))
    )
    cells = [(item["case_id"], item["arm"]) for item in report["attempts"]]
    planned = [(case.case_id, arm.value) for case in protocol.cases for arm in REQUIRED_ARMS]
    if (
        cells != planned
        or report["score"] != json.loads(json.dumps(score_trajectories(protocol, trajectories)))
        or report["protocol_digest"] != protocol.digest
    ):
        raise ValueError("comparison attempt accounting mismatch")
    databases = cast(dict[str, str | None], manifest["database_sha256"])
    if any(
        (
            _file_digest(output_dir / "cases" / f"{key}.db")
            if (output_dir / "cases" / f"{key}.db").is_file()
            else None
        )
        != digest
        for key, digest in databases.items()
    ):
        raise ValueError("comparison database integrity mismatch")
    return {
        "integrity_verified": True,
        "planned_cells": len(planned),
        "completed": sum(item["status"] == "completed" for item in report["attempts"]),
        "failed": sum(item["status"] == "failed" for item in report["attempts"]),
        "unavailable": sum(item["status"] == "unavailable" for item in report["attempts"]),
        "diagnostic_performance_admissible": False,
    }


def compare_replays(left_dir: Path, right_dir: Path) -> dict[str, object]:
    """Compare two saved runs at the same code/input revision without replay."""

    verify_comparison(left_dir)
    verify_comparison(right_dir)
    reports = [
        json.loads((path / "attempts.json").read_text(encoding="utf-8"))
        for path in (left_dir, right_dir)
    ]
    traces = [
        {
            (item.case_id, item.arm.value): item
            for item in (
                Trajectory.model_validate(raw)
                for raw in json.loads((path / "trajectories.json").read_text(encoding="utf-8"))
            )
        }
        for path in (left_dir, right_dir)
    ]
    reviews = [
        {
            (str(item["case_id"]), str(item["arm"])): item["review"]
            for item in json.loads((path / "evaluator-only" / "reviews.json").read_text())
        }
        for path in (left_dir, right_dir)
    ]
    left, right = reports
    if any(
        left[name] != right[name]
        for name in (
            "protocol_digest",
            "matrix_contract_sha256",
            "runner_git_sha",
            "runner_sha256",
            "runtime_investigator_sha256",
            "toy_reviewer_sha256",
            "cause_scorer_sha256",
        )
    ):
        raise ValueError("paired replay code or frozen input differs")
    rows: list[dict[str, object]] = []
    right_attempts = {(str(item["case_id"]), str(item["arm"])): item for item in right["attempts"]}
    for prior in left["attempts"]:
        key = (str(prior["case_id"]), str(prior["arm"]))
        later = right_attempts[key]
        if any(
            prior[name] != later[name]
            for name in (
                "visible_input_sha256",
                "initial_evidence_sha256",
                "ordered_tools_sha256",
                "budget_ms",
                "max_probes",
                "max_model_calls",
            )
        ):
            raise ValueError("paired replay budget or evidence parity differs")
        selections = [
            [
                str(item["probe_id"])
                for item in attempt["coverage"]["executions"]
                if item["probe_id"] != _BASELINE_ID
            ]
            if attempt["coverage"] is not None
            else []
            for attempt in (prior, later)
        ]
        record_pair = [trace.get(key) for trace in traces]
        useful = [
            None if record is None else sum(choice.outcome == "useful" for choice in record.choices)
            for record in record_pair
        ]
        provider_events = [
            [
                (
                    str(item["role"]),
                    str(item["attempted_provider_id"]),
                    str(item["effective_provider_id"]),
                    bool(item["failed"]),
                )
                for item in attempt["raw_provider_events"]
            ]
            for attempt in (prior, later)
        ]
        reviewed = [item.get(key) for item in reviews]
        cause_reviews = [
            None if item is None else item.get("cause_equivalence") for item in reviewed
        ]
        rows.append(
            {
                "case_id": key[0],
                "arm": key[1],
                "statuses": [prior["status"], later["status"]],
                "provider_configuration_equal": (
                    prior["provider_configuration"] == later["provider_configuration"]
                    if prior["provider_configuration"] is not None
                    and later["provider_configuration"] is not None
                    else None
                ),
                "provider_events_equal": (
                    sorted(provider_events[0]) == sorted(provider_events[1])
                    if provider_events[0] and provider_events[1]
                    else None
                ),
                "provider_event_order_equal": (
                    provider_events[0] == provider_events[1]
                    if provider_events[0] and provider_events[1]
                    else None
                ),
                "selection_set_equal": (
                    sorted(selections[0]) == sorted(selections[1])
                    if prior["coverage"] is not None and later["coverage"] is not None
                    else None
                ),
                "execution_order_equal": (
                    selections[0] == selections[1]
                    if prior["coverage"] is not None and later["coverage"] is not None
                    else None
                ),
                "useful_evidence": useful,
                "usefulness_equal": (
                    useful[0] == useful[1]
                    if useful[0] is not None
                    and useful[1] is not None
                    and prior["status"] == "completed"
                    and later["status"] == "completed"
                    else None
                ),
                "cause_labels_equal": (
                    cause_reviews[0]["compatible_cause_labels"]
                    == cause_reviews[1]["compatible_cause_labels"]
                    if cause_reviews[0] is not None and cause_reviews[1] is not None
                    else None
                ),
                "cause_reduction_credit_equal": (
                    cause_reviews[0]["cause_reducing_probe_ids"]
                    == cause_reviews[1]["cause_reducing_probe_ids"]
                    if cause_reviews[0] is not None and cause_reviews[1] is not None
                    else None
                ),
                "first_useful_ms": [
                    None if item is None else item.get("first_useful_evidence_ms")
                    for item in reviewed
                ],
                "wall_ms": [prior["latency_ms"], later["latency_ms"]],
            }
        )
    return {
        "schema_version": 1,
        "classification": "synthetic_exact_revision_replay_comparison_only",
        "protocol_digest": left["protocol_digest"],
        "runner_sha256": left["runner_sha256"],
        "runtime_investigator_sha256": left["runtime_investigator_sha256"],
        "toy_reviewer_sha256": left["toy_reviewer_sha256"],
        "cause_scorer_sha256": left["cause_scorer_sha256"],
        "rows": rows,
        "diagnostic_performance_admissible": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--case-id", action="append")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--compare-to", type=Path)
    args = parser.parse_args(argv)
    if args.compare_to is not None:
        if args.verify or args.case_id:
            parser.error("--compare-to cannot be combined with --verify or --case-id")
        print(json.dumps(compare_replays(args.output_dir, args.compare_to), sort_keys=True))
        return 0
    if args.verify:
        print(json.dumps(verify_comparison(args.output_dir), sort_keys=True))
        return 0
    case_ids = None if args.case_id is None else tuple(cast(list[str], args.case_id))
    protocol = freeze_sequential_comparison(case_ids)
    report = run_comparison(args.output_dir, protocol=protocol)
    print(
        json.dumps(
            {
                "protocol_digest": protocol.digest,
                "planned_cases": len(protocol.cases),
                "statuses": {
                    arm.value: {
                        status: sum(
                            attempt["arm"] == arm.value and attempt["status"] == status
                            for attempt in report["attempts"]
                        )
                        for status in ("completed", "failed", "unavailable")
                    }
                    for arm in REQUIRED_ARMS
                },
                "diagnostic_performance_admissible": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
