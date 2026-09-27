"""Run complete toy cases through the public Investigator.create/run interface.

Only registered in-process toy probes execute. The hidden simulator recipe is
captured by probe closures and kept in evaluator-only output. This exercises
runtime custody and policy trajectories, not Windows diagnostic performance.
Neural arms remain explicit unrun cells until A grants a shared model slot and
provides exact provider/toggle interfaces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict

from benchmarks.trajectory_fixture_protocols import build_fixture_protocols
from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import ProbeCapability
from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeOutputFieldV1,
    ProbeSafety,
    ProbeToolMetadataV1,
    SafetyClass,
    SelfWrite,
)
from systemsense.evaluation.simulated_pilot import (
    SimCandidate,
    SimModelInput,
    generate_simulated_episode,
)
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_ROOT = Path(__file__).resolve().parents[1]
_BASELINE = SimCandidate(
    probe_id="core.system", description="Read reported baseline facts", expected_cost_ms=1
)
_SELF_WRITES = (SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD)


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_head() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _git_dirty() -> bool | None:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "--", "benchmarks/full_trajectory_pilot.py"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return bool(result.stdout.strip()) if result.returncode == 0 else None


def _registered_case(
    store: SQLiteStore, *, visible: SimModelInput, scenario_id: str
) -> Investigator:
    """Create a real investigator whose only probe handlers read one toy world."""

    candidates = (_BASELINE, *visible.candidates)
    definitions: list[ProbeDefinition] = []
    capabilities: list[ProbeCapability] = []
    for candidate in candidates:
        probe_id = candidate.probe_id

        def collect(
            _parameters: dict[str, JsonValue], *, selected: str = probe_id
        ) -> ProbeObservation:
            now = datetime.now(UTC)
            if selected == _BASELINE.probe_id:
                return ProbeObservation(
                    summary="Toy baseline report",
                    facts={"baseline_facts": list(visible.baseline_facts)},
                    observed_at=now,
                    captured_at=now,
                )
            outcome = generate_simulated_episode(scenario_id, executed_probe_ids=(selected,))
            adjudication = next(item for item in outcome.adjudications if item.probe_id == selected)
            return ProbeObservation(
                summary=f"Toy {selected} measurement {adjudication.status}",
                facts={
                    "measurement_status": adjudication.status,
                    "observation": adjudication.observation,
                },
                limitations=(
                    ("The toy measurement is unavailable in this world.",)
                    if adjudication.status == "unavailable"
                    else ()
                ),
                observed_at=now,
                captured_at=now,
            )

        manifest = ProbeManifest(
            probe_id=probe_id,
            version=1,
            implementation_id=f"builtin.toy.{probe_id}",
            question=candidate.description,
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
                self_writes=_SELF_WRITES,
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=1_000, max_output_bytes=32_768, max_records=64),
            category=probe_id.split(".")[0],
        )
        discovery = ProbeToolMetadataV1(
            probe_id=probe_id,
            probe_version=1,
            observable_ids=(probe_id,),
            parameter_fields=(),
            supports_window=False,
            outputs=(ProbeOutputFieldV1(name="observation"),),
            estimated_cost_ms=candidate.expected_cost_ms,
            resource_class="cpu",
            sensitivity=Sensitivity.SYSTEM_METADATA,
            network_effect="none",
            io_intensity="light",
            target_state_effect="none",
            self_writes=_SELF_WRITES,
            purpose=candidate.description,
        )
        definitions.append(
            ProbeDefinition(
                manifest=manifest,
                parameter_model=_NoParameters,
                handler=collect,
                isolated=False,
                discovery=discovery,
            )
        )
        capabilities.append(
            ProbeCapability(
                probe_id=probe_id,
                description=candidate.description,
                keywords=frozenset(re.findall(r"[a-z0-9]+", candidate.description.casefold())),
                common=probe_id == _BASELINE.probe_id,
                cost_ms=candidate.expected_cost_ms,
                resource_class=ResourceClass.CPU,
            )
        )
    planner = DeterministicPlanner(
        candidates=tuple(
            ProbeCandidate(
                probe_id=item.probe_id,
                cost_ms=item.expected_cost_ms,
                value=1,
                common=item.probe_id == _BASELINE.probe_id,
            )
            for item in candidates
        )
    )
    runtime = DiagnosticRuntime(
        store=store,
        case_service=CaseService(store, planner),
        probe_runner=ProbeRunner(definitions=tuple(definitions)),
    )
    return Investigator(
        store=store,
        runtime=runtime,
        capabilities=tuple(capabilities),
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
        knowledge=ReferenceKnowledgeGraph.load_default(),
    )


def _observed_facts(store: SQLiteStore, execution_id: str) -> dict[str, JsonValue] | None:
    row = store.connection.execute(
        "SELECT record_json FROM evidence WHERE execution_id=? "
        "AND json_extract(record_json, '$.statement_kind')='observed_fact' "
        "ORDER BY captured_at,evidence_id LIMIT 1",
        (execution_id,),
    ).fetchone()
    if row is None:
        return None
    record = json.loads(str(row[0]))
    return {str(item["name"]): cast(JsonValue, item["value"]) for item in record["facts"]}


def _elapsed_ms(created_at: datetime, timestamp: str) -> int:
    return max(0, round((datetime.fromisoformat(timestamp) - created_at).total_seconds() * 1000))


def _run_one(
    database: Path,
    *,
    case_id: str,
    visible: SimModelInput,
    scenario_id: str,
    initial_input_sha256: str,
    budget_ms: int,
    max_rounds: int,
    max_probes: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Keep execution and independent oracle scoring on opposite sides of run()."""

    started = time.monotonic()
    execution: dict[str, Any] = {
        "case_id": case_id,
        "arm": "deterministic",
        "initial_input_sha256": initial_input_sha256,
        "status": "failed",
        "failure_stage": "case_setup",
        "probe_attempts": [],
        "provider_identities": [],
        "provider_calls": [],
        "claims": [],
        "first_single_probe_useful_ms": None,
        "host_impact_ms": None,
        "model_cost_usd": 0.0,
    }
    with SQLiteStore(database) as store:
        app = _registered_case(store, visible=visible, scenario_id=scenario_id)
        state = app.create(
            objective=visible.symptom,
            budget_ms=budget_ms,
            max_rounds=max_rounds,
            max_probes=max_probes,
        )
        created_at = state.created_at
        execution["runtime_case_id"] = str(state.case_id)
        try:
            execution["failure_stage"] = "investigator_run"
            state = app.run(str(state.case_id))
            execution["status"] = (
                "completed" if state.status is InvestigationStatus.COMPLETE else "failed"
            )
            execution["failure_stage"] = (
                None if execution["status"] == "completed" else "investigator_terminal"
            )
        except Exception as error:
            execution["failure_type"] = type(error).__name__
            state = app.repository.load(str(state.case_id))
        execution["wall_ms"] = round((time.monotonic() - started) * 1000)
        execution["outcome"] = state.outcome.value
        execution["stop_reason"] = state.stop_reason
        execution["round_count"] = state.round_count
        execution["provider_calls"] = [
            item.model_dump(mode="json") for item in state.provider_calls
        ]
        execution["provider_identities"] = sorted(
            {(item.provider_id, item.provider_version, item.role) for item in state.provider_calls},
            key=str,
        )
        execution["claims"] = [
            {
                "statement": item.statement,
                "status": item.status.value,
                "cited_evidence_ids": [
                    str(evidence_id)
                    for evidence_id in (
                        *item.supporting_evidence_ids,
                        *item.contradicting_evidence_ids,
                    )
                ],
                "independent_support": None,
            }
            for item in state.hypotheses
        ]
        prior_probe_ids: set[str] = set()
        independent_choices: list[dict[str, Any]] = []
        for execution_id, probe_id, status, finished_at in store.connection.execute(
            "SELECT execution_id,probe_id,status,finished_at FROM probe_executions "
            "WHERE case_id=? ORDER BY started_at,execution_id",
            (str(state.case_id),),
        ):
            finished_ms = (
                _elapsed_ms(created_at, str(finished_at)) if finished_at is not None else None
            )
            attempt = {
                "probe_id": str(probe_id),
                "status": str(status),
                "finished_ms": finished_ms,
                "execution_id": str(execution_id),
            }
            execution["probe_attempts"].append(attempt)
            if probe_id == _BASELINE.probe_id:
                continue
            if probe_id in prior_probe_ids:
                utility = "unknown"
                reason = "repeat_probe_effect_not_adjudicated"
            else:
                prior_probe_ids.add(str(probe_id))
                fresh = generate_simulated_episode(scenario_id, executed_probe_ids=(str(probe_id),))
                adjudication = next(
                    item for item in fresh.adjudications if item.probe_id == probe_id
                )
                facts = _observed_facts(store, str(execution_id))
                if status != "ok" or facts is None:
                    utility = "unknown"
                    reason = "probe_failed_or_no_evidence"
                elif (
                    facts.get("measurement_status") != adjudication.status
                    or facts.get("observation") != adjudication.observation
                ):
                    utility = "unknown"
                    reason = "captured_observation_differs_from_toy_oracle"
                else:
                    utility = adjudication.utility
                    reason = "independent_reset_single_probe_effect"
            independent_choices.append(
                {
                    "probe_id": str(probe_id),
                    "observed_status": str(status),
                    "finished_ms": finished_ms,
                    "single_probe_utility": utility,
                    "review_reason": reason,
                }
            )
        useful_times = [
            item["finished_ms"]
            for item in independent_choices
            if item["single_probe_utility"] == "useful" and item["finished_ms"] is not None
        ]
        execution["first_single_probe_useful_ms"] = min(useful_times) if useful_times else None
        execution["single_probe_useful_count"] = sum(
            item["single_probe_utility"] == "useful" for item in independent_choices
        )
        execution["single_probe_negative_count"] = sum(
            item["single_probe_utility"] == "negative" for item in independent_choices
        )
        execution["single_probe_unknown_count"] = sum(
            item["single_probe_utility"] == "unknown" for item in independent_choices
        )
        execution["eligible_probe_opportunities"] = len(visible.candidates)
        execution["unrun_probe_opportunities"] = len(visible.candidates) - len(prior_probe_ids)
        prefetch_steps = [
            json.loads(str(row[0]))
            for row in store.connection.execute(
                "SELECT record_json FROM investigation_steps WHERE case_id=? "
                "AND json_extract(record_json, '$.event') LIKE 'scout_prefetch_%' "
                "ORDER BY state_version",
                (str(state.case_id),),
            )
        ]
        execution["prefetch_events"] = [step["event"] for step in prefetch_steps]
        execution["prefetch_accounting"] = [
            json.loads(step["detail"])
            for step in prefetch_steps
            if step["event"] == "scout_prefetch_accounted"
        ]
        execution["evidence_rows"] = store.connection.execute(
            "SELECT count(*) FROM evidence WHERE case_id=?", (str(state.case_id),)
        ).fetchone()[0]
    execution["database_sha256"] = hashlib.sha256(database.read_bytes()).hexdigest()
    oracle = generate_simulated_episode(scenario_id)
    evaluator = {
        "case_id": case_id,
        "scenario_id": scenario_id,
        "root_causes": list(oracle.oracle.root_causes),
        "exact_diagnosis_abstain_required": oracle.oracle.exact_diagnosis_abstain_required,
        "compatible_root_cause_sets": [
            list(item) for item in oracle.oracle.compatible_root_cause_sets
        ],
        "observed_choice_reviews": independent_choices,
        "causal_answer_review": "unknown",
        "diagnostic_performance_admissible": False,
    }
    return execution, evaluator


def run_toy_suite(
    output_dir: Path,
    *,
    scenario_names: tuple[str, ...] | None = None,
    budget_ms: int = 30_000,
    max_rounds: int = 2,
    max_probes: int = 8,
) -> dict[str, Any]:
    """Run a fresh isolated deterministic DB per case; list neural cells unrun."""

    if not 1_000 <= budget_ms <= 600_000 or not 1 <= max_rounds <= 10 or not 1 <= max_probes <= 16:
        raise ValueError("pilot budget is outside bounded limits")
    export = build_fixture_protocols()
    known = {scenario for index in export.evaluator_index.values() for scenario in index.values()}
    if scenario_names is not None and (
        len(scenario_names) != len(set(scenario_names)) or not set(scenario_names) <= known
    ):
        raise ValueError("scenario selection is duplicate or outside the frozen toy matrix")
    selected = set(known if scenario_names is None else scenario_names)
    planned: list[tuple[str, str, str, SimModelInput, str, str]] = []
    for domain, protocol in export.protocols.items():
        for case in protocol.cases:
            scenario_id = export.evaluator_index[domain][case.case_id]
            if scenario_id not in selected:
                continue
            visible = SimModelInput.model_validate(export.visible_inputs[domain][case.case_id])
            input_digest = _digest(
                {
                    "model_input": visible.model_dump(mode="json"),
                    "registered_baseline": _BASELINE.model_dump(mode="json"),
                    "budget_ms": budget_ms,
                    "max_rounds": max_rounds,
                    "max_probes": max_probes,
                }
            )
            planned.append((case.case_id, domain, case.split, visible, scenario_id, input_digest))
    if not planned:
        raise ValueError("no selected scenarios")
    output_dir.mkdir(parents=False, exist_ok=False)
    (output_dir / "cases").mkdir()
    (output_dir / "evaluator-only").mkdir()
    (output_dir / "policy-visible").mkdir()
    report: dict[str, Any] = {
        "schema_version": 1,
        "classification": "synthetic_investigator_mechanics_only",
        "planned_cases": len(planned),
        "planned_inputs": [],
        "runs": [],
        "arms": {},
        "paired_complete_cases": 0,
        "runtime_request_parity_verified": False,
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
    }
    labels: list[dict[str, Any]] = []
    policy_inputs: dict[str, dict[str, Any]] = {}
    for case_id, domain, split, visible, scenario_id, digest in planned:
        policy_inputs[case_id] = {
            "model_input": visible.model_dump(mode="json"),
            "registered_baseline": _BASELINE.model_dump(mode="json"),
            "budget_ms": budget_ms,
            "max_rounds": max_rounds,
            "max_probes": max_probes,
        }
        if _digest(policy_inputs[case_id]) != digest:
            raise ValueError("registered visible input differs from frozen digest")
        report["planned_inputs"].append(
            {
                "case_id": case_id,
                "domain": domain,
                "split": split,
                "initial_input_sha256": digest,
                "budget_ms": budget_ms,
                "max_rounds": max_rounds,
                "max_probes": max_probes,
            }
        )
        database = output_dir / "cases" / f"{case_id}-deterministic.db"
        run: dict[str, Any]
        label: dict[str, Any]
        try:
            run, label = _run_one(
                database,
                case_id=case_id,
                visible=visible,
                scenario_id=scenario_id,
                initial_input_sha256=digest,
                budget_ms=budget_ms,
                max_rounds=max_rounds,
                max_probes=max_probes,
            )
        except Exception as error:
            run = {
                "case_id": case_id,
                "arm": "deterministic",
                "initial_input_sha256": digest,
                "status": "failed",
                "failure_stage": "case_setup_or_readback",
                "failure_type": type(error).__name__,
                "probe_attempts": [],
                "provider_identities": [],
                "first_single_probe_useful_ms": None,
                "eligible_probe_opportunities": len(visible.candidates),
                "unrun_probe_opportunities": len(visible.candidates),
                "host_impact_ms": None,
                "model_cost_usd": 0.0,
            }
            oracle = generate_simulated_episode(scenario_id)
            label = {
                "case_id": case_id,
                "scenario_id": scenario_id,
                "root_causes": list(oracle.oracle.root_causes),
                "observed_choice_reviews": [],
                "causal_answer_review": "unknown",
                "diagnostic_performance_admissible": False,
            }
        report["runs"].append(run)
        labels.append(label)
    report["arms"] = {
        "deterministic": {
            "eligible": len(planned),
            "completed": sum(run["status"] == "completed" for run in report["runs"]),
            "failed": sum(run["status"] == "failed" for run in report["runs"]),
            "unrun": 0,
            "probe_attempts": sum(len(run["probe_attempts"]) for run in report["runs"]),
            "eligible_probe_opportunities": sum(
                run.get("eligible_probe_opportunities", 0) for run in report["runs"]
            ),
            "unrun_probe_opportunities": sum(
                run.get("unrun_probe_opportunities", 0) for run in report["runs"]
            ),
            "single_probe_useful": sum(
                run.get("single_probe_useful_count", 0) for run in report["runs"]
            ),
            "single_probe_negative": sum(
                run.get("single_probe_negative_count", 0) for run in report["runs"]
            ),
            "single_probe_unknown": sum(
                run.get("single_probe_unknown_count", 0) for run in report["runs"]
            ),
            "independently_supported_causal_answers": 0,
            "unreviewed_claims": sum(len(run.get("claims", [])) for run in report["runs"]),
            "first_single_probe_useful_ms": [
                run["first_single_probe_useful_ms"]
                for run in report["runs"]
                if run["first_single_probe_useful_ms"] is not None
            ],
            "provider_call_count": sum(
                len(run.get("provider_calls", [])) for run in report["runs"]
            ),
            "provider_degraded_count": sum(
                call["degraded"] for run in report["runs"] for call in run.get("provider_calls", [])
            ),
            "prefetch_used": sum(
                item.get("usage") == "used"
                for run in report["runs"]
                for item in run.get("prefetch_accounting", [])
            ),
            "prefetch_wasted": sum(
                item.get("usage") == "wasted"
                for run in report["runs"]
                for item in run.get("prefetch_accounting", [])
            ),
            "prefetch_unknown": sum(
                item.get("usage") not in {"used", "wasted"}
                for run in report["runs"]
                for item in run.get("prefetch_accounting", [])
            ),
            "invalid_advice_count": None,
            "wrong_causal_claim_count": None,
            "model_cost_usd": 0.0,
            "host_impact_ms": None,
        },
        "current_default": {
            "eligible": len(planned),
            "completed": 0,
            "failed": 0,
            "unrun": len(planned),
            "reason": "A model slot has not been granted; no configured provider was run",
        },
        "deep_only": {
            "eligible": len(planned),
            "unrun": len(planned),
            "reason": "pinned-deep composition specified; shared model slot absent",
        },
        "fast_deep_scout_off": {
            "eligible": len(planned),
            "unrun": len(planned),
            "reason": "Scout toggle not adopted here; shared model slot absent",
        },
        "fast_deep_scout_on": {
            "eligible": len(planned),
            "unrun": len(planned),
            "reason": "shared model slot pending",
        },
    }
    manifest = {
        "schema_version": 1,
        "source_kind": "deterministic_toy_simulator",
        "source_sha256": export.source_sha256,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "code_sha": _git_head(),
        "runner_source_dirty": _git_dirty(),
        "fixture_protocol_digests": {
            domain: protocol.digest for domain, protocol in export.protocols.items()
        },
        "run_input_digest": _digest(report["planned_inputs"]),
        "policy_input_sha256": _digest(policy_inputs),
        "database_sha256": {run["case_id"]: run.get("database_sha256") for run in report["runs"]},
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
        "labels_separate_from_policy": True,
        "input_digest_scope": "planned semantic input, not a byte-identical runtime request",
        "runtime_request_parity_verified": False,
        "current_default_runnable": False,
    }
    (output_dir / "run-report.json").write_text(
        json.dumps(report, sort_keys=True, indent=2), encoding="utf-8"
    )
    (output_dir / "evaluator-only/outcomes.json").write_text(
        json.dumps({"cases": labels}, sort_keys=True, indent=2), encoding="utf-8"
    )
    (output_dir / "policy-visible/inputs.json").write_text(
        json.dumps(policy_inputs, sort_keys=True, indent=2), encoding="utf-8"
    )
    manifest["artifact_sha256"] = {
        relative: _file_sha256(output_dir / relative)
        for relative in (
            "run-report.json",
            "policy-visible/inputs.json",
            "evaluator-only/outcomes.json",
        )
    }
    (output_dir / "run-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8"
    )
    return report


def verify_toy_suite(output_dir: Path) -> dict[str, Any]:
    """Read-only replay/integrity check; hashes do not authenticate the source."""

    try:
        manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
        for relative, expected in manifest["artifact_sha256"].items():
            if (
                relative
                not in {
                    "run-report.json",
                    "policy-visible/inputs.json",
                    "evaluator-only/outcomes.json",
                }
                or _file_sha256(output_dir / relative) != expected
            ):
                raise ValueError("pilot artifact hash mismatch")
        report = json.loads((output_dir / "run-report.json").read_text(encoding="utf-8"))
        visible = json.loads(
            (output_dir / "policy-visible/inputs.json").read_text(encoding="utf-8")
        )
        labels = json.loads(
            (output_dir / "evaluator-only/outcomes.json").read_text(encoding="utf-8")
        )
        export = build_fixture_protocols()
        if (
            manifest["source_sha256"] != export.source_sha256
            or manifest["runner_sha256"] != _file_sha256(Path(__file__))
            or manifest["policy_input_sha256"] != _digest(visible)
            or manifest["run_input_digest"] != _digest(report["planned_inputs"])
            or manifest["fixture_protocol_digests"]
            != {domain: protocol.digest for domain, protocol in export.protocols.items()}
            or len(labels["cases"]) != report["planned_cases"]
            or len(report["runs"]) != report["planned_cases"]
        ):
            raise ValueError("pilot source or plan differs")
        plans = {item["case_id"]: item for item in report["planned_inputs"]}
        if (
            len(plans) != report["planned_cases"]
            or set(plans) != set(visible)
            or set(plans) != {item["case_id"] for item in labels["cases"]}
        ):
            raise ValueError("pilot plan and evaluator index differ")
        by_id = {
            case_id: scenario
            for index in export.evaluator_index.values()
            for case_id, scenario in index.items()
        }
        for case_id, plan in plans.items():
            if not re.fullmatch(r"[a-z][a-z0-9-]{3,79}", case_id):
                raise ValueError("pilot case ID is unsafe")
            if _digest(visible[case_id]) != plan["initial_input_sha256"]:
                raise ValueError("pilot visible input differs")
        for label in labels["cases"]:
            if label["scenario_id"] != by_id[label["case_id"]] or label["root_causes"] != list(
                generate_simulated_episode(label["scenario_id"]).oracle.root_causes
            ):
                raise ValueError("pilot hidden outcome differs")
        for run in report["runs"]:
            case_id = run["case_id"]
            if (
                case_id not in plans
                or run["initial_input_sha256"] != plans[case_id]["initial_input_sha256"]
            ):
                raise ValueError("pilot run is outside matched plan")
            expected = manifest["database_sha256"].get(case_id)
            if (
                expected is not None
                and _file_sha256(output_dir / "cases" / f"{case_id}-deterministic.db") != expected
            ):
                raise ValueError("pilot database hash mismatch")
    except (KeyError, OSError, TypeError, UnicodeError) as error:
        raise ValueError("pilot verification failed") from error
    return {
        "classification": report["classification"],
        "planned_cases": report["planned_cases"],
        "arms": report["arms"],
        "integrity_verified": True,
        "runtime_request_parity_verified": False,
        "diagnostic_performance_admissible": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--budget-ms", type=int, default=30_000)
    parser.add_argument("--max-rounds", type=int, default=2)
    parser.add_argument("--max-probes", type=int, default=8)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    if args.verify:
        print(json.dumps(verify_toy_suite(args.output_dir), sort_keys=True))
        return 0
    report = run_toy_suite(
        args.output_dir,
        scenario_names=tuple(args.scenario) or None,
        budget_ms=args.budget_ms,
        max_rounds=args.max_rounds,
        max_probes=args.max_probes,
    )
    print(
        json.dumps(
            {
                "planned_cases": report["planned_cases"],
                "arms": report["arms"],
                "paired_complete_cases": report["paired_complete_cases"],
                "output_dir": str(args.output_dir),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
