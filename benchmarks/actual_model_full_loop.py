"""One prospective local-model loop over a synthetic, registered read-only fixture.

This is a capability trial, not a matched policy benchmark or a Windows diagnosis.
The hidden follow-up value is given only to the fixture probe handler. An absent
prediction, probe execution, or second advisory is a recorded failed opportunity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from benchmarks.advisory_validation_boundary import classify_returned_advice
from benchmarks.source_backed_frontier_pilot import (
    _git_head,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_task_relation_red import run_balanced_relation_probe
from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.ids import JsonValue
from systemsense.inference.factory import AdvisoryProviders, load_deep_only_v4_providers
from systemsense.inference.host_lease import LeaseBudget
from systemsense.inference.ollama import LocalInferenceError, OutputTokenExhausted
from systemsense.inference.profile import load_inference_profile
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_FOLLOWUP = "fixture.direct_origin_after_source"
_FACT = "direct_origin_status"
_BUDGET_MS = 180_000


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: object) -> str:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return _sha(path)


def _error_category(error: Exception) -> str:
    if isinstance(error, OutputTokenExhausted):
        return "output_token_exhausted"
    if isinstance(error, LocalInferenceError):
        return "local_inference_error"
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, (ValueError, AssertionError)):
        return "validation_or_invariant"
    return "other_exception"


class _TracedReasoner:
    def __init__(self, providers: AdvisoryProviders, *, initial_request_path: Path) -> None:
        self._reasoner = providers.reasoning
        self._initial_request_path = initial_request_path
        self.exchanges: list[tuple[ReasoningRequest, ReasoningResponse]] = []
        self.receipts: list[dict[str, str | int]] = []
        self._current: ReasoningRequest | None = None
        client = cast(OllamaReasoningProvider, self._reasoner)._client  # pyright: ignore[reportPrivateUsage]
        original_complete = client.complete

        def traced_complete(
            *, model: str, prompt: str, schema: Mapping[str, object], timeout_seconds: float
        ) -> dict[str, JsonValue]:
            request = self._current
            if request is None:
                raise RuntimeError("model return has no active reasoning request")
            try:
                raw = original_complete(
                    model=model, prompt=prompt, schema=schema, timeout_seconds=timeout_seconds
                )
            except Exception as error:
                # Never retain transport text, raw advice, or a partial model answer.
                self.receipts.append(
                    {"call_index": len(self.receipts) + 1, "outcome": _error_category(error)}
                )
                raise
            self.receipts.append(
                classify_returned_advice(
                    raw,
                    request=request,
                    prompt=prompt,
                    schema=schema,
                    call_index=len(self.receipts) + 1,
                )
            )
            return raw

        client.complete = traced_complete

    @property
    def identity(self) -> ProviderIdentity:
        return self._reasoner.identity

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        if (
            not self._initial_request_path.exists()
            and request.selected_sources
            and not any(item.probe_id == _FOLLOWUP for item in request.evidence_context)
        ):
            _write(self._initial_request_path, request.model_dump(mode="json"))
        self._current = request
        try:
            response = self._reasoner.investigate(request)
            self.exchanges.append((request, response))
            return response
        finally:
            self._current = None


def select_trajectory(
    exchanges: list[tuple[ReasoningRequest, ReasoningResponse]],
    *,
    selected_source_id: str,
) -> tuple[dict[str, Any], dict[str, int | None]]:
    first_index = next(
        (
            index
            for index, (request, response) in enumerate(exchanges)
            if not response.degraded
            and selected_source_id in {str(item.evidence_id) for item in request.selected_sources}
            and _FOLLOWUP in {probe.probe_id for probe in response.distinguishing_probes}
            and _FOLLOWUP not in request.completed_probe_ids
            and not any(item.probe_id == _FOLLOWUP for item in request.evidence_context)
            and _FOLLOWUP in {probe.probe_id for probe in request.available_probes}
        ),
        None,
    )
    second_index = (
        next(
            (
                index
                for index, (request, response) in enumerate(exchanges)
                if index > first_index
                and not response.degraded
                and any(item.probe_id == _FOLLOWUP for item in request.evidence_context)
            ),
            None,
        )
        if first_index is not None
        else None
    )

    def packet(index: int | None) -> dict[str, Any] | None:
        if index is None:
            return None
        request, response = exchanges[index]
        return {
            "request": request.model_dump(mode="json"),
            "response": response.model_dump(mode="json"),
        }

    return (
        {"schema_version": 1, "first": packet(first_index), "second": packet(second_index)},
        {"first_index": first_index, "second_index": second_index},
    )


def run(output_dir: Path, *, profile_path: Path, outcome_file: Path) -> dict[str, Any]:
    """Run exactly one fixture cell after A has granted the model/host slot."""

    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    if outcome_file.stat().st_size > 32:
        raise ValueError("synthetic outcome file exceeds bounded value length")
    followup_value = outcome_file.read_text(encoding="ascii").strip()
    if followup_value not in {"online", "offline"}:
        raise ValueError("synthetic outcome must be one registered categorical value")
    profile = load_inference_profile(profile_path.resolve())
    resources, pin = profile.managed_resources, profile.managed_reasoning
    if resources is None or pin is None or profile.investigation_budget_ms != _BUDGET_MS:
        raise ValueError("expected pinned warm profile with 180-second case budget")
    ledger = TreeHostInferenceLeaseLedger(
        (Path(os.environ["LOCALAPPDATA"]) / "SystemSense" / "host-gpu-lease-v3.sqlite3").resolve(),
        LeaseBudget(
            cpu_slots=2,
            ram_bytes=resources.peak_ram_bytes + pin.peak_ram_bytes,
            vram_bytes=resources.peak_vram_bytes + pin.peak_vram_bytes,
            gpu_device_index=resources.gpu_device_index,
        ),
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "code_head": _git_head(),
        "started_at": datetime.now(UTC).isoformat(),
        "profile_sha256": _sha(profile_path),
        "runner_sha256": _sha(Path(__file__)),
        "fixture_sha256": {
            "source_backed_full_run": _sha(Path(__file__).with_name("source_backed_full_run.py")),
            "source_task_relation_red": _sha(
                Path(__file__).with_name("source_task_relation_red.py")
            ),
            "advisory_validation_boundary": _sha(
                Path(__file__).with_name("advisory_validation_boundary.py")
            ),
        },
        "model": pin.model,
        "model_digest": pin.model_digest,
        "case_budget_ms": _BUDGET_MS,
        "fixture_scope": "synthetic_network_browser_one_cell",
        "decision_policy": "keyword_baseline",
        "source_choice_policy": "frozen_fixture_ranker",
        "hidden_followup_value": "evaluator_only",
    }
    providers: AdvisoryProviders | None = None
    tracer: _TracedReasoner | None = None
    try:
        if ledger.migrate_from_v3() != "migrated":
            raise RuntimeError("host lease migration unavailable")
        providers = load_deep_only_v4_providers(profile, ledger)
        tracer = _TracedReasoner(
            providers, initial_request_path=output_dir / "policy-visible" / "initial-request.json"
        )
        cells = run_balanced_relation_probe(
            output_dir / "cases",
            domain_filter="network_browser",
            matched_indices=(49,),
            chosen_indices=(49,),
            reasoning_factory=lambda: tracer,
            followup_direct_status=followup_value,
            allow_evicted_choice=True,
            case_budget_ms=_BUDGET_MS,
        )
        if len(cells) != 1:
            raise ValueError("expected exactly one synthetic network cell")
        cell = cells[0]
        visible, indices = select_trajectory(
            tracer.exchanges, selected_source_id=cell["chosen_evidence_id"]
        )
        visible_sha = _write(output_dir / "policy-visible" / "trajectory.json", visible)
        with SQLiteStore(Path(cell["database"])) as store:
            case_id = cell["task_observation"]["case_id"]
            followup_rows = store.connection.execute(
                "SELECT record_json FROM evidence WHERE case_id=? AND "
                "json_extract(record_json,'$.collector.id')=?",
                (case_id, _FOLLOWUP),
            ).fetchall()
            executions = [
                {
                    "status": row[0],
                    "execution_id": row[1],
                    "probe_version": row[2],
                    "started_at": row[3],
                    "finished_at": row[4],
                    "followup_admission_id": row[5],
                }
                for row in store.connection.execute(
                    "SELECT status,execution_id,probe_version,started_at,finished_at,"
                    "followup_admission_id FROM probe_executions "
                    "WHERE case_id=? AND probe_id=?",
                    (case_id, _FOLLOWUP),
                )
            ]
        observed = [json.loads(row[0]) for row in followup_rows]
        first_index = indices["first_index"]
        first_present = first_index is not None
        second_present = indices["second_index"] is not None
        first_response = tracer.exchanges[first_index][1] if first_index is not None else None
        first_request = tracer.exchanges[first_index][0] if first_index is not None else None
        selected_source_visible = first_request is not None and cell["chosen_evidence_id"] in {
            str(item.evidence_id) for item in first_request.selected_sources
        }
        first_prediction_count = (
            sum(
                fact.probe_id == _FOLLOWUP and fact.fact_name == _FACT
                for hypothesis in first_response.hypotheses
                for fact in hypothesis.expected_facts
            )
            if first_response is not None
            else 0
        )
        successful_followup = (
            len(executions) == 1
            and executions[0]["status"] == "ok"
            and executions[0]["probe_version"] == 1
            and len(observed) == 1
            and any(
                fact["name"] == _FACT and fact["value"] == followup_value
                for fact in observed[0]["facts"]
            )
        )
        private = {
            "source_choice": cell["chosen_evidence_id"],
            "source_choice_policy": "frozen_fixture_ranker_not_model_selected",
            "alternative_evidence_id": cell["alternative_evidence_id"],
            "selected_readback": cell["selected_readback"],
            "alternative_readback": cell["alternative_readback"],
            "followup_record": observed,
            "followup_executions": executions,
            "model_call_receipts": tracer.receipts,
            "provider_exchanges": [
                {
                    "request": request.model_dump(mode="json"),
                    "response": response.model_dump(mode="json"),
                }
                for request, response in tracer.exchanges
            ],
            "terminal_status": cell["status"],
            "terminal_outcome": cell["outcome"],
            "terminal_assessment": cell["assessment"],
            "terminal_stop_reason": cell["terminal_stop_reason"],
        }
        private_sha = _write(output_dir / "evaluator-only" / "readback.json", private)
        manifest.update(
            {
                "status": "completed",
                "checkpoint_sha256": cell["checkpoint_sha256"],
                "first_registered_check_proposed": first_present,
                "selected_source_visible": selected_source_visible,
                "first_returned_prediction_count": first_prediction_count,
                "followup_executed_once": successful_followup,
                "second_advisory_after_observation": second_present,
                "check_loop_mechanics_gate": (
                    first_present
                    and selected_source_visible
                    and successful_followup
                    and second_present
                ),
                "prediction_then_probe_mechanics": (
                    first_prediction_count > 0 and successful_followup and second_present
                ),
                "rival_response_correctness": "independent_review_required",
                "reasoning_calls": len(tracer.exchanges),
                "model_returns_or_failures": len(tracer.receipts),
                "policy_visible_sha256": visible_sha,
                "evaluator_only_sha256": private_sha,
                "database_sha256": _sha(Path(cell["database"])),
                "app_run_elapsed_ms": cell["app_run_elapsed_ms"],
            }
        )
    except Exception as error:
        manifest.update({"status": "failed", "error_category": _error_category(error)})
    finally:
        if tracer is not None and manifest.get("status") == "failed":
            partial = {
                "model_call_receipts": tracer.receipts,
                "provider_exchanges": [
                    {
                        "request": request.model_dump(mode="json"),
                        "response": response.model_dump(mode="json"),
                    }
                    for request, response in tracer.exchanges
                ],
            }
            manifest["partial_exchanges_sha256"] = _write(
                output_dir / "evaluator-only" / "partial-exchanges.json", partial
            )
        if providers is not None:
            manifest["reasoning_provider_mode"] = providers.effective_mode
            manifest["reasoning_provider_id"] = providers.reasoning.identity.provider_id
            try:
                providers.close()
                manifest["provider_close"] = "returned"
            except Exception as error:
                manifest["provider_close"] = _error_category(error)
                manifest["status"] = "failed"
        if tracer is not None:
            manifest["model_call_receipts"] = tracer.receipts
            manifest["reasoning_calls"] = len(tracer.exchanges)
        initial_request_path = output_dir / "policy-visible" / "initial-request.json"
        if initial_request_path.exists():
            manifest["initial_request_sha256"] = _sha(initial_request_path)
        manifest["finished_at"] = datetime.now(UTC).isoformat()
        _write(output_dir / "manifest.json", manifest)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("examples/warm-local-development.profile.json"),
    )
    parser.add_argument("--outcome-file", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output_dir, profile_path=args.profile, outcome_file=args.outcome_file)
    print(json.dumps(result, sort_keys=True))
    if result["status"] != "completed" or not result.get("check_loop_mechanics_gate"):
        raise SystemExit(2)
