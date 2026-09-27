"""CPU-only audit of one archived local-model prediction against probe discovery.

The archived model call is never replayed. A prompt capture uses a client that
raises before transport, and the registered fixture handler is never executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from benchmarks.source_backed_frontier_pilot import (
    _CASES,  # pyright: ignore[reportPrivateUsage]
    _git_head,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_full_run import _app  # pyright: ignore[reportPrivateUsage]
from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import JsonValue
from systemsense.inference.ollama import OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.reasoning.contracts import ExpectedFact, ReasoningRequest, ReasoningResponse
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_SOURCE_SHA = "5ea8534ed8ecf118942ca7cad6c04d0a321361f582490b26b5cdf0068c6bf5cc"
_ACTUAL_SHA = "b0f5e4456481664f39b9193874e4889b9e3646d0232428e9a7b09a589f66ad8f"
_FOLLOWUP = "fixture.direct_origin_after_source"
# This is a B fixture-handler input bound, not a model-visible registry declaration.
_FIXTURE_VALUES = frozenset({"online", "offline"})


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Any) -> str:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return _sha(path)


class _CaptureOnly(RuntimeError):
    pass


class _CaptureClient(OllamaChatClient):
    def __init__(self, config: LocalInferenceConfig) -> None:
        super().__init__(config=config)
        self.packet: dict[str, object] | None = None

    def fits_context(self, prompt: str, schema: Mapping[str, object]) -> bool:
        del prompt, schema
        return True

    def complete(
        self, *, model: str, prompt: str, schema: Mapping[str, object], timeout_seconds: float
    ) -> dict[str, JsonValue]:
        del model, schema, timeout_seconds
        self.packet = cast(dict[str, object], json.loads(prompt))
        raise _CaptureOnly("capture before transport")


def _prompt_probe(request: ReasoningRequest, probe_id: str) -> dict[str, object]:
    """Read the actual prompt projection without making any model or network call."""

    config = LocalInferenceConfig(enabled=True, reasoning_model="capture-only")
    client = _CaptureClient(config)
    fresh = ReasoningRequest.model_validate(
        request.model_copy(
            update={"deadline_at": datetime.now(UTC) + timedelta(seconds=120)}
        ).model_dump(mode="json")
    )
    try:
        OllamaReasoningProvider(config, client=client).investigate(fresh)
    except _CaptureOnly:
        pass
    if client.packet is None:
        raise ValueError("no prompt was captured before transport")
    probes = cast(list[dict[str, object]], client.packet["available_probes"])
    return next(item for item in probes if item.get("probe_id") == probe_id)


def score_predictions(
    predictions_with_ids: tuple[tuple[str, ExpectedFact], ...],
    *,
    probe_id: str,
    declared_output_names: frozenset[str],
    declared_value_domain: frozenset[str] | None,
    fixture_value_domain: frozenset[str],
    prompt_probe: Mapping[str, object],
) -> dict[str, Any]:
    """An unregistered output name never earns prospective test credit."""

    visible_names = frozenset(
        str(item["name"]) for item in cast(list[dict[str, object]], prompt_probe.get("outputs", []))
    )
    visible_domain = [
        {"name": item.get("name"), "allowed_values": item.get("allowed_values")}
        for item in cast(list[dict[str, object]], prompt_probe.get("outputs", []))
    ]
    predictions: list[dict[str, Any]] = []
    for hypothesis_id, expected in predictions_with_ids:
        if expected.probe_id != probe_id:
            continue
        name_declared = expected.fact_name in declared_output_names
        fixture_value_valid = expected.expected_value in fixture_value_domain
        declared_value_valid = (
            None
            if declared_value_domain is None
            else expected.expected_value in declared_value_domain
        )
        predictions.append(
            {
                "hypothesis_id": hypothesis_id,
                "probe_id": expected.probe_id,
                "fact_name": expected.fact_name,
                "expected_value": expected.expected_value,
                "name_declared": name_declared,
                "value_in_fixture_domain": fixture_value_valid,
                "value_in_declared_domain": declared_value_valid,
                "useful_prospective_test": bool(name_declared and declared_value_valid is True),
            }
        )
    return {
        "probe_id": probe_id,
        "model_visible_probe_fields": sorted(prompt_probe),
        "model_visible_output_names": sorted(visible_names),
        "model_visible_value_domain": visible_domain,
        "registered_output_names": sorted(declared_output_names),
        "registered_value_domain": None
        if declared_value_domain is None
        else sorted(declared_value_domain),
        "fixture_value_domain_evaluator_only": sorted(fixture_value_domain),
        "predictions": predictions,
        "invalid_output_name_count": sum(not row["name_declared"] for row in predictions),
        "fixture_value_mismatch_count": sum(
            not row["value_in_fixture_domain"] for row in predictions
        ),
        "useful_prospective_test_count": sum(row["useful_prospective_test"] for row in predictions),
        "actual_model_followup_execution": "unrun",
    }


def write_audit(output_dir: Path, *, team_dir: Path) -> dict[str, Any]:
    """Freeze policy-visible exchange and separately score exact registry alignment."""

    source_path = team_dir / "b-two-turn-732ad14" / "policy-visible" / "trajectory.json"
    actual_path = team_dir / "a-actual-prospective-once-c.json"
    if _sha(source_path) != _SOURCE_SHA or _sha(actual_path) != _ACTUAL_SHA:
        raise ValueError("archived first request or actual response changed")
    source = json.loads(source_path.read_text(encoding="utf-8"))
    actual = json.loads(actual_path.read_text(encoding="utf-8"))
    response = ReasoningResponse.model_validate(actual["response"])
    original = ReasoningRequest.model_validate(source["first"]["request"])
    request = ReasoningRequest.model_validate(
        original.model_copy(
            update={"deadline_at": response.deadline_at, "budget_ms": 90_000}
        ).model_dump(mode="json")
    )
    request_sha = hashlib.sha256(request.model_dump_json().encode()).hexdigest()
    if request_sha != actual["replay_request_sha256"]:
        raise ValueError("archived replay request hash does not match")
    response.validate_against(request)

    output_dir.mkdir(parents=True, exist_ok=False)
    visible_dir = output_dir / "policy-visible"
    private_dir = output_dir / "evaluator-only"
    visible_dir.mkdir()
    private_dir.mkdir()
    visible = {
        "schema_version": 1,
        "source_policy_sha256": _SOURCE_SHA,
        "archived_actual_sha256": _ACTUAL_SHA,
        "actual_call_code_sha": actual["code_sha"],
        "evaluation_base_code_sha": "c4c8e9dd7536e0c0063df9c7729510de75d015a0",
        "model": actual["model"],
        "model_digest": actual["model_digest"],
        "replay_request_sha256": request_sha,
        "request": request.model_dump(mode="json"),
        "response": response.model_dump(mode="json"),
    }
    policy_sha = _write(visible_dir / "first_exchange.json", visible)
    if policy_sha != "51830bb0cf74d79a205fd3a60a6d37f119b584f88c130caacf1de54cf092cad3":
        raise ValueError("policy-visible first exchange differs from blind freeze")

    with SQLiteStore(private_dir / "registry.db") as store:
        app = _app(store, _CASES[0], None, followup_direct_status="offline")
        discovered = app.runtime.discover_applicable_tools(
            observed_probe_ids=frozenset({"fixture.task_baseline"}),
            available_target_kinds=frozenset(),
            allowed_sensitivities=frozenset({Sensitivity.SYSTEM_METADATA}),
            allowed_resources=frozenset({"cpu"}),
            remaining_budget_ms=90_000,
        )
        metadata = next(item for item in discovered if item.probe_id == _FOLLOWUP)
        for invalid in ("running", "disabled"):
            try:
                _app(store, _CASES[0], None, followup_direct_status=invalid)
            except ValueError:
                pass
            else:
                raise ValueError("fixture unexpectedly accepts model prediction value")
    prompt_probe = _prompt_probe(request, _FOLLOWUP)
    declared_domains = [getattr(item, "allowed_values", None) for item in metadata.outputs]
    declared_domain = (
        frozenset(str(value) for value in declared_domains[0])
        if len(declared_domains) == 1 and declared_domains[0] is not None
        else None
    )
    review = score_predictions(
        tuple(
            (hypothesis.hypothesis_id, expected)
            for hypothesis in response.hypotheses
            for expected in hypothesis.expected_facts
        ),
        probe_id=_FOLLOWUP,
        declared_output_names=frozenset(item.name for item in metadata.outputs),
        declared_value_domain=declared_domain,
        fixture_value_domain=_FIXTURE_VALUES,
        prompt_probe=prompt_probe,
    )
    review.update(
        {
            "archived_response_valid_against_request": True,
            "archived_provider": response.provider.model_dump(mode="json"),
            "registry_metadata": metadata.model_dump(mode="json"),
            "captured_prompt_probe": prompt_probe,
            "model_call_outcomes": actual["model_calls"],
            "archived_elapsed_seconds": actual["elapsed_seconds"],
            "interpretation": (
                "Registered probe proposal, but neither expected fact is an output of that "
                "probe. No model-directed follow-up was executed; no diagnostic utility credit."
            ),
        }
    )
    review_sha = _write(private_dir / "review.json", review)
    manifest = {
        "schema_version": 1,
        "evaluation_code_head": _git_head(),
        "archived_actual_sha256": _ACTUAL_SHA,
        "source_policy_sha256": _SOURCE_SHA,
        "replay_request_sha256": request_sha,
        "policy_visible_sha256": policy_sha,
        "evaluator_only_sha256": review_sha,
        "registered_output_count": len(metadata.outputs),
        "predictions": len(review["predictions"]),
        "invalid_output_name_count": review["invalid_output_name_count"],
        "useful_prospective_test_count": review["useful_prospective_test_count"],
        "actual_model_followup_execution": "unrun",
    }
    _write(output_dir / "manifest.json", manifest)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--team-dir", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(write_audit(arguments.output_dir, team_dir=arguments.team_dir), indent=2))
