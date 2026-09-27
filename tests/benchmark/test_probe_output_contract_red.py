"""Freeze the registered categorical output needed by prospective predictions."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from pydantic import BaseModel, ValidationError

from benchmarks.prospective_output_contract_audit import (
    _prompt_probe,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_frontier_pilot import _CASES  # pyright: ignore[reportPrivateUsage]
from benchmarks.source_backed_full_run import _app  # pyright: ignore[reportPrivateUsage]
from systemsense.decision.contracts import ProviderIdentity, ResourceClass
from systemsense.domain import probes as probe_domain
from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import CaseId
from systemsense.reasoning.contracts import (
    ExpectedFact,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
)
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_PROBE_ID = "fixture.direct_origin_after_source"


def _request(schema_version: int, *, output_contract: bool = False) -> ReasoningRequest:
    capability: dict[str, object] = {
        "probe_id": _PROBE_ID,
        "description": "Synthetic direct-origin observation",
        "cost_ms": 25,
        "resource_class": ResourceClass.CPU,
    }
    if output_contract:
        capability["probe_version"] = 1
        capability["prediction_outputs"] = [
            {"name": "direct_origin_status", "allowed_values": ["online", "offline"]}
        ]
    return ReasoningRequest.model_validate(
        {
            "schema_version": schema_version,
            "case_id": str(CaseId.new()),
            "state_version": 1,
            "correlation_id": "fixture_output_contract",
            "deadline_at": datetime.now(UTC) + timedelta(minutes=1),
            "objective": "Inspect a synthetic browser symptom",
            "available_probes": [capability],
            "budget_ms": 1000,
            "max_probes": 1,
        }
    )


def _response(request: ReasoningRequest, *, fact_name: str, value: str) -> ReasoningResponse:
    return ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="fixture-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="The synthetic symptom is unresolved.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_fixture",
                statement="A direct-origin issue remains possible.",
                status=HypothesisStatus.UNRESOLVED,
                expected_facts=(
                    ExpectedFact(
                        probe_id=_PROBE_ID,
                        fact_name=fact_name,
                        expected_value=value,
                    ),
                ),
            ),
        ),
    )


def test_registered_prediction_output_has_finite_value_domain() -> None:
    output_type = cast(
        type[BaseModel],
        probe_domain.ProbePredictionOutputV1,  # pyright: ignore[reportUnknownMemberType,reportAttributeAccessIssue]
    )
    output = output_type.model_validate(
        {"name": "direct_origin_status", "allowed_values": ["online", "offline"]}
    )
    assert set(output.model_dump(mode="json")["allowed_values"]) == {"online", "offline"}
    unbounded = output_type.model_validate({"name": "direct_origin_status", "allowed_values": []})
    assert unbounded.model_dump(mode="json")["allowed_values"] == []
    with pytest.raises(ValidationError):
        output_type.model_validate({"name": "direct_origin_status", "allowed_values": ["secret"]})


def test_discovery_output_hint_alone_does_not_declare_prediction_values(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "fixture.db") as store:
        app = _app(store, _CASES[0], None, followup_direct_status="offline")
        discovered = app.runtime.discover_applicable_tools(
            observed_probe_ids=frozenset({"fixture.task_baseline"}),
            available_target_kinds=frozenset(),
            allowed_sensitivities=frozenset({Sensitivity.SYSTEM_METADATA}),
            allowed_resources=frozenset({"cpu"}),
            remaining_budget_ms=90_000,
        )
    followup = next(item for item in discovered if item.probe_id == _PROBE_ID)
    assert followup.probe_version == 1
    assert len(followup.outputs) == 1
    assert followup.outputs[0].name == "direct_origin_status"
    assert "allowed_values" not in followup.outputs[0].model_dump(mode="json")


def test_v6_rejects_archived_wrong_name_and_value_but_accepts_aligned_prediction() -> None:
    request = _request(6, output_contract=True)
    assert _response(request, fact_name="direct_origin_status", value="offline").validate_against(
        request
    )
    for name, value in (
        ("browser_direct_origin_reachable", "running"),
        ("browser_direct_origin_reachable", "disabled"),
        ("direct_origin_status", "running"),
    ):
        with pytest.raises(ReasoningValidationError):
            _response(request, fact_name=name, value=value).validate_against(request)

    prompt_probe = _prompt_probe(request, _PROBE_ID)
    outputs = prompt_probe["prediction_outputs"]
    assert outputs == [{"name": "direct_origin_status", "allowed_values": ["online", "offline"]}]


def test_v6_probe_without_predictable_output_disables_expected_facts() -> None:
    request = _request(6)
    with pytest.raises(ReasoningValidationError):
        _response(request, fact_name="direct_origin_status", value="offline").validate_against(
            request
        )
    schema = OllamaReasoningProvider._advice_schema(  # pyright: ignore[reportPrivateUsage]
        request, request.evidence_ids
    )
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    fields = cast(dict[str, dict[str, object]], definitions["_HypothesisAdvice"]["properties"])
    assert fields["expected_facts"]["maxItems"] == 0


@pytest.mark.parametrize("schema_version", [1, 2, 3, 4, 5])
def test_historical_reasoning_requests_preserve_expected_fact_validation(
    schema_version: int,
) -> None:
    request = _request(schema_version)
    response = _response(request, fact_name="browser_direct_origin_reachable", value="running")
    assert response.validate_against(request) == response
