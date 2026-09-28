"""The private model-call recorder emits hashes and bounded failure labels only."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

from benchmarks.advisory_validation_boundary import classify_returned_advice
from systemsense.decision.contracts import ProbeCapability, ResourceClass
from systemsense.domain.ids import CaseId, JsonValue
from systemsense.domain.probes import ProbePredictionOutputV1
from systemsense.reasoning.contracts import ReasoningRequest


def _request() -> ReasoningRequest:
    return ReasoningRequest(
        schema_version=6,
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="capture:one",
        deadline_at=datetime.now(UTC) + timedelta(minutes=1),
        objective="Synthetic case for private validation receipt.",
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="Application follow-up",
                cost_ms=25,
                resource_class=ResourceClass.CPU,
                probe_version=1,
                prediction_outputs=(
                    ProbePredictionOutputV1(
                        name="application_state", allowed_values=("failed", "running")
                    ),
                ),
            ),
        ),
        budget_ms=500,
        max_probes=1,
    )


def test_returned_advice_receipt_distinguishes_schema_and_fitted_menu_without_raw_text() -> None:
    request = _request()
    schema = {"type": "object", "properties": {"summary": {"type": "string"}}}
    visible_prompt = json.dumps(
        {
            "available_probes": [
                {
                    "probe_id": "application.snapshot",
                    "prediction_outputs": [
                        {"name": "application_state", "allowed_values": ["failed", "running"]}
                    ],
                }
            ]
        }
    )
    hidden_prompt = json.dumps({"available_probes": [{"probe_id": "application.snapshot"}]})
    raw: dict[str, JsonValue] = {
        "summary": "PRIVATE_RESPONSE_CONTENT",
        "hypotheses": [
            {
                "hypothesis_id": "h_application",
                "statement": "The application may still be failed.",
                "expected_facts": [
                    {
                        "probe_id": "application.snapshot",
                        "fact_name": "application_state",
                        "expected_value": "failed",
                    }
                ],
            }
        ],
    }
    schema_rejected = classify_returned_advice(
        {**raw, "summary": "", "PRIVATE_EXTRA_FIELD": "PRIVATE_RESPONSE_CONTENT"},
        request=request,
        prompt=visible_prompt,
        schema=schema,
        call_index=1,
    )
    hidden_rejected = classify_returned_advice(
        raw, request=request, prompt=hidden_prompt, schema=schema, call_index=2
    )
    accepted_initially = classify_returned_advice(
        raw, request=request, prompt=visible_prompt, schema=schema, call_index=3
    )
    later_invalid = classify_returned_advice(
        {**raw, "distinguishing_probe_ids": ["unregistered.probe"]},
        request=request,
        prompt=visible_prompt,
        schema=schema,
        call_index=4,
    )

    assert [
        receipt["validation_boundary"]
        for receipt in (schema_rejected, hidden_rejected, accepted_initially)
    ] == ["pydantic_schema", "fitted_visible_prediction", "passed_initial_validation"]
    assert later_invalid["validation_boundary"] == "passed_initial_validation"
    loci = schema_rejected["validation_loci"]
    assert isinstance(loci, tuple)
    assert ("summary", "string_too_short") in loci
    assert 1 <= len(loci) <= 4
    assert hidden_rejected["validation_loci"] == ()
    assert accepted_initially["validation_loci"] == ()
    assert [
        receipt["call_index"] for receipt in (schema_rejected, hidden_rejected, accepted_initially)
    ] == [
        1,
        2,
        3,
    ]
    assert (
        accepted_initially["request_sha256"]
        == hashlib.sha256(request.model_dump_json().encode()).hexdigest()
    )
    assert (
        accepted_initially["prompt_sha256"] == hashlib.sha256(visible_prompt.encode()).hexdigest()
    )
    assert (
        accepted_initially["schema_sha256"]
        == hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()
    )
    for receipt in (schema_rejected, hidden_rejected, accepted_initially):
        serialized = json.dumps(receipt)
        assert "PRIVATE_RESPONSE_CONTENT" not in serialized
        assert "PRIVATE_EXTRA_FIELD" not in serialized
        assert "h_application" not in serialized
        assert set(receipt) == {
            "call_index",
            "request_sha256",
            "prompt_sha256",
            "schema_sha256",
            "validation_boundary",
            "validation_loci",
        }
