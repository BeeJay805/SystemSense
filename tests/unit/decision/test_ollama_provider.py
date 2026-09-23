from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from systemsense.decision.contracts import DecisionRequest, ProbeCapability, ResourceClass
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.domain.ids import CaseId
from systemsense.inference.ollama import LocalInferenceError
from systemsense.inference.settings import LocalInferenceConfig

NOW = datetime.now(UTC)


def test_default_request_deadline_tracks_request_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(_request.__globals__, "NOW", datetime.now(UTC) - timedelta(minutes=2))
    assert _request().deadline_at > datetime.now(UTC) + timedelta(seconds=50)


class FakeTransport:
    def __init__(self, content: str | Exception) -> None:
        self.content = content
        self.calls = 0

    def tags(self, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        del timeout_seconds, max_response_bytes
        return json.dumps(
            {
                "models": [
                    {
                        "name": "small-local:latest",
                        "model": "small-local:latest",
                        "size": 1024,
                        "digest": "a" * 64,
                        "details": {"format": "gguf"},
                    }
                ]
            }
        ).encode()

    def show(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        del body, timeout_seconds, max_response_bytes
        return json.dumps(
            {
                "details": {"format": "gguf"},
                "model_info": {"general.architecture": "test"},
            }
        ).encode()

    def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        del body, timeout_seconds, max_response_bytes
        self.calls += 1
        if isinstance(self.content, Exception):
            raise self.content
        return json.dumps(
            {"message": {"role": "assistant", "content": self.content}, "done": True}
        ).encode()


def _request(*, deadline_at: datetime | None = None, budget_ms: int = 500) -> DecisionRequest:
    return DecisionRequest(
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="corr_local",
        deadline_at=deadline_at or datetime.now(UTC) + timedelta(minutes=1),
        symptom="application fails to launch",
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="bounded application snapshot",
                keywords=frozenset({"application", "launch"}),
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=budget_ms,
        max_probes=1,
    )


def _config() -> LocalInferenceConfig:
    return LocalInferenceConfig(enabled=True, decision_model="small-local")


def test_provider_reconstructs_trusted_envelope_and_catalog_fields() -> None:
    transport = FakeTransport(
        json.dumps(
            {
                "proposals": [
                    {
                        "probe_id": "application.snapshot",
                        "purpose": "distinguish_hypotheses",
                        "priority": 0.9,
                        "depends_on": [],
                    }
                ],
                "requires_reasoning": True,
                "stop_reason": None,
            }
        )
    )
    request = _request()
    response = OllamaDecisionProvider(_config(), transport=transport).decide(request)

    assert response.case_id == request.case_id
    assert response.provider.provider_id == "ollama-local-decision"
    assert response.proposals[0].estimated_cost_ms == 100
    assert response.proposals[0].resource_class is ResourceClass.CPU
    assert response.validate_against(request) == response


def test_provider_fails_degraded_to_deterministic_baseline_on_invalid_or_unavailable() -> None:
    for failure in ("not-json", LocalInferenceError("unavailable")):
        provider = OllamaDecisionProvider(_config(), transport=FakeTransport(failure))
        response = provider.decide(_request())
        assert response.degraded is True
        assert response.provider.provider_id == "keyword-baseline"
        assert provider.status.available is False


def test_provider_does_not_infer_after_deadline_and_rejects_over_budget_advice() -> None:
    transport = FakeTransport("{}")
    provider = OllamaDecisionProvider(_config(), transport=transport)
    assert provider.decide(_request(deadline_at=NOW - timedelta(seconds=1))).degraded is True
    assert transport.calls == 0

    over_budget_transport = FakeTransport(
        json.dumps(
            {
                "proposals": [
                    {
                        "probe_id": "application.snapshot",
                        "purpose": "refresh_evidence",
                        "priority": 1,
                    }
                ]
            }
        )
    )
    over_budget = OllamaDecisionProvider(_config(), transport=over_budget_transport).decide(
        _request(budget_ms=1)
    )
    assert over_budget.degraded is True
    assert over_budget.proposals == ()
    assert over_budget_transport.calls == 1
