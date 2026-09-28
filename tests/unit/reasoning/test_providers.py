from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from systemsense.decision.contracts import (
    FastSignalKind,
    ProbeCapability,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.domain.affected_task import AffectedTaskKind, ReportedAffectedTaskV1
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, JsonValue
from systemsense.domain.probes import ProbePredictionOutputV1
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.ollama import LocalInferenceError, OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.knowledge.windows_errors import WindowsErrorCatalog, WindowsErrorSource
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    FastAttentionConcern,
    Hypothesis,
    HypothesisStatus,
    NoncausalHypothesisRefV1,
    NoncausalObservationReviewV1,
    PriorHypothesisRevisionRefV1,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
    hypothesis_revision_sha256,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.hypothesis_progression import progress_hypotheses
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.reasoning.structured import (
    _HypothesisAdvice,  # pyright: ignore[reportPrivateUsage]
    _ReasoningAdvice,  # pyright: ignore[reportPrivateUsage]
)

NOW = datetime.now(UTC)


class FakeTransport:
    def __init__(self, content: str) -> None:
        self.content = content
        self.last_body: bytes | None = None

    def tags(self, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        del timeout_seconds, max_response_bytes
        return json.dumps(
            {
                "models": [
                    {
                        "name": "reason-local:latest",
                        "model": "reason-local:latest",
                        "size": 1024,
                        "digest": "a" * 64,
                        "details": {"format": "gguf"},
                    },
                    {
                        "name": "small-local:latest",
                        "model": "small-local:latest",
                        "size": 1024,
                        "digest": "b" * 64,
                        "details": {"format": "gguf"},
                    },
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
        del timeout_seconds, max_response_bytes
        self.last_body = body
        return json.dumps(
            {"message": {"role": "assistant", "content": self.content}, "done": True}
        ).encode()


class SequencedAdviceTransport(FakeTransport):
    def __init__(self, contents: tuple[str, ...]) -> None:
        super().__init__(contents[0])
        self.contents = contents
        self.calls = 0

    def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.content = self.contents[min(self.calls, len(self.contents) - 1)]
        self.calls += 1
        return super().post(
            body, timeout_seconds=timeout_seconds, max_response_bytes=max_response_bytes
        )


class LengthThenAdviceTransport(FakeTransport):
    def __init__(self, *, always_length: bool = False) -> None:
        super().__init__('{"summary":"Cause remains unknown","hypotheses":[]}')
        self.always_length = always_length
        self.calls = 0
        self.bodies: list[dict[str, object]] = []

    def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.calls += 1
        self.bodies.append(json.loads(body))
        if self.always_length or self.calls == 1:
            return json.dumps(
                {
                    "message": {"role": "assistant", "content": "{"},
                    "done": True,
                    "done_reason": "length",
                }
            ).encode()
        return super().post(
            body, timeout_seconds=timeout_seconds, max_response_bytes=max_response_bytes
        )


def test_output_length_gets_one_tighter_retry_without_losing_evidence() -> None:
    transport = LengthThenAdviceTransport()
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(_request())

    assert transport.calls == 2
    assert not response.degraded
    first, second = transport.bodies
    output_schema = cast(dict[str, object], second["format"])
    properties = cast(dict[str, dict[str, object]], output_schema["properties"])
    assert properties["hypotheses"]["maxItems"] == 2
    first_messages = cast(list[dict[str, str]], first["messages"])
    second_messages = cast(list[dict[str, str]], second["messages"])
    first_prompt = json.loads(first_messages[1]["content"])
    second_prompt = json.loads(second_messages[1]["content"])
    assert first_prompt["evidence"] == second_prompt["evidence"]
    assert second_prompt["output_retry"]
    assert any("output token" in note for note in response.context_notes)


def test_output_length_twice_degrades_after_one_retry() -> None:
    transport = LengthThenAdviceTransport(always_length=True)
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(_request())

    assert transport.calls == 2
    assert response.degraded


def test_invalid_deep_shape_gets_one_bounded_retry_with_same_validation() -> None:
    invalid = json.dumps(
        {
            "summary": "Maybe",
            "hypotheses": [
                {"hypothesis_id": "invalid id", "statement": "Maybe", "status": "unresolved"}
            ],
        }
    )
    valid = json.dumps({"summary": "Cause remains unknown", "hypotheses": []})
    transport = SequencedAdviceTransport((invalid, valid))
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(_request())

    assert transport.calls == 2
    assert not response.degraded
    assert response.hypotheses[-1].hypothesis_id == "unknown_cause"
    assert transport.last_body is not None
    assert "validation_retry" in json.loads(transport.last_body)["messages"][1]["content"]


def test_twice_invalid_deep_shape_degrades_after_one_retry() -> None:
    invalid = json.dumps(
        {
            "summary": "Maybe",
            "hypotheses": [
                {"hypothesis_id": "invalid id", "statement": "Maybe", "status": "unresolved"}
            ],
        }
    )
    transport = SequencedAdviceTransport((invalid, invalid))
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(_request())

    assert transport.calls == 2
    assert response.degraded


def test_reasoner_accepts_only_a_client_bound_to_its_exact_config() -> None:
    config = LocalInferenceConfig(enabled=True, reasoning_model="reason-local")
    client = OllamaChatClient(config=config, transport=FakeTransport("{}"))
    assert OllamaReasoningProvider(config, client=client).identity.role == "reasoning"
    with pytest.raises(ValueError, match="differs"):
        OllamaReasoningProvider(
            config.model_copy(update={"endpoint": "http://127.0.0.1:11435/api/chat"}),
            client=client,
        )
    with pytest.raises(ValueError, match="either"):
        OllamaReasoningProvider(config, client=client, transport=FakeTransport("{}"))


def test_reasoner_uses_managed_client_gate_and_degrades_when_denied() -> None:
    config = LocalInferenceConfig(
        enabled=True,
        reasoning_model="reason-local:latest",
        reasoning_digest="a" * 64,
        allow_gpu=True,
    )
    transport = FakeTransport('{"summary":"Cause unknown","hypotheses":[]}')
    calls: list[str] = []
    client = OllamaChatClient(
        config=config,
        transport=transport,
        managed_call_admission=lambda: False,
        managed_abort=lambda: calls.append("retired") is None,
    )
    response = OllamaReasoningProvider(config, client=client).investigate(_request())
    assert response.degraded
    assert transport.last_body is None
    assert calls == ["retired"]


def test_reasoner_retains_bounded_transport_diagnostics_without_private_text() -> None:
    class BrokenTransport(FakeTransport):
        def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
            del body, timeout_seconds, max_response_bytes
            raise LocalInferenceError(
                "private request and response", phase="receive", error_code=10054
            )

    config = LocalInferenceConfig(
        enabled=True,
        reasoning_model="reason-local:latest",
        reasoning_digest="a" * 64,
    )
    provider = OllamaReasoningProvider(config, transport=BrokenTransport(""))
    response = provider.investigate(_request())
    assert response.degraded
    assert provider.status.detail == "LocalInferenceError:transport_receive_socket_10054"
    assert "private" not in provider.status.detail


def _request(
    status: EvidenceContextStatus = EvidenceContextStatus.OBSERVED,
    *,
    facts: dict[str, JsonValue] | None = None,
) -> ReasoningRequest:
    now = datetime.now(UTC)
    evidence_id = EvidenceId.new()
    return ReasoningRequest(
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="corr_reason",
        deadline_at=now + timedelta(minutes=1),
        objective="Explain the launch failure.",
        evidence_ids=(evidence_id,),
        evidence_context=(
            EvidenceContext(
                evidence_id=evidence_id,
                observed_at=now,
                captured_at=now,
                probe_id="application.snapshot",
                summary="The application snapshot reported a failed state.",
                facts=facts or {"application.state": "failed"},
                status=status,
            ),
        ),
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="application snapshot",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=500,
        max_probes=1,
    )


def _v6_prediction_request() -> ReasoningRequest:
    base = _request()
    capability = base.available_probes[0].model_copy(
        update={
            "probe_version": 1,
            "prediction_outputs": (
                ProbePredictionOutputV1(
                    name="application_state", allowed_values=("failed", "running")
                ),
            ),
        }
    )
    return ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "schema_version": 6,
            "available_probes": [capability.model_dump(mode="json")],
        }
    )


@pytest.mark.parametrize("length_first", [False, True])
def test_fitted_prediction_menu_cannot_authorize_hidden_fact_or_retry(
    monkeypatch: pytest.MonkeyPatch, length_first: bool
) -> None:
    request = _v6_prediction_request()
    hidden = json.dumps(
        {
            "summary": "A hidden prediction was proposed.",
            "hypotheses": [
                {
                    "hypothesis_id": "h_hidden",
                    "statement": "The next application state will be failed.",
                    "status": "unresolved",
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
    )
    transport = LengthThenAdviceTransport() if length_first else FakeTransport(hidden)
    if length_first:
        transport.content = hidden

    def fits(_self: OllamaChatClient, prompt: str, _schema: dict[str, object]) -> bool:
        probes = json.loads(prompt)["available_probes"]
        return not any("prediction_outputs" in probe for probe in probes)

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits)
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)

    assert response.degraded
    assert all(not hypothesis.expected_facts for hypothesis in response.hypotheses)
    bodies: list[dict[str, object]]
    if length_first:
        assert isinstance(transport, LengthThenAdviceTransport)
        bodies = transport.bodies
    else:
        assert transport.last_body is not None
        bodies = [cast(dict[str, object], json.loads(transport.last_body))]
    assert len(bodies) == (3 if length_first else 1)
    for body in bodies:
        messages = cast(list[dict[str, str]], body["messages"])
        fitted = json.loads(messages[1]["content"])
        assert fitted["evidence"][0]["evidence_id"] == str(request.evidence_ids[0])
        assert "prediction_outputs" not in fitted["available_probes"][0]
        schema = cast(dict[str, object], body["format"])
        definitions = cast(dict[str, dict[str, object]], schema["$defs"])
        fields = cast(dict[str, dict[str, object]], definitions["_HypothesisAdvice"]["properties"])
        assert fields["expected_facts"]["maxItems"] == 0


@pytest.mark.parametrize("optional_context", ("catalog", "graph"))
def test_v6_prompt_fit_keeps_registered_menu_after_optional_context_trim(
    monkeypatch: pytest.MonkeyPatch, optional_context: str
) -> None:
    base = _v6_prediction_request()
    cited = base.evidence_ids[0]
    prior = Hypothesis(
        hypothesis_id="h_prior",
        statement="A prior explanation still needs testing.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(cited,),
    )
    unseen = tuple(EvidenceId.new() for _ in range(8)) if optional_context == "catalog" else ()
    catalog = tuple(
        {"evidence_id": str(evidence_id), "summary": "Unseen catalog summary " * 40}
        for evidence_id in unseen
    )
    relations = (
        tuple(
            EvidenceRelation(
                relation_id=f"rel_{index:032x}",
                source_entity_id=EntityId.new(),
                target_entity_id=EntityId.new(),
                relationship=RelationKind.CORRELATED_WITH,
                memory_layer=MemoryLayer.MACHINE,
                assertion_status=AssertionStatus.OBSERVED,
                relation_version=1,
                evidence_ids=(cited,),
            )
            for index in range(6)
        )
        if optional_context == "graph"
        else ()
    )
    request = ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "evidence_ids": [str(cited), *(str(evidence_id) for evidence_id in unseen)],
            "previous_hypotheses": [prior.model_dump(mode="json")],
            "evidence_catalog": catalog,
            "catalog_has_more": bool(catalog),
            "relationships": [relation.model_dump(mode="json") for relation in relations],
        }
    )

    def fits(_self: OllamaChatClient, prompt: str, _schema: dict[str, object]) -> bool:
        packet = json.loads(prompt)
        # The simulated capacity admits the registered menu once this optional
        # material is bounded; cited observation content has no need to move.
        field = "evidence_catalog" if optional_context == "catalog" else "relationships"
        return len(packet[field]) <= 4

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits)
    transport = FakeTransport(
        json.dumps(
            {
                "summary": "The next application state remains uncertain.",
                "hypotheses": [
                    {
                        "hypothesis_id": "h_registered",
                        "statement": "The next application state will be failed.",
                        "status": "unresolved",
                        "supporting_evidence_ids": [str(cited)],
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
        )
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)

    assert transport.last_body is not None
    body = json.loads(transport.last_body)
    prompt = json.loads(body["messages"][1]["content"])
    assert prompt["evidence"][0]["evidence_id"] == str(cited)
    assert prompt["previous_hypotheses"][0]["supporting_evidence_ids"] == [str(cited)]
    assert prompt["available_probes"][0]["prediction_outputs"] == [
        {"name": "application_state", "allowed_values": ["failed", "running"]}
    ]
    assert body["format"]["$defs"]["ExpectedFact"]["anyOf"][0]["properties"]["expected_value"][
        "enum"
    ] == ["failed", "running"]
    if optional_context == "catalog":
        assert len(prompt["evidence_catalog"]) == 4
        assert prompt["catalog_page_truncated"] is True
    else:
        assert len(prompt["relationships"]) == 4
        assert prompt["relationship_omissions"] == 2
    assert not response.degraded
    assert response.hypotheses[0].expected_facts[0].expected_value == "failed"


@pytest.mark.parametrize("schema_version", [1, 2, 3, 4, 5])
def test_legacy_reasoning_probe_fields_and_prompt_remain_unchanged(schema_version: int) -> None:
    base = _request()
    request = ReasoningRequest.model_validate(
        {**base.model_dump(mode="json"), "schema_version": schema_version}
    )
    serialized = request.model_dump(mode="json")
    assert "probe_version" not in serialized["available_probes"][0]
    assert "prediction_outputs" not in serialized["available_probes"][0]
    transport = FakeTransport('{"summary":"Cause remains unknown","hypotheses":[]}')
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)
    assert not response.degraded
    assert transport.last_body is not None
    body = json.loads(transport.last_body)
    prompt = json.loads(body["messages"][1]["content"])
    assert prompt["available_probes"] == [
        {"probe_id": "application.snapshot", "description": "application snapshot"}
    ]
    assert "registered probes and categorical values only" in prompt["task"]


def test_reported_affected_task_reaches_deep_as_unverified_context() -> None:
    report = ReportedAffectedTaskV1(
        kind=AffectedTaskKind.APPLICATION_OPERATION,
        action="Open a document",
        reported_outcome="It stalls",
    )
    base = _request()
    request = ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "schema_version": 4,
            "reported_task": report.model_dump(mode="json"),
        }
    )
    transport = FakeTransport('{"summary":"The cause is unknown"}')
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)

    assert not response.degraded
    assert transport.last_body is not None
    packet = json.loads(json.loads(transport.last_body)["messages"][1]["content"])
    assert packet["reported_affected_task"]["verification"] == "unverified"
    assert packet["evidence"][0]["facts"] == base.evidence_context[0].facts


def test_frozen_nested_pressure_request_needs_16k_before_model_transport() -> None:
    request = _request(
        facts={
            "pressure": {
                "samples": [
                    {"processes": [{"name": "observer", "counters": "a" * 6200}]},
                    {"gpu_temperature_c": 82, "throttle_reasons_active": ["thermal"]},
                ]
            }
        }
    )
    frozen = ReasoningRequest.model_validate_json(request.model_dump_json())
    config = LocalInferenceConfig(
        enabled=True,
        reasoning_model="reason-local:latest",
        reasoning_digest="a" * 64,
        context_tokens=8192,
        output_tokens=1200,
    )
    narrow_transport = FakeTransport('{"summary":"Cause unknown","hypotheses":[]}')
    narrow = OllamaReasoningProvider(config, transport=narrow_transport)
    assert narrow.investigate(frozen).degraded
    assert narrow_transport.last_body is None
    assert "context budget" in narrow.status.detail

    wide_transport = FakeTransport('{"summary":"Cause unknown","hypotheses":[]}')
    wide = OllamaReasoningProvider(
        config.model_copy(update={"context_tokens": 16384}), transport=wide_transport
    )
    assert not wide.investigate(frozen).degraded
    assert wide_transport.last_body is not None


def test_warm_development_profile_covers_later_protected_context() -> None:
    path = Path(__file__).parents[3] / "examples" / "warm-local-development.profile.json"
    profile = json.loads(path.read_text(encoding="utf-8"))
    # Later cited requests exceeded the older 16k admission even after optional
    # material was paged; preserve the output reserve and bounded profile cap.
    assert profile["managed_reasoning"]["context_tokens"] == 32768
    assert profile["managed_reasoning"]["output_tokens"] == 1200


def test_request_fixture_deadline_is_relative_to_request_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys.modules[__name__], "NOW", datetime.now(UTC) - timedelta(minutes=2))
    request = _request()
    assert request.deadline_at > datetime.now(UTC) + timedelta(seconds=50)


def _error_reference():  # type: ignore[no-untyped-def]
    catalog = WindowsErrorCatalog.from_constants(
        {"WSAEADDRINUSE": 10048},
        message_resolver=lambda _code: "Only one usage of each socket address is permitted.",
        source=WindowsErrorSource(
            catalog_provider="fixture",
            catalog_version="1",
            message_provider="fixture",
            os_version="fixture Windows",
            runtime_observed=False,
        ),
    )
    result = catalog.lookup_win32(10048)
    assert result is not None
    return result


def test_deterministic_reasoning_cites_reviewed_observations_and_retains_unknown_cause() -> None:
    request = _request(facts={"resources": {"memory": {"percent": 96.0}}})
    response = DeterministicReasoningProvider().investigate(request)

    assert response.status is ReasoningStatus.UNRESOLVED
    assert "unknown" in response.summary.casefold()
    assert response.hypotheses[0].supporting_evidence_ids == request.evidence_ids
    assert "cause" not in response.hypotheses[0].statement.casefold()
    assert response.validate_against(request) == response


def test_deterministic_rules_cover_pending_restart_and_device_problem_codes() -> None:
    reboot = DeterministicReasoningProvider().investigate(
        _request(facts={"reboot": {"pending": True, "pending_sources": ["servicing"]}})
    )
    assert reboot.hypotheses[0].hypothesis_id == "h_pending_restart_observed"

    devices = DeterministicReasoningProvider().investigate(
        _request(facts={"devices": [{"problem_code": 10}, {"problem_code": 0}]})
    )
    assert devices.hypotheses[0].hypothesis_id == "h_device_problem_reported"


def test_collector_failure_is_only_an_observability_gap() -> None:
    response = DeterministicReasoningProvider().investigate(
        _request(status=EvidenceContextStatus.FAILED)
    )
    assert response.status is ReasoningStatus.INSUFFICIENT_OBSERVABILITY
    assert response.hypotheses[0].hypothesis_id == "h_observability_gap"


def test_model_supported_claim_is_downgraded_and_envelope_is_local() -> None:
    request = _request()
    content = json.dumps(
        {
            "summary": "The model thinks it knows the cause.",
            "hypotheses": [
                {
                    "hypothesis_id": "h_model_claim",
                    "statement": "A dependency caused the launch failure.",
                    "status": "supported",
                    "supporting_evidence_ids": [str(request.evidence_ids[0])],
                    "contradicting_evidence_ids": [],
                    "missing_evidence_ids": [],
                    "distinguishing_probe_ids": [],
                }
            ],
            "distinguishing_probe_ids": [],
        }
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(content),
    )
    response = provider.investigate(request)

    assert response.provider.provider_id == "ollama-local-reasoning"
    assert response.status is ReasoningStatus.UNRESOLVED
    assert response.hypotheses[0].status is HypothesisStatus.UNRESOLVED
    assert response.validate_against(request) == response


def test_duplicate_model_hypothesis_ids_fail_closed_to_bounded_fallback() -> None:
    request = _request()
    transport = FakeTransport(
        json.dumps(
            {
                "summary": "Two mechanisms remain possible.",
                "hypotheses": [
                    {"hypothesis_id": "h_repeated", "statement": "A service may be missing."},
                    {"hypothesis_id": "h_repeated", "statement": "A setting may be wrong."},
                ],
            }
        )
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    )

    response = provider.investigate(request)

    assert response.degraded
    assert provider.status.detail.startswith("ReasoningValidationError:")
    assert len({item.hypothesis_id for item in response.hypotheses}) == len(response.hypotheses)
    assert response.validate_against(request) == response
    assert transport.last_body is not None


def test_duplicate_model_hypothesis_ids_get_one_strict_retry() -> None:
    request = _request()
    transport = SequencedAdviceTransport(
        (
            json.dumps(
                {
                    "summary": "Two mechanisms remain possible.",
                    "hypotheses": [
                        {"hypothesis_id": "h_repeated", "statement": "A service may be missing."},
                        {"hypothesis_id": "h_repeated", "statement": "A setting may be wrong."},
                    ],
                }
            ),
            json.dumps(
                {
                    "summary": "Two mechanisms remain possible.",
                    "hypotheses": [
                        {"hypothesis_id": "h_service", "statement": "A service may be missing."},
                        {"hypothesis_id": "h_setting", "statement": "A setting may be wrong."},
                    ],
                }
            ),
        )
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)

    assert transport.calls == 2
    assert not response.degraded
    assert {item.hypothesis_id for item in response.hypotheses} >= {"h_service", "h_setting"}
    assert any("invalid local advisory" in note for note in response.context_notes)


def test_local_deep_brain_can_author_bounded_testable_fact_expectation() -> None:
    request = _request()
    content = json.dumps(
        {
            "summary": "The device state remains uncertain.",
            "hypotheses": [
                {
                    "hypothesis_id": "h_device",
                    "statement": "The application should remain in a failed state.",
                    "status": "unresolved",
                    "expected_facts": [
                        {
                            "probe_id": "application.snapshot",
                            "fact_name": "application.state",
                            "expected_value": "failed",
                        }
                    ],
                }
            ],
        }
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(content),
    ).investigate(request)

    assert response.degraded is False
    assert response.hypotheses[0].expected_facts[0].fact_name == "application.state"
    assert response.validate_against(request) == response


def test_expected_fact_schema_cannot_name_a_probe_outside_request() -> None:
    request = _request()
    schema = OllamaReasoningProvider._advice_schema(  # pyright: ignore[reportPrivateUsage]
        request, request.evidence_ids
    )
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    expected_fields = cast(dict[str, dict[str, object]], definitions["ExpectedFact"]["properties"])
    assert expected_fields["probe_id"]["enum"] == ["application.snapshot"]

    no_probes = request.model_copy(update={"available_probes": ()})
    schema = OllamaReasoningProvider._advice_schema(  # pyright: ignore[reportPrivateUsage]
        no_probes, no_probes.evidence_ids
    )
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    hypothesis_fields = cast(
        dict[str, dict[str, object]], definitions["_HypothesisAdvice"]["properties"]
    )
    assert hypothesis_fields["expected_facts"]["maxItems"] == 0


def test_model_can_request_next_complete_catalog_page() -> None:
    base = _request()
    unseen = EvidenceId.new()
    request = base.model_copy(
        update={
            "schema_version": 3,
            "catalog_has_more": True,
            "evidence_ids": (*base.evidence_ids, unseen),
            "evidence_catalog": ({"evidence_id": str(unseen), "summary": "unseen record"},),
        }
    )
    transport = FakeTransport(
        json.dumps({"summary": "Inspect the remaining catalog.", "request_next_catalog_page": True})
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)

    assert response.request_next_catalog_page is True
    assert response.catalog_page_truncated is False
    assert response.schema_version == 3
    assert transport.last_body is not None
    body = json.loads(transport.last_body)
    prompt = json.loads(body["messages"][1]["content"])
    assert prompt["catalog_has_more"] is True
    assert prompt["catalog_page_truncated"] is False


def test_conflicting_model_citation_is_retained_only_as_contradiction() -> None:
    request = _request()
    evidence_id = str(request.evidence_ids[0])
    content = json.dumps(
        {
            "summary": "The dependency may be involved.",
            "hypotheses": [
                {
                    "hypothesis_id": "h_conflicted",
                    "statement": "A dependency caused the failure.",
                    "status": "supported",
                    "supporting_evidence_ids": [evidence_id],
                    "contradicting_evidence_ids": [evidence_id],
                    "missing_evidence_ids": [],
                    "distinguishing_probe_ids": [],
                }
            ],
            "distinguishing_probe_ids": [],
        }
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(content),
    ).investigate(request)

    assert not response.degraded
    assert response.provider.provider_id == "ollama-local-reasoning"
    assert response.hypotheses[0].status is HypothesisStatus.CONTESTED
    assert response.hypotheses[0].supporting_evidence_ids == ()
    assert response.hypotheses[0].contradicting_evidence_ids == request.evidence_ids
    assert any("conflicting model citation" in note for note in response.context_notes)
    assert response.validate_against(request) == response


def test_explicit_windows_error_reference_is_labeled_reference_in_model_prompt() -> None:
    request = _request().model_copy(update={"error_references": (_error_reference(),)})
    transport = FakeTransport(json.dumps({"summary": "The error is reference context."}))
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    )

    response = provider.investigate(request)

    assert not response.degraded
    assert transport.last_body is not None
    body = json.loads(transport.last_body)
    packet = json.loads(body["messages"][1]["content"])
    assert packet["windows_error_references"][0]["win32_code"] == 10048
    assert packet["windows_error_references"][0]["knowledge_node_ids"] == ["kn_port_conflict"]
    assert "reference" in packet["task"].casefold()
    assert "measurement" in packet["task"].casefold()


def test_model_unknown_evidence_fails_to_deterministic_degraded_result() -> None:
    request = _request()
    content = json.dumps(
        {
            "summary": "Invalid reference.",
            "hypotheses": [
                {
                    "hypothesis_id": "h_unknown",
                    "statement": "Unknown evidence was used.",
                    "status": "unresolved",
                    "supporting_evidence_ids": [str(EvidenceId.new())],
                }
            ],
            "distinguishing_probe_ids": [],
        }
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(content),
    ).investigate(request)
    assert response.degraded is True
    assert response.provider.provider_id == "deterministic-reasoning"


def test_hypothesis_probe_requests_are_merged_and_completed_work_is_not_repeated() -> None:
    request = _request()
    content = json.dumps(
        {
            "summary": "Inspect the application next.",
            "hypotheses": [
                {
                    "hypothesis_id": "h_dependency",
                    "statement": "Dependency failure",
                    "distinguishing_probe_ids": ["application.snapshot"],
                }
            ],
            "requested_evidence_ids": [str(request.evidence_ids[0])],
        }
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(content),
    )
    response = provider.investigate(request)
    assert not response.degraded
    assert [p.probe_id for p in response.distinguishing_probes] == ["application.snapshot"]
    assert response.requested_evidence_ids == ()
    completed = request.model_copy(
        update={"completed_probe_ids": frozenset({"application.snapshot"})}
    )
    response = provider.investigate(completed)
    assert not response.degraded
    assert response.distinguishing_probes == ()


def test_local_reasoner_probe_id_cannot_choose_target_binding() -> None:
    handle = "proc_" + "a" * 32
    capability = ProbeCapability(
        probe_id="application.target_pressure",
        description="selected process counters",
        observable_ids=("application.target_pressure",),
        target_handles=(handle,),
        cost_ms=100,
        resource_class=ResourceClass.PROCESS,
    )
    request = _request().model_copy(update={"available_probes": (capability,)})
    advice = {
        "summary": "A selected process sample may distinguish pressure causes.",
        "distinguishing_probe_ids": [capability.probe_id],
    }

    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(json.dumps(advice)),
    ).investigate(request)

    assert not response.degraded
    assert len(response.distinguishing_probes) == 1
    proposal = response.distinguishing_probes[0]
    assert proposal.schema_version == 2
    assert proposal.measurement_need is not None
    assert proposal.measurement_need.target_handle == handle
    assert proposal.measurement_need.observable == capability.observable_ids[0]
    assert proposal.measurement_need.window is None

    ambiguous = capability.model_copy(update={"target_handles": (handle, "proc_" + "b" * 32)})
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(json.dumps(advice)),
    ).investigate(request.model_copy(update={"available_probes": (ambiguous,)}))
    assert not response.degraded
    assert response.distinguishing_probes == ()

    broad = capability.model_copy(update={"target_handles": (), "observable_ids": ()})
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(json.dumps(advice)),
    ).investigate(request.model_copy(update={"available_probes": (broad,)}))
    assert response.distinguishing_probes[0].schema_version == 1
    assert response.distinguishing_probes[0].measurement_need is None

    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(json.dumps({**advice, "target_handle": "proc_" + "c" * 32})),
    ).investigate(request)
    assert response.degraded
    assert response.distinguishing_probes == ()


def test_local_reasoner_can_explicitly_cancel_only_a_pending_probe() -> None:
    request = _request().model_copy(update={"pending_probe_ids": ("application.snapshot",)})
    transport = FakeTransport(
        json.dumps(
            {
                "summary": "The new fact rules out this branch.",
                "cancelled_probe_ids": ["application.snapshot"],
            }
        )
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    )

    response = provider.investigate(request)

    assert not response.degraded
    assert response.cancelled_probe_ids == ("application.snapshot",)
    assert transport.last_body is not None
    packet = json.loads(json.loads(transport.last_body)["messages"][1]["content"])
    assert packet["pending_probe_ids"] == ["application.snapshot"]


def test_catalog_only_evidence_cannot_support_a_model_claim() -> None:
    request = _request()
    absent = EvidenceId.new()
    request = request.model_copy(
        update={
            "evidence_ids": (*request.evidence_ids, absent),
            "evidence_catalog": ({"evidence_id": str(absent), "summary": "Catalog only"},),
        }
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(
            json.dumps(
                {
                    "summary": "Invalid unseen support.",
                    "hypotheses": [
                        {
                            "hypothesis_id": "h_unseen",
                            "statement": "A guess",
                            "supporting_evidence_ids": [str(absent)],
                        }
                    ],
                }
            )
        ),
    )
    assert provider.investigate(request).degraded


def test_reference_knowledge_cannot_displace_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    observations = tuple(
        request.evidence_context[0].model_copy(update={"evidence_id": EvidenceId.new()})
        for _ in range(4)
    )
    request = request.model_copy(
        update={
            "evidence_context": observations,
            "evidence_ids": tuple(e.evidence_id for e in observations),
        }
    )

    def small_context(_self: OllamaChatClient, prompt: str, _schema: dict[str, object]) -> bool:
        return len(prompt) < 4000

    monkeypatch.setattr(OllamaChatClient, "fits_context", small_context)
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    packet = {
        "evidence": [e.model_dump(mode="json") for e in observations],
        "relationships": [],
        "reference_knowledge": [{"mechanism": "reference " * 3000}],
        "previous_hypotheses": [],
        "evidence_catalog": [],
    }
    _, visible, notes, _ = provider._fit_prompt(json.dumps(packet), request)  # pyright: ignore[reportPrivateUsage]
    assert visible == request.evidence_ids
    assert any("reference" in note.lower() for note in notes)


def test_error_reference_is_omitted_before_minimal_observed_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = _error_reference().model_copy(
        update={"message": "x" * 4096, "mechanism_note": "y" * 1000}
    )
    request = _request().model_copy(update={"error_references": (reference,)})

    def small_context(_self: OllamaChatClient, prompt: str, _schema: dict[str, object]) -> bool:
        return len(prompt) < 2500

    monkeypatch.setattr(OllamaChatClient, "fits_context", small_context)
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    packet = {
        "evidence": [item.model_dump(mode="json") for item in request.evidence_context],
        "relationships": [],
        "reference_knowledge": [],
        "windows_error_references": [reference.model_dump(mode="json")],
        "previous_hypotheses": [],
        "evidence_catalog": [],
    }

    fitted, visible, notes, _ = provider._fit_prompt(  # pyright: ignore[reportPrivateUsage]
        json.dumps(packet), request
    )

    assert visible == request.evidence_ids
    assert json.loads(fitted)["windows_error_references"] == []
    assert any("error reference" in note.casefold() for note in notes)


def test_context_paging_preserves_prior_citation_before_uncited_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    observations = tuple(
        request.evidence_context[0].model_copy(
            update={"evidence_id": EvidenceId.new(), "facts": {"value": "x" * 1200}}
        )
        for _ in range(4)
    )
    hypothesis = Hypothesis(
        hypothesis_id="h_existing",
        statement="An existing branch requiring follow-up.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(observations[-1].evidence_id,),
    )
    request = request.model_copy(
        update={
            "evidence_context": observations,
            "evidence_ids": tuple(e.evidence_id for e in observations),
            "previous_hypotheses": (hypothesis,),
        }
    )

    def small_context(_self: OllamaChatClient, prompt: str, _schema: dict[str, object]) -> bool:
        return len(prompt) < 4500

    monkeypatch.setattr(OllamaChatClient, "fits_context", small_context)
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    packet = {
        "evidence": [e.model_dump(mode="json") for e in observations],
        "relationships": [],
        "reference_knowledge": [],
        "previous_hypotheses": [hypothesis.model_dump(mode="json")],
        "evidence_catalog": [],
    }
    fitted, visible, _, _ = provider._fit_prompt(json.dumps(packet), request)  # pyright: ignore[reportPrivateUsage]
    assert observations[-1].evidence_id in visible
    assert len(visible) < len(observations)
    assert json.loads(fitted)["uncited_visible_observation_ids"] == [
        str(item) for item in visible if item != observations[-1].evidence_id
    ]
    assert "target and time window may differ" in json.loads(fitted)["rival_review_instruction"]


def test_follow_up_review_focuses_later_observation_facts_without_claiming_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fits_context(_self: OllamaChatClient, _prompt: str, _schema: dict[str, object]) -> bool:
        return True

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits_context)
    request = _request()
    prior_observation = request.evidence_context[0].model_copy(
        update={"case_scope": "current_case", "incident_relevant": True}
    )
    older = prior_observation.model_copy(
        update={
            "evidence_id": EvidenceId.new(),
            "observed_at": prior_observation.observed_at - timedelta(seconds=1),
            "captured_at": prior_observation.captured_at - timedelta(seconds=1),
        }
    )
    later = prior_observation.model_copy(
        update={
            "evidence_id": EvidenceId.new(),
            "observed_at": prior_observation.observed_at + timedelta(seconds=1),
            "captured_at": prior_observation.captured_at + timedelta(seconds=1),
            "facts": {"application.state": "running"},
        }
    )
    latest = prior_observation.model_copy(
        update={
            "evidence_id": EvidenceId.new(),
            "observed_at": prior_observation.observed_at + timedelta(seconds=2),
            "captured_at": prior_observation.captured_at + timedelta(seconds=2),
            "facts": {"application.state": "stopped"},
        }
    )
    hypothesis = Hypothesis(
        hypothesis_id="h_launch_failure",
        statement="Launch may fail.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(prior_observation.evidence_id,),
    )
    observations = (prior_observation, older, later, latest)
    request = request.model_copy(
        update={
            "evidence_context": observations,
            "evidence_ids": tuple(item.evidence_id for item in observations),
            "previous_hypotheses": (hypothesis,),
        }
    )
    packet = {
        "evidence": [item.model_dump(mode="json") for item in observations],
        "relationships": [],
        "reference_knowledge": [],
        "previous_hypotheses": [hypothesis.model_dump(mode="json")],
        "evidence_catalog": [],
    }
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    fitted, _, _, _ = provider._fit_prompt(json.dumps(packet), request)  # pyright: ignore[reportPrivateUsage]
    focused = json.loads(fitted)["recent_uncited_observations"]
    assert [item["evidence_id"] for item in focused] == [
        str(latest.evidence_id),
        str(later.evidence_id),
    ]
    assert focused[1]["facts"] == {"application.state": "running"}
    assert "cause" in json.loads(fitted)["rival_review_instruction"]


def test_follow_up_model_omission_gets_one_bounded_review_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fits_context(_self: OllamaChatClient, _prompt: str, _schema: dict[str, object]) -> bool:
        return True

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits_context)
    request = _request()
    original = request.evidence_context[0].model_copy(
        update={"case_scope": "current_case", "incident_relevant": True}
    )
    later = original.model_copy(
        update={
            "evidence_id": EvidenceId.new(),
            "observed_at": original.observed_at + timedelta(seconds=1),
            "captured_at": original.captured_at + timedelta(seconds=1),
            "facts": {"application.state": "running"},
        }
    )
    prior = Hypothesis(
        hypothesis_id="h_launch_failure",
        statement="Launch may fail.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(original.evidence_id,),
    )
    request = request.model_copy(
        update={
            "evidence_context": (original, later),
            "evidence_ids": (original.evidence_id, later.evidence_id),
            "previous_hypotheses": (prior,),
        }
    )
    transport = SequencedAdviceTransport(
        (
            json.dumps({"summary": "The old explanation remains unresolved."}),
            json.dumps(
                {
                    "summary": (
                        f"{later.evidence_id}: a later running state weakens a continuous "
                        "launch failure, but the affected task window is unverified."
                    )
                }
            ),
        )
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)

    assert transport.calls == 2
    assert not response.degraded
    assert str(later.evidence_id) in response.summary
    assert any("invalid local advisory" in note for note in response.context_notes)


def test_follow_up_model_omission_remains_degraded_after_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fits_context(_self: OllamaChatClient, _prompt: str, _schema: dict[str, object]) -> bool:
        return True

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits_context)
    request = _request()
    original = request.evidence_context[0].model_copy(update={"case_scope": "current_case"})
    later = original.model_copy(
        update={
            "evidence_id": EvidenceId.new(),
            "observed_at": original.observed_at + timedelta(seconds=1),
            "captured_at": original.captured_at + timedelta(seconds=1),
        }
    )
    prior = Hypothesis(
        hypothesis_id="h_launch_failure",
        statement="Launch may fail.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(original.evidence_id,),
    )
    request = request.model_copy(
        update={
            "evidence_context": (original, later),
            "evidence_ids": (original.evidence_id, later.evidence_id),
            "previous_hypotheses": (prior,),
        }
    )
    transport = SequencedAdviceTransport(
        (json.dumps({"summary": "The old explanation remains unresolved."}),)
    )
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)

    assert transport.calls == 2
    assert response.degraded


def _unavailable_and_unrelated_review_request() -> tuple[ReasoningRequest, EvidenceId, EvidenceId]:
    """Mirror two actual-shaped focused rows without replaying a provider."""
    base = _request()
    older = base.evidence_context[0].model_copy(
        update={
            "case_scope": "current_case",
            "observed_at": base.evidence_context[0].observed_at - timedelta(seconds=3),
            "captured_at": base.evidence_context[0].captured_at - timedelta(seconds=3),
        }
    )
    unrelated = older.model_copy(
        update={
            "evidence_id": EvidenceId.new(),
            "probe_id": "incident.events",
            "observed_at": older.observed_at + timedelta(seconds=1),
            "captured_at": older.captured_at + timedelta(seconds=1),
            "facts": {"events": [{"AppName": "OtherTool.exe"}]},
        }
    )
    unavailable = older.model_copy(
        update={
            "evidence_id": EvidenceId.new(),
            "probe_id": "security.snapshot",
            "observed_at": older.observed_at + timedelta(seconds=2),
            "captured_at": older.captured_at + timedelta(seconds=2),
            "facts": {"collection_status": "unsupported"},
        }
    )
    prior = Hypothesis(
        hypothesis_id="application_fault",
        statement="The reported app fault remains possible.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(older.evidence_id,),
    )
    request = base.model_copy(
        update={
            "evidence_context": (older, unrelated, unavailable),
            "evidence_ids": (older.evidence_id, unrelated.evidence_id, unavailable.evidence_id),
            "previous_hypotheses": (prior,),
        }
    )
    return request, unrelated.evidence_id, unavailable.evidence_id


def _review_fits_context(_self: OllamaChatClient, _prompt: str, _schema: dict[str, object]) -> bool:
    return True


def test_unavailable_missing_review_accepts_actual_shaped_advice_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(OllamaChatClient, "fits_context", _review_fits_context)
    request, unrelated_id, unavailable_id = _unavailable_and_unrelated_review_request()
    advice = {
        "summary": "The OtherTool event is unrelated; security supplied no data.",
        "hypotheses": [
            {
                "hypothesis_id": "application_fault",
                "statement": "The OtherTool event is not bound to the reported application.",
                "status": "unresolved",
                "missing_evidence_ids": [str(unavailable_id)],
            }
        ],
        "noncausal_observation_reviews": [
            {
                "evidence_id": str(unrelated_id),
                "disposition": "unrelated",
                "explanation": "The event names another application, not the affected one.",
            }
        ],
    }
    transport = SequencedAdviceTransport((json.dumps(advice),))
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"), transport=transport
    ).investigate(request)
    assert transport.calls == 1
    assert not response.degraded
    assert response.noncausal_observation_reviews[0].evidence_id == unrelated_id
    assert response.hypotheses[0].missing_evidence_ids == (unavailable_id,)


def test_unavailable_missing_review_alone_handles_supported_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(OllamaChatClient, "fits_context", _review_fits_context)
    request, incident_id, unavailable_id = _unavailable_and_unrelated_review_request()
    advice = {
        "summary": "A matching event supports a possible fault; security supplied no data.",
        "hypotheses": [
            {
                "hypothesis_id": "application_fault",
                "statement": "An event supports a possible fault, with time binding unverified.",
                "status": "supported",
                "supporting_evidence_ids": [str(incident_id)],
                "missing_evidence_ids": [str(unavailable_id)],
            }
        ],
    }
    transport = SequencedAdviceTransport((json.dumps(advice),))
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"), transport=transport
    ).investigate(request)
    assert transport.calls == 1
    assert not response.degraded
    assert response.hypotheses[0].supporting_evidence_ids == (incident_id,)


def test_review_can_coexist_with_missing_and_generic_unknown_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(OllamaChatClient, "fits_context", _review_fits_context)
    request, unrelated_id, unavailable_id = _unavailable_and_unrelated_review_request()
    advice = {
        "summary": "The cause remains unknown; both observations have limited scope.",
        "hypotheses": [
            {
                "hypothesis_id": "unknown_cause",
                "statement": "The unsupported security check leaves the cause unlocalized.",
                "status": "unresolved",
                "supporting_evidence_ids": [str(unavailable_id)],
                "missing_evidence_ids": [str(unavailable_id)],
            }
        ],
        "noncausal_observation_reviews": [
            {
                "evidence_id": str(unavailable_id),
                "disposition": "unavailable",
                "explanation": "The registered check returned no security measurement.",
            },
            {
                "evidence_id": str(unrelated_id),
                "disposition": "target_unbound",
                "explanation": "The observed event names another application, not this task.",
            },
        ],
    }
    transport = SequencedAdviceTransport((json.dumps(advice),))
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"), transport=transport
    ).investigate(request)
    assert transport.calls == 1
    assert not response.degraded
    assert {str(review.evidence_id) for review in response.noncausal_observation_reviews} == {
        str(unrelated_id),
        str(unavailable_id),
    }


def test_unavailable_observation_can_be_reviewed_as_target_unbound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(OllamaChatClient, "fits_context", _review_fits_context)
    request, unrelated_id, unavailable_id = _unavailable_and_unrelated_review_request()
    advice = {
        "summary": "The event concerns another app, and security could not identify this target.",
        "hypotheses": [
            {
                "hypothesis_id": "application_fault",
                "statement": "The affected operation remains unverified.",
                "status": "unresolved",
                "missing_evidence_ids": [str(unavailable_id)],
            }
        ],
        "noncausal_observation_reviews": [
            {
                "evidence_id": str(unrelated_id),
                "disposition": "unrelated",
                "explanation": "The observed event names a different application.",
            },
            {
                "evidence_id": str(unavailable_id),
                "disposition": "target_unbound",
                "explanation": "The unavailable snapshot cannot identify the affected process.",
            },
        ],
    }
    transport = SequencedAdviceTransport((json.dumps(advice),))
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"), transport=transport
    ).investigate(request)
    assert transport.calls == 1
    assert not response.degraded


@pytest.mark.parametrize(
    "statement",
    (
        "Unverified possibility: The proxy setting may affect the reported task.",
        "Unverified possibility: An external source is not bound to this task.",
    ),
)
def test_echoed_prior_statement_is_not_prefixed_or_rejected(statement: str) -> None:
    prior = Hypothesis(
        hypothesis_id="unbound_rival", statement=statement, status=HypothesisStatus.UNRESOLVED
    )
    advice = _HypothesisAdvice(hypothesis_id=prior.hypothesis_id, statement=prior.statement)
    adapted = OllamaReasoningProvider._hypothesis(  # pyright: ignore[reportPrivateUsage]
        advice
    )
    result = progress_hypotheses(
        previous=(prior,), advisory=(adapted,), custodied_evidence_ids=(), visible_evidence_ids=()
    )
    assert result.hypotheses == (prior,)
    assert result.rejected_update_ids == ()


def test_unavailable_recent_observation_is_absent_from_new_ref_menu() -> None:
    request, unrelated_id, unavailable_id = _unavailable_and_unrelated_review_request()
    old_id = request.evidence_ids[0]
    prior = request.previous_hypotheses[0].model_copy(
        update={
            "noncausal_observation_refs": (
                NoncausalHypothesisRefV1(evidence_id=old_id, disposition="target_unbound"),
            )
        }
    )
    request = request.model_copy(update={"schema_version": 7, "previous_hypotheses": (prior,)})
    schema = OllamaReasoningProvider._advice_schema(  # pyright: ignore[reportPrivateUsage]
        request,
        (old_id, unrelated_id, unavailable_id),
        recent_review_ids=(unrelated_id, unavailable_id),
        presented_prior_hypothesis_ids=("application_fault",),
    )
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    ref_fields = cast(
        dict[str, dict[str, object]], definitions["NoncausalHypothesisRefV1"]["properties"]
    )
    assert ref_fields["evidence_id"]["enum"] == [str(old_id), str(unrelated_id)]


def test_shared_validator_rejects_new_unavailable_ref_with_matching_review() -> None:
    request, unrelated_id, unavailable_id = _unavailable_and_unrelated_review_request()
    request = request.model_copy(update={"schema_version": 7})
    prior = request.previous_hypotheses[0]
    response = ReasoningResponse(
        schema_version=6,
        provider=ProviderIdentity(
            provider_id="fixture-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="The unavailable check did not identify the affected target.",
        hypotheses=(
            prior.model_copy(
                update={
                    "noncausal_observation_refs": (
                        NoncausalHypothesisRefV1(
                            evidence_id=unavailable_id, disposition="target_unbound"
                        ),
                    )
                }
            ),
        ),
        considered_evidence_ids=(request.evidence_ids[0], unrelated_id, unavailable_id),
        presented_prior_hypothesis_ids=(prior.hypothesis_id,),
        noncausal_observation_reviews=(
            NoncausalObservationReviewV1(
                evidence_id=unavailable_id,
                disposition="target_unbound",
                explanation="The registered check returned no measurement.",
            ),
        ),
    )
    with pytest.raises(ReasoningValidationError, match="noncausal ref"):
        response.validate_against(request)


@pytest.mark.parametrize(
    "fault",
    (
        "foreign",
        "prior_cited",
        "duplicate",
        "conflicting_dispositions",
        "unavailable_spoof",
        "missing_spoof",
        "substantive_unavailable",
        "malformed_explanation",
    ),
)
def test_noncausal_review_rejects_invalid_identity_or_role(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(OllamaChatClient, "fits_context", _review_fits_context)
    request, unrelated_id, unavailable_id = _unavailable_and_unrelated_review_request()
    advice: dict[str, object] = {
        "summary": "The other application event is not bound to this affected task.",
        "hypotheses": [
            {
                "hypothesis_id": "application_fault",
                "statement": "This cause remains unresolved.",
                "status": "unresolved",
                "missing_evidence_ids": [str(unavailable_id)],
            }
        ],
        "noncausal_observation_reviews": [
            {
                "evidence_id": str(unrelated_id),
                "disposition": "unrelated",
                "explanation": "The event names another application, not the affected task.",
            }
        ],
    }
    reviews = cast(list[dict[str, object]], advice["noncausal_observation_reviews"])
    hypotheses = cast(list[dict[str, object]], advice["hypotheses"])
    if fault == "foreign":
        reviews[0]["evidence_id"] = str(EvidenceId.new())
    elif fault == "prior_cited":
        reviews[0]["evidence_id"] = str(request.evidence_context[0].evidence_id)
    elif fault == "duplicate":
        reviews.append(dict(reviews[0]))
    elif fault == "conflicting_dispositions":
        reviews.append({**reviews[0], "disposition": "target_unbound"})
    elif fault == "unavailable_spoof":
        reviews[0]["disposition"] = "unavailable"
    elif fault == "missing_spoof":
        advice["noncausal_observation_reviews"] = []
        hypotheses[0]["missing_evidence_ids"] = [str(unavailable_id), str(unrelated_id)]
    elif fault == "substantive_unavailable":
        context = list(request.evidence_context)
        context[-1] = context[-1].model_copy(
            update={"facts": {"collection_status": "unsupported", "events": ["observed"]}}
        )
        request = request.model_copy(update={"evidence_context": tuple(context)})
    elif fault == "malformed_explanation":
        reviews[0]["explanation"] = "x"
    transport = SequencedAdviceTransport((json.dumps(advice),))
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"), transport=transport
    ).investigate(request)
    assert transport.calls == 2
    assert response.degraded


def test_noncausal_review_requires_exact_fitted_recent_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(OllamaChatClient, "fits_context", _review_fits_context)
    request, unrelated_id, _ = _unavailable_and_unrelated_review_request()
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    packet = {
        "evidence": [item.model_dump(mode="json") for item in request.evidence_context],
        "relationships": [],
        "reference_knowledge": [],
        "previous_hypotheses": [
            item.model_dump(mode="json") for item in request.previous_hypotheses
        ],
        "evidence_catalog": [],
    }
    fitted, _, _, _ = provider._fit_prompt(json.dumps(packet), request)  # pyright: ignore[reportPrivateUsage]
    fitted_packet = json.loads(fitted)
    assert str(unrelated_id) in {
        item["evidence_id"] for item in fitted_packet["recent_uncited_observations"]
    }
    fitted_packet["recent_uncited_observations"] = []
    advice = {
        "summary": "The event names another application.",
        "noncausal_observation_reviews": [
            {
                "evidence_id": str(unrelated_id),
                "disposition": "unrelated",
                "explanation": "The event names another application, not the affected task.",
            }
        ],
    }
    with pytest.raises(ReasoningValidationError, match="outside fitted recent facts"):
        provider._validate_recent_review(  # pyright: ignore[reportPrivateUsage]
            _ReasoningAdvice.model_validate(advice), fitted_packet
        )
    fitted_packet["recent_uncited_observations"] = [{"evidence_id": str(unrelated_id)}]
    fitted_packet["evidence"] = [
        item for item in fitted_packet["evidence"] if item["evidence_id"] != str(unrelated_id)
    ]
    fitted_packet["evidence_catalog"] = [
        {"evidence_id": str(unrelated_id), "probe_id": "incident.events"}
    ]
    with pytest.raises(ReasoningValidationError, match="outside fitted recent facts"):
        provider._validate_recent_review(  # pyright: ignore[reportPrivateUsage]
            _ReasoningAdvice.model_validate(advice), fitted_packet
        )


def test_compact_fitted_evidence_retains_typed_source_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, _, _ = _unavailable_and_unrelated_review_request()

    def fit_after_one_omission(
        _self: OllamaChatClient, prompt: str, _schema: dict[str, object]
    ) -> bool:
        return len(json.loads(prompt)["evidence"]) <= 2

    monkeypatch.setattr(OllamaChatClient, "fits_context", fit_after_one_omission)
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    packet = {
        "evidence": [item.model_dump(mode="json") for item in request.evidence_context],
        "relationships": [],
        "reference_knowledge": [],
        "previous_hypotheses": [
            item.model_dump(mode="json") for item in request.previous_hypotheses
        ],
        "evidence_catalog": [],
    }
    fitted, visible, _, _ = provider._fit_prompt(json.dumps(packet), request)  # pyright: ignore[reportPrivateUsage]
    retained = json.loads(fitted)["evidence"]
    assert len(retained) == 2
    assert tuple(EvidenceContext.model_validate(item).evidence_id for item in retained) == visible
    assert request.previous_hypotheses[0].supporting_evidence_ids[0] in visible


def test_shared_response_rejects_uncustodied_or_unsolicited_reviews() -> None:
    request, unrelated_id, _ = _unavailable_and_unrelated_review_request()
    review = NoncausalObservationReviewV1(
        evidence_id=unrelated_id,
        disposition="unrelated",
        explanation="The event names another application, not the affected task.",
    )
    base = ReasoningResponse(
        schema_version=5,
        provider=ProviderIdentity(
            provider_id="fixture-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="A separate event is not bound to the affected task.",
        hypotheses=request.previous_hypotheses,
        considered_evidence_ids=request.evidence_ids,
        presented_prior_hypothesis_ids=(request.previous_hypotheses[0].hypothesis_id,),
        noncausal_observation_reviews=(review,),
    )
    assert base.validate_against(request) == base
    for altered in (
        base.model_copy(
            update={
                "noncausal_observation_reviews": (
                    review.model_copy(update={"evidence_id": EvidenceId.new()}),
                )
            }
        ),
        base.model_copy(update={"noncausal_observation_reviews": (review, review)}),
        base.model_copy(update={"considered_evidence_ids": request.evidence_ids[:1]}),
        base.model_copy(update={"schema_version": 4}),
        base.model_copy(update={"presented_prior_hypothesis_ids": ()}),
        base.model_copy(update={"presented_prior_hypothesis_ids": ("absent_prior",)}),
    ):
        with pytest.raises(ReasoningValidationError):
            altered.validate_against(request)

    generic_support = base.model_copy(
        update={
            "hypotheses": (
                request.previous_hypotheses[0].model_copy(
                    update={"supporting_evidence_ids": (unrelated_id,)}
                ),
            )
        }
    )
    assert generic_support.validate_against(request) == generic_support

    old = base.model_copy(update={"schema_version": 4, "noncausal_observation_reviews": ()})
    assert "noncausal_observation_reviews" not in old.model_dump(mode="json")
    assert ReasoningResponse.model_validate_json(old.model_dump_json()) == old


def test_reasoner_can_request_exact_detail_inside_visible_observation_but_not_repeat_it() -> None:
    request = _request()
    detail = EvidenceDetailRequest(evidence_id=request.evidence_ids[0], match_literals=("52048",))
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(
            json.dumps(
                {
                    "summary": "Need the complete process row.",
                    "requested_details": [detail.model_dump(mode="json")],
                }
            )
        ),
    )
    response = provider.investigate(request)
    assert not response.degraded
    assert response.requested_details == (detail,)
    completed = request.model_copy(update={"completed_detail_requests": (detail,)})
    assert provider.investigate(completed).requested_details == ()


def test_detail_search_cannot_reach_unknown_evidence() -> None:
    request = _request()
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport(
            json.dumps(
                {
                    "summary": "Invalid search.",
                    "requested_details": [
                        {"evidence_id": str(EvidenceId.new()), "match_literals": ["x"]}
                    ],
                }
            )
        ),
    )
    assert provider.investigate(request).degraded


def test_large_unseen_catalog_cannot_crowd_out_focused_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    unseen = tuple(EvidenceId.new() for _ in range(48))
    request = request.model_copy(
        update={
            "schema_version": 3,
            "catalog_has_more": True,
            "evidence_ids": (*request.evidence_ids, *unseen),
        }
    )
    reference = [{"mechanism": "A process may own a listening endpoint, not necessarily a fault."}]
    packet = {
        "evidence": [item.model_dump(mode="json") for item in request.evidence_context],
        "relationships": [],
        "reference_knowledge": reference,
        "previous_hypotheses": [],
        "evidence_catalog": [
            {"evidence_id": str(eid), "summary": "Catalog " * 60} for eid in unseen
        ],
    }

    def fits(_self: OllamaChatClient, prompt: str, schema: dict[str, object]) -> bool:
        return len(prompt) + len(json.dumps(schema)) < 7000

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits)
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    fitted, visible, notes, schema = provider._fit_prompt(json.dumps(packet), request)  # pyright: ignore[reportPrivateUsage]
    admitted = json.loads(fitted)
    assert visible == request.evidence_ids[:1]
    assert admitted["reference_knowledge"] == reference
    assert len(admitted["evidence_catalog"]) < len(unseen)
    assert admitted["catalog_page_truncated"] is True
    assert any("catalog" in note.casefold() for note in notes)
    fields = cast(dict[str, dict[str, object]], schema["properties"])
    assert fields["request_next_catalog_page"]["const"] is False
    item_schema = cast(dict[str, object], fields["requested_evidence_ids"]["items"])
    requestable = cast(list[str], item_schema.get("enum", []))
    assert set(requestable) == {item["evidence_id"] for item in admitted["evidence_catalog"]}


def test_model_cannot_request_id_hidden_by_catalog_context_fit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _request()
    shown, hidden = EvidenceId.new(), EvidenceId.new()
    request = base.model_copy(
        update={
            "schema_version": 3,
            "evidence_ids": (*base.evidence_ids, shown, hidden),
            "evidence_catalog": (
                {"evidence_id": str(shown), "summary": "Shown metadata"},
                {"evidence_id": str(hidden), "summary": "Hidden metadata"},
            ),
        }
    )

    def fits(_self: OllamaChatClient, prompt: str, _schema: dict[str, object]) -> bool:
        return len(json.loads(prompt)["evidence_catalog"]) <= 1

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits)
    transport = FakeTransport(
        json.dumps({"summary": "Request hidden ID", "requested_evidence_ids": [str(hidden)]})
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    )

    response = provider.investigate(request)

    assert response.degraded
    assert transport.last_body is not None
    fitted = json.loads(json.loads(transport.last_body)["messages"][1]["content"])
    assert [item["evidence_id"] for item in fitted["evidence_catalog"]] == [str(shown)]


def test_completed_generic_request_is_not_requestable_but_remains_detail_eligible() -> None:
    request = _request()
    completed = EvidenceId.new()
    unseen = EvidenceId.new()
    request = request.model_copy(
        update={
            "evidence_ids": (*request.evidence_ids, completed, unseen),
            "completed_evidence_requests": (completed,),
        }
    )

    schema = OllamaReasoningProvider._advice_schema(  # pyright: ignore[reportPrivateUsage]
        request,
        request.evidence_ids[:1],
        (completed, unseen),
    )

    fields = cast(dict[str, dict[str, object]], schema["properties"])
    requested_items = cast(dict[str, object], fields["requested_evidence_ids"]["items"])
    assert requested_items["enum"] == [str(unseen)]
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    detail_fields = cast(
        dict[str, dict[str, object]], definitions["EvidenceDetailRequest"]["properties"]
    )
    detail_ids = detail_fields["evidence_id"]["enum"]
    assert str(completed) in cast(list[str], detail_ids)


def test_prior_noncausal_ref_can_be_carried_without_new_review_queue() -> None:
    base = _request()
    evidence_id = base.evidence_ids[0]
    prior = Hypothesis(
        hypothesis_id="h_launch_failure",
        statement="An application snapshot is not bound to the reported task.",
        status=HypothesisStatus.UNRESOLVED,
        noncausal_observation_refs=(
            NoncausalHypothesisRefV1(evidence_id=evidence_id, disposition="target_unbound"),
        ),
    )
    request = ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "schema_version": 7,
            "previous_hypotheses": [prior.model_dump(mode="json")],
            "prior_hypothesis_revision_refs": [
                {
                    "hypothesis_id": prior.hypothesis_id,
                    "hypothesis_sha256": hypothesis_revision_sha256(prior),
                }
            ],
        }
    )
    schema = OllamaReasoningProvider._advice_schema(  # pyright: ignore[reportPrivateUsage]
        request,
        (evidence_id,),
        recent_review_ids=(),
        presented_prior_hypothesis_ids=(prior.hypothesis_id,),
    )
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    hypothesis_fields = cast(
        dict[str, dict[str, object]], definitions["_HypothesisAdvice"]["properties"]
    )
    assert "noncausal_observation_reviews" not in cast(dict[str, object], schema["properties"])
    assert "noncausal_observation_refs" in hypothesis_fields
    ref_fields = cast(
        dict[str, dict[str, object]], definitions["NoncausalHypothesisRefV1"]["properties"]
    )
    assert ref_fields["evidence_id"]["enum"] == [str(evidence_id)]
    response = ReasoningResponse(
        schema_version=6,
        provider=ProviderIdentity(
            provider_id="fixture-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="The target remains unbound.",
        hypotheses=(prior,),
        considered_evidence_ids=(evidence_id,),
        presented_prior_hypothesis_ids=(prior.hypothesis_id,),
    )
    assert response.validate_against(request) == response


def test_empty_noncausal_ref_field_preserves_legacy_hypothesis_digest() -> None:
    prior = Hypothesis(
        hypothesis_id="h_legacy",
        statement="The cause remains unresolved.",
        status=HypothesisStatus.UNRESOLVED,
    )
    serialized = prior.model_dump(mode="json")
    assert "noncausal_observation_refs" not in serialized
    assert Hypothesis.model_validate(serialized) == prior
    assert hypothesis_revision_sha256(Hypothesis.model_validate(serialized)) == (
        hypothesis_revision_sha256(prior)
    )


def test_unfittable_prior_noncausal_ref_fails_before_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _request()
    prior = Hypothesis(
        hypothesis_id="h_target",
        statement="The source target remains unbound.",
        status=HypothesisStatus.UNRESOLVED,
        noncausal_observation_refs=(
            NoncausalHypothesisRefV1(
                evidence_id=base.evidence_ids[0], disposition="target_unbound"
            ),
        ),
    )
    request = ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "schema_version": 7,
            "previous_hypotheses": [prior.model_dump(mode="json")],
            "prior_hypothesis_revision_refs": [
                {
                    "hypothesis_id": prior.hypothesis_id,
                    "hypothesis_sha256": hypothesis_revision_sha256(prior),
                }
            ],
        }
    )

    def does_not_fit(_self: OllamaChatClient, _prompt: str, _schema: dict[str, object]) -> bool:
        return False

    monkeypatch.setattr(OllamaChatClient, "fits_context", does_not_fit)
    transport = FakeTransport("{}")
    response = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    ).investigate(request)
    assert response.degraded
    assert transport.last_body is None


def test_provider_filters_repeated_completed_generic_request() -> None:
    request = _request()
    completed = EvidenceId.new()
    unseen = EvidenceId.new()
    request = request.model_copy(
        update={
            "evidence_ids": (*request.evidence_ids, completed, unseen),
            "completed_evidence_requests": (completed,),
            "priority_evidence_ids": request.evidence_ids,
            "evidence_catalog": (
                {"evidence_id": str(completed), "summary": "Already delivered evidence"},
                {"evidence_id": str(unseen), "summary": "Unseen current evidence"},
            ),
        }
    )
    transport = FakeTransport(
        json.dumps(
            {
                "summary": "Request unseen context.",
                "requested_evidence_ids": [str(completed), str(unseen)],
            }
        )
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    )

    response = provider.investigate(request)

    assert not response.degraded
    assert response.requested_evidence_ids == (unseen,)
    assert transport.last_body is not None
    prompt = json.loads(json.loads(transport.last_body)["messages"][1]["content"])
    assert prompt["completed_evidence_requests"] == [str(completed)]
    assert prompt["priority_evidence_ids"] == [str(request.evidence_ids[0])]
    assert [item["evidence_id"] for item in prompt["evidence_catalog"]] == [str(unseen)]


def test_priority_evidence_survives_context_fit_eviction(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _request()
    observations = tuple(
        request.evidence_context[0].model_copy(
            update={"evidence_id": EvidenceId.new(), "facts": {"value": "x" * 1800}}
        )
        for _ in range(3)
    )
    priority = observations[-1].evidence_id
    request = request.model_copy(
        update={
            "evidence_context": observations,
            "evidence_ids": tuple(item.evidence_id for item in observations),
            "priority_evidence_ids": (priority,),
        }
    )

    def fits(_self: OllamaChatClient, prompt: str, _schema: dict[str, object]) -> bool:
        return len(prompt) < 3000

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits)
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=FakeTransport("{}"),
    )
    packet = {
        "evidence": [item.model_dump(mode="json") for item in observations],
        "relationships": [],
        "reference_knowledge": [],
        "windows_error_references": [],
        "previous_hypotheses": [],
        "evidence_catalog": [],
    }

    _fitted, visible, _notes, _schema = provider._fit_prompt(  # pyright: ignore[reportPrivateUsage]
        json.dumps(packet), request
    )

    assert priority in visible
    assert len(visible) < len(observations)


def test_version_seven_provider_returns_intent_bound_to_fitted_prior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fits_context(
        _client: OllamaChatClient, _prompt: str, _schema: Mapping[str, object]
    ) -> bool:
        return True

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits_context)
    base = _request()
    older = base.evidence_ids[0]
    newer = EvidenceId.new()
    later = base.evidence_context[0].model_copy(
        update={
            "evidence_id": newer,
            "summary": "Available memory was observed.",
            "facts": {"memory.available_gb": 20},
        }
    )
    old = Hypothesis(
        hypothesis_id="memory_pressure",
        statement="Capacity is known but pressure is unmeasured.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(older,),
    )
    digest = hypothesis_revision_sha256(old)
    request = ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "schema_version": 7,
            "evidence_ids": [str(older), str(newer)],
            "evidence_context": [
                item.model_dump(mode="json") for item in (*base.evidence_context, later)
            ],
            "previous_hypotheses": [old.model_dump(mode="json")],
            "prior_hypothesis_revision_refs": [
                PriorHypothesisRevisionRefV1(
                    hypothesis_id=old.hypothesis_id, hypothesis_sha256=digest
                ).model_dump(mode="json")
            ],
        }
    )
    transport = FakeTransport(
        json.dumps(
            {
                "summary": "New observation contests broad pressure.",
                "hypotheses": [
                    {
                        "hypothesis_id": old.hypothesis_id,
                        "statement": "The available memory observation contests broad pressure.",
                        "status": "contested",
                        "contradicting_evidence_ids": [str(newer)],
                    }
                ],
                "hypothesis_revision_intents": [
                    {
                        "hypothesis_id": old.hypothesis_id,
                        "prior_hypothesis_sha256": digest,
                        "retired_supporting_evidence_ids": [str(older)],
                    }
                ],
            }
        )
    )
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    )
    response = provider.investigate(request)
    assert not response.degraded, provider.status.detail
    assert response.schema_version == 4
    assert response.presented_prior_hypothesis_ids == (old.hypothesis_id,)
    assert response.hypothesis_revision_intents[0].prior_hypothesis_sha256 == digest
    assert transport.last_body is not None
    packet = json.loads(json.loads(transport.last_body)["messages"][1]["content"])
    assert packet["prior_hypothesis_revision_refs"][0]["hypothesis_sha256"] == digest


def test_fast_attention_concern_reaches_deep_model_with_cited_observation() -> None:
    request = _request()
    cited = request.evidence_ids[0]
    concern = FastAttentionConcern(
        kind=FastSignalKind.CONTRADICTION_SUSPECTED,
        evidence_ids=(cited,),
        hypothesis_brief="The service may not be the cause.",
    )
    request = ReasoningRequest.model_validate(
        {**request.model_dump(mode="json"), "fast_concerns": [concern.model_dump(mode="json")]}
    )
    transport = FakeTransport("{}")
    provider = OllamaReasoningProvider(
        LocalInferenceConfig(enabled=True, reasoning_model="small-local"),
        transport=transport,
    )

    provider.investigate(request)

    assert transport.last_body is not None
    prompt = json.loads(json.loads(transport.last_body)["messages"][1]["content"])
    assert prompt["fast_attention_concerns"] == [concern.model_dump(mode="json")]
    assert prompt["evidence"][0]["evidence_id"] == str(cited)
    assert "may be mistaken" in prompt["task"]
