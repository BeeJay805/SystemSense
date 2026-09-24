from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from systemsense.decision.contracts import FastSignalKind, ProbeCapability, ResourceClass
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.ollama import OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.knowledge.windows_errors import WindowsErrorCatalog, WindowsErrorSource
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    FastAttentionConcern,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningStatus,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.ollama import OllamaReasoningProvider

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
    _, visible, _, _ = provider._fit_prompt(json.dumps(packet), request)  # pyright: ignore[reportPrivateUsage]
    assert observations[-1].evidence_id in visible
    assert len(visible) < len(observations)


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
