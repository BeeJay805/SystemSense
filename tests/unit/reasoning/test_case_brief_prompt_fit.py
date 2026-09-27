"""Protected case-brief citations must survive downstream prompt fitting."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest

from systemsense.decision.contracts import ProbeCapability, ResourceClass
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.ollama import LocalInferenceError, OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.reasoning.case_brief import assemble_case_brief
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus, ReasoningRequest
from systemsense.reasoning.ollama import OllamaReasoningProvider

NOW = datetime(2026, 9, 27, 3, 0, tzinfo=UTC)


class OneObservationBudgetClient(OllamaChatClient):
    """A fixed fit boundary; no tokenizer, transport, or model request is used."""

    def fits_context(self, prompt: str, schema: Mapping[str, object]) -> bool:
        del schema
        return len(json.loads(prompt)["evidence"]) <= 1


def _context(index: int, *, label: str) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=EvidenceId(root=f"ev_{index:032x}"),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="application.snapshot",
        summary=f"Recorded {label} observation",
        facts={"finding": label},
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )


def test_prompt_fit_fails_closed_when_every_visible_citation_is_protected() -> None:
    support = _context(1, label="support")
    contradiction = _context(2, label="counterevidence")
    hypothesis = Hypothesis(
        hypothesis_id="h_existing",
        statement="An earlier explanation must face its counterevidence.",
        status=HypothesisStatus.CONTESTED,
        supporting_evidence_ids=(support.evidence_id,),
        contradicting_evidence_ids=(contradiction.evidence_id,),
    )
    brief = assemble_case_brief(
        candidate_context=(support, contradiction),
        previous_hypotheses=(hypothesis,),
        ranked_evidence_ids=(contradiction.evidence_id, support.evidence_id),
        max_contexts=2,
        max_chars=4_000,
    )
    assert brief.context == (contradiction, support)
    assert not brief.insufficient_context

    request = ReasoningRequest(
        case_id=CaseId(root=f"case_{1:032x}"),
        state_version=2,
        correlation_id="reasoning:protected-citations",
        deadline_at=NOW + timedelta(minutes=1),
        objective="Compare the prior explanation with the new counterevidence.",
        evidence_ids=(support.evidence_id, contradiction.evidence_id),
        evidence_context=brief.context,
        previous_hypotheses=(hypothesis,),
        priority_evidence_ids=(support.evidence_id, contradiction.evidence_id),
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="Read application state",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=1_000,
        max_probes=1,
    )
    config = LocalInferenceConfig(enabled=True, reasoning_model="small-local")
    provider = OllamaReasoningProvider(config, client=OneObservationBudgetClient(config=config))
    packet = {
        "evidence": [item.model_dump(mode="json") for item in request.evidence_context],
        "relationships": [],
        "reference_knowledge": [],
        "windows_error_references": [],
        "previous_hypotheses": [hypothesis.model_dump(mode="json")],
        "evidence_catalog": [],
    }

    try:
        fitted, visible, _notes, _schema = provider._fit_prompt(  # pyright: ignore[reportPrivateUsage]
            json.dumps(packet), request
        )
    except LocalInferenceError as error:
        assert any(word in str(error).casefold() for word in ("budget", "citation", "protected"))
    else:
        fitted_hypotheses = json.loads(fitted)["previous_hypotheses"]
        pytest.fail(
            "Prompt fitting returned despite an unfit protected brief: "
            f"visible_ids={[str(item) for item in visible]}, "
            f"prior_hypotheses={len(fitted_hypotheses)}. "
            "It must report insufficient cited context."
        )
