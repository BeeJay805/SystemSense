"""Optional local Ollama provider for non-authoritative diagnostic hypotheses."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

from pydantic import Field, ValidationError

from systemsense.decision.contracts import (
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId
from systemsense.inference.ollama import (
    JsonTransport,
    LocalInferenceError,
    OllamaChatClient,
    OllamaPreloadResult,
)
from systemsense.inference.settings import LocalInferenceConfig, ProviderStatus
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider


class _HypothesisAdvice(FrozenModel):
    hypothesis_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_.-]*$")
    statement: str = Field(min_length=1, max_length=1000)
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED
    supporting_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    contradicting_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    missing_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    distinguishing_probe_ids: tuple[str, ...] = Field(default=(), max_length=16)


class _ReasoningAdvice(FrozenModel):
    summary: str = Field(min_length=1, max_length=1600)
    hypotheses: tuple[_HypothesisAdvice, ...] = Field(default=(), max_length=16)
    distinguishing_probe_ids: tuple[str, ...] = Field(default=(), max_length=32)
    requested_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    requested_details: tuple[EvidenceDetailRequest, ...] = Field(default=(), max_length=4)


class OllamaReasoningProvider:
    """Convert model hypotheses to explicitly unresolved, locally validated advice."""

    def __init__(
        self,
        config: LocalInferenceConfig,
        *,
        transport: JsonTransport | None = None,
        fallback: DeterministicReasoningProvider | None = None,
    ) -> None:
        if not config.enabled or config.reasoning_model is None:
            raise ValueError("Ollama reasoning provider requires explicit enablement and a model")
        self._config = config
        self._model = config.reasoning_model
        self._client = OllamaChatClient(config=config, transport=transport)
        self._fallback = fallback or DeterministicReasoningProvider()
        self._status = ProviderStatus(
            provider_id="ollama-local-reasoning",
            enabled=True,
            available=False,
            detail="not_checked",
        )

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="ollama-local-reasoning",
            provider_version="1",
            role="reasoning",
        )

    @property
    def status(self) -> ProviderStatus:
        return self._status

    def prewarm(self, *, timeout_seconds: float) -> OllamaPreloadResult:
        """Check and load the pinned local model without issuing diagnostic advice."""

        return self._client.preload(model=self._model, timeout_seconds=timeout_seconds)

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        timeout = self._timeout_for(request)
        if timeout is None:
            return self._degraded(request, "inference_budget_unavailable")
        prompt = json.dumps(
            {
                "task": (
                    "Propose competing, falsifiable explanations. Do not assert certainty or "
                    "request actions outside registered probes. Cite exact evidence IDs. "
                    "Never repeat completed probes. Documentation describes conditional general "
                    "mechanisms, not observations. You may redirect the fast brain to any "
                    "uncompleted registered probe or request detail by evidence ID from the "
                    "catalog only when it is NOT already in evidence. For additional facts inside "
                    "an already visible observation, use requested_details with its evidence_id "
                    "and 1-3 short literal strings, e.g. a PID or exact endpoint. This searches "
                    "complete local fact rows containing ALL literals, not the internet. Never "
                    "repeat completed_detail_requests or completed generic evidence requests. "
                    "Completed generic requests may still use requested_details for additional "
                    "rows. Include an unknown-cause "
                    "alternative when alternatives remain. Write at most 4 concise hypotheses, "
                    "a summary under 600 characters, and use empty arrays for absent citations. "
                    "Cite observed facts that motivate each explanation. Put next probe IDs in "
                    "distinguishing_probe_ids, never suggest an unregistered command. "
                    "Co-occurrence is NOT a dependency: do not blame a full unrelated volume, "
                    "a pending reboot, a stopped demand-start service, or a driver merely because "
                    "it appears in this packet. Require an observed dependency or explicitly "
                    "name the missing causal link and distinguishing measurement. Normal values "
                    "may contradict a theory; do not list them as positive support. Windows "
                    "error references are operating-system/catalog semantics, not measurements "
                    "from this case and not proof that the referenced condition occurred."
                ),
                "objective": request.objective,
                "observer_context": request.observer_context,
                "evidence": [
                    context.model_dump(mode="json") for context in request.evidence_context
                ],
                "relationships": [
                    {
                        "kind": relation.relationship.value,
                        "source": str(relation.source_entity_id),
                        "target": str(relation.target_entity_id),
                        "evidence_ids": [str(eid) for eid in relation.evidence_ids],
                        "assertion_status": relation.assertion_status.value,
                        "observed_identity": relation.version_metadata,
                    }
                    for relation in request.relationships[:12]
                ],
                "relationship_omissions": max(0, len(request.relationships) - 12),
                "previous_hypotheses": [
                    hypothesis.model_dump(mode="json") for hypothesis in request.previous_hypotheses
                ],
                "completed_probe_ids": sorted(request.completed_probe_ids),
                "completed_detail_requests": [
                    item.model_dump(mode="json") for item in request.completed_detail_requests
                ],
                "priority_evidence_ids": [str(item) for item in request.priority_evidence_ids],
                "completed_evidence_requests": [
                    str(item) for item in request.completed_evidence_requests
                ],
                "reference_knowledge": request.reference_context,
                "windows_error_references": [
                    item.model_dump(mode="json") for item in request.error_references
                ],
                "evidence_catalog": [
                    item
                    for item in request.evidence_catalog
                    if item.get("evidence_id")
                    not in {
                        *(str(e.evidence_id) for e in request.evidence_context),
                        *(str(e) for e in request.completed_evidence_requests),
                    }
                ],
                "available_probes": [
                    {"probe_id": capability.probe_id, "description": capability.description}
                    for capability in request.available_probes
                    if capability.probe_id not in request.completed_probe_ids
                ],
                "max_probes": request.max_probes,
                "budget_ms": request.budget_ms,
            },
            separators=(",", ":"),
        )
        try:
            prompt, visible_ids, context_notes, schema = self._fit_prompt(prompt, request)
            raw = self._client.complete(
                model=self._model,
                prompt=prompt,
                schema=schema,
                timeout_seconds=timeout,
            )
            advice = _ReasoningAdvice.model_validate(raw)
            if any(
                eid not in visible_ids
                for h in advice.hypotheses
                for eid in (
                    *h.supporting_evidence_ids,
                    *h.contradicting_evidence_ids,
                    *h.missing_evidence_ids,
                )
            ):
                raise ReasoningValidationError(
                    "hypothesis cites evidence outside the admitted context"
                )
            capabilities = {probe.probe_id: probe for probe in request.available_probes}
            if any(
                set(item.supporting_evidence_ids) & set(item.contradicting_evidence_ids)
                for item in advice.hypotheses
            ):
                context_notes = (
                    *context_notes,
                    "A conflicting model citation was retained only as contradictory evidence; "
                    "this hypothesis is not verified.",
                )
            hypotheses = tuple(self._hypothesis(item) for item in advice.hypotheses)
            if not any("unknown" in h.hypothesis_id for h in hypotheses):
                hypotheses = (
                    *hypotheses[:15],
                    Hypothesis(
                        hypothesis_id="unknown_cause",
                        statement="An unobserved cause remains possible; "
                        "current measurements and dependency coverage may be insufficient.",
                        status=HypothesisStatus.UNRESOLVED,
                    ),
                )
            proposed_ids = tuple(
                dict.fromkeys(
                    (
                        *advice.distinguishing_probe_ids,
                        *(
                            pid
                            for item in advice.hypotheses
                            for pid in item.distinguishing_probe_ids
                        ),
                    )
                )
            )
            if any(pid not in capabilities for pid in proposed_ids):
                raise ReasoningValidationError("unknown probe requested")
            selected: list[str] = []
            remaining = request.budget_ms
            for pid in proposed_ids:
                capability = capabilities[pid]
                if pid in request.completed_probe_ids or capability.cost_ms > remaining:
                    continue
                if len(selected) >= request.max_probes:
                    break
                selected.append(pid)
                remaining -= capability.cost_ms
            probes = tuple(
                ProbeProposal(
                    probe_id=probe_id,
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=capabilities[probe_id].baseline_priority,
                    estimated_cost_ms=capabilities[probe_id].cost_ms,
                    resource_class=capabilities[probe_id].resource_class,
                    dedupe_key=f"{probe_id}:reasoning",
                    permission_class=capabilities[probe_id].permission_class,
                    safety_class=capabilities[probe_id].safety_class,
                )
                for probe_id in selected
            )
            response = ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary=f"Unverified local model proposal: {advice.summary}",
                hypotheses=hypotheses,
                considered_evidence_ids=visible_ids,
                context_notes=context_notes,
                requested_evidence_ids=tuple(
                    eid
                    for eid in advice.requested_evidence_ids
                    if eid not in visible_ids and eid not in request.completed_evidence_requests
                ),
                requested_details=tuple(
                    item
                    for item in advice.requested_details
                    if item.key() not in {done.key() for done in request.completed_detail_requests}
                ),
                distinguishing_probes=probes,
            ).validate_against(request)
        except (KeyError, LocalInferenceError, ReasoningValidationError, ValidationError) as error:
            detail = (
                error.errors(include_input=False)[0]["type"]
                if isinstance(error, ValidationError)
                else str(error)
            )
            return self._degraded(request, f"{type(error).__name__}:{detail}"[:120])
        self._status = self._status.model_copy(update={"available": True, "detail": "ready"})
        return response

    def _fit_prompt(
        self,
        prompt: str,
        request: ReasoningRequest,
    ) -> tuple[str, tuple[EvidenceId, ...], tuple[str, ...], dict[str, object]]:
        """Deterministically page the focused map before inference, never inside the model."""
        packet = cast(dict[str, object], json.loads(prompt))
        visible = list(request.evidence_context)
        notes: list[str] = []
        protected = {
            str(eid)
            for hypothesis in request.previous_hypotheses
            for eid in (
                *hypothesis.supporting_evidence_ids,
                *hypothesis.contradicting_evidence_ids,
                *hypothesis.missing_evidence_ids,
            )
        }
        protected.update(str(item) for item in request.priority_evidence_ids)
        for _ in range(80):
            visible_ids = tuple(item.evidence_id for item in visible)
            catalog_ids = {
                str(item.get("evidence_id"))
                for item in cast(list[dict[str, object]], packet.get("evidence_catalog", []))
            }
            requestable = tuple(eid for eid in request.evidence_ids if str(eid) in catalog_ids)
            schema = self._advice_schema(request, visible_ids, requestable)
            prompt = json.dumps(packet, separators=(",", ":"))
            if self._client.fits_context(prompt, schema):
                return (
                    prompt,
                    visible_ids,
                    tuple(dict.fromkeys(notes)),
                    schema,
                )
            relations = cast(list[object], packet["relationships"])
            if len(relations) > 4:
                packet["relationships"] = relations[:4]
                packet["relationship_omissions"] = (
                    int(cast(int, packet.get("relationship_omissions", 0))) + len(relations) - 4
                )
                notes.append("Machine graph excerpt bounded to four edges for this reasoning pass.")
            elif packet.get("evidence_catalog"):
                catalog = cast(list[dict[str, object]], packet["evidence_catalog"])
                retained = catalog[: len(catalog) // 2]
                packet["evidence_catalog"] = retained
                packet["catalog_omissions"] = (
                    int(cast(int, packet.get("catalog_omissions", 0)))
                    + len(catalog)
                    - len(retained)
                )
                notes.append(
                    "Unseen evidence catalog and request schema bounded before observed facts."
                )
            elif packet.get("reference_knowledge"):
                packet["reference_knowledge"] = self._smaller_reference(
                    cast(list[dict[str, object]], packet["reference_knowledge"])
                )
                notes.append("Optional reference knowledge bounded before observed evidence.")
            elif packet.get("windows_error_references"):
                references = cast(list[dict[str, object]], packet["windows_error_references"])
                packet["windows_error_references"] = (
                    references[: max(1, len(references) // 2)] if len(references) > 1 else []
                )
                notes.append("Windows error reference context omitted before observed evidence.")
            elif len(visible) > 1:
                index = next(
                    (
                        i
                        for i in reversed(range(len(visible)))
                        if str(visible[i].evidence_id) not in protected
                    ),
                    len(visible) - 1,
                )
                omitted = visible.pop(index)
                catalog = list(cast(list[object], packet["evidence_catalog"]))
                catalog.append(
                    {
                        "evidence_id": str(omitted.evidence_id),
                        "probe_id": omitted.probe_id,
                        "summary": "Observation detail deferred by context budget.",
                    }
                )
                packet["evidence_catalog"] = catalog
                packet["evidence"] = [item.model_dump(mode="json") for item in visible]
                admitted = {str(item.evidence_id) for item in visible}
                kept_relations = [
                    relation
                    for relation in cast(list[dict[str, object]], packet["relationships"])
                    if set(cast(list[str], relation.get("evidence_ids", []))) <= admitted
                ]
                packet["relationship_omissions"] = (
                    int(cast(int, packet.get("relationship_omissions", 0)))
                    + len(relations)
                    - len(kept_relations)
                )
                packet["relationships"] = kept_relations
                prior = [
                    hypothesis
                    for hypothesis in request.previous_hypotheses
                    if set(
                        map(
                            str,
                            (
                                *hypothesis.supporting_evidence_ids,
                                *hypothesis.contradicting_evidence_ids,
                                *hypothesis.missing_evidence_ids,
                            ),
                        )
                    )
                    <= admitted
                ]
                packet["previous_hypotheses"] = [item.model_dump(mode="json") for item in prior]
                if len(prior) < len(request.previous_hypotheses):
                    notes.append(
                        "Prior hypotheses with unavailable citations deferred, not disproved."
                    )
                notes.append("Some observation details deferred to the catalog by token budget.")
            else:
                raise LocalInferenceError("minimal focused evidence exceeds context budget")
            packet["context_limitations"] = list(dict.fromkeys(notes))
        raise LocalInferenceError("context paging limit exceeded")

    @staticmethod
    def _smaller_reference(packets: list[dict[str, object]]) -> list[dict[str, object]]:
        """Keep complete mechanisms, conditions and sources, never a misleading text slice."""
        if len(packets) > 1:
            return packets[:1]
        reference = dict(packets[0])
        relations = cast(list[dict[str, object]], reference.get("relations", []))
        if len(relations) <= 1:
            return []
        retained = relations[: max(1, len(relations) // 2)]
        nodes = {str(r[key]) for r in retained for key in ("source_node_id", "target_node_id")}
        sources = {source for r in retained for source in cast(list[str], r["source_ids"])}
        reference.update(
            relations=retained,
            nodes=[
                n
                for n in cast(list[dict[str, object]], reference.get("nodes", []))
                if n.get("node_id") in nodes
            ],
            sources=[
                s
                for s in cast(list[dict[str, object]], reference.get("sources", []))
                if s.get("source_id") in sources
            ],
            truncated=True,
            omitted_relation_count=int(cast(int, reference.get("omitted_relation_count", 0)))
            + len(relations)
            - len(retained),
        )
        return [reference]

    @staticmethod
    def _advice_schema(
        request: ReasoningRequest,
        visible: tuple[EvidenceId, ...],
        requestable: tuple[EvidenceId, ...] | None = None,
    ) -> dict[str, object]:
        schema = cast(dict[str, object], _ReasoningAdvice.model_json_schema())
        definitions = cast(dict[str, dict[str, object]], schema["$defs"])
        if visible:
            definitions["EvidenceId"]["enum"] = [str(eid) for eid in visible]
        detail_fields = cast(
            dict[str, dict[str, object]], definitions["EvidenceDetailRequest"]["properties"]
        )
        known_requestable = (
            request.evidence_ids
            if requestable is None
            else tuple(dict.fromkeys((*visible, *requestable)))
        )
        completed = set(request.completed_evidence_requests)
        detail_eligible = tuple(
            dict.fromkeys((*known_requestable, *request.completed_evidence_requests))
        )
        generic_requestable = tuple(item for item in known_requestable if item not in completed)
        detail_fields["evidence_id"] = {
            "type": "string",
            "enum": [str(eid) for eid in detail_eligible],
        }
        if not detail_eligible:
            cast(dict[str, dict[str, object]], schema["properties"])["requested_details"][
                "maxItems"
            ] = 0
        properties = cast(dict[str, dict[str, object]], schema["properties"])
        properties["summary"]["maxLength"] = 600
        properties["hypotheses"]["maxItems"] = 4
        schema["required"] = list(properties)
        hypothesis = definitions["_HypothesisAdvice"]
        hypothesis_fields = cast(dict[str, dict[str, object]], hypothesis["properties"])
        hypothesis["required"] = list(hypothesis_fields)
        if not visible:
            for name in (
                "supporting_evidence_ids",
                "contradicting_evidence_ids",
                "missing_evidence_ids",
            ):
                hypothesis_fields[name]["maxItems"] = 0
        probes = [
            p.probe_id
            for p in request.available_probes
            if p.probe_id not in request.completed_probe_ids
        ]
        requested = [str(eid) for eid in generic_requestable if eid not in visible]
        for field, ids in (
            (properties["distinguishing_probe_ids"], probes),
            (hypothesis_fields["distinguishing_probe_ids"], probes),
            (properties["requested_evidence_ids"], requested),
        ):
            field["items"] = {"type": "string", "enum": ids} if ids else {"type": "string"}
            if not ids:
                field["maxItems"] = 0
        return schema

    @staticmethod
    def _hypothesis(advice: _HypothesisAdvice) -> Hypothesis:
        support = set(advice.supporting_evidence_ids)
        contradiction = set(advice.contradicting_evidence_ids)
        status = advice.status
        if support & contradiction:
            status = HypothesisStatus.CONTESTED
        elif status is HypothesisStatus.SUPPORTED:
            status = HypothesisStatus.CONTESTED if contradiction else HypothesisStatus.UNRESOLVED
        return Hypothesis(
            hypothesis_id=advice.hypothesis_id,
            statement=f"Unverified possibility: {advice.statement}",
            status=status,
            supporting_evidence_ids=tuple(
                eid for eid in advice.supporting_evidence_ids if eid not in contradiction
            ),
            contradicting_evidence_ids=advice.contradicting_evidence_ids,
            missing_evidence_ids=advice.missing_evidence_ids,
            distinguishing_probe_ids=advice.distinguishing_probe_ids,
        )

    def _timeout_for(self, request: ReasoningRequest) -> float | None:
        remaining = (request.deadline_at - datetime.now(UTC)).total_seconds()
        timeout = min(self._config.timeout_seconds, remaining)
        return timeout if timeout > 0 else None

    def _degraded(self, request: ReasoningRequest, detail: str) -> ReasoningResponse:
        self._status = self._status.model_copy(update={"available": False, "detail": detail})
        response = self._fallback.investigate(request)
        return response.model_copy(update={"degraded": True}).validate_against(request)
