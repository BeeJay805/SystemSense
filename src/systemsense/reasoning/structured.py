"""Shared bounded JSON advisory contract, independent of inference transport."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol, cast

from pydantic import Field, ValidationError

from systemsense.decision.contracts import (
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.decision.measurement import catalog_bound_measurement_need
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.ollama import (
    LocalInferenceError,
    OutputTokenExhausted,
)
from systemsense.inference.settings import ProviderStatus
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    ExpectedFact,
    Hypothesis,
    HypothesisRevisionIntentV1,
    HypothesisStatus,
    NoncausalHypothesisRefV1,
    NoncausalObservationReviewV1,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
    is_unavailable_observation,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.request_window import parse_request_window_facts


class _HypothesisAdvice(FrozenModel):
    hypothesis_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_.-]*$")
    statement: str = Field(min_length=1, max_length=1000)
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED
    claim_window_evidence_id: EvidenceId | None = None
    supporting_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    contradicting_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    missing_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    noncausal_observation_refs: tuple[NoncausalHypothesisRefV1, ...] = Field(
        default=(), max_length=4
    )
    distinguishing_probe_ids: tuple[str, ...] = Field(default=(), max_length=16)
    expected_facts: tuple[ExpectedFact, ...] = Field(default=(), max_length=4)


class _ReasoningAdvice(FrozenModel):
    summary: str = Field(min_length=1, max_length=1600)
    hypotheses: tuple[_HypothesisAdvice, ...] = Field(default=(), max_length=16)
    hypothesis_revision_intents: tuple[HypothesisRevisionIntentV1, ...] = Field(
        default=(), max_length=16
    )
    noncausal_observation_reviews: tuple[NoncausalObservationReviewV1, ...] = Field(
        default=(), max_length=2
    )
    distinguishing_probe_ids: tuple[str, ...] = Field(default=(), max_length=32)
    cancelled_probe_ids: tuple[str, ...] = Field(default=(), max_length=32)
    requested_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    requested_details: tuple[EvidenceDetailRequest, ...] = Field(default=(), max_length=4)
    request_next_catalog_page: bool = False


class StructuredJsonClient(Protocol):
    def fits_context(self, prompt: str, schema: Mapping[str, object]) -> bool: ...

    def complete(
        self, *, model: str, prompt: str, schema: Mapping[str, object], timeout_seconds: float
    ) -> Mapping[str, object]: ...


class StructuredReasoningProvider:
    """Validate advisory hypotheses against the exact fitted evidence packet."""

    def __init__(
        self,
        *,
        client: StructuredJsonClient,
        model: str,
        timeout_seconds: float,
        identity: ProviderIdentity,
        proposal_label: str,
        fallback: DeterministicReasoningProvider | None = None,
    ) -> None:
        self._client = client
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._identity = identity
        self._proposal_label = proposal_label
        self._fallback = fallback or DeterministicReasoningProvider()
        self._status = ProviderStatus(
            provider_id=identity.provider_id, enabled=True, available=False, detail="not_checked"
        )

    @property
    def identity(self) -> ProviderIdentity:
        return self._identity

    @property
    def status(self) -> ProviderStatus:
        return self._status

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        timeout = self._timeout_for(request)
        if timeout is None:
            return self._degraded(request, "inference_budget_unavailable")
        prompt = json.dumps(
            {
                "task": (
                    "Compare falsifiable causes and unknown cause. Cite observed evidence IDs "
                    "only; catalog summaries, Windows error references, and documentation are "
                    "not measurements. Fast concerns may be mistaken. Co-occurrence is not "
                    "causality: require an observed dependency or name the missing link and "
                    "distinguishing measurement. Normal readings may contradict a theory. "
                    "Suggest only registered read-only uncompleted probes, never commands. "
                    + (
                        "Expected facts are optional predictions, not observations; use only "
                        "the exact finite prediction outputs shown for a registered probe. "
                        "If none are shown, omit expected facts. "
                        if request.schema_version >= 6
                        else "Expected facts are optional predictions, not observations; use "
                        "registered probes and categorical values only. "
                    )
                    + "Request missing catalog IDs. Use "
                    "requested_details with 1-3 exact literals for more facts in a visible "
                    "observation; local fact-row matching is enforced. Do not repeat completed "
                    "requests. Pending probes persist across detail follow-ups; cancel only when "
                    "new evidence makes one obsolete. Advance the catalog only after reviewing "
                    "an untruncated page; if truncated, request visible IDs instead."
                    " Diagnostic progress answers only its scoped state question; it is "
                    "not a cause, repair claim, or permission. Respect unknown results "
                    "and custody gaps."
                    + (
                        " When a claim concerns one request, set "
                        "claim_window_evidence_id to that exact observed request ID. "
                        "A later successful retry does not contradict an earlier failed "
                        "request; leave the cause unresolved when the windows differ."
                        if request.schema_version >= 7
                        else ""
                    )
                    + (
                        " For recent uncited observations, cite support or contradiction only "
                        "when target and time bear on a hypothesis. An unavailable result may "
                        "appear as missing evidence; otherwise give its exact ID, a bounded "
                        "disposition and missing-link explanation under "
                        "noncausal_observation_reviews. The review field itself adds no "
                        "causal authority for the affected outcome."
                        if request.previous_hypotheses
                        else ""
                    )
                    + (
                        " To update a prior same-ID statement using a noncausal observation, "
                        "keep every prior causal citation and prediction unchanged, and add "
                        "the exact reviewed ID and disposition to that hypothesis's "
                        "noncausal_observation_refs. Preserve prior refs. A ref is context, "
                        "never support, contradiction, or an unavailable result."
                        if request.schema_version >= 7 and request.previous_hypotheses
                        else ""
                    )
                    + (
                        " To change a prior same-ID hypothesis while retiring old support, "
                        "include hypothesis_revision_intents with its exact supplied prior digest "
                        "and every retired support ID. Retired support becomes history, not "
                        "support or contradiction for the new statement. Preserve old "
                        "contradictions and predictions; cite a newly visible observation."
                        if request.schema_version >= 7 and request.previous_hypotheses
                        else ""
                    )
                ),
                "diagnostic_progress": [
                    item.model_dump(mode="json") for item in request.diagnostic_progress
                ],
                "objective": request.objective,
                **(
                    {
                        "task_observation": request.task_observation.model_visible(),
                        "task_observation_caveat": (
                            "The URL redacted from the objective is this exact GET. It is "
                            "not a separate page. The user-owned loopback health task was "
                            "replayed once initially; its result verifies that replay, "
                            "not an earlier report or internal cause. A later registered "
                            "probe may contain another exact GET. For a concurrent "
                            "measurement, state which rival its value favors or weakens "
                            "at that replay's time without claiming handler cause."
                            if request.task_observation.scope == "user_owned_loopback"
                            and request.task_observation.reported_task_relation
                            == "exact_action_replayed"
                            else "The user selected one immutable local file capture for Dyad's "
                            "strict UTF-8 JSON parser. Acceptance or rejection concerns that "
                            "parser and captured bytes only, not another application's behavior, "
                            "schema validity, file corruption, or a repair. Available encoding "
                            "and syntax checks report fixed codes without file contents."
                            if request.task_observation.scope == "user_selected_file"
                            else "The exact reported test-owned loopback GET was independently "
                            "replayed once initially. Its result verifies that replay, "
                            "not an earlier report, internal cause, or repair. A later "
                            "registered probe may contain another exact GET. For a "
                            "concurrent measurement, state which rival its value favors "
                            "or weakens at that replay's time without claiming handler cause."
                            if request.task_observation.reported_task_relation
                            == "exact_action_replayed"
                            else "One loopback GET is observed; its result does not "
                            "establish application-internal cause or permit action."
                            if request.task_observation.scope
                            in {
                                "test_owned_loopback",
                                "user_owned_loopback",
                            }
                            else "Synthetic fixture observation only; source coverage and symptom "
                            "do not establish cause or permit action."
                        ),
                        "selected_sources": [
                            {
                                "item_id": item.item_id,
                                "evidence_id": str(item.evidence_id),
                                "source_record_sha256": item.source_record_sha256,
                                "source_task_relation": (
                                    None
                                    if item.source_task_relation is None
                                    else item.source_task_relation.model_dump(mode="json")
                                ),
                            }
                            for item in request.selected_sources
                        ],
                    }
                    if request.task_observation is not None
                    else {}
                ),
                **(
                    {
                        "reported_affected_task": request.reported_task.model_dump(mode="json"),
                        "reported_task_caveat": (
                            "The earlier user-reported result remains unverified. The exact "
                            "action was independently replayed in task_observation; its new "
                            "outcome is observed, not proof of an earlier state or cause."
                            if request.task_observation is not None
                            and request.task_observation.reported_task_relation
                            == "exact_action_replayed"
                            else "User-reported action and result are unverified context, "
                            "not an observed outcome or causal proof."
                        ),
                    }
                    if request.reported_task is not None
                    else {}
                ),
                "observer_context": request.observer_context,
                "fast_attention_concerns": [
                    item.model_dump(mode="json") for item in request.fast_concerns
                ],
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
                **(
                    {
                        "prior_hypothesis_revision_refs": [
                            item.model_dump(mode="json")
                            for item in request.prior_hypothesis_revision_refs
                        ]
                    }
                    if request.prior_hypothesis_revision_refs
                    else {}
                ),
                "completed_probe_ids": sorted(request.completed_probe_ids),
                "pending_probe_ids": list(request.pending_probe_ids),
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
                "catalog_has_more": request.catalog_has_more,
                "catalog_page_truncated": False,
                "available_probes": [
                    {
                        "probe_id": capability.probe_id,
                        "description": capability.description,
                        **(
                            {
                                "probe_version": capability.probe_version,
                                "prediction_outputs": [
                                    {
                                        "name": output.name,
                                        "allowed_values": list(output.allowed_values),
                                    }
                                    for output in capability.prediction_outputs
                                ],
                            }
                            if request.schema_version >= 6
                            else {}
                        ),
                    }
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
            catalog_page_truncated = bool(
                cast(dict[str, object], json.loads(prompt)).get("catalog_page_truncated", False)
            )
            try:
                raw = self._client.complete(
                    model=self._model,
                    prompt=prompt,
                    schema=schema,
                    timeout_seconds=timeout,
                )
            except OutputTokenExhausted:
                # One completed length stop can recover under a tighter output
                # contract. Preserve the exact admitted evidence and case bind.
                retry_schema = cast(dict[str, object], json.loads(json.dumps(schema)))
                retry_properties = cast(dict[str, dict[str, object]], retry_schema["properties"])
                retry_properties["summary"]["maxLength"] = 240
                retry_properties["hypotheses"]["maxItems"] = 2
                retry_defs = cast(dict[str, dict[str, object]], retry_schema["$defs"])
                retry_hypothesis = cast(
                    dict[str, dict[str, object]], retry_defs["_HypothesisAdvice"]["properties"]
                )
                retry_hypothesis["statement"]["maxLength"] = 320
                retry_hypothesis["expected_facts"]["maxItems"] = min(
                    1, cast(int, retry_hypothesis["expected_facts"]["maxItems"])
                )
                retry_packet = cast(dict[str, object], json.loads(prompt))
                retry_packet["output_retry"] = (
                    "Previous JSON reached the output token limit. Return at most two brief "
                    "competing unresolved explanations, exact cited evidence IDs, one "
                    "distinguishing prediction each only if the fitted schema permits one, "
                    "and unknown cause if needed. "
                    "Use empty arrays for unsupported optional facts."
                )
                retry_prompt = json.dumps(retry_packet, separators=(",", ":"))
                retry_timeout = self._timeout_for(request)
                if retry_timeout is None or not self._client.fits_context(
                    retry_prompt, retry_schema
                ):
                    raise
                raw = self._client.complete(
                    model=self._model,
                    prompt=retry_prompt,
                    schema=retry_schema,
                    timeout_seconds=min(timeout, retry_timeout),
                )
                context_notes = (
                    *context_notes,
                    "One completed output token limit was rejected before a bounded tighter retry.",
                )
            try:
                advice = _ReasoningAdvice.model_validate(raw)
                self._validate_hypothesis_ids(advice)
                self._validate_visible_predictions(
                    advice, cast(dict[str, object], json.loads(prompt)), request
                )
                self._validate_recent_review(advice, cast(dict[str, object], json.loads(prompt)))
            except (ValidationError, ReasoningValidationError) as validation_error:
                # A malformed advisory answer has no authority. Retry once with
                # the same schema and case binding, never a repaired or relaxed
                # interpretation of the invalid output.
                retry_packet = cast(dict[str, object], json.loads(prompt))
                retry_packet["validation_retry"] = (
                    "The previous answer failed the required schema. Return every required "
                    "field with only admitted evidence and probe IDs; omit unsupported "
                    "predictions. Keep unresolved hypotheses and unknown cause possible."
                )
                if retry_packet.get("recent_uncited_observations"):
                    recent_ids = [
                        str(item["evidence_id"])
                        for item in cast(
                            list[dict[str, object]],
                            retry_packet["recent_uncited_observations"],
                        )
                    ]
                    retry_packet["validation_retry"] = (
                        "The previous answer failed a focused observation review. The only "
                        f"fitted recent observation IDs are {recent_ids}. Use each at most once "
                        "in noncausal_observation_reviews; do not review older cited IDs, "
                        "catalog entries, or unavailable data as observed facts. For each "
                        "listed ID, either cite it under a prior rival "
                        "when the same target and window support that link, cite a verified "
                        "unavailable result as missing evidence, or add its exact ID and "
                        "missing-link explanation to noncausal_observation_reviews. "
                        "Use disposition unavailable only for an actually unavailable result. "
                        "Keep uncertainty; "
                        "abnormality alone is not cause. Return the full required schema."
                    )
                    if isinstance(validation_error, ReasoningValidationError):
                        retry_packet["validation_retry"] += (
                            " Rejected answer: " + str(validation_error) + "."
                        )
                retry_prompt = json.dumps(retry_packet, separators=(",", ":"))
                retry_timeout = self._timeout_for(request)
                if retry_timeout is None or not self._client.fits_context(retry_prompt, schema):
                    raise
                raw = self._client.complete(
                    model=self._model,
                    prompt=retry_prompt,
                    schema=schema,
                    timeout_seconds=min(timeout, retry_timeout),
                )
                advice = _ReasoningAdvice.model_validate(raw)
                self._validate_hypothesis_ids(advice)
                self._validate_visible_predictions(
                    advice, cast(dict[str, object], json.loads(prompt)), request
                )
                self._validate_recent_review(advice, cast(dict[str, object], json.loads(prompt)))
                context_notes = (
                    *context_notes,
                    "One invalid local advisory output was rejected before a bounded retry.",
                )
            fitted_packet = cast(dict[str, object], json.loads(prompt))
            shown_prior_ids = tuple(
                str(item["hypothesis_id"])
                for item in cast(
                    list[dict[str, object]], fitted_packet.get("previous_hypotheses", [])
                )
            )
            shown_catalog_ids = {
                str(item.get("evidence_id"))
                for item in cast(list[dict[str, object]], fitted_packet["evidence_catalog"])
            }
            shown_ids = {str(item) for item in visible_ids} | shown_catalog_ids
            completed_ids = {str(item) for item in request.completed_evidence_requests}
            if any(
                str(item) not in shown_ids | completed_ids for item in advice.requested_evidence_ids
            ):
                raise ReasoningValidationError(
                    "model requested evidence omitted from the fitted prompt"
                )
            detail_ids = shown_ids | completed_ids
            if any(str(item.evidence_id) not in detail_ids for item in advice.requested_details):
                raise ReasoningValidationError(
                    "model requested detail omitted from the fitted prompt"
                )
            if any(
                eid not in visible_ids
                for h in advice.hypotheses
                for eid in (
                    *((h.claim_window_evidence_id,) if h.claim_window_evidence_id else ()),
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
                if capability.target_handles and catalog_bound_measurement_need(capability) is None:
                    continue
                if pid in request.completed_probe_ids or capability.cost_ms > remaining:
                    continue
                if len(selected) >= request.max_probes:
                    break
                selected.append(pid)
                remaining -= capability.cost_ms
            proposals: list[ProbeProposal] = []
            for probe_id in selected:
                capability = capabilities[probe_id]
                need = catalog_bound_measurement_need(capability)
                proposals.append(
                    ProbeProposal(
                        schema_version=2 if need is not None else 1,
                        probe_id=probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=capability.baseline_priority,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key=f"{probe_id}:reasoning",
                        permission_class=capability.permission_class,
                        safety_class=capability.safety_class,
                        measurement_need=need,
                    )
                )
            probes = tuple(proposals)
            response = ReasoningResponse(
                schema_version=(
                    6
                    if any(item.noncausal_observation_refs for item in advice.hypotheses)
                    else 5
                    if advice.noncausal_observation_reviews
                    else 4
                    if advice.hypothesis_revision_intents
                    else 3
                ),
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary=f"{self._proposal_label}: {advice.summary}",
                hypotheses=hypotheses,
                hypothesis_revision_intents=advice.hypothesis_revision_intents,
                noncausal_observation_reviews=advice.noncausal_observation_reviews,
                presented_prior_hypothesis_ids=shown_prior_ids
                if advice.hypothesis_revision_intents
                or advice.noncausal_observation_reviews
                or any(item.noncausal_observation_refs for item in advice.hypotheses)
                else (),
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
                cancelled_probe_ids=advice.cancelled_probe_ids,
                request_next_catalog_page=advice.request_next_catalog_page,
                catalog_page_truncated=catalog_page_truncated,
            ).validate_against(request)
        except (KeyError, LocalInferenceError, ReasoningValidationError, ValidationError) as error:
            if isinstance(error, LocalInferenceError) and error.phase is not None:
                detail = f"transport_{error.phase}"
                if error.http_status is not None:
                    detail += f"_http_{error.http_status}"
                elif error.error_code is not None:
                    detail += f"_socket_{error.error_code}"
            elif isinstance(error, ValidationError):
                detail = str(error.errors(include_input=False)[0]["type"])
            else:
                detail = str(error)
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
        packet.setdefault("catalog_has_more", request.catalog_has_more)
        packet.setdefault("catalog_page_truncated", False)
        visible = list(request.evidence_context)
        notes: list[str] = []
        protected = {
            str(eid)
            for hypothesis in request.previous_hypotheses
            for eid in (
                *(
                    (hypothesis.claim_window_evidence_id,)
                    if hypothesis.claim_window_evidence_id
                    else ()
                ),
                *hypothesis.supporting_evidence_ids,
                *hypothesis.contradicting_evidence_ids,
                *hypothesis.missing_evidence_ids,
                *(item.evidence_id for item in hypothesis.noncausal_observation_refs),
            )
        }
        protected.update(str(item) for item in request.priority_evidence_ids)
        protected.update(
            str(evidence_id)
            for concern in request.fast_concerns
            for evidence_id in concern.evidence_ids
        )
        include_recent_review = True
        for _ in range(80):
            visible_ids = tuple(item.evidence_id for item in visible)
            prior = cast(list[dict[str, object]], packet.get("previous_hypotheses", []))
            if prior:
                packet["rival_review_instruction"] = (
                    "Compare recent uncited current-case facts with prior rivals. Their "
                    "target and time window may differ. Cite support or contradiction only "
                    "when they bear on a rival; otherwise explain the missing link. "
                    "Abnormality alone is not cause."
                )
                cited = {
                    str(evidence_id)
                    for hypothesis in prior
                    for name in (
                        "supporting_evidence_ids",
                        "contradicting_evidence_ids",
                        "missing_evidence_ids",
                    )
                    for evidence_id in cast(list[str], hypothesis.get(name, []))
                }
                cited.update(
                    str(ref["evidence_id"])
                    for hypothesis in prior
                    for ref in cast(
                        list[dict[str, object]],
                        hypothesis.get("noncausal_observation_refs", []),
                    )
                )
                packet["uncited_visible_observation_ids"] = [
                    str(evidence_id) for evidence_id in visible_ids if str(evidence_id) not in cited
                ]
                cited_context = [item for item in visible if str(item.evidence_id) in cited]
                recent = (
                    sorted(
                        (
                            item
                            for item in visible
                            if item.case_scope == "current_case"
                            and item.status is EvidenceContextStatus.OBSERVED
                            and str(item.evidence_id) not in cited
                            and item.observed_at > max(row.observed_at for row in cited_context)
                        ),
                        key=lambda item: item.observed_at,
                        reverse=True,
                    )[:2]
                    if cited_context and include_recent_review
                    else []
                )
                if recent:
                    packet["recent_uncited_observations"] = [
                        {
                            "evidence_id": str(item.evidence_id),
                            "probe_id": item.probe_id,
                            "observed_at": item.observed_at.isoformat(),
                            "facts": item.facts,
                            "limitations": item.limitations,
                            "allowed_noncausal_dispositions": (
                                ["unavailable", "target_unbound", "time_unbound", "unrelated"]
                                if is_unavailable_observation(item)
                                else ["target_unbound", "time_unbound", "unrelated"]
                            ),
                        }
                        for item in recent
                    ]
                else:
                    packet.pop("recent_uncited_observations", None)
            else:
                packet.pop("uncited_visible_observation_ids", None)
                packet.pop("rival_review_instruction", None)
                packet.pop("recent_uncited_observations", None)
            catalog_ids = {
                str(item.get("evidence_id"))
                for item in cast(list[dict[str, object]], packet.get("evidence_catalog", []))
            }
            requestable = tuple(eid for eid in request.evidence_ids if str(eid) in catalog_ids)
            schema = self._advice_schema(
                request,
                visible_ids,
                requestable,
                catalog_page_truncated=bool(packet["catalog_page_truncated"]),
                recent_review_ids=tuple(
                    EvidenceId(root=str(item["evidence_id"]))
                    for item in cast(
                        list[dict[str, object]], packet.get("recent_uncited_observations", [])
                    )
                ),
                presented_prior_hypothesis_ids=tuple(
                    str(item["hypothesis_id"])
                    for item in cast(list[dict[str, object]], packet.get("previous_hypotheses", []))
                ),
            )
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
                packet["catalog_page_truncated"] = True
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
                compact = self._compact_error_references(references)
                if compact is not None and compact != references:
                    packet["windows_error_references"] = compact
                    notes.append(
                        "Windows error references retain codes, mechanism, source, and limits; "
                        "noncausal catalog metadata was omitted."
                    )
                else:
                    packet["windows_error_references"] = (
                        references[: max(1, len(references) // 2)] if len(references) > 1 else []
                    )
                    notes.append(
                        "Windows error reference context omitted before observed evidence."
                    )
            elif request.schema_version >= 6 and any(
                probe.prediction_outputs for probe in request.available_probes
            ):
                # Keep the small prospective contract if optional catalog and
                # reference pages can shrink first. Never evict cited facts for it.
                packet["available_probes"] = [
                    {
                        key: value
                        for key, value in probe.items()
                        if key not in {"probe_version", "prediction_outputs"}
                    }
                    for probe in cast(list[dict[str, object]], packet["available_probes"])
                ]
                request = request.model_copy(
                    update={
                        "available_probes": tuple(
                            probe.model_copy(
                                update={"probe_version": None, "prediction_outputs": ()}
                            )
                            for probe in request.available_probes
                        )
                    }
                )
                notes.append("Optional prediction outputs omitted to preserve observed evidence.")
                continue
            elif packet.get("recent_uncited_observations"):
                # The focused comparison is redundant with complete admitted
                # observations. Drop it before evicting observed facts.
                include_recent_review = False
                packet.pop("recent_uncited_observations", None)
                notes.append("Recent-observation review queue omitted by context budget.")
            elif len(visible) > 1:
                index = next(
                    (
                        i
                        for i in reversed(range(len(visible)))
                        if str(visible[i].evidence_id) not in protected
                    ),
                    None,
                )
                if index is None:
                    raise LocalInferenceError("protected cited evidence exceeds context budget")
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
                                *(
                                    (hypothesis.claim_window_evidence_id,)
                                    if hypothesis.claim_window_evidence_id
                                    else ()
                                ),
                                *hypothesis.supporting_evidence_ids,
                                *hypothesis.contradicting_evidence_ids,
                                *hypothesis.missing_evidence_ids,
                                *(
                                    item.evidence_id
                                    for item in hypothesis.noncausal_observation_refs
                                ),
                            ),
                        )
                    )
                    <= admitted
                ]
                packet["previous_hypotheses"] = [item.model_dump(mode="json") for item in prior]
                if "prior_hypothesis_revision_refs" in packet:
                    kept_ids = {item.hypothesis_id for item in prior}
                    packet["prior_hypothesis_revision_refs"] = [
                        item.model_dump(mode="json")
                        for item in request.prior_hypothesis_revision_refs
                        if item.hypothesis_id in kept_ids
                    ]
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
    def _compact_error_references(
        references: list[dict[str, object]],
    ) -> list[dict[str, object]] | None:
        """Drop redundant catalog metadata, never the bounded code's caveats."""

        if any(
            len(str(item.get("message", ""))) > 512
            or len(str(item.get("mechanism_note", ""))) > 512
            for item in references
        ):
            return None
        compact: list[dict[str, object]] = []
        for item in references:
            source = item.get("source")
            if not isinstance(source, dict):
                return None
            typed_source = cast(dict[str, object], source)
            compact.append(
                {
                    key: item[key]
                    for key in (
                        "reference_id",
                        "namespace",
                        "win32_code",
                        "hresult",
                        "constant_names",
                        "message",
                        "mechanism_note",
                        "knowledge_node_ids",
                        "limitations",
                    )
                    if key in item
                }
                | {
                    "source": {
                        key: typed_source[key]
                        for key in (
                            "catalog_provider",
                            "catalog_version",
                            "message_provider",
                            "os_version",
                            "runtime_observed",
                        )
                        if key in typed_source
                    }
                }
            )
        return compact

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
        *,
        catalog_page_truncated: bool = False,
        recent_review_ids: tuple[EvidenceId, ...] = (),
        presented_prior_hypothesis_ids: tuple[str, ...] | None = None,
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
        if recent_review_ids:
            review_field = properties["noncausal_observation_reviews"]
            review_field["maxItems"] = len(recent_review_ids)
            review_definition = cast(
                dict[str, dict[str, object]],
                definitions["NoncausalObservationReviewV1"]["properties"],
            )
            review_definition["evidence_id"] = {
                "type": "string",
                "enum": [str(evidence_id) for evidence_id in recent_review_ids],
            }
            context = {item.evidence_id: item for item in request.evidence_context}
            constraints: list[dict[str, object]] = []
            any_unavailable = False
            for evidence_id in recent_review_ids:
                observation = context.get(evidence_id)
                if observation is None:
                    continue
                unavailable = is_unavailable_observation(observation)
                any_unavailable = any_unavailable or unavailable
                constraints.append(
                    {
                        "if": {
                            "properties": {"evidence_id": {"const": str(evidence_id)}},
                            "required": ["evidence_id"],
                        },
                        "then": {
                            "properties": {
                                "disposition": {
                                    "enum": (
                                        [
                                            "unavailable",
                                            "target_unbound",
                                            "time_unbound",
                                            "unrelated",
                                        ]
                                        if unavailable
                                        else ["target_unbound", "time_unbound", "unrelated"]
                                    )
                                }
                            }
                        },
                    }
                )
            review_schema = definitions["NoncausalObservationReviewV1"]
            review_schema["allOf"] = constraints
            if not any_unavailable:
                review_definition["disposition"]["enum"] = [
                    "target_unbound",
                    "time_unbound",
                    "unrelated",
                ]
        else:
            properties.pop("noncausal_observation_reviews", None)
            definitions.pop("NoncausalObservationReviewV1", None)
        if request.schema_version < 7:
            properties.pop("hypothesis_revision_intents", None)
            definitions.pop("HypothesisRevisionIntentV1", None)
        else:
            presented_ids = (
                {item.hypothesis_id for item in request.previous_hypotheses}
                if presented_prior_hypothesis_ids is None
                else set(presented_prior_hypothesis_ids)
            )
            intent_field = properties["hypothesis_revision_intents"]
            intent_field["maxItems"] = len(presented_ids)
            intent_definition = cast(
                dict[str, dict[str, object]],
                definitions["HypothesisRevisionIntentV1"]["properties"],
            )
            intent_definition["hypothesis_id"]["enum"] = sorted(presented_ids)
        if not request.catalog_has_more or catalog_page_truncated:
            properties["request_next_catalog_page"]["const"] = False
        properties["summary"]["maxLength"] = 600
        properties["hypotheses"]["maxItems"] = 4
        schema["required"] = list(properties)
        hypothesis = definitions["_HypothesisAdvice"]
        hypothesis_fields = cast(dict[str, dict[str, object]], hypothesis["properties"])
        if request.schema_version >= 7:
            request_window_ids = tuple(
                dict.fromkeys(
                    str(item.evidence_id)
                    for item in request.evidence_context
                    if item.evidence_id in visible
                    and item.case_scope == "current_case"
                    and item.status is EvidenceContextStatus.OBSERVED
                    and parse_request_window_facts(item.facts) is not None
                )
            )
            window_options: list[dict[str, object]] = (
                [{"type": "string", "enum": list(request_window_ids)}] if request_window_ids else []
            )
            window_options.append({"type": "null"})
            hypothesis_fields["claim_window_evidence_id"] = {"anyOf": window_options}
        else:
            hypothesis_fields.pop("claim_window_evidence_id", None)
        shown_ids = (
            {item.hypothesis_id for item in request.previous_hypotheses}
            if presented_prior_hypothesis_ids is None
            else set(presented_prior_hypothesis_ids)
        )
        prior_ref_ids = tuple(
            ref.evidence_id
            for item in request.previous_hypotheses
            if item.hypothesis_id in shown_ids
            for ref in item.noncausal_observation_refs
        )
        context = {item.evidence_id: item for item in request.evidence_context}
        eligible_recent_refs = tuple(
            evidence_id
            for evidence_id in recent_review_ids
            if evidence_id in context and not is_unavailable_observation(context[evidence_id])
        )
        allowed_ref_ids = tuple(dict.fromkeys((*prior_ref_ids, *eligible_recent_refs)))
        if request.schema_version < 7 or not allowed_ref_ids or not shown_ids:
            hypothesis_fields.pop("noncausal_observation_refs", None)
            definitions.pop("NoncausalHypothesisRefV1", None)
        else:
            ref_fields = cast(
                dict[str, dict[str, object]],
                definitions["NoncausalHypothesisRefV1"]["properties"],
            )
            ref_fields["evidence_id"] = {
                "type": "string",
                "enum": [str(item) for item in allowed_ref_ids],
            }
        hypothesis["required"] = list(hypothesis_fields)
        # Optional prediction metadata must not evict a concrete error reference
        # merely because Pydantic emitted redundant titles/descriptions.
        expected_schema = definitions["ExpectedFact"]
        expected_schema.pop("title", None)
        expected_schema.pop("description", None)
        for field in cast(dict[str, dict[str, object]], expected_schema["properties"]).values():
            field.pop("title", None)
        hypothesis_fields["expected_facts"].pop("title", None)
        expected_fields = cast(dict[str, dict[str, object]], expected_schema["properties"])
        expected_fields.pop("probe_version", None)
        known_probe_ids = [probe.probe_id for probe in request.available_probes]
        if request.schema_version >= 6:
            prediction_pairs = [
                (probe.probe_id, output.name, output.allowed_values)
                for probe in request.available_probes
                if probe.probe_id not in request.completed_probe_ids
                for output in probe.prediction_outputs
                if probe.probe_version is not None
            ]
            if prediction_pairs:
                expected_schema["anyOf"] = [
                    {
                        "properties": {
                            "probe_id": {"const": probe_id},
                            "fact_name": {"const": name},
                            "expected_value": {"enum": list(values)},
                        }
                    }
                    for probe_id, name, values in prediction_pairs
                ]
                known_probe_ids = list(dict.fromkeys(pair[0] for pair in prediction_pairs))
            else:
                hypothesis_fields["expected_facts"]["maxItems"] = 0
        if known_probe_ids:
            expected_fields["probe_id"]["enum"] = known_probe_ids
        else:
            hypothesis_fields["expected_facts"]["maxItems"] = 0
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
        cancelled_field = properties["cancelled_probe_ids"]
        cancelled_field["items"] = (
            {"type": "string", "enum": list(request.pending_probe_ids)}
            if request.pending_probe_ids
            else {"type": "string"}
        )
        if not request.pending_probe_ids:
            cancelled_field["maxItems"] = 0
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
    def _validate_hypothesis_ids(advice: _ReasoningAdvice) -> None:
        ids = [item.hypothesis_id for item in advice.hypotheses]
        if len(ids) != len(set(ids)):
            raise ReasoningValidationError("hypotheses must have unique IDs")

    @staticmethod
    def _validate_recent_review(advice: _ReasoningAdvice, packet: dict[str, object]) -> None:
        """An accepted follow-up must account for each bounded focused observation.

        An explicit ID-bound explanation can leave the cause unresolved when
        target or time binding is absent. Mere inclusion in the input is not a
        review. This does not infer support or manufacture a contradiction.
        """
        recent = cast(list[dict[str, object]], packet.get("recent_uncited_observations", []))
        recent_ids = {str(item["evidence_id"]) for item in recent}
        fitted_context = {
            str(item["evidence_id"]): EvidenceContext.model_validate(item)
            for item in cast(list[dict[str, object]], packet["evidence"])
        }
        cited = {
            str(evidence_id)
            for hypothesis in advice.hypotheses
            for evidence_id in (
                *hypothesis.supporting_evidence_ids,
                *hypothesis.contradicting_evidence_ids,
            )
        }
        missing = {
            str(evidence_id)
            for hypothesis in advice.hypotheses
            for evidence_id in hypothesis.missing_evidence_ids
            if str(evidence_id) in fitted_context
            and is_unavailable_observation(fitted_context[str(evidence_id)])
        }
        reviewed: set[str] = set()
        for review in advice.noncausal_observation_reviews:
            evidence_id = str(review.evidence_id)
            observation = fitted_context.get(evidence_id)
            if evidence_id not in recent_ids:
                raise ReasoningValidationError(
                    "noncausal review is outside fitted recent facts: ID is not one of the "
                    "fitted recent observation IDs"
                )
            if observation is None:
                raise ReasoningValidationError(
                    "noncausal review is outside fitted recent facts: observation detail "
                    "was not admitted"
                )
            if evidence_id in reviewed:
                raise ReasoningValidationError(
                    "noncausal review is outside fitted recent facts: duplicate ID"
                )
            if review.disposition == "unavailable" and not is_unavailable_observation(observation):
                raise ReasoningValidationError(
                    "noncausal review is outside fitted recent facts: unavailable disposition "
                    "does not match observed data"
                )
            reviewed.add(evidence_id)
        review_pairs = {
            (str(item.evidence_id), item.disposition)
            for item in advice.noncausal_observation_reviews
        }
        shown_prior = {
            str(item["hypothesis_id"]): item
            for item in cast(list[dict[str, object]], packet.get("previous_hypotheses", []))
        }
        for hypothesis in advice.hypotheses:
            refs = hypothesis.noncausal_observation_refs
            if not refs:
                continue
            old = shown_prior.get(hypothesis.hypothesis_id)
            if old is None:
                raise ReasoningValidationError("noncausal ref has no fitted prior rival")
            old_refs = tuple(
                NoncausalHypothesisRefV1.model_validate(item)
                for item in cast(list[dict[str, object]], old.get("noncausal_observation_refs", []))
            )
            if refs[: len(old_refs)] != old_refs:
                raise ReasoningValidationError("noncausal ref lost fitted prior basis")
            if any(
                str(ref.evidence_id) not in recent_ids
                or (str(ref.evidence_id), ref.disposition) not in review_pairs
                for ref in refs[len(old_refs) :]
            ):
                raise ReasoningValidationError("noncausal ref was not reviewed in fitted facts")
        if any(
            str(item["evidence_id"]) not in cited | missing | reviewed
            and str(item["evidence_id"]) not in advice.summary
            for item in recent
        ):
            raise ReasoningValidationError("focused observation was not reviewed")

    @staticmethod
    def _validate_visible_predictions(
        advice: _ReasoningAdvice, packet: dict[str, object], request: ReasoningRequest
    ) -> None:
        """A hidden optional contract cannot authorize a model prediction."""

        if request.schema_version < 6:
            return
        visible: set[tuple[str, str, type[object], object]] = set()
        for probe in cast(list[dict[str, object]], packet["available_probes"]):
            probe_id = str(probe["probe_id"])
            for output in cast(list[dict[str, object]], probe.get("prediction_outputs", [])):
                name = str(output["name"])
                for value in cast(list[object], output["allowed_values"]):
                    visible.add((probe_id, name, type(value), value))
        if any(
            (
                fact.probe_id,
                fact.fact_name,
                type(fact.expected_value),
                fact.expected_value,
            )
            not in visible
            for hypothesis in advice.hypotheses
            for fact in hypothesis.expected_facts
        ):
            raise ReasoningValidationError("prediction was outside the fitted visible contract")

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
            statement=(
                advice.statement
                if advice.statement.startswith("Unverified possibility: ")
                else f"Unverified possibility: {advice.statement}"
            ),
            status=status,
            claim_window_evidence_id=advice.claim_window_evidence_id,
            supporting_evidence_ids=tuple(
                eid for eid in advice.supporting_evidence_ids if eid not in contradiction
            ),
            contradicting_evidence_ids=advice.contradicting_evidence_ids,
            missing_evidence_ids=advice.missing_evidence_ids,
            noncausal_observation_refs=advice.noncausal_observation_refs,
            distinguishing_probe_ids=advice.distinguishing_probe_ids,
            expected_facts=advice.expected_facts,
        )

    def _timeout_for(self, request: ReasoningRequest) -> float | None:
        remaining = (request.deadline_at - datetime.now(UTC)).total_seconds()
        timeout = min(self._timeout_seconds, remaining)
        return timeout if timeout > 0 else None

    def _degraded(self, request: ReasoningRequest, detail: str) -> ReasoningResponse:
        self._status = self._status.model_copy(update={"available": False, "detail": detail})
        response = self._fallback.investigate(request)
        return response.model_copy(update={"degraded": True}).validate_against(request)
