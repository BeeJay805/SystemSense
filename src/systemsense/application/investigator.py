"""A bounded, durable investigation loop over read-only collection and advice."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import timedelta

from systemsense.application.assessment import AssessmentDisposition, assess_investigation
from systemsense.application.case_service import OpenedCase
from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
    ProviderCall,
)
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DiagnosticPurpose,
    ProbeCapability,
    ProbeProposal,
)
from systemsense.decision.provider import FastDecisionProvider
from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    CaseTimeWindowBasis,
    DiagnosticCase,
)
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.time import utc_now
from systemsense.evidence.attention import focus_evidence
from systemsense.evidence.graph import EvidenceRelation
from systemsense.evidence.pages import attention_pages
from systemsense.evidence.projection import ExplicitRelationProjector
from systemsense.evidence.redaction import Redactor
from systemsense.evidence.retrieval import (
    EvidencePacket,
    EvidenceRelationRepository,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
)
from systemsense.evidence.targets import retrieve_details, select_target_evidence
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.control import inference_cancellation
from systemsense.inference.settings import ProviderStatus
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.knowledge.models import KnowledgeQuery
from systemsense.knowledge.windows_errors import WindowsErrorReference, reference_for_text
from systemsense.orchestration.planner import CasePlan, PlannedProbe
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    ReasoningRequest,
    ReasoningStatus,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True)
class _RelationshipSelection:
    context: tuple[EvidenceContext, ...]
    relationships: tuple[EvidenceRelation, ...]
    loaded_grounded_count: int
    omitted_count: int
    candidate_scan_truncated: bool


def _baseline_probe_ids(objective: str, available: frozenset[str]) -> tuple[str, ...]:
    """Seed attention with at most one symptom family, not a machine-wide scan.

    This is not a diagnosis or a replacement for the fast brain. The model sees
    these first observations and remains responsible for choosing further probes.
    Unknown symptoms receive only the small host-identity observation.
    """

    text = objective.casefold()
    selected: list[str] = []

    def add_first(*probe_ids: str) -> None:
        for probe_id in probe_ids:
            if probe_id in available:
                selected.append(probe_id)
                break

    if re.search(r"\b(wi-?fi|wireless|internet|network|connect|dns|proxy|gateway)\b", text):
        add_first("network.connectivity", "network.configuration")
    elif re.search(r"\b(game|gaming|fps|frame(?:s|time)?|gpu|graphics)\b", text):
        add_first("gpu.telemetry.sample", "local_ai.snapshot")
    elif re.search(r"\b(slow|freeze|hang|stutter|cpu|memory|pdf)\b", text):
        add_first("core.resources")
    elif re.search(r"\b(driver|device|audio|camera|bluetooth)\b", text):
        add_first("devices.snapshot")
    elif re.search(r"\b(disk|drive|storage|volume|filesystem)\b", text):
        add_first("storage.snapshot")
    if "core.system" in available:
        selected.append("core.system")
    return tuple(dict.fromkeys(selected))


class Investigator:
    def __init__(
        self,
        *,
        store: SQLiteStore,
        runtime: DiagnosticRuntime,
        capabilities: tuple[ProbeCapability, ...],
        decision: FastDecisionProvider,
        reasoning: ReasoningProvider,
        knowledge: ReferenceKnowledgeGraph | None = None,
    ) -> None:
        self.store = store
        self.repository = InvestigationRepository(store)
        self.runtime = runtime
        self.capabilities = capabilities
        self.decision = decision
        self.reasoning = reasoning
        self.knowledge = knowledge
        self.redactor = Redactor()

    def create(
        self,
        *,
        objective: str,
        budget_ms: int = 30_000,
        max_rounds: int = 4,
        max_probes: int = 16,
    ) -> InvestigationState:
        now = utc_now()
        incident_start = now - timedelta(minutes=15)
        historical = self.store.cases(
            created_from=incident_start.isoformat(),
            created_until=now.isoformat(),
            kinds=(CaseKind.PASSIVE.value,),
            limit=16,
        )
        state = InvestigationState(
            case_id=CaseId.new(),
            objective=self.redactor.redact_text(objective.strip()).text,
            created_at=now,
            updated_at=now,
            deadline_at=now + timedelta(milliseconds=budget_ms),
            incident_start=incident_start,
            incident_end=now + timedelta(minutes=5),
            historical_case_ids=tuple(CaseId(root=row.case_id) for row in historical),
            budget_ms=budget_ms,
            max_rounds=max_rounds,
            max_probes=max_probes,
        )
        self.repository.create(state)
        return state

    def resume(self, case_id: str) -> InvestigationState:
        state = self.repository.load(case_id)
        if state.status in {InvestigationStatus.RUNNING, InvestigationStatus.QUEUED}:
            raise ValueError("investigation is already active")
        if state.status is InvestigationStatus.COMPLETE:
            raise ValueError(
                "completed investigations are immutable; start a new case for recurrence"
            )
        if state.round_count >= 120:
            raise ValueError("case history is full; start a new investigation")
        state = state.model_copy(
            update={
                "status": InvestigationStatus.QUEUED,
                "outcome": InvestigationOutcome.INVESTIGATING,
                "deadline_at": utc_now() + timedelta(milliseconds=state.budget_ms),
                "run_start_round": state.round_count,
                "spent_cost_ms": 0,
                "stagnant_rounds": 0,
                "stop_reason": None,
            }
        )
        return self._save(state, "resumed", "Resumed with a new bounded collection budget.")

    def run(
        self, case_id: str, *, cancel_event: threading.Event | None = None
    ) -> InvestigationState:
        with inference_cancellation(cancel_event):
            return self._run(case_id, cancel_event=cancel_event)

    def _run(
        self, case_id: str, *, cancel_event: threading.Event | None = None
    ) -> InvestigationState:
        state = self.repository.load(case_id)
        if state.status not in {InvestigationStatus.QUEUED, InvestigationStatus.RUNNING}:
            return state
        # Pending work survived a crash. It may have observed the host already, so
        # retain it as attempted and surface uncertainty instead of replaying it.
        if state.pending_probe_ids:
            state = state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys(
                            (
                                *state.completed_probe_ids,
                                *state.pending_probe_ids,
                            )
                        )
                    ),
                    "pending_probe_ids": (),
                    "warnings": self._warnings(
                        state, "Interrupted attempts were not automatically repeated."
                    ),
                }
            )
        state = self._save(
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "started",
            "Read-only investigation started.",
        )
        if self.reasoning.identity.provider_id == "ollama-local-reasoning":
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state,
                        "Local inference uses host CPU/GPU resources. Samples taken during "
                        "the investigation include this observer workload, "
                        "not an unloaded baseline.",
                    )
                }
            )
        if not state.completed_probe_ids:
            seed_ids = _baseline_probe_ids(
                state.objective, frozenset(c.probe_id for c in self.capabilities)
            )
            capabilities_by_id = {
                capability.probe_id: capability for capability in self.capabilities
            }
            baseline = tuple(
                ProbeProposal(
                    probe_id=capability.probe_id,
                    purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
                    priority=1.0,
                    estimated_cost_ms=capability.cost_ms,
                    resource_class=capability.resource_class,
                    safety_class=capability.safety_class,
                    dedupe_key=f"baseline:{capability.probe_id}",
                )
                for capability in (capabilities_by_id[probe_id] for probe_id in seed_ids)
            )
            baseline = self._eligible(baseline, state, self._remaining_ms(state))
            if baseline and not (cancel_event is not None and cancel_event.is_set()):
                state = self._collect(state, baseline, cancel_event, baseline=True)
        if len(state.completed_probe_ids) >= state.max_probes:
            stopped = self._stop_if_needed(state, cancel_event, check_probe_budget=False)
            if stopped is not None:
                return stopped
            context = self.context(case_id)
            state = self._refresh_attention(state, context)
            stopped = self._stop_if_needed(state, cancel_event, check_probe_budget=False)
            if stopped is not None:
                return stopped
            state, _ = self._reason_with_details(state, context)
            observed = self._complete_observed(state, context, cancel_event)
            if observed is not None:
                return observed
            return self._finish(
                state,
                InvestigationOutcome.BUDGET_EXHAUSTED,
                "The probe budget is exhausted; collected evidence was assessed.",
            )
        requested: tuple[ProbeProposal, ...] = ()
        for _ in range(state.max_rounds):
            stopped = self._stop_if_needed(state, cancel_event)
            if stopped is not None:
                return stopped
            state = self._save(
                state, "attention", "Fast brain is ranking evidence and eligible investigations."
            )
            context = self.context(case_id)
            remaining = self._remaining_ms(state)
            if remaining <= 0:
                return self._finish(
                    state,
                    InvestigationOutcome.BUDGET_EXHAUSTED,
                    "The case budget expired while retrieving evidence.",
                )
            graph = self._relationships(context)
            context = graph.context
            decision_request = DecisionRequest(
                case_id=state.case_id,
                state_version=state.state_version,
                correlation_id=f"decision:{state.case_id}:{state.state_version}",
                deadline_at=self._decision_deadline(state),
                symptom=state.objective,
                evidence_ids=tuple(item.evidence_id for item in context),
                evidence_context=context,
                attention_context=attention_pages(self.store, context),
                relationships=graph.relationships,
                reference_context=self.reference_context(state),
                available_probes=self.capabilities,
                completed_probe_ids=frozenset(state.completed_probe_ids),
                # Completion is an execution fact, not a freshness guarantee.
                fresh_probe_ids=frozenset(),
                preferred_probe_ids=tuple(p.probe_id for p in requested),
                hypothesis_briefs=tuple(h.statement for h in state.hypotheses),
                budget_ms=remaining,
                max_probes=max(1, min(4, state.max_probes - len(state.completed_probe_ids))),
            )
            call_started_at = utc_now()
            call_started = time.monotonic()
            rejected = False
            try:
                response = self.decision.decide(decision_request).validate_against(decision_request)
                if response.provider != self.decision.identity and not (
                    response.degraded
                    and response.provider == KeywordBaselineDecisionProvider().identity
                ):
                    raise ValueError("decision provider identity mismatch")
                if utc_now() >= decision_request.deadline_at:
                    raise ValueError("decision result missed its deadline")
            except Exception as error:
                rejected = True
                response = KeywordBaselineDecisionProvider().decide(decision_request)
                state = state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state,
                            f"Decision provider rejected: {type(error).__name__}. Baseline used.",
                        )
                    }
                )
            decision_status = getattr(self.decision, "status", None)
            state = state.model_copy(
                update={
                    "decision_provider": response.provider.provider_id,
                    "ranked_evidence_ids": response.ranked_evidence_ids,
                    "ranked_attention_page_ids": response.ranked_attention_page_ids,
                    "attention_notes": response.attention_notes,
                    "considered_evidence_count": response.considered_evidence_count,
                    "provider_calls": (
                        *state.provider_calls,
                        ProviderCall(
                            role="fast_decision",
                            provider_id=response.provider.provider_id,
                            provider_version=response.provider.provider_version,
                            state_version=decision_request.state_version,
                            started_at=call_started_at,
                            elapsed_ms=(time.monotonic() - call_started) * 1000,
                            degraded=rejected or response.degraded,
                            detail=decision_status.detail
                            if isinstance(decision_status, ProviderStatus)
                            else None,
                        ),
                    )[-128:],
                }
            )
            if response.degraded:
                state = state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state, "Decision provider degraded to the keyword baseline."
                        )
                    }
                )
            stopped = self._stop_if_needed(state, cancel_event)
            if stopped is not None:
                return stopped
            proposals = tuple({p.probe_id: p for p in (*response.proposals, *requested)}.values())
            proposals = self._eligible(proposals, state, remaining)
            if not proposals and len(state.completed_probe_ids) < len(self.capabilities):
                proposals = self._exploration(state, remaining)
            if not proposals:
                state, _ = self._reason_with_details(state, context)
                observed = self._complete_observed(state, context, cancel_event)
                if observed is not None:
                    return observed
                stopped = self._stop_if_needed(state, cancel_event)
                if stopped is not None:
                    return stopped
                return self._finish(
                    state,
                    InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
                    "No eligible unused probe can distinguish the remaining explanations.",
                )
            state = self._collect(state, proposals, cancel_event)
            stopped = self._stop_if_needed(state, cancel_event, check_probe_budget=False)
            if stopped is not None:
                return stopped
            context = self.context(case_id)
            state = self._refresh_attention(state, context)
            stopped = self._stop_if_needed(state, cancel_event, check_probe_budget=False)
            if stopped is not None:
                return stopped
            state, requested = self._reason_with_details(state, context)
            observed = self._complete_observed(state, context, cancel_event)
            if observed is not None:
                return observed
            stopped = self._stop_if_needed(state, cancel_event)
            if stopped is not None:
                return stopped
            fingerprint = self._fingerprint(context)
            stagnant = state.stagnant_rounds + 1 if fingerprint == state.evidence_fingerprint else 0
            state = self._save(
                state.model_copy(
                    update={
                        "evidence_fingerprint": fingerprint,
                        "stagnant_rounds": stagnant,
                    }
                ),
                "assessed",
                state.summary,
            )
            if stagnant >= 2:
                return self._finish(
                    state,
                    InvestigationOutcome.NO_PROGRESS,
                    "Repeated evidence added no useful distinction.",
                )
            if state.round_count - state.run_start_round >= state.max_rounds:
                break
        return self._finish(
            state,
            InvestigationOutcome.BUDGET_EXHAUSTED,
            "The bounded investigation round budget is exhausted.",
        )

    def _complete_observed(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
        cancellation: threading.Event | None,
    ) -> InvestigationState | None:
        if (cancellation is not None and cancellation.is_set()) or self._remaining_ms(state) <= 0:
            return None
        assessment = assess_investigation(
            state=state,
            context=self._merge_excerpts(
                self._retain_assessed(state, context),
                select_target_evidence(self.store, context, state.objective).context,
            ),
            relationships=self.relationships(context),
        )
        if assessment.disposition is not AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION:
            return None
        state = state.model_copy(
            update={"assessment": assessment, "summary": assessment.explanation}
        )
        return self._finish(
            state,
            InvestigationOutcome.SUPPORTED_EXPLANATION,
            "The narrow observed question is answered; broader causal claims remain unverified.",
        )

    def _collect(
        self,
        state: InvestigationState,
        proposals: tuple[ProbeProposal, ...],
        cancel_event: threading.Event | None,
        *,
        baseline: bool = False,
    ) -> InvestigationState:
        state = self._save(
            state.model_copy(
                update={
                    "pending_probe_ids": tuple(p.probe_id for p in proposals),
                    "spent_cost_ms": state.spent_cost_ms
                    + sum(p.estimated_cost_ms for p in proposals),
                }
            ),
            "baseline_collecting" if baseline else "collecting",
            "Collecting: " + ", ".join(p.probe_id for p in proposals),
        )
        self.runtime.execute_plan(self._opened(state, proposals), cancel_event=cancel_event)
        self._project(str(state.case_id))
        return self._save(
            state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys((*state.completed_probe_ids, *state.pending_probe_ids))
                    ),
                    "pending_probe_ids": (),
                    "round_count": state.round_count + (0 if baseline else 1),
                }
            ),
            "baseline_collected" if baseline else "collected",
            "Probe results and coverage persisted.",
        )

    def _reason_with_details(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
        state, proposals = self._reason(state, context)
        for _ in range(2):
            if (
                not (state.requested_details or state.requested_evidence_ids)
                or self._remaining_ms(state) <= 0
            ):
                break
            state, proposals = self._reason(state, context)
        unsatisfied = len({str(item) for item in state.requested_evidence_ids}) + len(
            {item.key() for item in state.requested_details}
        )
        if unsatisfied:
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state,
                        f"Reasoning ended with {unsatisfied} unsatisfied evidence/detail "
                        "requests after the bounded follow-up or case budget limit.",
                    )
                }
            )
        return state, proposals

    def _reason(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
        state = self._save(
            state,
            "reasoning",
            "Deep brain is comparing explanations against the focused evidence map.",
        )
        all_context = context
        done_keys = {item.key() for item in state.completed_detail_requests}
        scoped_ids = {str(item.evidence_id) for item in context}
        outstanding_details = tuple(
            item for item in state.requested_details if item.key() not in done_keys
        )
        pending_details = tuple(
            item for item in outstanding_details if str(item.evidence_id) in scoped_ids
        )
        targets = select_target_evidence(self.store, context, state.objective)
        details = retrieve_details(self.store, context, pending_details)
        if pending_details:
            for note in details.notes:
                state = state.model_copy(update={"warnings": self._warnings(state, note)})
        if targets.truncated:
            for note in targets.notes:
                state = state.model_copy(update={"warnings": self._warnings(state, note)})
        required_ids = tuple(
            dict.fromkeys(
                (
                    *state.requested_evidence_ids,
                    *(item.evidence_id for item in outstanding_details),
                    *(item.evidence_id for item in details.context),
                    *(item.evidence_id for item in targets.context),
                    *(
                        item.evidence_id
                        for item in context
                        if any(
                            limitation.startswith("Retrieval packet omitted ")
                            for limitation in item.limitations
                        )
                    ),
                    *(
                        eid
                        for h in state.hypotheses
                        for eid in (
                            *h.supporting_evidence_ids,
                            *h.contradicting_evidence_ids,
                            *h.missing_evidence_ids,
                        )
                    ),
                )
            )
        )
        ranked_context = self._retain_assessed(
            state,
            self._merge_excerpts(
                self._ranked_details(state, context),
                (*details.context, *targets.context),
            ),
        )
        ranked_graph = self._relationships(ranked_context)
        focused = focus_evidence(
            ranked_graph.context,
            ranked_ids=state.ranked_evidence_ids,
            relationships=ranked_graph.relationships,
            required_ids=required_ids,
        )
        focused_graph = self._relationships(focused.context)
        context = focused_graph.context
        all_context_ids = {str(item.evidence_id) for item in all_context}
        priority_evidence_ids = tuple(
            evidence_id for evidence_id in required_ids if str(evidence_id) in all_context_ids
        )[:64]
        completed_evidence_requests = tuple(
            evidence_id
            for evidence_id in state.completed_evidence_requests
            if str(evidence_id) in all_context_ids
        )[:64]
        known = {str(item.evidence_id) for item in context}
        previous = tuple(
            h
            for h in state.hypotheses
            if set(
                map(
                    str,
                    (
                        *h.supporting_evidence_ids,
                        *h.contradicting_evidence_ids,
                        *h.missing_evidence_ids,
                    ),
                )
            )
            <= known
        )
        if len(previous) != len(state.hypotheses):
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state,
                        "Some earlier hypotheses are outside this bounded evidence packet; "
                        "history is preserved.",
                    )
                }
            )
        request = ReasoningRequest(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id=f"reasoning:{state.case_id}:{state.state_version}",
            deadline_at=state.deadline_at,
            objective=state.objective,
            observer_context=(
                "SystemSense collection and local inference share this measured host. "
                "Follow-up CPU/GPU utilization and memory include the observer's own "
                "Laya/Qwen work. This is not an unloaded baseline; do not attribute "
                "observer activity to the original symptom without independent evidence.",
            )
            if self.reasoning.identity.provider_id == "ollama-local-reasoning"
            else (),
            evidence_ids=tuple(item.evidence_id for item in all_context),
            evidence_context=context,
            relationships=focused_graph.relationships,
            previous_hypotheses=previous,
            available_probes=self.capabilities,
            completed_probe_ids=frozenset(state.completed_probe_ids),
            completed_detail_requests=state.completed_detail_requests,
            reference_context=self.reference_context(state),
            error_references=self.error_references(state),
            evidence_catalog=tuple(
                {
                    "evidence_id": str(item.evidence_id),
                    "probe_id": item.probe_id,
                    "status": item.status.value,
                    "summary": item.summary[:200],
                }
                for item in all_context
            ),
            priority_evidence_ids=priority_evidence_ids,
            completed_evidence_requests=completed_evidence_requests,
            budget_ms=max(1, self._remaining_ms(state)),
            max_probes=max(1, min(4, state.max_probes - len(state.completed_probe_ids))),
        )
        call_started_at = utc_now()
        call_started = time.monotonic()
        rejected = False
        try:
            response = self.reasoning.investigate(request).validate_against(request)
            if response.provider != self.reasoning.identity and not (
                response.degraded and response.provider == DeterministicReasoningProvider().identity
            ):
                raise ValueError("reasoning provider identity mismatch")
            if utc_now() >= state.deadline_at:
                raise ValueError("reasoning result missed its deadline")
        except Exception as error:
            rejected = True
            response = UnavailableReasoningProvider().investigate(request)
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state, f"Reasoning unavailable or rejected: {type(error).__name__}."
                    )
                }
            )
        # Do not promote model assertions into a confirmed root cause. Hypotheses
        # retain their citations and status and are displayed as advisory claims.
        hypotheses = tuple(
            h.model_copy(
                update={
                    "statement": self.redactor.redact_text(h.statement).text,
                }
            )
            for h in response.hypotheses
        )
        summary = self.redactor.redact_text(response.summary).text
        if response.degraded and state.hypotheses:
            hypotheses = state.hypotheses
            summary = state.summary
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state,
                        "Latest reasoning failed; the previous assessment is retained and "
                        "may not account for newly collected evidence.",
                    )
                }
            )
        for note in response.context_notes:
            state = state.model_copy(update={"warnings": self._warnings(state, note)})
        delivered_requests: tuple[EvidenceId, ...] = ()
        delivered_details: tuple[EvidenceDetailRequest, ...] = ()
        if not response.degraded and not rejected:
            considered = {str(item) for item in response.considered_evidence_ids}
            admitted_with_facts = {str(item.evidence_id) for item in context if item.facts}
            delivered_requests = tuple(
                evidence_id
                for evidence_id in state.requested_evidence_ids
                if str(evidence_id) in considered and str(evidence_id) in admitted_with_facts
            )
            matched_detail_keys = set(details.matched_request_keys)
            delivered_details = tuple(
                item
                for item in pending_details
                if item.key() in matched_detail_keys
                and str(item.evidence_id) in considered
                and self._detail_visible(item, context)
            )
        all_completed_requests = tuple(
            {
                str(evidence_id): evidence_id
                for evidence_id in (*state.completed_evidence_requests, *delivered_requests)
            }.values()
        )[-128:]
        completed_set = {str(evidence_id) for evidence_id in all_completed_requests}
        still_pending = tuple(
            evidence_id
            for evidence_id in state.requested_evidence_ids
            if evidence_id not in delivered_requests
        )
        next_evidence_requests = tuple(
            {
                str(evidence_id): evidence_id
                for evidence_id in (
                    *still_pending,
                    *(
                        item
                        for item in response.requested_evidence_ids
                        if str(item) not in completed_set
                    ),
                )
            }.values()
        )[:8]
        all_completed_details = tuple(
            {
                item.key(): item for item in (*state.completed_detail_requests, *delivered_details)
            }.values()
        )[-32:]
        completed_detail_keys = {item.key() for item in all_completed_details}
        still_pending_details = tuple(
            item for item in outstanding_details if item.key() not in completed_detail_keys
        )
        next_detail_requests = tuple(
            {
                item.key(): item
                for item in (*still_pending_details, *response.requested_details)
                if item.key() not in completed_detail_keys
            }.values()
        )[:4]
        provider_status = getattr(self.reasoning, "status", None)
        state = state.model_copy(
            update={
                "hypotheses": hypotheses,
                "summary": summary,
                "reasoning_provider": response.provider.provider_id,
                "focused_evidence_ids": response.considered_evidence_ids
                or tuple(item.evidence_id for item in context),
                "assessed_context": state.assessed_context
                if response.degraded and state.hypotheses
                else tuple(
                    item
                    for item in context
                    if not response.considered_evidence_ids
                    or item.evidence_id in response.considered_evidence_ids
                ),
                "requested_evidence_ids": next_evidence_requests,
                "completed_evidence_requests": all_completed_requests,
                "requested_details": next_detail_requests,
                "completed_detail_requests": all_completed_details,
                "provider_calls": (
                    *state.provider_calls,
                    ProviderCall(
                        role="reasoning",
                        provider_id=response.provider.provider_id,
                        provider_version=response.provider.provider_version,
                        state_version=request.state_version,
                        started_at=call_started_at,
                        elapsed_ms=(time.monotonic() - call_started) * 1000,
                        degraded=rejected or response.degraded,
                        detail=provider_status.detail
                        if isinstance(provider_status, ProviderStatus)
                        else None,
                    ),
                )[-128:],
                "warnings": self._warnings(state, "Reasoning is operating in degraded mode.")
                if response.degraded or response.status is ReasoningStatus.UNAVAILABLE
                else state.warnings,
            }
        )
        return state, response.distinguishing_probes

    @staticmethod
    def _detail_visible(
        request: EvidenceDetailRequest,
        context: tuple[EvidenceContext, ...],
    ) -> bool:
        """Return whether one exact matched object survived into the provider packet."""
        literals = tuple(value.casefold() for value in request.match_literals)
        for item in context:
            if item.evidence_id != request.evidence_id:
                continue
            for value in item.facts.values():
                serialized = json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).casefold()
                if all(literal in serialized for literal in literals):
                    return True
        return False

    def reference_context(self, state: InvestigationState) -> tuple[dict[str, JsonValue], ...]:
        if self.knowledge is None:
            return ()
        # Knowledge is sourced general mechanism, never an observation or permission.
        stop_words = {
            "the",
            "and",
            "this",
            "that",
            "with",
            "from",
            "why",
            "not",
            "has",
            "are",
            "for",
        }
        search_text = " ".join((state.objective, *(h.statement for h in state.hypotheses[:3])))
        terms = set(re.findall(r"[a-z0-9]+", search_text.casefold())) - stop_words
        scored = sorted(
            (
                (
                    len(
                        terms.intersection(
                            re.findall(
                                r"[a-z0-9]+", " ".join((node.label, *node.aliases)).casefold()
                            )
                        )
                    ),
                    node.node_id,
                )
                for node in self.knowledge.pack.nodes
            ),
            key=lambda entry: (-entry[0], entry[1]),
        )
        error_seeds = tuple(
            node_id
            for reference in self.error_references(state)
            for node_id in reference.knowledge_node_ids
        )
        semantic_seeds = tuple(node_id for score, node_id in scored if score > 0)
        seeds = tuple(dict.fromkeys((*error_seeds, *semantic_seeds)))[:3]
        packet = (
            self.knowledge.expand(start_node_ids=seeds, max_depth=2, max_edges=6, max_chars=6000)
            if seeds
            else self.knowledge.query(
                KnowledgeQuery(keywords=(state.objective[:80],), max_relations=4, max_chars=6000)
            )
        )
        return (packet.model_dump(mode="json"),)

    def error_references(self, state: InvestigationState) -> tuple[WindowsErrorReference, ...]:
        """Resolve only explicit typed errors in the objective as non-evidence reference data."""

        return reference_for_text(state.objective, max_items=4)

    def _refresh_attention(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> InvestigationState:
        """New observations are ranked before the deep brain sees its focused map."""
        state = self._save(
            state, "attention", "Fast brain is ranking the newly collected evidence."
        )
        graph = self._relationships(context)
        context = graph.context
        request = DecisionRequest(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id=f"attention:{state.case_id}:{state.state_version}",
            deadline_at=self._decision_deadline(state),
            symptom=state.objective,
            attention_only=True,
            evidence_ids=tuple(item.evidence_id for item in context),
            evidence_context=context,
            attention_context=attention_pages(self.store, context),
            relationships=graph.relationships,
            reference_context=self.reference_context(state),
            available_probes=self.capabilities,
            completed_probe_ids=frozenset(state.completed_probe_ids),
            fresh_probe_ids=frozenset(),
            hypothesis_briefs=tuple(h.statement for h in state.hypotheses),
            budget_ms=max(1, self._remaining_ms(state)),
            max_probes=1,
        )
        started = utc_now()
        tick = time.monotonic()
        try:
            response = self.decision.decide(request).validate_against(request)
            if response.provider != self.decision.identity and not (
                response.degraded
                and response.provider == KeywordBaselineDecisionProvider().identity
            ):
                raise ValueError("attention provider identity mismatch")
            if utc_now() >= request.deadline_at:
                raise ValueError("attention result missed deadline")
        except Exception:
            response = (
                KeywordBaselineDecisionProvider()
                .decide(request)
                .model_copy(update={"degraded": True})
            )
        decision_status = getattr(self.decision, "status", None)
        return state.model_copy(
            update={
                "ranked_evidence_ids": response.ranked_evidence_ids,
                "ranked_attention_page_ids": response.ranked_attention_page_ids,
                "attention_notes": response.attention_notes,
                "considered_evidence_count": response.considered_evidence_count,
                "provider_calls": (
                    *state.provider_calls,
                    ProviderCall(
                        role="fast_decision",
                        provider_id=response.provider.provider_id,
                        provider_version=response.provider.provider_version,
                        state_version=request.state_version,
                        started_at=started,
                        elapsed_ms=(time.monotonic() - tick) * 1000,
                        degraded=response.degraded,
                        detail=decision_status.detail
                        if isinstance(decision_status, ProviderStatus)
                        else None,
                    ),
                )[-128:],
            }
        )

    @staticmethod
    def _merge_excerpts(
        context: tuple[EvidenceContext, ...],
        excerpts: tuple[EvidenceContext, ...],
    ) -> tuple[EvidenceContext, ...]:
        """Prioritize deterministic requested rows within the existing observation boundary."""
        by_id = {str(item.evidence_id): item for item in context}
        for excerpt in reversed(excerpts):
            key = str(excerpt.evidence_id)
            original = by_id.get(key)
            if original is None:
                continue
            facts = dict(excerpt.facts)
            for name, value in original.facts.items():
                if name in facts:
                    continue
                trial = {**facts, name: value}
                if len(trial) <= 32 and len(json.dumps(trial).encode("utf-8")) <= 8000:
                    facts = trial
            by_id[key] = excerpt.model_copy(update={"facts": facts})
        return tuple(by_id[str(item.evidence_id)] for item in context)

    @staticmethod
    def _retain_assessed(
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> tuple[EvidenceContext, ...]:
        """Citations refer to immutable facts, not whichever page ranks highest next."""
        required = {
            str(eid)
            for hypothesis in state.hypotheses
            for eid in (
                *hypothesis.supporting_evidence_ids,
                *hypothesis.contradicting_evidence_ids,
                *hypothesis.missing_evidence_ids,
            )
        }
        anchors = {
            str(item.evidence_id): item
            for item in state.assessed_context
            if str(item.evidence_id) in required
        }
        result: list[EvidenceContext] = []
        for item in context:
            prior = anchors.get(str(item.evidence_id))
            if prior is None:
                result.append(item)
                continue
            facts = dict(prior.facts)
            omitted = False
            for key, value in item.facts.items():
                if key in facts:
                    continue
                trial = {**facts, key: value}
                if len(trial) <= 32 and len(json.dumps(trial).encode("utf-8")) <= 8000:
                    facts = trial
                else:
                    omitted = True
            notes = tuple(dict.fromkeys((*prior.limitations, *item.limitations)))
            if omitted:
                notes = (*notes[:15], "Additional pages deferred to preserve prior cited facts.")
            result.append(item.model_copy(update={"facts": facts, "limitations": notes[:16]}))
        return tuple(result)

    def _ranked_details(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> tuple[EvidenceContext, ...]:
        if not state.ranked_attention_page_ids:
            return context
        pages = attention_pages(self.store, context)
        by_key = {f"{item.evidence_id}:{index}": item for index, item in enumerate(pages)}
        facts: dict[str, dict[str, JsonValue]] = {}
        for key in state.ranked_attention_page_ids:
            page = by_key.get(key)
            if page is None:
                continue
            eid = str(page.evidence_id)
            combined = {**facts.get(eid, {}), **page.facts}
            if len(combined) <= 32 and len(json.dumps(combined).encode("utf-8")) <= 8000:
                facts[eid] = combined
        return tuple(
            item.model_copy(
                update={
                    "facts": facts[str(item.evidence_id)],
                    "limitations": (
                        *item.limitations[:15],
                        "Exact fact pages selected by local attention; "
                        "full observation remains stored.",
                    ),
                }
            )
            if str(item.evidence_id) in facts
            else item
            for item in context
        )

    def _project(self, case_id: str) -> None:
        projector = ExplicitRelationProjector()
        relations = EvidenceRelationRepository(self.store)
        rows = self.store.connection.execute(
            "SELECT record_json FROM evidence WHERE case_id = ? ORDER BY captured_at LIMIT 256",
            (case_id,),
        ).fetchall()
        for row in rows:
            payload = json.loads(str(row[0]))
            if "source" not in payload:
                continue
            record = EvidenceRecord.model_validate(payload)
            for relation in projector.project(record).relations:
                relations.append(relation)

    def context(self, case_id: str) -> tuple[EvidenceContext, ...]:
        state = self.repository.load(case_id)
        packet = self.packet(case_id)
        result: list[EvidenceContext] = []
        for record in packet.evidence:
            limitations = list(record.limitations)
            if str(record.case_id) == case_id and not (
                state.incident_start <= record.observed_at <= state.incident_end
            ):
                limitations.insert(
                    0,
                    "Current collection is outside the incident window; "
                    "it does not establish conditions during that incident.",
                )
            facts: dict[str, JsonValue] = {}
            for fact in record.facts:
                candidate = {**facts, fact.name: fact.value}
                if len(candidate) > 32 or len(json.dumps(candidate).encode("utf-8")) > 8000:
                    limitations.append("Evidence facts exceeded the inference context byte budget.")
                    continue
                facts = candidate
            if record.facts_truncated:
                limitations.append("Evidence facts were truncated for this compact packet.")
            if str(record.case_id) != case_id:
                limitations.append(
                    f"Historical observation from {record.case_id}; freshness requires review."
                )
            result.append(
                EvidenceContext(
                    evidence_id=record.evidence_id,
                    observed_at=record.observed_at,
                    captured_at=record.captured_at,
                    probe_id=record.category,
                    summary=record.summary[:1000],
                    facts=facts,
                    status=EvidenceContextStatus.OBSERVED,
                    limitations=tuple(item[:240] for item in limitations[:16]),
                )
            )
        for coverage in packet.coverage:
            limitations = list(coverage.limitations)
            if str(coverage.case_id) == case_id and not (
                state.incident_start <= coverage.captured_at <= state.incident_end
            ):
                limitations.insert(
                    0,
                    "Current collection is outside the incident window; "
                    "it does not establish conditions during that incident.",
                )
            status = (
                EvidenceContextStatus.OBSERVED
                if coverage.status.value == "covered"
                else EvidenceContextStatus(coverage.status.value)
            )
            result.append(
                EvidenceContext(
                    evidence_id=coverage.evidence_id,
                    observed_at=coverage.captured_at,
                    captured_at=coverage.captured_at,
                    probe_id=f"{coverage.category}.coverage",
                    summary=(coverage.reason or "Coverage recorded.")[:1000],
                    facts={},
                    status=status,
                    limitations=tuple(item[:240] for item in limitations[:16]),
                )
            )
        if result and (packet.omitted_evidence_count or packet.omitted_coverage_count):
            omission = (
                f"Retrieval packet omitted {packet.omitted_evidence_count} evidence records and "
                f"{packet.omitted_coverage_count} coverage records; omitted content remains "
                "in local evidence."
            )
            first = result[0]
            result[0] = first.model_copy(
                update={"limitations": (*first.limitations[:15], omission)}
            )
        return tuple(result)

    def packet(self, case_id: str) -> EvidencePacket:
        state = self.repository.load(case_id)
        return EvidenceRetriever(self.store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=state.case_id,
                include_historical=bool(state.historical_case_ids),
                historical_case_ids=state.historical_case_ids,
                observed_from=state.incident_start,
                observed_until=state.incident_end,
                current_collection_start=state.created_at,
                evidence_limit=48,
                coverage_limit=16,
                max_chars=48000,
                max_fact_chars=4096,
            )
        )

    def relationships(self, context: tuple[EvidenceContext, ...]) -> tuple[EvidenceRelation, ...]:
        """Compatibility view of the bounded relationship packet."""

        return self._relationships(context).relationships

    def _relationships(self, context: tuple[EvidenceContext, ...]) -> _RelationshipSelection:
        known = {str(item.evidence_id) for item in context}
        candidate_limit = 1000
        candidates = EvidenceRelationRepository(self.store).relations(
            limit=candidate_limit,
            evidence_ids=tuple(item.evidence_id for item in context),
        )
        relations = tuple(
            relation
            for relation in candidates
            if relation.evidence_ids and set(map(str, relation.evidence_ids)) <= known
        )
        # Interleave relation families: hundreds of service edges must not erase
        # the few disk/driver dependencies from a bounded model packet.
        groups: dict[str, list[EvidenceRelation]] = {}
        for relation in relations:
            groups.setdefault(relation.relationship.value, []).append(relation)
        identities = set[str]().union(*(self._identity_values(item.facts) for item in context))
        for group in groups.values():
            group.sort(
                key=lambda relation: (
                    -len(identities & self._identity_values(relation.version_metadata)),
                    relation.relation_id,
                )
            )
        selected: list[EvidenceRelation] = []
        for index in range(64):
            for group in groups.values():
                if index < len(group):
                    selected.append(group[index])
                    if len(selected) == 64:
                        break
            if len(selected) == 64:
                break
        omitted = max(0, len(relations) - len(selected))
        candidate_scan_truncated = len(candidates) == candidate_limit
        notes: list[str] = []
        if candidate_scan_truncated:
            notes.append(
                f"Graph packet omitted {omitted} loaded grounded relationships; candidate "
                "scan reached 1000, so additional matching relationships may exist."
            )
        elif omitted:
            notes.append(
                f"Graph packet omitted {omitted} of {len(relations)} grounded relationships "
                "because the model edge limit is 64."
            )
        if selected:
            notes.append(
                "Graph relationships are provenance-grounded associations; selection or "
                "traversal does not establish causality."
            )
        annotated = context
        if notes and context:
            first = context[0]
            retained = first.limitations[: max(0, 16 - len(notes))]
            annotated_first = first.model_copy(
                update={"limitations": tuple(dict.fromkeys((*retained, *notes)))}
            )
            annotated = (annotated_first, *context[1:])
        return _RelationshipSelection(
            context=annotated,
            relationships=tuple(selected),
            loaded_grounded_count=len(relations),
            omitted_count=omitted,
            candidate_scan_truncated=candidate_scan_truncated,
        )

    @classmethod
    def _identity_values(
        cls,
        value: JsonValue,
        *,
        field_name: str | None = None,
        path: tuple[str, ...] = (),
    ) -> set[str]:
        if isinstance(value, list):
            return set[str]().union(
                *(cls._identity_values(item, field_name=field_name, path=path) for item in value)
            )
        if isinstance(value, dict):
            return set[str]().union(
                *(
                    cls._identity_values(
                        item,
                        field_name=name.casefold(),
                        path=(*path, name.casefold()),
                    )
                    for name, item in value.items()
                )
            )
        identity_kind = cls._identity_kind(field_name, path)
        if identity_kind is None:
            return set()
        if isinstance(value, str):
            normalized = value.strip().casefold()
            return (
                {f"{identity_kind}:{normalized}"}
                if normalized and len(normalized) <= 512
                else set()
            )
        if isinstance(value, int) and not isinstance(value, bool):
            if identity_kind == "process_id" and value <= 0:
                return set()
            if identity_kind != "disk_index" and value < 0:
                return set()
            return {f"{identity_kind}:{value}"}
        return set()

    @staticmethod
    def _identity_kind(field_name: str | None, path: tuple[str, ...]) -> str | None:
        if field_name is None:
            return None
        direct = {
            "pid": "process_id",
            "process_id": "process_id",
            "creation_time": "process_creation_time",
            "process_creation_time": "process_creation_time",
            "source_service": "service_name",
            "target_service": "service_name",
            "service_name": "service_name",
            "target_process_name": "process_name",
            "process_name": "process_name",
            "device_id": "device_id",
            "instance_id": "device_id",
            "gpu_uuid": "gpu_uuid",
            "gpu_name": "gpu_name",
            "driver_version": "driver_version",
            "inf_name": "driver_inf",
            "volume_id": "volume_id",
            "partition_id": "partition_id",
            "disk_index": "disk_index",
        }
        if field_name in direct:
            return direct[field_name]
        ancestors = set(path[:-1])
        if field_name == "name":
            if "processes" in ancestors:
                return "process_name"
            if "services" in ancestors:
                return "service_name"
            if "gpus" in ancestors:
                return "gpu_name"
        if field_name == "uuid" and "gpus" in ancestors:
            return "gpu_uuid"
        if field_name == "version" and "drivers" in ancestors:
            return "driver_version"
        return None

    def _eligible(
        self,
        proposals: tuple[ProbeProposal, ...],
        state: InvestigationState,
        remaining: int,
    ) -> tuple[ProbeProposal, ...]:
        known = {item.probe_id: item for item in self.capabilities}
        selected: list[ProbeProposal] = []
        for proposal in proposals:
            capability = known.get(proposal.probe_id)
            if capability is None or proposal.probe_id in state.completed_probe_ids:
                continue
            if proposal.estimated_cost_ms != capability.cost_ms or capability.cost_ms > remaining:
                continue
            if len(selected) + len(state.completed_probe_ids) >= state.max_probes:
                break
            selected.append(proposal)
            remaining -= capability.cost_ms
        # Remove dependents if their prerequisite was excluded by admission.
        while any(set(p.depends_on) - {item.probe_id for item in selected} for p in selected):
            ids = {item.probe_id for item in selected}
            selected = [p for p in selected if set(p.depends_on) <= ids]
        return tuple(selected)

    def _exploration(self, state: InvestigationState, remaining: int) -> tuple[ProbeProposal, ...]:
        # At most one alternate branch per round prevents the keyword fallback
        # from making its shortlist the limit of the investigation.
        if len(state.completed_probe_ids) >= state.max_probes:
            return ()
        for capability in sorted(self.capabilities, key=lambda p: (p.cost_ms, p.probe_id)):
            if (
                capability.probe_id not in state.completed_probe_ids
                and capability.cost_ms <= remaining
            ):
                return (
                    ProbeProposal(
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.CHECK_COVERAGE,
                        priority=0.25,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        safety_class=capability.safety_class,
                        dedupe_key=f"explore:{capability.probe_id}",
                    ),
                )
        return ()

    def _stop_if_needed(
        self,
        state: InvestigationState,
        cancellation: threading.Event | None,
        *,
        check_probe_budget: bool = True,
    ) -> InvestigationState | None:
        if cancellation is not None and cancellation.is_set():
            return self._finish(state, InvestigationOutcome.CANCELLED, "Cancelled by the user.")
        if self._remaining_ms(state) <= 0 or (
            check_probe_budget and len(state.completed_probe_ids) >= state.max_probes
        ):
            return self._finish(
                state,
                InvestigationOutcome.BUDGET_EXHAUSTED,
                "The case time or probe budget is exhausted.",
            )
        return None

    def _remaining_ms(self, state: InvestigationState) -> int:
        return max(
            0,
            min(
                state.budget_ms - state.spent_cost_ms,
                int((state.deadline_at - utc_now()).total_seconds() * 1000),
            ),
        )

    def _decision_deadline(self, state: InvestigationState):
        # Attention cannot consume the whole case and starve deep reasoning.
        # Actual providers must honor the per-call deadline, not only the case deadline.
        remaining = self._remaining_ms(state)
        return min(state.deadline_at, utc_now() + timedelta(milliseconds=max(1, remaining * 0.45)))

    def _finish(
        self,
        state: InvestigationState,
        outcome: InvestigationOutcome,
        reason: str,
    ) -> InvestigationState:
        unsatisfied = len({str(item) for item in state.requested_evidence_ids}) + len(
            {item.key() for item in state.requested_details}
        )
        if unsatisfied and outcome in {
            InvestigationOutcome.BUDGET_EXHAUSTED,
            InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
            InvestigationOutcome.NO_PROGRESS,
        }:
            suffix = f" {unsatisfied} unsatisfied evidence/detail requests remain explicit."
            reason = f"{reason[: 1000 - len(suffix)]}{suffix}"
        status = (
            InvestigationStatus.CANCELLED
            if outcome is InvestigationOutcome.CANCELLED
            else InvestigationStatus.COMPLETE
        )
        return self._save(
            state.model_copy(
                update={
                    "status": status,
                    "outcome": outcome,
                    "stop_reason": reason,
                }
            ),
            "stopped",
            reason,
        )

    def _save(self, state: InvestigationState, event: str, detail: str) -> InvestigationState:
        return self.repository.save(
            state, expected_version=state.state_version, event=event, detail=detail
        )

    @staticmethod
    def _warnings(state: InvestigationState, message: str) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*state.warnings, message)))[-64:]

    @staticmethod
    def _fingerprint(context: tuple[EvidenceContext, ...]) -> str:
        payload = [(item.probe_id, item.status.value, item.summary, item.facts) for item in context]
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def _opened(state: InvestigationState, proposals: tuple[ProbeProposal, ...]) -> OpenedCase:
        return OpenedCase(
            case=DiagnosticCase(
                case_id=state.case_id,
                kind=CaseKind.GENERAL,
                status=CaseStatus.COLLECTING,
                symptom=state.objective,
                created_at=state.created_at,
                time_window=CaseTimeWindow(
                    start=state.incident_start,
                    end=state.incident_end,
                    basis=CaseTimeWindowBasis.CASE_OPEN_DERIVED,
                ),
                state_version=state.state_version,
            ),
            deadline_at=state.deadline_at,
            plan=CasePlan(
                probes=tuple(
                    PlannedProbe(
                        probe_id=p.probe_id,
                        cost_ms=p.estimated_cost_ms,
                        value=p.priority,
                        reason=p.purpose.value,
                        depends_on=p.depends_on,
                    )
                    for p in proposals
                ),
                total_cost_ms=sum(p.estimated_cost_ms for p in proposals),
                skipped_fresh=(),
                skipped_budget=(),
                skipped_low_value=(),
            ),
        )
