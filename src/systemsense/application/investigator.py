"""A bounded, durable investigation loop over read-only collection and advice."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import timedelta

from systemsense.application.assessment import (
    AssessmentDisposition,
    assess_investigation,
    explicit_bind_conflict_target,
)
from systemsense.application.case_service import OpenedCase
from systemsense.application.graph_routing import bind_trusted_machine_probe_targets
from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
    ProviderCall,
)
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DiagnosticPurpose,
    PermissionClass,
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
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue, stable_source_id
from systemsense.domain.probes import SafetyClass
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
from systemsense.knowledge.models import KnowledgePacket, KnowledgeQuery
from systemsense.knowledge.windows_errors import WindowsErrorReference, reference_for_text
from systemsense.orchestration.planner import CasePlan, PlannedProbe
from systemsense.orchestration.scheduler import ResourceClass
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

    if _is_pdf_performance_objective(objective):
        add_first("application.snapshot")
        add_first("core.resources")
    elif _wifi_reference_objective(objective) or _NETWORK_CONTEXT.search(text):
        add_first("network.connectivity", "network.configuration")
    elif re.search(r"\b(game|gaming|fps|frame(?:s|time)?|gpu|graphics)\b", text):
        add_first("gpu.telemetry.sample", "local_ai.snapshot")
    elif re.search(r"\b(slow|freeze|hang|stutter|cpu|memory|pdf)\b", text):
        add_first("core.resources")
    elif re.search(
        r"\b(driver|device|audio|camera|bluetooth|mouse|keyboard|headset|headphones|controller|gamepad)\b",
        text,
    ):
        add_first("devices.snapshot")
    elif re.search(r"\b(disk|drive|storage|volume|filesystem)\b", text):
        add_first("storage.snapshot")
    if "core.system" in available:
        selected.append("core.system")
    return tuple(dict.fromkeys(selected))


def _is_pdf_performance_objective(objective: str) -> bool:
    text = objective.casefold()
    return bool(
        re.search(r"\bpdf\b", text)
        and re.search(r"\b(slow|hang|freeze|stutter|lag|latency|unresponsive)\b", text)
    )


_EXPLICIT_WIFI = re.compile(r"\bwi[\s-]?fi\b", re.IGNORECASE)
_WIRELESS = re.compile(r"\bwireless\b", re.IGNORECASE)
_NETWORK_CONTEXT = re.compile(
    r"\b(?:network|internet|wlan|ssid|router|hotspot|ethernet|gateway|dhcp|dns|"
    r"proxy|vpn|website|webpage|server|host)\b",
    re.IGNORECASE,
)


def _wifi_reference_objective(objective: str) -> bool:
    """Treat bare 'wireless' as ambiguous without a network-specific noun."""

    return bool(
        _EXPLICIT_WIFI.search(objective)
        or (_WIRELESS.search(objective) and _NETWORK_CONTEXT.search(objective))
    )


_TARGET_PRESSURE_COST_MS = 10_000


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
        if state.status is InvestigationStatus.AWAITING_TARGET:
            raise ValueError("select a trusted process target and use resume_after_target")
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
                "evidence_fingerprint": "",
                "stop_reason": None,
            }
        )
        return self._save(state, "resumed", "Resumed with a new bounded collection budget.")

    def resume_after_target(self, case_id: str) -> InvestigationState:
        state = self.repository.load(case_id)
        if state.status is not InvestigationStatus.AWAITING_TARGET:
            raise ValueError("investigation is not awaiting a process target")
        ProcessTargetRepository(self.store).resolve_process_target_for_sampling(state.case_id)
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
                "evidence_fingerprint": "",
                "stop_reason": None,
            }
        )
        return self._save(state, "target_resumed", "Resumed after trusted process selection.")

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
                    "pending_distinguishing_probes": tuple(
                        item
                        for item in state.pending_distinguishing_probes
                        if item.probe_id not in state.pending_probe_ids
                    ),
                    "warnings": self._warnings(
                        state, "Interrupted attempts were not automatically repeated."
                    ),
                }
            )
        state = self._retire_stale_deep_requests(state)
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
        # Read-only probes may have been executed against this case before the
        # investigation loop starts. Assess their persisted evidence before a
        # baseline refresh changes the time-sensitive bind/listener pairing.
        precollected = self.context(case_id)
        if {
            "target.bind_failure",
            "network.listeners",
        } <= {item.probe_id for item in precollected}:
            observed = self._complete_observed(state, precollected, cancel_event)
            if observed is not None:
                return observed
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
        if _is_pdf_performance_objective(state.objective):
            target_transition = self._handle_pdf_target(state, cancel_event)
            if target_transition is not None:
                state, waiting = target_transition
                if waiting:
                    return state
        if not state.evidence_fingerprint:
            state = self._save(
                state.model_copy(
                    update={"evidence_fingerprint": self._fingerprint(self.context(case_id))}
                ),
                "progress_seeded",
                "Usable current-incident observations seeded for directed-round progress.",
            )
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
        for _ in range(state.max_rounds):
            retired = self._retire_stale_deep_requests(state)
            if retired is not state:
                state = self._save(
                    retired,
                    "deep_requests_retired",
                    "Stale deep-brain probe requests were retired before routing.",
                )
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
            routed_capabilities = bind_trusted_machine_probe_targets(
                store=self.store,
                case_id=state.case_id,
                incident_start=state.incident_start,
                incident_end=state.incident_end,
                context=context,
                relationships=graph.relationships,
                capabilities=self.capabilities,
                completed_probe_ids=frozenset(state.completed_probe_ids),
            )
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
                available_probes=routed_capabilities,
                completed_probe_ids=frozenset(state.completed_probe_ids).intersection(
                    item.probe_id for item in routed_capabilities
                ),
                # Completion is an execution fact, not a freshness guarantee.
                fresh_probe_ids=frozenset(),
                preferred_probe_ids=tuple(p.probe_id for p in state.pending_distinguishing_probes),
                hypothesis_briefs=tuple(h.statement for h in state.hypotheses),
                budget_ms=remaining,
                max_probes=max(1, min(4, state.max_probes - len(state.completed_probe_ids))),
            )
            stopped = self._stop_if_needed(state, cancel_event)
            if stopped is not None:
                return stopped
            # Deep-brain proposals are admitted by the same deterministic policy
            # as every other proposal before deciding whether fast routing is needed.
            remaining = self._remaining_ms(state)
            requested = self._eligible(
                state.pending_distinguishing_probes,
                state,
                remaining,
                batch_limit=decision_request.max_probes,
            )
            if len(requested) >= decision_request.max_probes:
                state = self._save(
                    state,
                    "routing_superseded",
                    "Fast routing was skipped because trusted deep-brain probes fill the "
                    "available batch.",
                )
                routing_proposals: tuple[ProbeProposal, ...] = ()
            else:
                call_started_at = utc_now()
                call_started = time.monotonic()
                rejected = False
                try:
                    response = self.decision.decide(decision_request).validate_against(
                        decision_request
                    )
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
                                f"Decision provider rejected: {type(error).__name__}. "
                                "Baseline used.",
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
                routing_proposals = response.proposals
            stopped = self._stop_if_needed(state, cancel_event)
            if stopped is not None:
                return stopped
            # Provider latency or the durable supersession trace spends case time.
            remaining = self._remaining_ms(state)
            requested_ids = {item.probe_id for item in requested}
            proposals = (
                *requested,
                *(p for p in routing_proposals if p.probe_id not in requested_ids),
            )
            proposals = self._eligible(
                proposals, state, remaining, batch_limit=decision_request.max_probes
            )
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
                retired = self._retire_stale_deep_requests(state)
                if retired is not state:
                    state = self._save(
                        retired,
                        "deep_requests_retired",
                        "Stale deep-brain probe requests were retired before routing.",
                    )
                # An empty fast-brain route is not evidence that no useful test
                # exists. The deep brain may request one after seeing the focused
                # map; admit it now instead of closing the case prematurely.
                proposals = self._eligible(
                    state.pending_distinguishing_probes,
                    state,
                    self._remaining_ms(state),
                    batch_limit=decision_request.max_probes,
                )
                if not proposals:
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
            # Assess whether the last batch added usable evidence before a
            # completed-probe budget masks repeated collection failure.
            stopped = self._stop_if_needed(state, cancel_event, check_probe_budget=False)
            if stopped is not None:
                return stopped
            fingerprint = self._fingerprint(context)
            previous_fingerprint = state.evidence_fingerprint or self._fingerprint(())
            stagnant = state.stagnant_rounds + 1 if fingerprint == previous_fingerprint else 0
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
                remaining = self._remaining_ms(state)
                if not self._eligible(requested, state, remaining) and not self._exploration(
                    state, remaining
                ):
                    return self._finish(
                        state,
                        InvestigationOutcome.NO_PROGRESS,
                        "Two rounds added no fresh usable observations and no directed "
                        "distinguishing probe remains.",
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
        target = select_target_evidence(self.store, context, state.objective)
        if target.truncated or self._retrieval_omitted_evidence(context):
            return None
        assessment = assess_investigation(
            state=state,
            context=self._merge_excerpts(
                self._retain_assessed(state, context),
                target.context,
            ),
            relationships=self.relationships(context),
            trusted_bind_evidence_ids=self._trusted_probe_evidence_ids(
                state, context, "target.bind_failure"
            ),
            trusted_listener_records=self._trusted_probe_records(
                state, context, "network.listeners"
            ),
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

    def _trusted_probe_evidence_ids(
        self, state: InvestigationState, context: tuple[EvidenceContext, ...], probe_id: str
    ) -> frozenset[str]:
        return frozenset(
            str(record.evidence_id)
            for record in self._trusted_probe_records(state, context, probe_id)
        )

    def _trusted_probe_records(
        self, state: InvestigationState, context: tuple[EvidenceContext, ...], probe_id: str
    ) -> tuple[EvidenceRecord, ...]:
        """Admit only exact current-case probe facts re-read from durable storage."""

        trusted: list[EvidenceRecord] = []
        for item in context:
            if item.probe_id != probe_id:
                continue
            row = self.store.connection.execute(
                "SELECT case_id, record_json FROM evidence WHERE evidence_id = ?",
                (str(item.evidence_id),),
            ).fetchone()
            if row is None or row[0] != str(state.case_id):
                continue
            try:
                record = EvidenceRecord.model_validate_json(row[1])
            except ValueError:
                continue
            if (
                record.case_id != state.case_id
                or record.evidence_id != item.evidence_id
                or record.source.type != "systemsense.probe"
                or record.source.locator != {"probe_id": probe_id}
                or record.source.source_id
                != stable_source_id(
                    "systemsense.probe",
                    {
                        "probe_id": probe_id,
                        "probe_version": record.collector.version,
                    },
                )
                or record.collector.id != probe_id
                or record.extraction.parser != "builtin.probe"
                or record.observed_at != item.observed_at
                or record.captured_at != item.captured_at
                or (
                    probe_id != "network.listeners"
                    and {fact.name: fact.value for fact in record.facts} != item.facts
                )
            ):
                continue
            trusted.append(record)
        return tuple(trusted)

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
                    "pending_distinguishing_probes": tuple(
                        item
                        for item in state.pending_distinguishing_probes
                        if item.probe_id not in state.pending_probe_ids
                    ),
                    "pending_probe_ids": (),
                    "round_count": state.round_count + (0 if baseline else 1),
                }
            ),
            "baseline_collected" if baseline else "collected",
            "Probe results and coverage persisted.",
        )

    def _handle_pdf_target(
        self,
        state: InvestigationState,
        cancel_event: threading.Event | None,
    ) -> tuple[InvestigationState, bool] | None:
        target_probe = "application.target_pressure"
        if (
            "application.snapshot" not in state.completed_probe_ids
            or target_probe in state.completed_probe_ids
            or target_probe in state.pending_probe_ids
        ):
            return None
        targets = ProcessTargetRepository(self.store)
        binding = targets.selected_process_target(state.case_id)
        if binding is None:
            try:
                inventory = targets.list_process_candidates(state.case_id)
            except TargetSelectionError:
                return None
            if not inventory.candidates or len(state.completed_probe_ids) >= state.max_probes:
                return None
            if state.budget_ms < _TARGET_PRESSURE_COST_MS:
                limited = self._save(
                    state.model_copy(
                        update={
                            "warnings": self._warnings(
                                state,
                                "Selected-process sampling needs at least a 10-second case budget; "
                                "no target sample was collected.",
                            )
                        }
                    ),
                    "target_budget_unavailable",
                    "Case budget cannot admit the bound-process probe.",
                )
                return limited, False
            if cancel_event is not None and cancel_event.is_set():
                return None
            waiting = self._save(
                state.model_copy(
                    update={
                        "status": InvestigationStatus.AWAITING_TARGET,
                        "outcome": InvestigationOutcome.AWAITING_TARGET,
                        "summary": (
                            "Select the affected process from the observed application "
                            "snapshot to continue. No PDF slowdown cause has been established."
                        ),
                    }
                ),
                "awaiting_target",
                "Current-case process candidates are available for trusted selection.",
            )
            return waiting, True
        if len(state.completed_probe_ids) >= state.max_probes:
            return None
        if cancel_event is not None and cancel_event.is_set():
            return None
        if self._remaining_ms(state) < _TARGET_PRESSURE_COST_MS:
            return None
        return self._collect_bound_target(state, cancel_event), False

    def _collect_bound_target(
        self,
        state: InvestigationState,
        cancel_event: threading.Event | None,
    ) -> InvestigationState:
        proposal = ProbeProposal(
            probe_id="application.target_pressure",
            purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
            priority=1.0,
            estimated_cost_ms=_TARGET_PRESSURE_COST_MS,
            resource_class=ResourceClass.PROCESS,
            dedupe_key=f"bound-target:{state.case_id}",
        )
        state = self._save(
            state.model_copy(
                update={
                    "pending_probe_ids": (proposal.probe_id,),
                    "spent_cost_ms": state.spent_cost_ms + proposal.estimated_cost_ms,
                }
            ),
            "target_collecting",
            "Collecting the selected process identity with bounded read-only sampling.",
        )
        self.runtime.execute_bound_target_pressure(
            self._opened(state, (proposal,)), cancel_event=cancel_event
        )
        self._project(str(state.case_id))
        return self._save(
            state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys((*state.completed_probe_ids, proposal.probe_id))
                    ),
                    "pending_probe_ids": (),
                    "round_count": state.round_count + 1,
                }
            ),
            "target_collected",
            "Selected-process evidence or coverage persisted; slowdown cause remains open.",
        )

    def _reason_with_details(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
        state, proposals = self._reason(state, context)
        attempted_packets: set[str] = set()
        for _ in range(2):
            if self._remaining_ms(state) <= 0:
                break
            packet = self._new_requested_fact_packet(state, context)
            if packet is None or packet in attempted_packets:
                if state.requested_details or state.requested_evidence_ids:
                    state = state.model_copy(
                        update={
                            "warnings": self._warnings(
                                state,
                                "No new requested facts reached the focused packet; immediate "
                                "reasoning follow-up was skipped.",
                            )
                        }
                    )
                break
            attempted_packets.add(packet)
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

    def _new_requested_fact_packet(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> str | None:
        """Identify newly available scoped facts before spending another model call."""
        assessed = {str(item.evidence_id): item.facts for item in state.assessed_context}
        scoped = {str(item.evidence_id): item for item in context}
        requested_ids = {str(item) for item in state.requested_evidence_ids}
        additions: list[tuple[str, str, JsonValue]] = []

        def new_fact(prior: dict[str, JsonValue], name: str, value: JsonValue) -> bool:
            if name in prior and prior[name] == value:
                return False
            # Equal rows at different source paths remain distinct observations.
            if isinstance(value, dict) and "source_path" in value and "value" in value:
                source_path = value["source_path"]
                if isinstance(source_path, str):
                    for prior_name, prior_value in prior.items():
                        if isinstance(prior_value, dict) and (
                            prior_value.get("source_path") == source_path
                            and prior_value.get("value") == value["value"]
                        ):
                            return False
                        if (
                            json.dumps([prior_name], ensure_ascii=False, separators=(",", ":"))
                            == source_path
                            and prior_value == value["value"]
                        ):
                            return False
            return True

        completed_details = {item.key() for item in state.completed_detail_requests}
        pending_details = tuple(
            item
            for item in state.requested_details
            if item.key() not in completed_details and str(item.evidence_id) in scoped
        )
        if not pending_details and not requested_ids.intersection(scoped):
            return None
        details = retrieve_details(self.store, context, pending_details)
        matched_ids = {
            str(item.evidence_id)
            for item in pending_details
            if item.key() in details.matched_request_keys
        }
        if not requested_ids and not matched_ids:
            return None
        targets = select_target_evidence(self.store, context, state.objective)
        ranked = self._retain_assessed(
            state,
            self._merge_excerpts(
                self._ranked_details(state, context), (*details.context, *targets.context)
            ),
        )
        graph = self._relationships(ranked)
        required_ids = tuple(
            dict.fromkeys(
                (
                    *state.requested_evidence_ids,
                    *(item.evidence_id for item in state.requested_details),
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
        focused = focus_evidence(
            graph.context,
            ranked_ids=state.ranked_evidence_ids,
            relationships=graph.relationships,
            required_ids=required_ids,
        )
        admitted = self._relationships(focused.context).context
        for item in admitted:
            evidence_id = str(item.evidence_id)
            if evidence_id not in requested_ids and evidence_id not in matched_ids:
                continue
            prior = assessed.get(evidence_id, {})
            additions.extend(
                (evidence_id, name, value)
                for name, value in item.facts.items()
                if new_fact(prior, name, value)
            )
        if not additions:
            return None
        additions.sort(key=lambda item: (item[0], item[1]))
        payload = json.dumps(additions, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

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
            completed_probe_ids=frozenset(state.completed_probe_ids).intersection(
                item.probe_id for item in self.capabilities
            ),
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
            response = (
                UnavailableReasoningProvider()
                .investigate(request)
                .model_copy(
                    update={"summary": "Reasoning could not complete; no supported diagnosis."}
                )
            )
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
                "pending_distinguishing_probes": (
                    state.pending_distinguishing_probes
                    if response.degraded or rejected
                    else response.distinguishing_probes
                ),
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
        if not _wifi_reference_objective(state.objective):
            terms.discard("wireless")
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
        # The reference pack spells this technology "Wi-Fi", while callers
        # commonly type "WiFi". Keep these conditional alternatives together
        # before generic word overlap can seed an unrelated branch (for
        # example, the word "no" in "no internet"). The graph still supplies
        # the mechanisms and registered probes; this alias is not case evidence.
        wifi_seeds = (
            tuple(
                node_id
                for node_id in (
                    "kn_network_failure",
                    "kn_wifi_association_failure",
                    "kn_wifi_auth_failure",
                )
                if any(node.node_id == node_id for node in self.knowledge.pack.nodes)
            )
            if _wifi_reference_objective(state.objective)
            else ()
        )
        semantic_seeds = tuple(node_id for score, node_id in scored if score > 0)
        seeds = tuple(dict.fromkeys((*error_seeds, *wifi_seeds, *semantic_seeds)))[:3]
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
        routed_capabilities = bind_trusted_machine_probe_targets(
            store=self.store,
            case_id=state.case_id,
            incident_start=state.incident_start,
            incident_end=state.incident_end,
            context=context,
            relationships=graph.relationships,
            capabilities=self.capabilities,
            completed_probe_ids=frozenset(state.completed_probe_ids),
        )
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
            available_probes=routed_capabilities,
            completed_probe_ids=frozenset(state.completed_probe_ids).intersection(
                item.probe_id for item in routed_capabilities
            ),
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
            current_case = str(record.case_id) == case_id
            incident_relevant = state.incident_start <= record.observed_at <= state.incident_end
            if current_case and not incident_relevant:
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
                    case_scope="current_case" if current_case else "historical",
                    incident_relevant=incident_relevant,
                    limitations=tuple(item[:240] for item in limitations[:16]),
                )
            )
        for coverage in packet.coverage:
            limitations = list(coverage.limitations)
            current_case = str(coverage.case_id) == case_id
            incident_relevant = state.incident_start <= coverage.captured_at <= state.incident_end
            if current_case and not incident_relevant:
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
                    case_scope="current_case" if current_case else "historical",
                    incident_relevant=incident_relevant,
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
        *,
        batch_limit: int | None = None,
    ) -> tuple[ProbeProposal, ...]:
        known = {item.probe_id: item for item in self.capabilities}
        by_id: dict[str, ProbeProposal] = {}
        for proposal in proposals:
            # The merged list is deep-first. Keep the first advisory claim for
            # an ID so a later provider cannot replace its dependencies.
            by_id.setdefault(proposal.probe_id, proposal)
        slots = max(0, state.max_probes - len(state.completed_probe_ids))
        if batch_limit is not None:
            slots = min(slots, batch_limit)
        selected: list[ProbeProposal] = []
        selected_ids: set[str] = set()

        def closure(probe_id: str, visiting: set[str]) -> tuple[ProbeProposal, ...] | None:
            proposal = by_id.get(probe_id)
            if (
                proposal is None
                or probe_id in state.completed_probe_ids
                or probe_id in visiting
                or not self._registered_read_only(proposal, known.get(probe_id))
            ):
                return None
            dependencies: list[ProbeProposal] = []
            next_visiting = {*visiting, probe_id}
            for dependency_id in proposal.depends_on:
                chain = closure(dependency_id, next_visiting)
                if chain is None:
                    return None
                dependencies.extend(chain)
            return (*dependencies, proposal)

        for proposal in by_id.values():
            chain = closure(proposal.probe_id, set())
            if chain is None:
                continue
            needed: list[ProbeProposal] = []
            needed_ids = set(selected_ids)
            for item in chain:
                if item.probe_id not in needed_ids:
                    needed.append(item)
                    needed_ids.add(item.probe_id)
            cost = sum(item.estimated_cost_ms for item in needed)
            if len(selected) + len(needed) > slots or cost > remaining:
                continue
            selected.extend(needed)
            selected_ids.update(item.probe_id for item in needed)
            remaining -= cost
            if len(selected) >= slots:
                break
        return tuple(selected)

    @staticmethod
    def _registered_read_only(proposal: ProbeProposal, capability: ProbeCapability | None) -> bool:
        return (
            capability is not None
            and proposal.estimated_cost_ms == capability.cost_ms
            and proposal.resource_class is capability.resource_class
            and proposal.permission_class is PermissionClass.READ_ONLY
            and capability.permission_class is PermissionClass.READ_ONLY
            and proposal.safety_class is capability.safety_class
            and capability.safety_class in {SafetyClass.R0, SafetyClass.R1}
            and capability.target_state_effect == "none"
            and not capability.outbound_network
        )

    def _retire_stale_deep_requests(self, state: InvestigationState) -> InvestigationState:
        """Validate only the proposal's own dependency bundle, not a catalog DAG."""

        known = {item.probe_id: item for item in self.capabilities}
        candidates: dict[str, ProbeProposal] = {}
        for item in state.pending_distinguishing_probes:
            if (
                item.probe_id not in candidates
                and item.probe_id not in state.completed_probe_ids
                and self._registered_read_only(item, known.get(item.probe_id))
            ):
                candidates[item.probe_id] = item

        def valid(probe_id: str, visiting: set[str]) -> bool:
            item = candidates.get(probe_id)
            return (
                item is not None
                and probe_id not in visiting
                and all(valid(dependency, {*visiting, probe_id}) for dependency in item.depends_on)
            )

        pending = tuple(item for item in candidates.values() if valid(item.probe_id, set()))
        if pending == state.pending_distinguishing_probes:
            return state
        return state.model_copy(
            update={
                "pending_distinguishing_probes": pending,
                "warnings": self._warnings(
                    state,
                    "Stale, duplicate, or no-longer-registered deep probe requests were retired.",
                ),
            }
        )

    def _exploration(self, state: InvestigationState, remaining: int) -> tuple[ProbeProposal, ...]:
        # Follow a relevant, sourced distinguishing probe when a provider has
        # no proposal. An arbitrary cheapest probe is not investigative progress.
        if self.knowledge is None or len(state.completed_probe_ids) >= state.max_probes:
            return ()
        references = self.reference_context(state)
        if not references:
            return ()
        packet = KnowledgePacket.model_validate(references[0])
        known = {capability.probe_id: capability for capability in self.capabilities}
        for relation in packet.relations:
            for probe_id in relation.distinguishing_probe_ids:
                capability = known.get(probe_id)
                if (
                    capability is None
                    or probe_id in state.completed_probe_ids
                    or capability.cost_ms > remaining
                ):
                    continue
                return (
                    ProbeProposal(
                        probe_id=probe_id,
                        purpose=DiagnosticPurpose.CHECK_COVERAGE,
                        priority=0.25,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        safety_class=capability.safety_class,
                        dedupe_key=f"reference-explore:{probe_id}",
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
        if (
            state.assessment is None
            and not state.requested_evidence_ids
            and not state.requested_details
            and "network.listeners" in state.completed_probe_ids
            and explicit_bind_conflict_target(state.objective) is not None
            and outcome
            in {
                InvestigationOutcome.BUDGET_EXHAUSTED,
                InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
                InvestigationOutcome.NO_PROGRESS,
            }
        ):
            try:
                context = self.context(str(state.case_id))
                target = select_target_evidence(self.store, context, state.objective)
                incomplete = target.truncated or self._retrieval_omitted_evidence(context)
                if incomplete:
                    state = state.model_copy(
                        update={
                            "warnings": self._warnings(
                                state,
                                "Exact target scan incomplete; observed owner finding withheld.",
                            )
                        }
                    )
                else:
                    assessment = assess_investigation(
                        state=state,
                        context=self._merge_excerpts(
                            self._retain_assessed(state, context), target.context
                        ),
                        relationships=(),
                    )
                    if assessment.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_FINDING:
                        state = state.model_copy(update={"assessment": assessment})
            except Exception as error:
                state = state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state,
                            f"Observed-finding enrichment unavailable: {type(error).__name__}.",
                        )
                    }
                )
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
        summary = state.summary
        if summary == "Queued for read-only investigation.":
            summary = f"No supported diagnosis was reached. {reason}"
        return self._save(
            state.model_copy(
                update={
                    "status": status,
                    "outcome": outcome,
                    "stop_reason": reason,
                    "summary": summary,
                }
            ),
            "stopped",
            reason,
        )

    @staticmethod
    def _retrieval_omitted_evidence(context: tuple[EvidenceContext, ...]) -> bool:
        return any(
            "Retrieval packet omitted " in limitation
            for item in context
            for limitation in item.limitations
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
        # A new failed/denied/unsupported record updates coverage and remains
        # visible to the user, but it cannot by itself distinguish root causes.
        # Clock-inconsistent facts also cannot be counted as investigative gain.
        payload = sorted(
            json.dumps(
                (item.probe_id, item.status.value, item.summary, item.facts),
                sort_keys=True,
                separators=(",", ":"),
            )
            for item in context
            if item.status in {EvidenceContextStatus.OBSERVED, EvidenceContextStatus.PARTIAL}
            and item.case_scope == "current_case"
            and item.incident_relevant is True
            and not item.probe_id.endswith(".coverage")
            and (item.status is EvidenceContextStatus.OBSERVED or bool(item.facts))
            and item.observed_at <= item.captured_at
            and "source_clock_after_capture" not in item.limitations
        )
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
