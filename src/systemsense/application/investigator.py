"""A bounded, durable investigation loop over read-only collection and advice."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from systemsense.application.assessment import (
    AssessmentDisposition,
    assess_investigation,
    explicit_bind_conflict_target,
)
from systemsense.application.candidate_provider_call import call_candidate_provider
from systemsense.application.case_service import OpenedCase
from systemsense.application.deep_worker import (
    DeepMailboxCompletionV1,
    DeepMailboxRepository,
    DeepWorkerLane,
    FrozenDeepTaskV1,
    assess_deep_result,
    freeze_deep_task,
)
from systemsense.application.frontier_branch import process_claimed_branch
from systemsense.application.frontier_discovery import (
    discover_retrieval_page,
    seed_frontier_discovery,
)
from systemsense.application.frontier_policy import FrontierPolicyStepV1, run_frontier_step
from systemsense.application.graph_routing import bind_trusted_machine_probe_targets
from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
    MeasurementGap,
    ProviderCall,
)
from systemsense.application.runtime import (
    DiagnosticRuntime,
    FollowupSelection,
    PersistedProbeResult,
)
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
)
from systemsense.decision.catalog_attention import (
    CatalogAttentionProvider,
    CatalogAttentionRequest,
)
from systemsense.decision.contracts import (
    DecisionRequest,
    DiagnosticPurpose,
    FastHypothesisCheck,
    FastSignal,
    PermissionClass,
    ProbeCapability,
    ProbeProposal,
)
from systemsense.decision.frontier_ranker import MixedFrontierRanker, SemanticPacketRefV1
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.provider import CandidateDecisionProvider, FastDecisionProvider
from systemsense.decision.semantic_packets import evidence_packets
from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    CaseTimeWindowBasis,
    DiagnosticCase,
)
from systemsense.domain.diagnostic_progress import (
    DiagnosticProgressContextV1,
    DiagnosticProgressScopeV1,
)
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue, stable_source_id
from systemsense.domain.probes import (
    MeasurementNeed,
    MeasurementWindow,
    Privilege,
    ProbeInvocation,
    SafetyClass,
)
from systemsense.domain.time import utc_now
from systemsense.evidence.attention import focus_evidence
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
)
from systemsense.evidence.pages import attention_pages
from systemsense.evidence.projection import ExplicitRelationProjector
from systemsense.evidence.redaction import Redactor
from systemsense.evidence.retrieval import (
    EvidenceCatalogCursor,
    EvidenceCatalogEntry,
    EvidenceCatalogExactQuery,
    EvidenceCatalogPage,
    EvidenceCatalogQuery,
    EvidencePacket,
    EvidenceRelationRepository,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
)
from systemsense.evidence.targets import retrieve_details, select_target_evidence
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.control import current_cancellation, inference_cancellation
from systemsense.inference.settings import ProviderStatus
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.knowledge.models import KnowledgePacket, probe_roles_for_relation
from systemsense.knowledge.windows_errors import WindowsErrorReference, reference_for_text
from systemsense.orchestration.invocations import ObservabilityGap
from systemsense.orchestration.planner import CasePlan, PlannedProbe
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import TargetPressureParametersV1
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    FastAttentionConcern,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.decision_snapshots import (
    DecisionSnapshotRepository,
    ProbeManifestRef,
)
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.investigations import (
    FrontierMeasurementAdmissionIntent,
    InvestigationRepository,
)
from systemsense.storage.presented_read_set import (
    PresentedReadSetV1,
    capture_presented_read_set,
    revalidate_presented_read_set,
)
from systemsense.storage.search_frontier import (
    FrontierInvestigatorItemTransitionV1,
    FrontierInvestigatorTurnClosureIntentV1,
    FrontierInvestigatorTurnCompletionV1,
    FrontierInvestigatorTurnCompletionV3,
    FrontierInvestigatorTurnOutcomeV3,
    FrontierInvestigatorTurnV3,
    FrontierItemCapacityError,
    FrontierPendingRefreshV3,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True)
class _RelationshipSelection:
    context: tuple[EvidenceContext, ...]
    relationships: tuple[EvidenceRelation, ...]
    loaded_grounded_count: int
    omitted_count: int
    candidate_scan_truncated: bool


@dataclass(frozen=True)
class _ReasoningBookkeeping:
    requested_evidence_ids: tuple[EvidenceId, ...]
    completed_evidence_requests: tuple[EvidenceId, ...]
    requested_details: tuple[EvidenceDetailRequest, ...]
    completed_detail_requests: tuple[EvidenceDetailRequest, ...]
    catalog_cursor: EvidenceCatalogCursor | None
    catalog_generation: int | None
    catalog_limit: int
    catalog_followup_pending: bool
    catalog_fit_blocked: bool = False


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
_WLAN_BASELINE_MAX_AGE = timedelta(seconds=15)


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
        catalog_attention: CatalogAttentionProvider | None = None,
        frontier_ranker: MixedFrontierRanker | None = None,
    ) -> None:
        self.store = store
        self.repository = InvestigationRepository(store)
        self.decision_snapshots = DecisionSnapshotRepository(store)
        self.candidate_snapshots = CandidateDecisionSnapshotRepository(store)
        self.runtime = runtime
        self.capabilities = capabilities
        self.decision = decision
        self.reasoning = reasoning
        self.knowledge = knowledge
        self.catalog_attention = catalog_attention
        self.frontier_ranker = frontier_ranker
        self.redactor = Redactor()
        self._deep_lane = DeepWorkerLane()
        self._deep_mailbox = DeepMailboxRepository(store)
        self._deep_task: FrozenDeepTaskV1 | None = None
        self._last_deep_admission: FrozenDeepTaskV1 | None = None
        self._run_owner = threading.Lock()

    def _diagnostic_progress_context(
        self, state: InvestigationState
    ) -> tuple[DiagnosticProgressContextV1, ...]:
        """Revalidate terminal custody immediately before each advisory request."""
        from systemsense.storage.diagnostic_intents import (
            DiagnosticIntentAdmissionV2,
            DiagnosticIntentRepository,
        )
        from systemsense.storage.diagnostic_progress import DiagnosticProgressRepository

        try:
            projections = DiagnosticProgressRepository(self.store).for_case(state.case_id)
            contexts: list[DiagnosticProgressContextV1] = []
            for projection in projections[-8:]:
                admission = DiagnosticIntentRepository(self.store).admission_record(
                    projection.admission_id
                )
                if not isinstance(admission, DiagnosticIntentAdmissionV2):
                    continue
                question = admission.question
                event = projection.event
                observed = (
                    None
                    if projection.terminal_status != "evaluated"
                    else event.evaluation.observed
                    if event.evaluation is not None
                    else None
                )
                custody = (
                    "missing"
                    if projection.terminal_reason == "admission_source_unverifiable"
                    else "verified"
                )
                branch_dead_ends = sum(
                    item.branch_id == question.branch_id and item.dead_end for item in contexts
                ) + int(observed is None)
                contexts.append(
                    DiagnosticProgressContextV1(
                        question_id=question.question_id,
                        branch_id=question.branch_id,
                        uncertainty_id=question.uncertainty_id,
                        scope=DiagnosticProgressScopeV1(
                            case_id=question.scope.case_id,
                            target_handle=question.scope.target_handle,
                            window=question.scope.window,
                        ),
                        terminal_status=projection.terminal_status,
                        observed=observed,
                        reason=projection.terminal_reason,
                        evidence_ids=event.evidence_ids,
                        matched_alternative_ids=(
                            event.prediction_matched_hypothesis_ids if observed is not None else ()
                        ),
                        disfavored_alternative_ids=(
                            event.prediction_disfavored_hypothesis_ids
                            if observed is not None
                            else ()
                        ),
                        unresolved_assumption_ids=event.unresolved_assumption_ids[:8],
                        custody_status=custody,
                        unknown=observed is None,
                        dead_end=observed is None,
                        branch_dead_end_count=branch_dead_ends,
                    )
                )
            return tuple(contexts)
        except ValueError:
            # Reconstruct only scope from immutable admission bytes. Never reuse
            # the projected Boolean when its source custody failed revalidation.
            row = self.store.connection.execute(
                "SELECT admission_id FROM diagnostic_progress WHERE case_id=? "
                "ORDER BY projected_at DESC LIMIT 1",
                (str(state.case_id),),
            ).fetchone()
            if row is None:
                return ()
            try:
                admission = DiagnosticIntentRepository(self.store).admission_record(str(row[0]))
                if not isinstance(admission, DiagnosticIntentAdmissionV2):
                    return ()
                question = admission.question
                return (
                    DiagnosticProgressContextV1(
                        question_id=question.question_id,
                        branch_id=question.branch_id,
                        uncertainty_id=question.uncertainty_id,
                        scope=DiagnosticProgressScopeV1(
                            case_id=question.scope.case_id,
                            target_handle=question.scope.target_handle,
                            window=question.scope.window,
                        ),
                        terminal_status="unknown",
                        observed=None,
                        reason="diagnostic_projection_or_source_custody_unverifiable",
                        custody_status="invalid",
                        unknown=True,
                        dead_end=True,
                        branch_dead_end_count=1,
                    ),
                )
            except ValueError:
                return ()

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
        if not self._run_owner.acquire(blocking=False):
            raise RuntimeError("another case runner owns this investigator")
        try:
            with inference_cancellation(cancel_event):
                return self._run(case_id, cancel_event=cancel_event)
        finally:
            try:
                if self._deep_task is not None and str(self._deep_task.request.case_id) == case_id:
                    self._deep_lane.cancel()
                    self._deep_mailbox.finish(
                        self._deep_task, "cancelled", reason="case runner stopped"
                    )
                    self._close_deep_frontier(self._deep_task)
            finally:
                self._run_owner.release()

    def _run(
        self, case_id: str, *, cancel_event: threading.Event | None = None
    ) -> InvestigationState:
        state = self.repository.load(case_id)
        if state.status is InvestigationStatus.RUNNING:
            # The application service owns recovery under its workspace lease.
            # A bare second runner cannot distinguish a crash from an active
            # collector and must not invalidate that collector's checkpoint.
            raise RuntimeError("investigation is already running")
        if state.status is not InvestigationStatus.QUEUED:
            return state
        # Claim the durable case version before recovery. A second Investigator
        # racing this owner loses the compare-and-swap and cannot interrupt its task.
        state = self._save(
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "started",
            "Read-only investigation started.",
        )
        owner_started_version = state.state_version
        orphaned = self._deep_mailbox.recover(
            state.case_id,
            live_request_sha256=self._deep_task.request_sha256 if self._deep_task else None,
        )
        if orphaned:
            state = self._save(
                state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state,
                            "Interrupted deep requests were retained; "
                            "automatic replay is disabled.",
                        )
                    }
                ),
                "deep_interrupted",
                "Recovered orphaned deep mailbox custody.",
            )
        # A consumed diagnostic claim may have outlived its collector process.
        # This recovery path runs only after the new owner has claimed the case
        # epoch under the application workspace lease; it never re-dispatches.
        from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository
        from systemsense.storage.diagnostic_progress import DiagnosticProgressRepository

        with self.store.transaction():
            recovered_diagnostics = DiagnosticIntentRepository(self.store).recover_consumed(
                state.case_id
            )
            DiagnosticProgressRepository(self.store).project_unprojected(state.case_id)
        if recovered_diagnostics:
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state,
                        "Interrupted diagnostic questions were reconciled without replay.",
                    )
                }
            )
        self._reconcile_frontier_candidate_claims(state.case_id)
        frontier_repository = SearchFrontierRepository(self.store)
        frontier_repository.interrupt_uncertain(state.case_id)
        active_attention = frontier_repository.active_investigator_session(state.case_id)
        if active_attention is not None:
            recovered_attention_turn = None
            for turn in frontier_repository.investigator_turns(
                state.case_id, active_attention.event_id
            ):
                outcome = frontier_repository.read_investigator_turn_outcome(turn.turn_id)
                if outcome is None:
                    outcome = frontier_repository.recover_interrupted_investigator_turn(
                        turn.turn_id
                    )
                recovered_attention_turn = turn if outcome.outcome == "interrupted" else None
            if recovered_attention_turn is not None:
                with self.store.transaction():
                    source_missing = (
                        frontier_repository.read_event(active_attention.event_id).source_state
                        == "missing_unverifiable"
                    )
                    frontier_repository.close_investigator_session_in_transaction(
                        FrontierInvestigatorTurnClosureIntentV1(
                            event_id=active_attention.event_id,
                            case_id=state.case_id,
                            final_turn_id=recovered_attention_turn.turn_id,
                            outcome="gap",
                            reason_code=(
                                "source_unverifiable" if source_missing else "owner_interrupted"
                            ),
                        )
                    )
                state = state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state, "Interrupted event attention was retained without replay."
                        )
                    }
                )
        # Pending work survived a crash. It may have observed the host already, so
        # retain it as attempted and surface uncertainty instead of replaying it.
        if state.pending_probe_ids:
            history = self._attempt_history(state)
            claimed_diagnostic_ids = frozenset(
                str(row[0])
                for row in self.store.connection.execute(
                    "SELECT json_extract(a.record_json, '$.probe_id') "
                    "FROM diagnostic_intent_admissions AS a "
                    "JOIN diagnostic_intent_dispatch_claims AS c "
                    "ON c.admission_id=a.admission_id WHERE a.case_id=?",
                    (str(state.case_id),),
                )
            )
            unrecorded = sum(
                probe_id not in claimed_diagnostic_ids
                and len(history.get(probe_id, ())) <= int(probe_id in state.completed_probe_ids)
                for probe_id in state.pending_probe_ids
            )
            state = state.model_copy(
                update={
                    "schema_version": 5,
                    "completed_probe_ids": tuple(
                        dict.fromkeys(
                            (
                                *state.completed_probe_ids,
                                *state.pending_probe_ids,
                            )
                        )
                    ),
                    "interrupted_probe_ids": tuple(
                        dict.fromkeys((*state.interrupted_probe_ids, *state.pending_probe_ids))
                    ),
                    "unrecorded_attempt_count": state.unrecorded_attempt_count + unrecorded,
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
        uncertain_followup_ids = tuple(
            dict.fromkeys(
                (
                    *self._unlinked_followup_probe_ids(state),
                    *self._unsafe_followup_probe_ids(state),
                )
            )
        )
        if uncertain_followup_ids:
            state = state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys((*state.completed_probe_ids, *uncertain_followup_ids))
                    ),
                    "interrupted_probe_ids": tuple(
                        dict.fromkeys((*state.interrupted_probe_ids, *uncertain_followup_ids))
                    ),
                    "warnings": self._warnings(
                        state,
                        "Follow-up custody is uncertain; it was not replayed.",
                    ),
                }
            )
        uncertain_candidate_ids = self._unlinked_candidate_probe_ids(state)
        if uncertain_candidate_ids:
            state = state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys((*state.completed_probe_ids, *uncertain_candidate_ids))
                    ),
                    "interrupted_probe_ids": tuple(
                        dict.fromkeys((*state.interrupted_probe_ids, *uncertain_candidate_ids))
                    ),
                    "warnings": self._warnings(
                        state, "Candidate dispatch custody is uncertain; it was not replayed."
                    ),
                }
            )
        state = self._retire_stale_deep_requests(state)
        state = self._save(
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "recovered",
            "Investigation custody reconciled.",
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
        state = self._collect_wlan_question(state, cancel_event)
        if _is_pdf_performance_objective(state.objective):
            frontier_routed = False
            if self.frontier_ranker is not None:
                state, frontier_routed = self._route_frontier_pdf_candidate(state, cancel_event)
            if not frontier_routed:
                state = self._route_pdf_candidate(state, cancel_event)
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
        if self._attempts_consumed(state) >= state.max_probes:
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
        catalog_attention_failed = False
        while True:
            state = self._drain_deep(state)
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
            frontier_delivered = False
            if self.frontier_ranker is not None:
                previous_selected = state.fast_catalog_selected_ids
                state, context, event_handled = self._event_frontier_turn(
                    state, context, owner_started_version
                )
                if event_handled:
                    frontier_delivered = state.fast_catalog_selected_ids != previous_selected
                else:
                    state, context, frontier_delivered = self._frontier_retrieval(state, context)
            if self.catalog_attention is not None and not catalog_attention_failed:
                if not frontier_delivered:
                    state, context, catalog_attention_failed = self._catalog_attention(
                        state, context
                    )
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
                capabilities=self._case_capabilities(state),
                completed_probe_ids=frozenset(state.completed_probe_ids),
                symptom=state.objective,
            )
            registered_probe_ids = {item.probe_id for item in routed_capabilities}
            decision_request = DecisionRequest(
                schema_version=4,
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
                completed_probe_ids=self._completed_for_models(state).intersection(
                    item.probe_id for item in routed_capabilities
                ),
                satisfied_probe_ids=self._satisfied_probe_ids(state).intersection(
                    item.probe_id for item in routed_capabilities
                ),
                retryable_probe_ids=self._retryable_probe_ids(state).intersection(
                    item.probe_id for item in routed_capabilities
                ),
                # Completion is an execution fact, not a freshness guarantee.
                fresh_probe_ids=frozenset(),
                preferred_probe_ids=tuple(p.probe_id for p in state.pending_distinguishing_probes),
                hypothesis_briefs=tuple(h.statement for h in state.hypotheses),
                hypothesis_checks=tuple(
                    FastHypothesisCheck(
                        hypothesis_index=index,
                        probe_id=expected.probe_id,
                        fact_name=expected.fact_name,
                        expected_value=expected.expected_value,
                        observed_after=hypothesis.expected_facts_observed_after,
                    )
                    for index, hypothesis in enumerate(state.hypotheses)
                    if hypothesis.expected_facts_observed_after is not None
                    for expected in hypothesis.expected_facts
                    if expected.probe_id in registered_probe_ids
                )[:8],
                stagnant_rounds=state.stagnant_rounds,
                budget_ms=remaining,
                max_probes=max(1, min(4, state.max_probes - self._attempts_consumed(state))),
                diagnostic_progress=self._diagnostic_progress_context(state),
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
            reasoned_before_collection = False
            decision_snapshot_id: str | None = None
            if len(requested) >= decision_request.max_probes:
                state = self._save(
                    state,
                    "routing_superseded",
                    "Fast routing was skipped because trusted deep-brain probes fill the "
                    "available batch.",
                )
                routing_proposals: tuple[ProbeProposal, ...] = ()
            else:
                # Providers receive independent mutable nested data. The
                # original request remains the pre-provider replay source.
                provider_request = decision_request.model_copy(deep=True)
                call_started_at = utc_now()
                call_started = time.monotonic()
                rejected = False
                try:
                    response = self.decision.decide(provider_request).validate_against(
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
                # Persist the already-frozen pre-probe input after inference so
                # optional training capture cannot consume the model's deadline.
                try:
                    decision_snapshot = self.decision_snapshots.capture(
                        decision_request,
                        request_frozen_at=call_started_at,
                        presentation_trace=response.presentation_trace if not rejected else None,
                        probe_manifest_refs=tuple(
                            ProbeManifestRef.from_manifest(
                                capability.probe_id,
                                self.runtime.probe_manifest(capability.probe_id),
                            )
                            for capability in decision_request.available_probes
                        ),
                    )
                    decision_snapshot_id = decision_snapshot.snapshot_id
                except Exception as error:
                    state = state.model_copy(
                        update={
                            "warnings": self._warnings(
                                state,
                                f"Decision snapshot unavailable: {type(error).__name__}.",
                            )
                        }
                    )
                decision_status = getattr(self.decision, "status", None)
                with self.store.transaction() as transaction:
                    transaction.append_coordinator_event(
                        case_id=str(state.case_id),
                        kind="provider",
                        fields={
                            "role": "decision",
                            "attempted_provider_id": self.decision.identity.provider_id,
                            "effective_provider_id": response.provider.provider_id,
                            "failed": rejected or response.degraded,
                        },
                    )
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
                if response.requires_reasoning and not rejected and not response.degraded:
                    # Fast signals are advisory. They can bring forward a deep
                    # review, but cannot themselves establish a cause or execute
                    # a probe. A new deep plan supersedes the older fast shortlist.
                    reasons = ", ".join(signal.kind.value for signal in response.signals)
                    state = self._save(
                        state,
                        "fast_escalation",
                        "Fast brain requested deep review before collection: "
                        + (reasons or "reason not specified"),
                    )
                    state, _ = self._reason_with_details(
                        state, context, fast_signals=response.signals
                    )
                    reasoned_before_collection = True
                    observed = self._complete_observed(state, context, cancel_event)
                    if observed is not None:
                        return observed
                    routing_proposals = ()
                    requested = self._eligible(
                        state.pending_distinguishing_probes,
                        state,
                        self._remaining_ms(state),
                        batch_limit=decision_request.max_probes,
                    )
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
            if not proposals:
                # The provider has had its choice. Preserve selected-process
                # sampling as a deterministic fallback, never a preemption.
                target_fallback = self._bound_target_proposal(state)
                if target_fallback is not None:
                    proposals = self._eligible(
                        (target_fallback,),
                        state,
                        remaining,
                        batch_limit=decision_request.max_probes,
                    )
                    if proposals:
                        # The frozen snapshot records the model's choice, not
                        # this coordinator-owned fallback choice.
                        decision_snapshot_id = None
            typed_index = next(
                (
                    index
                    for index, item in enumerate(proposals)
                    if item.probe_id == "application.target_pressure"
                ),
                None,
            )
            if typed_index is not None:
                # The first typed adapter admits one measurement. Execute the
                # preceding model choices first, then re-evaluate the rest.
                proposals = proposals[:typed_index] if typed_index else proposals[:1]
            if not proposals and self._attempts_consumed(state) < state.max_probes:
                proposals = self._exploration(state, remaining)
            if not proposals:
                if not reasoned_before_collection:
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
                if not proposals and self._deep_task is not None:
                    state = self._await_deep_when_idle(state)
                    proposals = self._eligible(
                        state.pending_distinguishing_probes,
                        state,
                        self._remaining_ms(state),
                        batch_limit=decision_request.max_probes,
                    )
                    if not proposals and self._has_deep_work() and self._remaining_ms(state) > 0:
                        continue
                if not proposals:
                    resolved_wlan = any(
                        item.observed is not None
                        and item.custody_status == "verified"
                        and item.branch_id == "wlan.association_transition"
                        for item in self._diagnostic_progress_context(state)
                    )
                    return self._finish(
                        state,
                        InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
                        (
                            "The scoped WLAN association question is answered; no supported "
                            "causal explanation is established."
                            if resolved_wlan
                            else (
                                "No eligible unused probe can distinguish the remaining "
                                "explanations."
                            )
                        ),
                    )
            concurrent_deep = (
                self.frontier_ranker is not None
                and bool(context)
                and not reasoned_before_collection
            )
            if concurrent_deep:
                # The opt-in adaptive profile can reason over its frozen current
                # packet while the owning thread collects and persists results.
                # Deep application still occurs at this collection boundary.
                state, _ = self._reason(
                    state,
                    context,
                    concurrent_proposals=proposals,
                    decision_snapshot_id=decision_snapshot_id,
                )
            else:
                state = self._collect(
                    state, proposals, cancel_event, decision_snapshot_id=decision_snapshot_id
                )
            stopped = self._stop_if_needed(state, cancel_event, check_probe_budget=False)
            if stopped is not None:
                return stopped
            context = self.context(case_id)
            state = self._refresh_attention(state, context)
            stopped = self._stop_if_needed(state, cancel_event, check_probe_budget=False)
            if stopped is not None:
                return stopped
            if concurrent_deep:
                # Do not immediately replace a bounded background attempt with
                # another foreground call that stalls the next fast-policy turn.
                requested = state.pending_distinguishing_probes
            else:
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

    def _collect_wlan_question(
        self, state: InvestigationState, cancel_event: threading.Event | None
    ) -> InvestigationState:
        """Ask one registered state question after a fresh transitional baseline."""
        from systemsense.evaluation.progress import (
            AssociationAlternativeV1,
            DiagnosticQuestionV1,
            PredicateScope,
        )
        from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository
        from systemsense.storage.diagnostic_progress import DiagnosticProgressRepository

        if (
            not _wifi_reference_objective(state.objective)
            or (cancel_event is not None and cancel_event.is_set())
            or self._attempts_consumed(state) >= state.max_probes
            or self.store.connection.execute(
                "SELECT 1 FROM diagnostic_intent_admissions WHERE case_id=? LIMIT 1",
                (str(state.case_id),),
            ).fetchone()
            is not None
        ):
            return state
        capability = next(
            (item for item in self.capabilities if item.probe_id == "network.connectivity"),
            None,
        )
        manifest = self.runtime.probe_manifest("network.connectivity")
        if (
            capability is None
            or manifest is None
            or manifest.version != 3
            or not self._registered_read_only(
                ProbeProposal(
                    probe_id=capability.probe_id,
                    purpose=DiagnosticPurpose.CHECK_COVERAGE,
                    priority=1.0,
                    estimated_cost_ms=capability.cost_ms,
                    resource_class=capability.resource_class,
                    safety_class=capability.safety_class,
                    dedupe_key="wlan.association.question",
                ),
                capability,
            )
            or self._remaining_ms(state) < capability.cost_ms + 250
        ):
            return state
        source = self.store.connection.execute(
            "SELECT evidence_id FROM evidence WHERE case_id=? AND execution_id IN "
            "(SELECT execution_id FROM probe_executions WHERE case_id=? "
            "AND probe_id='network.connectivity' AND probe_version=3 AND status='ok') "
            "ORDER BY captured_at DESC LIMIT 1",
            (str(state.case_id), str(state.case_id)),
        ).fetchone()
        if source is None:
            return state
        intents = DiagnosticIntentRepository(self.store)
        try:
            source_id = EvidenceId(root=str(source[0]))
            _, snapshot = intents.trusted_source(state.case_id, source_id)
            owner_now = utc_now()
            if (
                snapshot.wifi_status.value != "available"
                or snapshot.omitted_wifi_count != 0
                or len(snapshot.wifi_interfaces) != 1
                or snapshot.wifi_interfaces[0].details_status.value != "available"
                or snapshot.wifi_interfaces[0].association_state
                not in {"authenticating", "associating"}
                or not state.created_at <= snapshot.wifi_observed_at <= owner_now
                or not state.incident_start <= snapshot.wifi_observed_at <= state.incident_end
                or owner_now - snapshot.wifi_observed_at > _WLAN_BASELINE_MAX_AGE
                or state.deadline_at - owner_now < timedelta(milliseconds=capability.cost_ms + 250)
                or min(state.deadline_at, owner_now + timedelta(seconds=5)) > state.incident_end
            ):
                return state
            target = str(UUID(snapshot.wifi_interfaces[0].interface_guid))
            if target != snapshot.wifi_interfaces[0].interface_guid:
                return state
        except ValueError:
            return state
        question = DiagnosticQuestionV1(
            question_id="wlan.next_association_state",
            branch_id="wlan.association_transition",
            uncertainty_id="wlan.next_association_state",
            scope=PredicateScope(
                case_id=state.case_id,
                target_handle=target,
                window=MeasurementWindow(
                    start=owner_now,
                    end=min(state.deadline_at, owner_now + timedelta(seconds=5)),
                ),
            ),
            alternatives=(
                AssociationAlternativeV1(
                    alternative_id="wlan.associated", association_state="connected", expected=True
                ),
                AssociationAlternativeV1(
                    alternative_id="wlan.disconnected",
                    association_state="disconnected",
                    expected=False,
                ),
            ),
        )
        proposal = ProbeProposal(
            probe_id="network.connectivity",
            purpose=DiagnosticPurpose.CHECK_COVERAGE,
            priority=1.0,
            estimated_cost_ms=capability.cost_ms,
            resource_class=capability.resource_class,
            safety_class=capability.safety_class,
            dedupe_key="wlan.association.question",
        )
        state = self._save(
            state.model_copy(
                update={
                    "pending_probe_ids": (proposal.probe_id,),
                    "spent_cost_ms": state.spent_cost_ms + proposal.estimated_cost_ms,
                }
            ),
            "diagnostic_question_reserved",
            "One scoped WLAN association follow-up reserved.",
        )
        opened = self._opened(state, (proposal,))
        try:
            with self.store.transaction():
                admission = intents.admit_question(
                    question,
                    expected_state_version=state.state_version,
                    source_evidence_id=source_id,
                    plan_instance_id=opened.plan.probes[0].plan_instance_id,
                    parameters={},
                )
        except ValueError:
            return self._save(
                state.model_copy(
                    update={
                        "pending_probe_ids": (),
                        "spent_cost_ms": state.spent_cost_ms - proposal.estimated_cost_ms,
                        "warnings": self._warnings(
                            state, "WLAN question admission was unavailable."
                        ),
                    }
                ),
                "diagnostic_question_declined",
                "Scoped WLAN admission failed before dispatch.",
            )
        try:
            self.runtime.execute_plan(
                opened,
                cancel_event=cancel_event,
                diagnostic_admissions_by_instance={
                    opened.plan.probes[0].plan_instance_id: admission.admission_id
                },
            )
        except ValueError as error:
            claim = self.store.connection.execute(
                "SELECT 1 FROM diagnostic_intent_dispatch_claims WHERE admission_id=?",
                (admission.admission_id,),
            ).fetchone()
            if (
                str(error) != "diagnostic question observation window expired before dispatch"
                or utc_now() < question.scope.window.end
                or claim is not None
            ):
                raise
            with self.store.transaction():
                intents.interrupt(admission.admission_id, reason="question_window_expired")
                DiagnosticProgressRepository(self.store).project_terminal(admission.admission_id)
            return self._save(
                state.model_copy(
                    update={
                        "pending_probe_ids": (),
                        "spent_cost_ms": state.spent_cost_ms - proposal.estimated_cost_ms,
                        "warnings": self._warnings(
                            state, "WLAN question window expired before dispatch."
                        ),
                    }
                ),
                "diagnostic_question_expired",
                "Scoped WLAN question expired without a read-only dispatch.",
            )
        with self.store.transaction():
            intents.recover_consumed(state.case_id)
            DiagnosticProgressRepository(self.store).project_terminal(admission.admission_id)
        self._project(str(state.case_id))
        return self._save(
            state.model_copy(
                update={
                    "pending_probe_ids": (),
                    "completed_probe_ids": tuple(
                        dict.fromkeys((*state.completed_probe_ids, proposal.probe_id))
                    ),
                    "round_count": state.round_count + 1,
                }
            ),
            "diagnostic_question_collected",
            "Scoped WLAN association question received a verified terminal.",
        )

    def _collect(
        self,
        state: InvestigationState,
        proposals: tuple[ProbeProposal, ...],
        cancel_event: threading.Event | None,
        *,
        baseline: bool = False,
        decision_snapshot_id: str | None = None,
        adaptive_followups: bool = False,
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
        gap: ObservabilityGap | None = None
        if len(proposals) == 1 and proposals[0].measurement_need is not None:
            result = self.runtime.execute_measurement_need(
                self._opened(state, proposals),
                proposals[0].measurement_need,
                cancel_event=cancel_event,
                decision_snapshot_id=decision_snapshot_id,
            )
            if isinstance(result, ObservabilityGap):
                gap = result
        else:
            # Follow-up inference runs on bounded workers with their own store.
            # Only the concrete Laya provider honors this short request deadline;
            # unproven providers remain on post-batch routing.
            followup_catalog = (
                self._followup_catalog(state)
                if (baseline or adaptive_followups) and type(self.decision) is LayaDecisionProvider
                else ()
            )
            model_lock = threading.Lock()

            def offer_followup(
                parent: PersistedProbeResult, worker_store: SQLiteStore
            ) -> FollowupSelection | None:
                if (
                    parent.case_id != str(state.case_id)
                    or parent.epoch_state_version != state.state_version
                    or (cancel_event is not None and cancel_event.is_set())
                    or utc_now() >= state.deadline_at
                ):
                    return None
                worker = Investigator(
                    store=worker_store,
                    runtime=self.runtime,
                    capabilities=self.capabilities,
                    decision=self.decision,
                    reasoning=self.reasoning,
                    knowledge=self.knowledge,
                    catalog_attention=self.catalog_attention,
                    frontier_ranker=self.frontier_ranker,
                )
                with worker_store.read_snapshot():
                    context = worker.context(str(state.case_id))
                    if not any(item.probe_id == parent.probe_id for item in context):
                        return None
                    graph = worker._relationships(context)
                    context = tuple(
                        sorted(graph.context, key=lambda item: item.probe_id != parent.probe_id)
                    )
                    available_ids = {item.probe_id for item in followup_catalog}
                    completed_ids = frozenset(
                        str(row[0])
                        for row in worker_store.connection.execute(
                            "SELECT DISTINCT x.probe_id FROM probe_executions AS x "
                            "JOIN evidence AS e ON e.execution_id=x.execution_id "
                            "WHERE x.case_id=? AND x.state_version=? AND x.status='ok'",
                            (parent.case_id, parent.epoch_state_version),
                        )
                        if str(row[0]) in available_ids
                    )
                    request = DecisionRequest(
                        schema_version=4,
                        case_id=state.case_id,
                        state_version=state.state_version,
                        correlation_id=f"followup:{state.case_id}:{parent.execution_id}",
                        deadline_at=min(state.deadline_at, utc_now() + timedelta(seconds=1.5)),
                        symptom=state.objective,
                        evidence_ids=tuple(item.evidence_id for item in context),
                        evidence_context=context,
                        attention_context=attention_pages(worker_store, context),
                        relationships=graph.relationships,
                        reference_context=worker.reference_context(state),
                        available_probes=followup_catalog,
                        completed_probe_ids=completed_ids,
                        budget_ms=worker._remaining_ms(state),
                        max_probes=1,
                        diagnostic_progress=worker._diagnostic_progress_context(state),
                    )
                    contexts = request.attention_context or request.evidence_context
                    current_ids = {
                        str(item.evidence_id)
                        for item in contexts
                        if item.case_scope == "current_case"
                    }
                    packet_ids = tuple(
                        dict.fromkeys(
                            item["evidence_id"]
                            for item in LayaDecisionProvider.evidence_fragments_for_laya(request)
                        )
                    )
                    presented_ids = tuple(
                        EvidenceId(root=item) for item in packet_ids if item in current_ids
                    )
                    historical_count = sum(item not in current_ids for item in packet_ids)
                    read_set = capture_presented_read_set(
                        worker_store, state.case_id, presented_ids
                    )
                    frozen_at = utc_now()
                if worker_store.connection.in_transaction:
                    raise RuntimeError("follow-up inference must not hold a store transaction")
                with model_lock:
                    response = self.decision.decide(request.model_copy(deep=True)).validate_against(
                        request
                    )
                if (
                    response.degraded
                    or response.provider != self.decision.identity
                    or utc_now() >= request.deadline_at
                    or not response.proposals
                ):
                    return None
                proposal = response.proposals[0]
                capability = next(
                    (item for item in followup_catalog if item.probe_id == proposal.probe_id),
                    None,
                )
                if capability is None or not self._registered_read_only(proposal, capability):
                    return None
                snapshot = worker.decision_snapshots.capture(
                    request,
                    request_frozen_at=frozen_at,
                    presentation_trace=response.presentation_trace,
                    probe_manifest_refs=tuple(
                        ProbeManifestRef.from_manifest(
                            item.probe_id, self.runtime.probe_manifest(item.probe_id)
                        )
                        for item in followup_catalog
                    ),
                )
                with worker_store.transaction() as transaction:
                    transaction.append_coordinator_event(
                        case_id=str(state.case_id),
                        kind="provider",
                        fields={
                            "role": "decision",
                            "attempted_provider_id": self.decision.identity.provider_id,
                            "effective_provider_id": response.provider.provider_id,
                            "failed": False,
                        },
                    )
                return FollowupSelection(
                    probe_id=proposal.probe_id,
                    decision_snapshot_id=snapshot.snapshot_id,
                    presented_read_set=read_set,
                    unprotected_historical_count=historical_count,
                )

            self.runtime.execute_plan(
                self._opened(state, proposals),
                cancel_event=cancel_event,
                decision_snapshot_id=decision_snapshot_id,
                followup_capabilities=followup_catalog,
                async_offer_followup=offer_followup if followup_catalog else None,
            )
        if gap is not None:
            state = self._with_measurement_gap(
                state,
                gap,
                warning=f"Selected-process measurement unavailable: {gap.reason}.",
            )
        else:
            self._project(str(state.case_id))
        followup_cost, followup_completed, followup_interrupted, followup_warning = (
            self._followup_outcome(state)
        )
        return self._save(
            state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys(
                            (
                                *state.completed_probe_ids,
                                *(() if gap is not None else state.pending_probe_ids),
                                *followup_completed,
                                *followup_interrupted,
                            )
                        )
                    ),
                    "pending_distinguishing_probes": tuple(
                        item
                        for item in state.pending_distinguishing_probes
                        if item.probe_id not in state.pending_probe_ids
                    ),
                    "pending_probe_ids": (),
                    "spent_cost_ms": state.spent_cost_ms
                    - (sum(p.estimated_cost_ms for p in proposals) if gap is not None else 0)
                    + followup_cost,
                    "interrupted_probe_ids": tuple(
                        dict.fromkeys((*state.interrupted_probe_ids, *followup_interrupted))
                    ),
                    "warnings": self._warnings(state, followup_warning)
                    if followup_warning
                    else state.warnings,
                    "round_count": state.round_count + (0 if baseline else 1),
                }
            ),
            "measurement_gap"
            if gap is not None
            else ("baseline_collected" if baseline else "collected"),
            f"Selected measurement returned an explicit observability gap: {gap.reason}."
            if gap is not None
            else "Probe results and coverage persisted.",
        )

    def _followup_catalog(self, state: InvestigationState) -> tuple[ProbeCapability, ...]:
        """Admit only broad, registered, standard-privilege probes not in flight."""

        if self._attempts_consumed(state) >= state.max_probes:
            return ()
        excluded = (
            frozenset((*state.pending_probe_ids, *state.completed_probe_ids))
            | (self._satisfied_probe_ids(state))
            | frozenset(self._attempt_history(state))
            | frozenset(self._unlinked_followup_probe_ids(state))
            | frozenset(self._unsafe_followup_probe_ids(state))
        )
        symptom_terms = frozenset(re.findall(r"[a-z0-9-]+", state.objective.casefold()))
        candidates: list[ProbeCapability] = []
        for capability in self._case_capabilities(state):
            if capability.probe_id in excluded or capability.cost_ms > self._remaining_ms(state):
                continue
            manifest = self.runtime.probe_manifest(capability.probe_id)
            if manifest is None or manifest.input_model != "NoParametersV1":
                continue
            if (
                manifest.safety.privilege is not Privilege.STANDARD
                or manifest.safety.safety_class is not capability.safety_class
                or manifest.safety.target_state_effect != "none"
                or manifest.safety.outbound_network
                or capability.permission_class is not PermissionClass.READ_ONLY
                or capability.target_handles
                or capability.observable_ids
                or capability.supports_window
                or capability.resource_class is not self._followup_resource_class(manifest.category)
            ):
                continue
            candidates.append(capability)
        # The runtime catalog is capped at eight, so order by deterministic
        # symptom relevance before Laya ranks within that admitted window.
        # This admission heuristic is not a diagnosis or learned attention.
        candidates.sort(
            key=lambda item: (
                -len(symptom_terms.intersection(item.keywords)),
                -item.baseline_priority,
                -int(item.common),
                item.probe_id,
            )
        )
        return tuple(candidates[:8])

    @staticmethod
    def _followup_resource_class(category: str) -> ResourceClass:
        if category == "network":
            return ResourceClass.NETWORK
        if category in {"servicing", "storage", "events"}:
            return ResourceClass.DISK
        if category == "local_ai":
            return ResourceClass.GPU
        if category in {"application", "devices", "power", "security"}:
            return ResourceClass.PROCESS
        return ResourceClass.CPU

    def _reconcile_frontier_candidate_claims(self, case_id: CaseId) -> None:
        """Close prior frontier claims from the append-only dispatch ledger on recovery."""

        frontier = SearchFrontierRepository(self.store)
        admissions = CandidateDispatchAdmissionRepository(self.store)
        rows = self.store.connection.execute(
            "SELECT snapshot_id,correlation_id FROM candidate_decision_snapshots "
            "WHERE case_id=? AND schema_version=2 ORDER BY captured_at,snapshot_id",
            (str(case_id),),
        ).fetchall()
        for snapshot_id, item_id in rows:
            item = frontier.readback(str(item_id))
            if item.status not in {
                FrontierStatus.CLAIMED,
                FrontierStatus.ADMITTED,
                FrontierStatus.RUNNING,
            }:
                continue
            row = self.store.connection.execute(
                "SELECT admission_id FROM candidate_dispatch_admissions WHERE snapshot_id=?",
                (str(snapshot_id),),
            ).fetchone()
            if row is None:
                frontier.transition(
                    item.item_id,
                    item.status,
                    FrontierStatus.INTERRUPTED,
                    "recovery_no_admission",
                )
                continue
            try:
                admission = admissions.readback(str(row[0]))
            except ValueError:
                frontier.transition(
                    item.item_id,
                    item.status,
                    FrontierStatus.INTERRUPTED,
                    "recovery_custody_invalid",
                )
                continue
            if admission.outcome_status != "linked":
                frontier.transition(
                    item.item_id,
                    item.status,
                    FrontierStatus.INTERRUPTED,
                    "recovery_unlinked",
                )
                continue
            if item.status is FrontierStatus.CLAIMED:
                item = frontier.transition(
                    item.item_id,
                    FrontierStatus.CLAIMED,
                    FrontierStatus.ADMITTED,
                    "recovery_admission_observed",
                )
            if item.status is FrontierStatus.ADMITTED:
                item = frontier.transition(
                    item.item_id,
                    FrontierStatus.ADMITTED,
                    FrontierStatus.RUNNING,
                    "recovery_claim_observed",
                )
            outcome = self._frontier_execution_outcome(
                admission.execution_id, case_id, admission.candidate_id
            )
            frontier.transition(
                item.item_id,
                FrontierStatus.RUNNING,
                outcome,
                "recovery_execution_" + outcome.value,
            )

    def _frontier_execution_outcome(
        self, execution_id: str | None, case_id: CaseId, candidate_id: str
    ) -> FrontierStatus:
        """A link proves persistence; only an OK observation proves satisfaction."""

        if execution_id is None:
            return FrontierStatus.INTERRUPTED
        row = self.store.connection.execute(
            "SELECT p.status FROM probe_executions AS p "
            "JOIN case_measurement_candidates AS c ON c.case_id=p.case_id "
            "AND c.probe_id=p.probe_id "
            "WHERE p.execution_id=? AND p.case_id=? AND c.candidate_id=?",
            (execution_id, str(case_id), candidate_id),
        ).fetchone()
        if row is None:
            return FrontierStatus.INTERRUPTED
        if row[0] != "ok":
            return FrontierStatus.FAILED
        observed = self.store.connection.execute(
            "SELECT 1 FROM evidence WHERE case_id=? AND execution_id=? AND dedupe_key=?",
            (str(case_id), execution_id, f"execution:{execution_id}"),
        ).fetchone()
        return FrontierStatus.SATISFIED if observed is not None else FrontierStatus.INTERRUPTED

    def _route_frontier_pdf_candidate(
        self, state: InvestigationState, cancel_event: threading.Event | None
    ) -> tuple[InvestigationState, bool]:
        """Route one ranked registry ID through the ordinary candidate dispatcher."""

        ranker = self.frontier_ranker
        if (
            ranker is None
            or "application.snapshot" not in state.completed_probe_ids
            or ProcessTargetRepository(self.store).selected_process_target(state.case_id)
            is not None
            or "application.target_pressure" in self._effective_completed_probe_ids(state)
            or self._attempts_consumed(state) >= state.max_probes
            or self._remaining_ms(state) < _TARGET_PRESSURE_COST_MS
            or (cancel_event is not None and cancel_event.is_set())
        ):
            return state, False
        frontier = SearchFrontierRepository(self.store)
        rank_started_at: datetime | None = None
        rank_started = 0.0
        step: FrontierPolicyStepV1 | None = None
        try:
            registry, needs = self.runtime.candidate_catalog(state.case_id)
            records = tuple(
                record
                for need in needs
                if not isinstance(
                    (record := registry.issue(state.case_id, state.state_version, need)),
                    CandidateGap,
                )
            )
            if not records:
                return state, False
            if self._remaining_ms(state) < _TARGET_PRESSURE_COST_MS:
                return state, False
            retriever = EvidenceRetriever(self.store)
            with self.store.read_snapshot():
                generation = retriever.discover(
                    EvidenceCatalogQuery(case_id=state.case_id, limit=1)
                ).case_evidence_generation
                context = self.context(str(state.case_id), state=state)
                visible_ids = tuple(dict.fromkeys(item.evidence_id for item in context))[:64]
                source_ids = visible_ids[:16]
            versions = RelevantVersionsV1(
                objective=1,
                evidence=generation,
                graph=None if self.knowledge is None else self.knowledge.pack.version,
            )
            refs = tuple(
                AdmittedCandidateRefV1.model_validate(
                    item.model_dump(mode="json", exclude={"schema_version"})
                )
                for item in records
            )
            catalog_entries: dict[EvidenceId, EvidenceCatalogEntry] = {}
            if self.knowledge is not None:
                packet = self.knowledge.focused_packet(
                    objective=state.objective,
                    hypothesis_briefs=tuple(item.statement for item in state.hypotheses[:3]),
                    max_relations=6,
                    max_chars=6_000,
                )
                discovered = seed_frontier_discovery(
                    case_id=state.case_id,
                    retriever=retriever,
                    frontier=frontier,
                    versions=versions,
                    candidates=refs[:16],
                    knowledge=packet,
                    packet_evidence_ids=visible_ids,
                    page_limit=32,
                    max_pages=4,
                    max_items=32,
                )
                items = discovered.items
                cursor = None
                for _ in range(4):
                    page = retriever.discover(
                        EvidenceCatalogQuery(case_id=state.case_id, cursor=cursor, limit=32)
                    )
                    if page.case_evidence_generation != generation:
                        raise ValueError("frontier catalog changed during source readback")
                    catalog_entries.update((entry.evidence_id, entry) for entry in page.entries)
                    cursor = page.next_cursor
                    if cursor is None:
                        break
            else:
                items = tuple(
                    frontier.upsert_item(
                        state.case_id,
                        FrontierReferenceV1(kind="measure", candidate_id=item.candidate_id),
                        versions,
                        cost_ms=item.cost_ms,
                    )
                    for item in refs[:32]
                )
            requested = tuple(item for item in items if item.status is FrontierStatus.REQUESTED)
            requested = tuple(
                item
                for item in requested
                if item.reference.kind == "measure"
                or (
                    item.reference.kind == "retrieve_evidence"
                    and item.reference.evidence_id in catalog_entries
                    and (
                        state.incident_start
                        <= catalog_entries[item.reference.evidence_id].observed_at
                        <= state.incident_end
                        or catalog_entries[item.reference.evidence_id].captured_at
                        >= state.created_at
                    )
                )
            )[:8]
            if not requested:
                return state, False
            offered_ids = {
                item.reference.candidate_id
                for item in requested
                if item.reference.kind == "measure"
            }
            offered_refs = tuple(item for item in refs if item.candidate_id in offered_ids)
            deadline = min(state.deadline_at, utc_now() + timedelta(seconds=1.5))
            if deadline <= utc_now() + timedelta(milliseconds=50):
                return state, False
            packet_receipt_id = None
            if source_ids:
                packet_receipt_id = (
                    FrontierPacketReceiptRepository(self.store)
                    .freeze(
                        case_id=state.case_id,
                        epoch_state_version=state.state_version,
                        evidence_ids=source_ids,
                        expected_generation=generation,
                    )
                    .receipt_id
                )
            rank_started_at = utc_now()
            rank_started = time.monotonic()
            step = run_frontier_step(
                case_id=state.case_id,
                items=requested,
                versions=versions,
                symptom=state.objective,
                hypothesis_briefs=tuple(item.statement[:240] for item in state.hypotheses[:8]),
                deadline_at=deadline,
                provider=ranker.provider,
                model_weight_sha256=ranker.model_weight_sha256,
                catalog_entries=tuple(
                    catalog_entries[evidence_id]
                    for item in requested
                    if (evidence_id := item.reference.evidence_id) is not None
                ),
                candidate_refs=offered_refs,
                candidate_registry=registry,
                candidate_epoch=state.state_version,
                store=self.store,
                retriever=retriever,
                frontier=frontier,
                ranker=ranker,
                packet_receipt_id=packet_receipt_id,
                defer_retrieval_satisfaction=True,
            )
            call = ProviderCall(
                role="fast_decision",
                provider_id=ranker.provider.provider_id,
                provider_version=ranker.provider.provider_version,
                state_version=state.state_version,
                started_at=rank_started_at,
                elapsed_ms=max(0.0, (time.monotonic() - rank_started) * 1000),
                degraded=step.ranking.model_abstained,
                detail=(
                    f"frontier_{step.ranking.degraded_reason}"
                    if step.ranking.degraded_reason is not None
                    else "frontier_laya"
                ),
            )
            if step.retrieval is not None:
                if (
                    step.retrieval.status is not FrontierStatus.RUNNING
                    or step.retrieval.evidence is None
                ):
                    return self._save(
                        state.model_copy(
                            update={"provider_calls": (*state.provider_calls, call)[-128:]}
                        ),
                        "frontier_retrieval_gap",
                        "Selected stored evidence could not be retrieved.",
                    ), True
                selected_id = step.retrieval.evidence.evidence_id
                selected = tuple(dict.fromkeys((selected_id, *state.fast_catalog_selected_ids)))[:8]
                tentative = state.model_copy(
                    update={
                        "schema_version": 5,
                        "fast_catalog_generation": generation,
                        "fast_catalog_selected_ids": selected,
                    }
                )
                delivered = str(selected_id) in {
                    str(item.evidence_id)
                    for item in self.context(str(state.case_id), state=tentative)
                }
                current_generation = retriever.discover(
                    EvidenceCatalogQuery(case_id=state.case_id, limit=1)
                ).case_evidence_generation
                if not delivered or current_generation != generation:
                    raise ValueError("frontier retrieval was not delivered in a stable case packet")
                saved = self._save(
                    tentative.model_copy(
                        update={"provider_calls": (*state.provider_calls, call)[-128:]}
                    ),
                    "frontier_retrieved",
                    "Exact stored case evidence selected by mixed PDF frontier.",
                )
                frontier.transition(
                    step.selected.item_id,
                    FrontierStatus.RUNNING,
                    FrontierStatus.SATISFIED,
                    "focused_delivery_confirmed",
                )
                return saved, True
            if step.measurement is None or step.snapshot_id is None:
                return state, False
            chosen = step.measurement
            if self.knowledge is not None and versions.graph != self.knowledge.pack.version:
                raise ValueError("frontier graph version changed before dispatch")
            if (cancel_event is not None and cancel_event.is_set()) or utc_now() >= deadline:
                frontier.transition(
                    step.selected.item_id,
                    FrontierStatus.CLAIMED,
                    FrontierStatus.CANCELLED
                    if cancel_event is not None and cancel_event.is_set()
                    else FrontierStatus.OBSOLETE,
                    "candidate_cancelled_before_dispatch"
                    if cancel_event is not None and cancel_event.is_set()
                    else "candidate_deadline_before_dispatch",
                )
                return self._save(
                    state.model_copy(
                        update={"provider_calls": (*state.provider_calls, call)[-128:]}
                    ),
                    "frontier_candidate_deferred",
                    "Frontier candidate was not dispatched after cancellation or deadline.",
                ), True
        except (TargetSelectionError, ValueError) as error:
            # A ranked reference may already have been claimed even though a
            # later source/version check rejected dispatch. Close that claim;
            # it must not remain pending as if it could still be executed.
            if step is not None:
                current = frontier.readback(step.selected.item_id)
                if current.status in {FrontierStatus.CLAIMED, FrontierStatus.RUNNING}:
                    frontier.transition(
                        current.item_id,
                        current.status,
                        FrontierStatus.OBSOLETE,
                        "candidate_source_changed_before_dispatch",
                    )
            calls = state.provider_calls
            if rank_started_at is not None:
                calls = (
                    *calls,
                    ProviderCall(
                        role="fast_decision",
                        provider_id=ranker.provider.provider_id,
                        provider_version=ranker.provider.provider_version,
                        state_version=state.state_version,
                        started_at=rank_started_at,
                        elapsed_ms=max(0.0, (time.monotonic() - rank_started) * 1000),
                        degraded=True,
                        detail=type(error).__name__,
                    ),
                )[-128:]
            return self._save(
                state.model_copy(
                    update={
                        "provider_calls": calls,
                        "warnings": self._warnings(
                            state, f"Frontier candidate unavailable: {type(error).__name__}."
                        ),
                    }
                ),
                "frontier_candidate_fallback",
                "Frontier candidate selection was rejected before dispatch.",
            ), True

        proposal = ProbeProposal(
            probe_id=chosen.probe_id,
            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
            priority=1.0,
            estimated_cost_ms=chosen.cost_ms,
            resource_class=chosen.resource_class,
            safety_class=chosen.safety_class,
            dedupe_key=f"candidate:{chosen.candidate_id}",
        )
        try:
            result = self.runtime.execute_candidate_measurement(
                self._opened(state, (proposal,)),
                chosen.candidate_id,
                step.snapshot_id,
                cancel_event=cancel_event,
            )
            row = self.store.connection.execute(
                "SELECT admission_id FROM candidate_dispatch_admissions "
                "WHERE snapshot_id=? AND candidate_id=?",
                (step.snapshot_id, chosen.candidate_id),
            ).fetchone()
            if row is None:
                frontier.transition(
                    step.selected.item_id,
                    FrontierStatus.CLAIMED,
                    FrontierStatus.OBSOLETE,
                    "candidate_not_admitted",
                )
                if isinstance(result, ObservabilityGap):
                    state = self._with_measurement_gap(
                        state,
                        result,
                        warning="Frontier-selected process measurement was not admitted.",
                    )
                else:
                    return self._frontier_candidate_uncertain(
                        state,
                        step.selected.item_id,
                        chosen.probe_id,
                        call,
                        admission_recorded=False,
                    ), True
                return self._save(
                    state.model_copy(
                        update={"provider_calls": (*state.provider_calls, call)[-128:]}
                    ),
                    "frontier_candidate_gap",
                    "Candidate dispatch was not admitted.",
                ), True
            admission = CandidateDispatchAdmissionRepository(self.store).readback(str(row[0]))
            linked = admission.outcome_status == "linked"
            outcome = (
                self._frontier_execution_outcome(
                    admission.execution_id, state.case_id, chosen.candidate_id
                )
                if linked
                else FrontierStatus.INTERRUPTED
            )
            current = frontier.readback(step.selected.item_id)
            if linked and current.status is FrontierStatus.RUNNING:
                frontier.transition(
                    step.selected.item_id,
                    FrontierStatus.RUNNING,
                    outcome,
                    "candidate_execution_" + outcome.value,
                )
            elif not linked and current.status in {
                FrontierStatus.CLAIMED,
                FrontierStatus.ADMITTED,
                FrontierStatus.RUNNING,
            }:
                frontier.transition(
                    step.selected.item_id,
                    current.status,
                    FrontierStatus.INTERRUPTED,
                    "candidate_uncertain",
                )
            if linked:
                self._project(str(state.case_id))
            updated = state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys((*state.completed_probe_ids, chosen.probe_id))
                    ),
                    "interrupted_probe_ids": (
                        state.interrupted_probe_ids
                        if outcome is FrontierStatus.SATISFIED
                        else tuple(dict.fromkeys((*state.interrupted_probe_ids, chosen.probe_id)))
                    ),
                    "warnings": state.warnings
                    if outcome is FrontierStatus.SATISFIED
                    else self._warnings(
                        state,
                        "Frontier candidate did not produce a successful observation; "
                        "it was not replayed.",
                    ),
                    "provider_calls": (*state.provider_calls, call)[-128:],
                    "round_count": state.round_count + 1,
                }
            )
            return self._save(
                updated,
                "frontier_candidate_collected"
                if outcome is FrontierStatus.SATISFIED
                else "frontier_candidate_unsatisfied",
                "Frontier candidate probe result persisted."
                if outcome is FrontierStatus.SATISFIED
                else "Frontier candidate did not satisfy the measurement.",
            ), True
        except Exception:
            admission_recorded = (
                self.store.connection.execute(
                    "SELECT 1 FROM candidate_dispatch_admissions WHERE snapshot_id=? "
                    "AND candidate_id=?",
                    (step.snapshot_id, chosen.candidate_id),
                ).fetchone()
                is not None
            )
            return self._frontier_candidate_uncertain(
                state,
                step.selected.item_id,
                chosen.probe_id,
                call,
                admission_recorded=admission_recorded,
            ), True

    def _frontier_candidate_uncertain(
        self,
        state: InvestigationState,
        item_id: str,
        probe_id: str,
        call: ProviderCall,
        *,
        admission_recorded: bool,
    ) -> InvestigationState:
        frontier = SearchFrontierRepository(self.store)
        item = frontier.readback(item_id)
        if item.status in {FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, FrontierStatus.RUNNING}:
            frontier.transition(
                item_id,
                item.status,
                FrontierStatus.INTERRUPTED,
                "candidate_outcome_uncertain",
            )
        return self._save(
            state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys((*state.completed_probe_ids, probe_id))
                    ),
                    "interrupted_probe_ids": tuple(
                        dict.fromkeys((*state.interrupted_probe_ids, probe_id))
                    ),
                    "unrecorded_attempt_count": (
                        state.unrecorded_attempt_count + (0 if admission_recorded else 1)
                    ),
                    "provider_calls": (*state.provider_calls, call)[-128:],
                    "warnings": self._warnings(
                        state, "Frontier candidate outcome is uncertain; it was not replayed."
                    ),
                }
            ),
            "frontier_candidate_uncertain",
            "Candidate dispatch may have sampled the host; custody requires review.",
        )

    def _route_pdf_candidate(
        self, state: InvestigationState, cancel_event: threading.Event | None
    ) -> InvestigationState:
        """Let a replaceable fast brain choose one inventory-bound process instance.

        Candidate IDs are model-visible lookup keys. The runtime alone resolves,
        reserves, revalidates, and executes the exact registered measurement.
        """

        if (
            not isinstance(self.decision, CandidateDecisionProvider)
            or "application.snapshot" not in state.completed_probe_ids
            or ProcessTargetRepository(self.store).selected_process_target(state.case_id)
            is not None
            or "application.target_pressure" in self._effective_completed_probe_ids(state)
            or self._attempts_consumed(state) >= state.max_probes
            or self._remaining_ms(state) < _TARGET_PRESSURE_COST_MS
            or (cancel_event is not None and cancel_event.is_set())
        ):
            return state
        try:
            registry, needs = self.runtime.candidate_catalog(state.case_id)
            records = tuple(
                record
                for need in needs
                if not isinstance(
                    (record := registry.issue(state.case_id, state.state_version, need)),
                    CandidateGap,
                )
            )
        except (TargetSelectionError, ValueError):
            return state
        if not records:
            return state
        context = self.context(str(state.case_id))
        graph = self._relationships(context)
        context = graph.context
        remaining_ms = self._remaining_ms(state)
        if remaining_ms < _TARGET_PRESSURE_COST_MS:
            # Evidence projection itself can consume the final case seconds.
            # Leave completion to the ordinary budget terminal path.
            return state
        request = CandidateDecisionRequestV1(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id=f"candidate:{state.case_id}:{state.state_version}",
            deadline_at=self._decision_deadline(state),
            symptom=state.objective,
            evidence_ids=tuple(item.evidence_id for item in context),
            evidence_context=context,
            attention_context=attention_pages(self.store, context),
            relationships=graph.relationships,
            reference_context=self.reference_context(state),
            hypothesis_briefs=tuple(item.statement for item in state.hypotheses),
            available_candidates=tuple(
                AdmittedCandidateRefV1.model_validate(
                    item.model_dump(mode="json", exclude={"schema_version"})
                )
                for item in records
            ),
            budget_ms=remaining_ms,
            max_candidates=1,
        )
        started_at = utc_now()
        started = time.monotonic()
        provider = self.decision
        try:
            response = call_candidate_provider(provider, request, cancel_event).validate_against(
                request
            )
            if response.provider != provider.identity:
                raise ValueError("candidate provider identity mismatch")
            if (
                isinstance(response, CandidateDecisionResponseV1)
                and utc_now() >= request.deadline_at
            ):
                raise ValueError("candidate response missed its deadline")
            snapshot = self.candidate_snapshots.capture(
                request, response, request_frozen_at=started_at
            )
        except Exception as error:
            degraded = ProviderCall(
                role="fast_decision",
                provider_id=provider.identity.provider_id,
                provider_version=provider.identity.provider_version,
                state_version=state.state_version,
                started_at=started_at,
                elapsed_ms=max(0.0, (time.monotonic() - started) * 1000),
                degraded=True,
                detail=type(error).__name__,
            )
            return self._save(
                state.model_copy(
                    update={
                        "provider_calls": (*state.provider_calls, degraded)[-128:],
                        "warnings": self._warnings(
                            state,
                            "Candidate decision unavailable; selected-process fallback remains.",
                        ),
                    }
                ),
                "candidate_fallback",
                "Candidate decision was rejected without executing a target probe.",
            )
        call = ProviderCall(
            role="fast_decision",
            provider_id=provider.identity.provider_id,
            provider_version=provider.identity.provider_version,
            state_version=state.state_version,
            started_at=started_at,
            elapsed_ms=max(0.0, (time.monotonic() - started) * 1000),
            degraded=isinstance(response, CandidateDecisionGapV1),
            detail=(response.reason_code if isinstance(response, CandidateDecisionGapV1) else None),
        )
        if isinstance(response, CandidateDecisionGapV1) or not response.proposals:
            return self._save(
                state.model_copy(
                    update={
                        "provider_calls": (*state.provider_calls, call)[-128:],
                        "warnings": self._warnings(
                            state,
                            "Candidate decision provided no target; "
                            "selected-process fallback remains.",
                        ),
                    }
                ),
                "candidate_fallback",
                "No model-selected candidate was dispatched.",
            )
        candidate_id = response.proposals[0].candidate_id
        chosen = next(item for item in records if item.candidate_id == candidate_id)
        proposal = ProbeProposal(
            probe_id=chosen.probe_id,
            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
            priority=1.0,
            estimated_cost_ms=chosen.cost_ms,
            resource_class=chosen.resource_class,
            safety_class=chosen.safety_class,
            dedupe_key=f"candidate:{candidate_id}",
        )
        result = self.runtime.execute_candidate_measurement(
            self._opened(state, (proposal,)),
            candidate_id,
            snapshot.snapshot_id,
            cancel_event=cancel_event,
        )
        row = self.store.connection.execute(
            "SELECT admission_id FROM candidate_dispatch_admissions "
            "WHERE snapshot_id=? AND candidate_id=?",
            (snapshot.snapshot_id, candidate_id),
        ).fetchone()
        if row is None:
            if isinstance(result, ObservabilityGap):
                state = self._with_measurement_gap(
                    state,
                    result,
                    warning="Autonomous process measurement was not admitted; "
                    "manual selection remains.",
                )
            else:
                state = state.model_copy(
                    update={
                        "completed_probe_ids": tuple(
                            dict.fromkeys((*state.completed_probe_ids, chosen.probe_id))
                        ),
                        "interrupted_probe_ids": tuple(
                            dict.fromkeys((*state.interrupted_probe_ids, chosen.probe_id))
                        ),
                        "unrecorded_attempt_count": state.unrecorded_attempt_count + 1,
                        "warnings": self._warnings(
                            state,
                            "Candidate execution custody is missing; the target was not replayed.",
                        ),
                    }
                )
            return self._save(
                state.model_copy(update={"provider_calls": (*state.provider_calls, call)[-128:]}),
                "candidate_gap",
                "Candidate dispatch was not durably admitted.",
            )
        try:
            admission = CandidateDispatchAdmissionRepository(self.store).readback(str(row[0]))
            linked = admission.outcome_status == "linked"
        except ValueError:
            linked = False
        if linked:
            self._project(str(state.case_id))
        updated = state.model_copy(
            update={
                "completed_probe_ids": tuple(
                    dict.fromkeys((*state.completed_probe_ids, chosen.probe_id))
                ),
                "interrupted_probe_ids": (
                    state.interrupted_probe_ids
                    if linked
                    else tuple(dict.fromkeys((*state.interrupted_probe_ids, chosen.probe_id)))
                ),
                "provider_calls": (*state.provider_calls, call)[-128:],
                "warnings": state.warnings
                if linked
                else self._warnings(
                    state, "Candidate dispatch is unlinked or unverifiable; it was not replayed."
                ),
                "round_count": state.round_count + 1,
            }
        )
        return self._save(
            updated,
            "candidate_collected" if linked else "candidate_uncertain",
            "Candidate probe result persisted." if linked else "Candidate attempt is uncertain.",
        )

    def _followup_outcome(
        self, state: InvestigationState
    ) -> tuple[int, tuple[str, ...], tuple[str, ...], str | None]:
        rows = self.store.connection.execute(
            "SELECT admission_id,invocation_json,invocation_sha256,estimated_cost_ms "
            "FROM collection_followup_admissions WHERE case_id=? AND epoch_state_version=?",
            (str(state.case_id), state.state_version),
        ).fetchall()
        if not rows:
            return 0, (), (), None
        try:
            outcomes = FollowupAdmissionRepository(self.store).readback(
                case_id=str(state.case_id), epoch_state_version=state.state_version
            )
            probes = {
                str(row[0]): ProbeInvocation.model_validate_json(str(row[1])).probe_id
                for row in rows
            }
        except (ValueError, TypeError):
            # Do not trust a raw cost or an execution claim from failed custody
            # verification. Conservatively consume the remaining case budget.
            return (
                max(0, state.budget_ms - state.spent_cost_ms),
                (),
                self._probe_ids_from_admission_rows(rows),
                "Follow-up provenance unavailable; case budget closed without replay.",
            )
        cost = sum(item.estimated_cost_ms for item in outcomes)
        completed = tuple(
            probes[item.admission_id] for item in outcomes if item.execution_id is not None
        )
        interrupted = tuple(
            probes[item.admission_id] for item in outcomes if item.execution_id is None
        )
        return (
            cost,
            completed,
            interrupted,
            "Admitted follow-up has no durable execution; it was not replayed."
            if interrupted
            else None,
        )

    def _handle_pdf_target(
        self,
        state: InvestigationState,
        cancel_event: threading.Event | None,
    ) -> tuple[InvestigationState, bool] | None:
        target_probe = "application.target_pressure"
        if (
            "application.snapshot" not in state.completed_probe_ids
            or target_probe in self._completed_for_models(state)
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
            if not inventory.candidates or self._attempts_consumed(state) >= state.max_probes:
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
        need = MeasurementNeed(
            capability_id=target_probe,
            observable=target_probe,
            target_handle=binding.candidate_id,
        )
        if self._has_measurement_gap(state, need):
            return None
        try:
            targets.resolve_process_target_for_sampling(state.case_id)
        except TargetSelectionError:
            reason = "selected process binding is stale and cannot be renewed in this case"
            state = self._with_measurement_gap(
                state,
                ObservabilityGap(need=need, reason=reason),
                warning=(
                    "Selected process binding is stale. Start a new case and select the process "
                    "from a fresh application snapshot; no target sample was executed."
                ),
            )
            return (
                self._save(
                    state,
                    "measurement_gap",
                    "Selected process binding cannot authorize sampling; a new case is required.",
                ),
                False,
            )
        # A selected target is offered to the fast brain in the next round.
        # Collection happens only after a typed proposal passes admission.
        return None

    @staticmethod
    def _has_measurement_gap(state: InvestigationState, need: MeasurementNeed) -> bool:
        return any(item.need == need for item in state.measurement_gaps)

    def _with_measurement_gap(
        self, state: InvestigationState, gap: ObservabilityGap, *, warning: str
    ) -> InvestigationState:
        if self._has_measurement_gap(state, gap.need):
            return state
        return state.model_copy(
            update={
                "measurement_gaps": (
                    *state.measurement_gaps,
                    MeasurementGap(need=gap.need, reason=gap.reason, recorded_at=utc_now()),
                )[-32:],
                "warnings": self._warnings(state, warning),
            }
        )

    def _case_capabilities(self, state: InvestigationState) -> tuple[ProbeCapability, ...]:
        """Expose one selected-process handle, never a raw process selector."""

        general = tuple(
            capability
            for capability in self.capabilities
            if capability.probe_id != "application.target_pressure"
        )
        if (
            not _is_pdf_performance_objective(state.objective)
            or "application.snapshot" not in state.completed_probe_ids
            or "application.target_pressure" in self._completed_for_models(state)
            or self._attempts_consumed(state) >= state.max_probes
            or self._remaining_ms(state) < _TARGET_PRESSURE_COST_MS
        ):
            return general
        manifest = self.runtime.probe_manifest("application.target_pressure")
        if (
            manifest is None
            or manifest.input_model != TargetPressureParametersV1.__name__
            or manifest.safety.safety_class not in {SafetyClass.R0, SafetyClass.R1}
            or manifest.safety.privilege is not Privilege.STANDARD
            or manifest.safety.target_state_effect != "none"
            or manifest.safety.outbound_network
        ):
            return general
        try:
            binding = ProcessTargetRepository(self.store).resolve_process_target_for_sampling(
                state.case_id
            )
        except TargetSelectionError:
            return general
        need = MeasurementNeed(
            capability_id="application.target_pressure",
            observable="application.target_pressure",
            target_handle=binding.candidate_id,
        )
        if self._has_measurement_gap(state, need):
            return general
        return (
            *general,
            ProbeCapability(
                probe_id="application.target_pressure",
                description="Sample bounded CPU and memory pressure for the selected PDF process.",
                keywords=frozenset({"pdf", "slow", "performance", "process"}),
                target_traits=frozenset({"selected_process"}),
                observable_ids=("application.target_pressure",),
                target_handles=(binding.candidate_id,),
                common=True,
                baseline_priority=1.0,
                cost_ms=_TARGET_PRESSURE_COST_MS,
                resource_class=ResourceClass.PROCESS,
                safety_class=manifest.safety.safety_class,
            ),
        )

    def _bound_target_proposal(self, state: InvestigationState) -> ProbeProposal | None:
        capability = next(
            (
                item
                for item in self._case_capabilities(state)
                if item.probe_id == "application.target_pressure"
            ),
            None,
        )
        if capability is None:
            return None
        return ProbeProposal(
            schema_version=2,
            probe_id=capability.probe_id,
            purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
            priority=1.0,
            estimated_cost_ms=capability.cost_ms,
            resource_class=capability.resource_class,
            safety_class=capability.safety_class,
            dedupe_key=f"bound-target:{state.case_id}",
            measurement_need=MeasurementNeed(
                capability_id=capability.probe_id,
                observable=capability.observable_ids[0],
                target_handle=capability.target_handles[0],
            ),
        )

    @staticmethod
    def _deep_hypothesis_revision(hypotheses: tuple[Hypothesis, ...]) -> int:
        payload = json.dumps([h.model_dump(mode="json") for h in hypotheses], sort_keys=True)
        return int(hashlib.sha256(payload.encode()).hexdigest()[:15], 16)

    def _has_deep_work(self) -> bool:
        return self._deep_task is not None and self._deep_lane.occupied

    def _queue_deep_review(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
        question_id: str,
    ) -> tuple[InvestigationState, str | None]:
        """Nonblocking frontier consultation; return identity only for a new admission."""
        if self.frontier_ranker is None:
            return state, None
        before = self._last_deep_admission
        state, _ = self._reason(state, context, deep_question_id=question_id)
        task = self._last_deep_admission
        if task is None or task is before:
            return state, None
        state = self._save(
            state, "deep_question", f"Question {question_id[:80]}: {task.request_sha256}"
        )
        return state, task.request_sha256

    def _close_deep_frontier(self, task: FrozenDeepTaskV1) -> None:
        """Close only a real question-bound advisory with terminal mailbox custody."""

        if task.question_id is None:
            return
        row = self.store.connection.execute(
            "SELECT status FROM deep_mailbox WHERE case_id=? AND request_sha256=?",
            (str(task.request.case_id), task.request_sha256),
        ).fetchone()
        if row is None or row[0] == "running":
            return
        destination = {
            "applied": FrontierStatus.SATISFIED,
            "rejected": FrontierStatus.FAILED,
            "failed": FrontierStatus.FAILED,
            "cancelled": FrontierStatus.CANCELLED,
            "interrupted": FrontierStatus.INTERRUPTED,
        }.get(str(row[0]))
        if destination is None:
            raise ValueError("deep mailbox has an invalid terminal status")
        frontier = SearchFrontierRepository(self.store)
        rows = self.store.connection.execute(
            "SELECT item_id FROM search_frontier_items WHERE case_id=? "
            "AND json_extract(identity_json, '$.reference.question_id')=? "
            "ORDER BY created_at,item_id LIMIT 128",
            (str(task.request.case_id), task.question_id),
        ).fetchall()
        for (item_id,) in rows:
            item = frontier.readback(str(item_id))
            if item.status is FrontierStatus.RUNNING:
                frontier.transition(
                    item.item_id,
                    FrontierStatus.RUNNING,
                    destination,
                    "deep_mailbox_" + str(row[0]),
                )

    def _deep_dependency_error(
        self, state: InvestigationState, task: FrozenDeepTaskV1
    ) -> str | None:
        if state.objective != task.request.objective:
            return "objective changed"
        current = {h.hypothesis_id: h for h in state.hypotheses}
        basis = task.request.previous_hypotheses
        if any(current.get(h.hypothesis_id) != h for h in basis):
            return "relevant hypothesis changed"
        if not revalidate_presented_read_set(self.store, task.presented_read_set).consistent:
            return "presented evidence changed"
        if any(
            not revalidate_presented_read_set(self.store, source).consistent
            for source in task.historical_read_sets
        ):
            return "historical source evidence changed"
        relations = EvidenceRelationRepository(self.store)
        for relation in task.request.relationships:
            if relations.read_latest(relation.relation_id) != relation:
                return "presented relationship changed"
        return None

    def _capture_deep_history(self, request: ReasoningRequest) -> tuple[PresentedReadSetV1, ...]:
        grouped: dict[CaseId, list[EvidenceId]] = {}
        for item in request.evidence_context:
            if item.case_scope != "historical":
                continue
            row = self.store.connection.execute(
                "SELECT case_id FROM evidence WHERE evidence_id=?", (str(item.evidence_id),)
            ).fetchone()
            if row is None:
                raise ValueError("historical deep source missing")
            grouped.setdefault(CaseId(root=str(row[0])), []).append(item.evidence_id)
        return tuple(
            capture_presented_read_set(self.store, case_id, tuple(ids))
            for case_id, ids in grouped.items()
        )

    def _drain_deep(self, state: InvestigationState) -> InvestigationState:
        """Merge one completed advisory on the coordinator; never wait for inference."""
        task = getattr(self, "_deep_task", None)
        if task is None:
            return state
        if task.request.case_id != state.case_id:
            # Another case may run only after the prior owner stopped. Its
            # cancelled worker still occupies capacity until actual exit.
            if self._deep_lane.poll() is not None:
                self._deep_task = None
            return state
        cancel = current_cancellation()
        terminal = state.status in {
            InvestigationStatus.COMPLETE,
            InvestigationStatus.CANCELLED,
            InvestigationStatus.FAILED,
            InvestigationStatus.INTERRUPTED,
        }
        try:
            dependency_error = self._deep_dependency_error(state, task)
        except Exception as error:
            dependency_error = f"dependency validation unavailable: {type(error).__name__}"
        reason = (
            "case terminal"
            if terminal
            else "cancelled"
            if cancel is not None and cancel.is_set()
            else "deadline expired"
            if utc_now() >= task.request.deadline_at
            else dependency_error
        )
        if reason:
            self._deep_lane.cancel()
            recorded = self._deep_mailbox.finish(
                task, "rejected" if dependency_error else "cancelled", reason=reason
            )
            self._close_deep_frontier(task)
            if recorded and dependency_error:
                state = self._save(
                    state.model_copy(
                        update={
                            "warnings": self._warnings(
                                state, f"Deep advisory rejected: {dependency_error}."
                            )
                        }
                    ),
                    "deep_rejected",
                    reason,
                )
        result = self._deep_lane.poll()
        if result is None:
            return state
        self._deep_task = None
        active = self.store.connection.execute(
            "SELECT status FROM deep_mailbox WHERE case_id=? AND request_sha256=?",
            (str(state.case_id), task.request_sha256),
        ).fetchone()
        if active is None or active[0] != "running":
            self._close_deep_frontier(task)
            return state
        check = revalidate_presented_read_set(self.store, task.presented_read_set)
        applicability = assess_deep_result(
            task,
            result,
            check,
            current_hypothesis_revision=task.hypothesis_revision,
            case_terminal=terminal,
            cancelled=cancel is not None and cancel.is_set(),
            now=utc_now(),
        )
        response = result.response
        rejected = (
            reason is not None
            or applicability.applicability == "reject"
            or response is None
            or response.degraded
        )
        calls = (
            *state.provider_calls,
            ProviderCall(
                role="reasoning",
                provider_id=task.provider_identity.provider_id,
                provider_version=task.provider_identity.provider_version,
                state_version=task.request.state_version,
                started_at=result.started_at,
                elapsed_ms=result.elapsed_ms,
                degraded=rejected,
                detail=f"basis generation={task.presented_read_set.case_generation}; "
                f"request={task.request_sha256}",
            ),
        )[-128:]
        if rejected:
            updated = state.model_copy(
                update={
                    "provider_calls": calls,
                    "warnings": self._warnings(
                        state,
                        "Deep advice was unavailable or rejected "
                        "against its immutable source basis.",
                    ),
                }
            )
        else:
            assert response is not None
            # The immutable source basis survived. A newer catalog does not
            # invalidate unrelated strategic advice. All model hypotheses remain
            # advisory/unresolved until independent deterministic assessment.
            hypotheses = {h.hypothesis_id: h for h in state.hypotheses}
            for hypothesis in response.hypotheses:
                hypotheses[hypothesis.hypothesis_id] = hypothesis.model_copy(
                    update={
                        "statement": self.redactor.redact_text(hypothesis.statement).text,
                        "status": HypothesisStatus.CONTESTED
                        if hypothesis.contradicting_evidence_ids
                        else HypothesisStatus.UNRESOLVED,
                        "expected_facts_observed_after": result.finished_at
                        if hypothesis.expected_facts
                        else None,
                    }
                )
            proposals = self._eligible(
                response.distinguishing_probes, state, self._remaining_ms(state)
            )
            pending = {p.probe_id: p for p in state.pending_distinguishing_probes}
            pending.update({p.probe_id: p for p in proposals})
            contexts = {str(c.evidence_id): c for c in state.assessed_context}
            contexts.update({str(c.evidence_id): c for c in task.request.evidence_context})
            catalog_basis_valid = (
                task.catalog_generation is not None
                and task.catalog_limit == state.evidence_catalog_limit
                and task.catalog_current_cursor == state.evidence_catalog_cursor
                and EvidenceRetriever(self.store)
                .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
                .case_evidence_generation
                == task.catalog_generation
            )
            bookkeeping = self._reasoning_bookkeeping(
                state,
                response,
                task.request.evidence_context,
                matched_detail_keys=task.matched_detail_request_keys,
                catalog_current_cursor=task.catalog_current_cursor,
                catalog_next_cursor=task.catalog_next_cursor,
                catalog_generation=task.catalog_generation,
                catalog_limit=task.catalog_limit,
                catalog_basis_valid=catalog_basis_valid,
                accepted=True,
            )
            updated = state.model_copy(
                update={
                    "hypotheses": tuple(hypotheses.values())[-16:],
                    "assessed_context": tuple(contexts.values())[-64:],
                    "summary": "Advisory explanation: "
                    + self.redactor.redact_text(response.summary).text[:1900],
                    "pending_distinguishing_probes": tuple(pending.values())[:32],
                    "requested_evidence_ids": bookkeeping.requested_evidence_ids,
                    "completed_evidence_requests": bookkeeping.completed_evidence_requests,
                    "requested_details": bookkeeping.requested_details,
                    "completed_detail_requests": bookkeeping.completed_detail_requests,
                    "evidence_catalog_cursor": bookkeeping.catalog_cursor,
                    "evidence_catalog_generation": bookkeeping.catalog_generation,
                    "evidence_catalog_limit": bookkeeping.catalog_limit,
                    "evidence_catalog_followup_pending": bookkeeping.catalog_followup_pending,
                    "provider_calls": calls,
                    "warnings": self._warnings(
                        state,
                        "Deep advice retains its historical source basis; "
                        "hypotheses and predictions are advisory, not verified facts."
                        + (
                            " A one-entry catalog page did not fit the local reasoning context."
                            if bookkeeping.catalog_fit_blocked
                            else ""
                        ),
                    ),
                }
            )
        completion = DeepMailboxCompletionV1(
            task=task,
            result=result,
            status="rejected" if rejected else "applied",
            reason=reason
            or ("invalid or degraded response" if rejected else "source basis revalidated"),
        )
        saved = self.repository.save(
            updated,
            expected_version=state.state_version,
            event="deep_rejected" if rejected else "deep_applied",
            detail=f"Deep mailbox {completion.status}: {task.request_sha256}",
            deep_completion=completion,
        )
        self._close_deep_frontier(task)
        return saved

    def _await_deep_when_idle(self, state: InvestigationState) -> InvestigationState:
        """Wait only when fast routing has no eligible work; wake on evidence changes."""
        generation = capture_presented_read_set(self.store, state.case_id, ()).case_generation
        while (
            self._deep_task is not None
            and self._deep_lane.occupied
            and self._remaining_ms(state) > 0
        ):
            state = self._drain_deep(state)
            cancel = current_cancellation()
            if not self._has_deep_work() or (cancel is not None and cancel.is_set()):
                break
            if (
                capture_presented_read_set(self.store, state.case_id, ()).case_generation
                != generation
            ):
                break
            self._deep_lane.wait(0.01)
        return self._drain_deep(state)

    def _reason_with_details(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
        *,
        fast_signals: tuple[FastSignal, ...] = (),
    ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
        if getattr(self, "frontier_ranker", None) is not None:
            return self._reason(state, context, fast_signals=fast_signals)
        state, proposals = self._reason(state, context, fast_signals=fast_signals)
        attempted_packets: set[str] = set()
        # Catalog pagination may need several short pages after context fitting.
        # The case deadline and this cap bound the extra deep-brain calls.
        for _ in range(6):
            if (
                state.provider_calls
                and state.provider_calls[-1].role == "reasoning"
                and (state.provider_calls[-1].degraded)
            ):
                # A provider failure cannot make an unchanged page informative.
                # Retain its cursor for a later explicit retry, but do not spend
                # the remaining case budget on immediate identical calls.
                break
            if self._remaining_ms(state) <= 0:
                break
            refreshed = self.context(str(state.case_id), state=state)
            refreshed_ids = {str(item.evidence_id) for item in refreshed}
            refreshed_context = (
                *refreshed,
                *(item for item in context if str(item.evidence_id) not in refreshed_ids),
            )
            packet = self._new_requested_fact_packet(state, refreshed_context)
            if (packet is None or packet in attempted_packets) and not (
                state.evidence_catalog_followup_pending
            ):
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
            if packet is not None:
                attempted_packets.add(packet)
            state, proposals = self._reason(state, refreshed_context)
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
        if state.evidence_catalog_followup_pending:
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state,
                        "The case budget or bounded follow-up stopped before catalog discovery "
                        "was complete; unreviewed entries remain local.",
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
        *,
        fast_signals: tuple[FastSignal, ...] = (),
        concurrent_proposals: tuple[ProbeProposal, ...] = (),
        decision_snapshot_id: str | None = None,
        deep_question_id: str | None = None,
    ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
        state = self._drain_deep(state)
        if self._deep_lane.occupied:
            if concurrent_proposals:
                state = self._collect(
                    state,
                    concurrent_proposals,
                    current_cancellation(),
                    decision_snapshot_id=decision_snapshot_id,
                    adaptive_followups=True,
                )
                state = self._drain_deep(state)
            return state, state.pending_distinguishing_probes
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
                    *(eid for signal in fast_signals for eid in signal.evidence_ids),
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
        focused_ids = {str(item.evidence_id) for item in context}
        fast_concerns = tuple(
            FastAttentionConcern(
                kind=signal.kind,
                evidence_ids=signal.evidence_ids,
                hypothesis_brief=(
                    state.hypotheses[signal.hypothesis_index].statement[:400]
                    if signal.hypothesis_index is not None
                    and signal.hypothesis_index < len(state.hypotheses)
                    else None
                ),
            )
            for signal in fast_signals
            if {str(item) for item in signal.evidence_ids}.issubset(focused_ids)
            and (signal.hypothesis_index is None or signal.hypothesis_index < len(state.hypotheses))
        )
        if len(fast_concerns) != len(fast_signals):
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state, "Fast attention concern lost its focused evidence and was omitted."
                    )
                }
            )
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
        retriever = EvidenceRetriever(self.store)
        catalog_query = EvidenceCatalogQuery(
            case_id=state.case_id,
            observed_from=state.incident_start,
            observed_until=state.incident_end,
            current_collection_start=state.created_at,
            cursor=state.evidence_catalog_cursor,
            limit=state.evidence_catalog_limit,
        )
        catalog_page = retriever.discover(catalog_query)
        if state.evidence_catalog_cursor is not None and (
            state.evidence_catalog_generation != catalog_page.case_evidence_generation
        ):
            # New evidence may sort before the saved keyset cursor. Revisit the
            # head instead of silently skipping it on the next discovery page.
            state = state.model_copy(update={"evidence_catalog_cursor": None})
            catalog_query = catalog_query.model_copy(update={"cursor": None})
            catalog_page = retriever.discover(catalog_query)
        catalog_ids = tuple(item.evidence_id for item in catalog_page.entries)
        case_capabilities = self._case_capabilities(state)
        request = ReasoningRequest(
            schema_version=4,
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
            fast_concerns=fast_concerns,
            evidence_ids=tuple(
                dict.fromkeys((*catalog_ids, *(item.evidence_id for item in all_context)))
            ),
            evidence_context=context,
            relationships=focused_graph.relationships,
            previous_hypotheses=previous,
            available_probes=case_capabilities,
            completed_probe_ids=self._completed_for_models(state).intersection(
                item.probe_id for item in case_capabilities
            ),
            satisfied_probe_ids=self._satisfied_probe_ids(state).intersection(
                item.probe_id for item in case_capabilities
            ),
            pending_probe_ids=tuple(
                proposal.probe_id for proposal in state.pending_distinguishing_probes
            ),
            completed_detail_requests=state.completed_detail_requests,
            reference_context=self.reference_context(state),
            error_references=self.error_references(state),
            evidence_catalog=tuple(
                {
                    "evidence_id": str(item.evidence_id),
                    "collector_id": item.collector_id,
                    "source_id": item.source_id,
                    "observed_at": item.observed_at.isoformat(),
                    "captured_at": item.captured_at.isoformat(),
                    "summary": item.summary[:200],
                }
                for item in catalog_page.entries
            ),
            catalog_has_more=catalog_page.next_cursor is not None,
            priority_evidence_ids=priority_evidence_ids,
            completed_evidence_requests=completed_evidence_requests,
            budget_ms=max(1, self._remaining_ms(state)),
            max_probes=max(1, min(4, state.max_probes - self._attempts_consumed(state))),
            diagnostic_progress=self._diagnostic_progress_context(state),
        )
        call_started_at = utc_now()
        call_started = time.monotonic()
        rejected = False
        if self.frontier_ranker is not None or concurrent_proposals:
            read_set = capture_presented_read_set(
                self.store,
                state.case_id,
                tuple(
                    item.evidence_id
                    for item in request.evidence_context
                    if item.case_scope == "current_case"
                ),
            )
            task: FrozenDeepTaskV1 | None = None
            admitted = False
            try:
                task = freeze_deep_task(
                    request,
                    read_set,
                    provider_identity=self.reasoning.identity,
                    hypothesis_revision=self._deep_hypothesis_revision(request.previous_hypotheses),
                    historical_read_sets=self._capture_deep_history(request),
                    question_id=deep_question_id,
                    matched_detail_request_keys=details.matched_request_keys,
                    catalog_current_cursor=state.evidence_catalog_cursor,
                    catalog_next_cursor=catalog_page.next_cursor,
                    catalog_generation=catalog_page.case_evidence_generation,
                    catalog_limit=state.evidence_catalog_limit,
                )
                admitted = not self._deep_lane.occupied and self._deep_mailbox.admit(task)
            except ValueError as error:
                state = state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state,
                            f"Deep request could not be admitted: {type(error).__name__}.",
                        )
                    }
                )
            if admitted and task is not None:
                self._deep_task = task
                try:
                    if not self._deep_lane.start(self.reasoning, task):
                        raise RuntimeError("deep worker capacity occupied")
                except Exception as error:
                    self._deep_mailbox.finish(task, "failed", reason=type(error).__name__)
                    self._deep_task = None
                    state = state.model_copy(
                        update={
                            "warnings": self._warnings(
                                state,
                                f"Deep worker unavailable: {type(error).__name__}.",
                            )
                        }
                    )
                else:
                    self._last_deep_admission = task
                    state = self._save(
                        state,
                        "deep_submitted",
                        f"Frozen deep task submitted: {task.request_sha256}",
                    )
            if concurrent_proposals:
                state = self._collect(
                    state,
                    concurrent_proposals,
                    current_cancellation(),
                    decision_snapshot_id=decision_snapshot_id,
                    adaptive_followups=True,
                )
            state = self._drain_deep(state)
            return state, state.pending_distinguishing_probes
        try:
            # Keep provider-owned nested dictionaries detached from validation input.
            provider_request = request.model_copy(deep=True)
            if self._deep_lane.occupied:
                raise ValueError("earlier reasoning worker still occupies provider capacity")
            response = self.reasoning.investigate(provider_request).validate_against(request)
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
        predictions_issued_at = utc_now()
        hypotheses = tuple(
            h.model_copy(
                update={
                    "statement": self.redactor.redact_text(h.statement).text,
                    "expected_facts_observed_after": (
                        predictions_issued_at if h.expected_facts else None
                    ),
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
        accepted = not response.degraded and not rejected
        catalog_basis_valid = (
            EvidenceRetriever(self.store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
            == catalog_page.case_evidence_generation
        )
        bookkeeping = self._reasoning_bookkeeping(
            state,
            response,
            context,
            matched_detail_keys=details.matched_request_keys,
            catalog_current_cursor=catalog_query.cursor,
            catalog_next_cursor=catalog_page.next_cursor,
            catalog_generation=catalog_page.case_evidence_generation,
            catalog_limit=state.evidence_catalog_limit,
            catalog_basis_valid=catalog_basis_valid,
            accepted=accepted,
        )
        provider_status = getattr(self.reasoning, "status", None)
        if bookkeeping.catalog_fit_blocked:
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state,
                        "A one-entry catalog page did not fit the local reasoning "
                        "context; discovery cannot advance safely.",
                    )
                }
            )
        pending_proposals = {item.probe_id: item for item in state.pending_distinguishing_probes}
        if not response.degraded and not rejected:
            for probe_id in response.cancelled_probe_ids:
                pending_proposals.pop(probe_id, None)
            for proposal in response.distinguishing_probes:
                pending_proposals[proposal.probe_id] = proposal
        next_proposals = tuple(pending_proposals.values())[:32]
        with self.store.transaction() as transaction:
            transaction.append_coordinator_event(
                case_id=str(state.case_id),
                kind="provider",
                fields={
                    "role": "reasoning",
                    "attempted_provider_id": self.reasoning.identity.provider_id,
                    "effective_provider_id": response.provider.provider_id,
                    "failed": rejected or response.degraded,
                },
            )
        state = state.model_copy(
            update={
                "schema_version": 5,
                "evidence_catalog_cursor": bookkeeping.catalog_cursor,
                "evidence_catalog_generation": bookkeeping.catalog_generation,
                "evidence_catalog_limit": bookkeeping.catalog_limit,
                "evidence_catalog_followup_pending": bookkeeping.catalog_followup_pending,
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
                "requested_evidence_ids": bookkeeping.requested_evidence_ids,
                "completed_evidence_requests": bookkeeping.completed_evidence_requests,
                "requested_details": bookkeeping.requested_details,
                "completed_detail_requests": bookkeeping.completed_detail_requests,
                "pending_distinguishing_probes": next_proposals,
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
        return state, next_proposals

    def _reasoning_bookkeeping(
        self,
        state: InvestigationState,
        response: ReasoningResponse,
        presented_context: tuple[EvidenceContext, ...],
        *,
        matched_detail_keys: tuple[str, ...],
        catalog_current_cursor: EvidenceCatalogCursor | None,
        catalog_next_cursor: EvidenceCatalogCursor | None,
        catalog_generation: int | None,
        catalog_limit: int | None,
        catalog_basis_valid: bool,
        accepted: bool,
    ) -> _ReasoningBookkeeping:
        """Apply only acknowledged, source-bound requests and page movement."""

        considered: set[str] = (
            {str(item) for item in response.considered_evidence_ids} if accepted else set()
        )
        presented_facts = {str(item.evidence_id) for item in presented_context if item.facts}
        delivered_evidence = tuple(
            item
            for item in state.requested_evidence_ids
            if str(item) in considered and str(item) in presented_facts
        )
        completed_evidence = tuple(
            {
                str(item): item
                for item in (*state.completed_evidence_requests, *delivered_evidence)
            }.values()
        )[-128:]
        completed_ids = {str(item) for item in completed_evidence}
        requested_evidence = tuple(
            {
                str(item): item
                for item in (
                    *(
                        item
                        for item in state.requested_evidence_ids
                        if item not in delivered_evidence
                    ),
                    *(response.requested_evidence_ids if accepted else ()),
                )
                if str(item) not in completed_ids
            }.values()
        )[:8]

        matched = set(matched_detail_keys)
        delivered_details = tuple(
            item
            for item in state.requested_details
            if item.key() in matched
            and str(item.evidence_id) in considered
            and self._detail_visible(item, presented_context)
        )
        completed_details = tuple(
            {
                item.key(): item for item in (*state.completed_detail_requests, *delivered_details)
            }.values()
        )[-32:]
        completed_keys = {item.key() for item in completed_details}
        requested_details = tuple(
            {
                item.key(): item
                for item in (
                    *state.requested_details,
                    *(response.requested_details if accepted else ()),
                )
                if item.key() not in completed_keys
            }.values()
        )[:4]

        cursor = state.evidence_catalog_cursor
        generation = state.evidence_catalog_generation
        limit = state.evidence_catalog_limit
        pending = state.evidence_catalog_followup_pending
        fit_blocked = False
        if accepted and catalog_basis_valid and catalog_generation is not None:
            if state.evidence_catalog_cursor != catalog_current_cursor:
                raise ValueError("catalog cursor changed before reasoning bookkeeping")
            generation = catalog_generation
            pending = False
            if response.catalog_page_truncated:
                if catalog_limit is not None and catalog_limit > 1:
                    limit = max(1, catalog_limit // 2)
                    pending = True
                else:
                    fit_blocked = True
            elif response.request_next_catalog_page:
                cursor = catalog_next_cursor
                pending = cursor is not None
        return _ReasoningBookkeeping(
            requested_evidence_ids=requested_evidence,
            completed_evidence_requests=completed_evidence,
            requested_details=requested_details,
            completed_detail_requests=completed_details,
            catalog_cursor=cursor,
            catalog_generation=generation,
            catalog_limit=limit,
            catalog_followup_pending=pending,
            catalog_fit_blocked=fit_blocked,
        )

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
        error_seeds = tuple(
            node_id
            for reference in self.error_references(state)
            for node_id in reference.knowledge_node_ids
        )
        wifi_objective = _wifi_reference_objective(state.objective)
        wifi_seeds = (
            (
                "kn_wifi_association_failure",
                "kn_wifi_auth_failure",
                "kn_ip_config_failure",
            )
            if wifi_objective
            else ()
        )
        packet = self.knowledge.focused_packet(
            objective=state.objective,
            hypothesis_briefs=tuple(item.statement for item in state.hypotheses[:3]),
            seed_node_ids=(*error_seeds, *wifi_seeds),
            exclude_terms=frozenset() if wifi_objective else frozenset({"wireless"}),
            max_relations=6,
            max_chars=6_000,
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
            capabilities=self._case_capabilities(state),
            completed_probe_ids=frozenset(state.completed_probe_ids),
            symptom=state.objective,
        )
        request = DecisionRequest(
            schema_version=2,
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
            completed_probe_ids=self._completed_for_models(state).intersection(
                item.probe_id for item in routed_capabilities
            ),
            satisfied_probe_ids=self._satisfied_probe_ids(state).intersection(
                item.probe_id for item in routed_capabilities
            ),
            retryable_probe_ids=self._retryable_probe_ids(state).intersection(
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
        with self.store.transaction() as transaction:
            transaction.append_coordinator_event(
                case_id=str(state.case_id),
                kind="provider",
                fields={
                    "role": "decision",
                    "attempted_provider_id": self.decision.identity.provider_id,
                    "effective_provider_id": response.provider.provider_id,
                    "failed": response.degraded,
                },
            )
        return state.model_copy(
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

    def context(
        self, case_id: str, *, state: InvestigationState | None = None
    ) -> tuple[EvidenceContext, ...]:
        state = self.repository.load(case_id) if state is None else state
        packet = self.packet(case_id, state=state)
        result: list[EvidenceContext] = []
        for record in packet.evidence:
            limitations = list(record.limitations)
            if record.statement_kind is not StatementKind.OBSERVED_FACT:
                limitations.insert(0, f"statement_kind={record.statement_kind.value}")
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
                    status={
                        StatementKind.MISSING: EvidenceContextStatus.MISSING,
                        StatementKind.UNAVAILABLE: EvidenceContextStatus.UNAVAILABLE,
                    }.get(record.statement_kind, EvidenceContextStatus.OBSERVED),
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

    def packet(self, case_id: str, *, state: InvestigationState | None = None) -> EvidencePacket:
        state = self.repository.load(case_id) if state is None else state
        if str(state.case_id) != case_id:
            raise ValueError("packet state belongs to another case")
        query = EvidenceRetrievalQuery(
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
        retriever = EvidenceRetriever(self.store)
        packet = retriever.retrieve(query)
        priority_ids = self._graph_priority_evidence_ids(state, packet)
        priority_ids = tuple(
            dict.fromkeys(
                (
                    *state.fast_catalog_selected_ids[:1],
                    *(item.evidence_id for item in state.requested_details),
                    *state.requested_evidence_ids,
                    *state.fast_catalog_selected_ids[1:],
                    *priority_ids,
                )
            )
        )[:8]
        if not priority_ids:
            return packet
        expanded = retriever.retrieve(
            query.model_copy(update={"priority_evidence_ids": priority_ids})
        )
        if {str(item) for item in priority_ids} <= {
            str(item.evidence_id) for item in expanded.evidence
        }:
            return expanded
        return packet

    def _graph_priority_evidence_ids(
        self, state: InvestigationState, packet: EvidencePacket
    ) -> tuple[EvidenceId, ...]:
        """Follow observed machine edges to surface nearby, already stored case facts."""

        if not packet.omitted_evidence_count:
            return ()
        visible_ids = {
            str(item.evidence_id)
            for item in packet.evidence
            if item.case_id == state.case_id
            and state.incident_start <= item.observed_at <= state.incident_end
            and item.observed_at <= item.captured_at
            and item.statement_kind is StatementKind.OBSERVED_FACT
        }
        if not visible_ids:
            return ()
        relations = EvidenceRelationRepository(self.store)
        seed_ids = tuple(
            item.evidence_id for item in packet.evidence if str(item.evidence_id) in visible_ids
        )
        seeds = tuple(
            relation
            for relation in relations.prioritized_relations(evidence_ids=seed_ids, limit=64)
            if relation.evidence_ids
            and {str(item) for item in relation.evidence_ids} <= visible_ids
            and relation.memory_layer is MemoryLayer.MACHINE
            and relation.assertion_status is AssertionStatus.OBSERVED
            and relation.is_valid_at(state.incident_end)
        )[:8]
        if not seeds:
            return ()
        targets = tuple(
            {str(seed.target_entity_id): seed.target_entity_id for seed in seeds}.values()
        )[:8]
        outgoing = relations.outgoing(source_entity_ids=targets, limit=64)
        by_source: dict[str, list[EvidenceRelation]] = {}
        for relation in outgoing:
            by_source.setdefault(str(relation.source_entity_id), []).append(relation)

        record_cache: dict[str, EvidenceRecord | None] = {}

        def current_record(evidence_id: EvidenceId) -> EvidenceRecord | None:
            key = str(evidence_id)
            if key not in record_cache:
                row = self.store.connection.execute(
                    "SELECT record_json FROM evidence WHERE evidence_id = ? AND case_id = ?",
                    (key, str(state.case_id)),
                ).fetchone()
                try:
                    record = EvidenceRecord.model_validate_json(str(row[0])) if row else None
                except ValueError:
                    record = None
                record_cache[key] = (
                    record
                    if record is not None
                    and record.case_id == state.case_id
                    and record.evidence_id == evidence_id
                    and record.statement_kind is StatementKind.OBSERVED_FACT
                    and state.incident_start <= record.observed_at <= state.incident_end
                    and record.observed_at <= record.captured_at
                    else None
                )
            return record_cache[key]

        def current_relation(relation: EvidenceRelation) -> bool:
            if not relation.evidence_ids or len(relation.evidence_ids) > 8:
                return False
            if any(current_record(evidence_id) is None for evidence_id in relation.evidence_ids):
                return False
            sources = {
                record.source.source_id
                for evidence_id in relation.evidence_ids
                if (record := current_record(evidence_id)) is not None
            }
            return set(relation.source_ids) <= sources

        selected: list[EvidenceId] = []
        for seed in seeds:
            if not current_relation(seed):
                continue
            for relation in by_source.get(str(seed.target_entity_id), ()):
                if (
                    relation.memory_layer is not MemoryLayer.MACHINE
                    or relation.assertion_status is not AssertionStatus.OBSERVED
                    or not relation.is_valid_at(state.incident_end)
                    or not current_relation(relation)
                    or {str(item) for item in relation.evidence_ids} <= visible_ids
                ):
                    continue
                required = tuple(
                    {
                        str(item): item for item in (*seed.evidence_ids, *relation.evidence_ids)
                    }.values()
                )
                additions = tuple(item for item in required if item not in selected)
                if len(selected) + len(additions) > 8:
                    continue
                selected.extend(additions)
                if len(selected) == 8:
                    return tuple(selected)
        return tuple(selected)

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
        known = {item.probe_id: item for item in self._case_capabilities(state)}
        satisfied = self._satisfied_probe_ids(state)
        retryable = self._retryable_probe_ids(state)
        completed = self._effective_completed_probe_ids(state)
        by_id: dict[str, ProbeProposal] = {}
        for proposal in proposals:
            # The merged list is deep-first. Keep the first advisory claim for
            # an ID so a later provider cannot replace its dependencies.
            by_id.setdefault(proposal.probe_id, proposal)
        slots = max(0, state.max_probes - self._attempts_consumed(state))
        if batch_limit is not None:
            slots = min(slots, batch_limit)
        selected: list[ProbeProposal] = []
        selected_ids: set[str] = set()

        def closure(probe_id: str, visiting: set[str]) -> tuple[ProbeProposal, ...] | None:
            if probe_id in satisfied:
                return ()
            proposal = by_id.get(probe_id)
            if (
                proposal is None
                or (probe_id in completed and probe_id not in retryable)
                or probe_id in visiting
                or (
                    proposal.measurement_need is not None
                    and self._has_measurement_gap(state, proposal.measurement_need)
                )
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
            if proposal.probe_id in satisfied:
                continue
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

    def _satisfied_probe_ids(self, state: InvestigationState) -> frozenset[str]:
        """Trust current-manifest successes with usable current-incident observations."""

        satisfied: set[str] = set()
        rows = self.store.connection.execute(
            """SELECT execution.probe_id, execution.probe_version,
                      execution.finished_at, observation.observed_at,
                      observation.captured_at
               FROM probe_executions AS execution
               JOIN evidence AS observation
                 ON observation.case_id = execution.case_id
                AND observation.execution_id = execution.execution_id
                AND json_extract(observation.record_json, '$.statement_kind') = 'observed_fact'
               WHERE execution.case_id = ? AND execution.status = 'ok'
                 AND execution.finished_at IS NOT NULL""",
            (str(state.case_id),),
        )
        for probe_id, version, finished_at, observed_at, captured_at in rows:
            manifest = self.runtime.probe_manifest(str(probe_id))
            if manifest is None or manifest.version != int(version):
                continue
            try:
                finished = datetime.fromisoformat(str(finished_at))
                observed = datetime.fromisoformat(str(observed_at))
                captured = datetime.fromisoformat(str(captured_at))
                valid_time = (
                    state.incident_start <= observed <= captured <= finished <= state.incident_end
                )
            except (TypeError, ValueError):
                continue
            if valid_time:
                satisfied.add(str(probe_id))
        return frozenset(satisfied)

    def _attempt_history(self, state: InvestigationState) -> dict[str, tuple[str, ...]]:
        history: dict[str, list[str]] = {}
        for probe_id, status in self.store.connection.execute(
            "SELECT probe_id, status FROM probe_executions WHERE case_id = ? ORDER BY rowid",
            (str(state.case_id),),
        ):
            history.setdefault(str(probe_id), []).append(str(status))
        return {probe_id: tuple(statuses) for probe_id, statuses in history.items()}

    def _attempts_consumed(self, state: InvestigationState) -> int:
        history = self._attempt_history(state)
        unknown_completed = set((*state.completed_probe_ids, *state.pending_probe_ids)).difference(
            history, state.interrupted_probe_ids
        )
        unlinked = self.store.connection.execute(
            "SELECT COUNT(*) FROM collection_followup_admissions AS a "
            "LEFT JOIN collection_followup_execution_links AS l "
            "ON l.admission_id=a.admission_id "
            "WHERE a.case_id=? AND l.execution_id IS NULL",
            (str(state.case_id),),
        ).fetchone()
        candidate_unlinked = self.store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions AS a "
            "LEFT JOIN candidate_decision_execution_links AS l "
            "ON l.snapshot_id=a.snapshot_id AND l.candidate_id=a.candidate_id "
            "WHERE a.case_id=? AND l.execution_id IS NULL",
            (str(state.case_id),),
        ).fetchone()
        diagnostic_unlinked = self.store.connection.execute(
            "SELECT COUNT(*) FROM diagnostic_intent_dispatch_claims AS c "
            "JOIN diagnostic_intent_admissions AS a ON a.admission_id=c.admission_id "
            "LEFT JOIN diagnostic_intent_execution_links AS l "
            "ON l.admission_id=c.admission_id WHERE a.case_id=? AND l.execution_id IS NULL",
            (str(state.case_id),),
        ).fetchone()
        return (
            sum(len(statuses) for statuses in history.values())
            + len(unknown_completed)
            + state.unrecorded_attempt_count
            + (0 if unlinked is None else int(unlinked[0]))
            + (0 if candidate_unlinked is None else int(candidate_unlinked[0]))
            + (0 if diagnostic_unlinked is None else int(diagnostic_unlinked[0]))
        )

    def _effective_completed_probe_ids(self, state: InvestigationState) -> frozenset[str]:
        return frozenset(
            (
                *state.completed_probe_ids,
                *state.pending_probe_ids,
                *self._attempt_history(state),
                *self._unlinked_followup_probe_ids(state),
                *self._unsafe_followup_probe_ids(state),
                *self._unlinked_candidate_probe_ids(state),
            )
        )

    def _unlinked_candidate_probe_ids(self, state: InvestigationState) -> tuple[str, ...]:
        rows = self.store.connection.execute(
            "SELECT c.probe_id FROM candidate_dispatch_admissions AS a "
            "LEFT JOIN candidate_decision_execution_links AS l "
            "ON l.snapshot_id=a.snapshot_id AND l.candidate_id=a.candidate_id "
            "LEFT JOIN case_measurement_candidates AS c ON c.candidate_id=a.candidate_id "
            "WHERE a.case_id=? AND l.execution_id IS NULL",
            (str(state.case_id),),
        ).fetchall()
        return tuple(
            dict.fromkeys(
                str(row[0]) if row[0] is not None else "application.target_pressure" for row in rows
            )
        )

    def _unlinked_followup_probe_ids(self, state: InvestigationState) -> tuple[str, ...]:
        rows = self.store.connection.execute(
            "SELECT a.invocation_json,a.invocation_sha256 "
            "FROM collection_followup_admissions AS a "
            "LEFT JOIN collection_followup_execution_links AS l "
            "ON l.admission_id=a.admission_id "
            "WHERE a.case_id=? AND l.execution_id IS NULL",
            (str(state.case_id),),
        ).fetchall()
        return self._probe_ids_from_admission_rows(rows)

    def _probe_ids_from_admission_rows(self, rows: Iterable[tuple[object, ...]]) -> tuple[str, ...]:
        probe_ids: list[str] = []
        for row in rows:
            try:
                invocation_json = str(row[1]) if len(row) == 4 else str(row[0])
                digest = str(row[2]) if len(row) == 4 else str(row[1])
                if hashlib.sha256(invocation_json.encode()).hexdigest() != digest:
                    raise ValueError("follow-up invocation digest mismatch")
                probe_ids.append(ProbeInvocation.model_validate_json(invocation_json).probe_id)
            except ValueError:
                # A malformed admission cannot authorize another probe. The
                # count remains consumed and collection will be budget-closed.
                return tuple(item.probe_id for item in self.capabilities)
        return tuple(dict.fromkeys(probe_ids))

    def _unsafe_followup_probe_ids(self, state: InvestigationState) -> tuple[str, ...]:
        epochs = self.store.connection.execute(
            "SELECT DISTINCT epoch_state_version FROM collection_followup_admissions "
            "WHERE case_id=?",
            (str(state.case_id),),
        ).fetchall()
        unsafe: list[str] = []
        repository = FollowupAdmissionRepository(self.store)
        for (epoch,) in epochs:
            try:
                repository.readback(case_id=str(state.case_id), epoch_state_version=int(epoch))
            except (ValueError, TypeError):
                rows = self.store.connection.execute(
                    "SELECT invocation_json,invocation_sha256 "
                    "FROM collection_followup_admissions "
                    "WHERE case_id=? AND epoch_state_version=?",
                    (str(state.case_id), int(epoch)),
                ).fetchall()
                unsafe.extend(self._probe_ids_from_admission_rows(rows))
        return tuple(dict.fromkeys(unsafe))

    def _retryable_probe_ids(self, state: InvestigationState) -> frozenset[str]:
        history = self._attempt_history(state)
        unsafe = frozenset(self._unsafe_followup_probe_ids(state))
        return frozenset(
            probe_id
            for probe_id in self._effective_completed_probe_ids(state)
            if probe_id not in state.interrupted_probe_ids and probe_id not in unsafe
            if history.get(probe_id) in {("failed",), ("timed_out",), ("unavailable",)}
        )

    def _completed_for_models(self, state: InvestigationState) -> frozenset[str]:
        # A known transient failure is available for one explicit repeat. An
        # interrupted attempt without a durable outcome is never replayed.
        return self._effective_completed_probe_ids(state).difference(
            self._retryable_probe_ids(state)
        ) | self._satisfied_probe_ids(state)

    @staticmethod
    def _registered_read_only(proposal: ProbeProposal, capability: ProbeCapability | None) -> bool:
        if capability is None:
            return False
        need = proposal.measurement_need
        if capability.target_handles:
            if (
                proposal.schema_version != 2
                or need is None
                or need.capability_id != capability.probe_id
                or need.observable not in capability.observable_ids
                or need.target_handle not in capability.target_handles
                or (need.window is not None and not capability.supports_window)
                or proposal.depends_on
            ):
                return False
        elif need is not None:
            # Generic catalog probes cannot acquire selectors by model text.
            return False
        return (
            proposal.estimated_cost_ms == capability.cost_ms
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

        known = {item.probe_id: item for item in self._case_capabilities(state)}
        satisfied = self._satisfied_probe_ids(state)
        retryable = self._retryable_probe_ids(state)
        completed = self._effective_completed_probe_ids(state)
        candidates: dict[str, ProbeProposal] = {}
        for item in state.pending_distinguishing_probes:
            if (
                item.probe_id not in candidates
                and (item.probe_id not in completed or item.probe_id in retryable)
                and (
                    item.measurement_need is None
                    or not self._has_measurement_gap(state, item.measurement_need)
                )
                and self._registered_read_only(item, known.get(item.probe_id))
            ):
                candidates[item.probe_id] = item

        def valid(probe_id: str, visiting: set[str]) -> bool:
            if probe_id in satisfied:
                return True
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
        if self.knowledge is None or self._attempts_consumed(state) >= state.max_probes:
            return ()
        references = self.reference_context(state)
        if not references:
            return ()
        packet = KnowledgePacket.model_validate(references[0])
        known = {capability.probe_id: capability for capability in self.capabilities}
        for relation in packet.relations:
            roles = probe_roles_for_relation(packet, relation)
            for probe_id in roles.discriminating_probe_ids:
                capability = known.get(probe_id)
                if (
                    capability is None
                    or probe_id in self._completed_for_models(state)
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
            check_probe_budget and self._attempts_consumed(state) >= state.max_probes
        ):
            return self._finish(
                state,
                InvestigationOutcome.BUDGET_EXHAUSTED,
                "The case time or probe budget is exhausted.",
            )
        return None

    def _remaining_ms(self, state: InvestigationState) -> int:
        reserved = self.store.connection.execute(
            "SELECT COALESCE(SUM(cost_ms),0) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        candidate_cost_ms = 0 if reserved is None else int(reserved[0])
        return max(
            0,
            min(
                state.budget_ms - state.spent_cost_ms - candidate_cost_ms,
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
        state = self._drain_deep(state)
        deep_task = getattr(self, "_deep_task", None)
        if deep_task is not None and deep_task.request.case_id == state.case_id:
            self._deep_lane.cancel()
            self._deep_mailbox.finish(
                deep_task, "cancelled", reason=f"case terminal: {outcome.value}"
            )
            self._close_deep_frontier(deep_task)
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
        frontier_closure = None
        frontier = SearchFrontierRepository(self.store) if hasattr(self, "store") else None
        active_attention = (
            frontier.active_investigator_session(state.case_id) if frontier is not None else None
        )
        if active_attention is not None and frontier is not None:
            turns = frontier.investigator_turns(state.case_id, active_attention.event_id)
            if turns:
                last_outcome = frontier.read_investigator_turn_outcome(turns[-1].turn_id)
                if last_outcome is None:
                    raise ValueError("case cannot stop with an unaccounted attention turn")
                if (
                    last_outcome.remaining_item_ids
                    or last_outcome.remaining_refs
                    or last_outcome.cursor_after
                ):
                    source_missing = (
                        frontier.read_event(active_attention.event_id).source_state
                        == "missing_unverifiable"
                    )
                    frontier_closure = FrontierInvestigatorTurnClosureIntentV1(
                        event_id=active_attention.event_id,
                        case_id=state.case_id,
                        final_turn_id=turns[-1].turn_id,
                        outcome="gap",
                        reason_code="source_unverifiable" if source_missing else "case_stopped",
                    )
            else:
                # The owner may stop after event intake but before its first
                # bounded turn. The existing no-turn terminal records that gap.
                self._close_unstarted_frontier_session(
                    state,
                    frontier,
                    active_attention.event_id,
                    budget_exhausted=outcome is InvestigationOutcome.BUDGET_EXHAUSTED,
                )
        terminal_state = state.model_copy(
            update={
                "status": status,
                "outcome": outcome,
                "stop_reason": reason,
                "summary": summary,
            }
        )
        if frontier_closure is None:
            return self._save(terminal_state, "stopped", reason)
        try:
            return self._save(
                terminal_state,
                "stopped",
                reason,
                frontier_session_closure=frontier_closure,
            )
        except ValueError as error:
            if (
                str(error) != "investigator source unverifiable requires explicit closure gap"
                or frontier_closure.reason_code == "source_unverifiable"
            ):
                raise
            return self._save(
                terminal_state,
                "stopped",
                reason,
                frontier_session_closure=frontier_closure.model_copy(
                    update={"reason_code": "source_unverifiable"}
                ),
            )

    @staticmethod
    def _retrieval_omitted_evidence(context: tuple[EvidenceContext, ...]) -> bool:
        return any(
            "Retrieval packet omitted " in limitation
            for item in context
            for limitation in item.limitations
        )

    @staticmethod
    def _frontier_context_digest(context: tuple[EvidenceContext, ...]) -> str:
        body = json.dumps(
            [item.model_dump(mode="json") for item in context],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def _close_budgeted_frontier_session(
        self,
        state: InvestigationState,
        frontier: SearchFrontierRepository,
        event_id: str,
    ) -> InvestigationState:
        """Close a completed last turn without reserving an impossible ninth turn."""
        turns = frontier.investigator_turns(state.case_id, event_id)
        if not turns or frontier.read_investigator_turn_outcome(turns[-1].turn_id) is None:
            raise ValueError("budgeted frontier session lacks a completed last turn")
        return self._save(
            state.model_copy(
                update={
                    "warnings": self._warnings(
                        state, "Event frontier turn budget ended with unresolved references."
                    )
                }
            ),
            "frontier_event_gap",
            "Event attention closed at its durable turn limit.",
            frontier_session_closure=FrontierInvestigatorTurnClosureIntentV1(
                event_id=event_id,
                case_id=state.case_id,
                final_turn_id=turns[-1].turn_id,
                outcome="gap",
                reason_code="budget_exhausted",
            ),
        )

    def _close_unstarted_frontier_session(
        self,
        state: InvestigationState,
        frontier: SearchFrontierRepository,
        event_id: str,
        *,
        budget_exhausted: bool,
    ) -> None:
        session = frontier.active_investigator_session(state.case_id)
        if session is None or session.event_id != event_id:
            raise ValueError("unstarted frontier session is not active")
        if frontier.investigator_turns(state.case_id, event_id):
            raise ValueError("unstarted frontier session already has a turn")
        source = frontier.read_event(event_id)
        generation = (
            EvidenceRetriever(self.store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        if source.source_state == "missing_unverifiable":
            gap_reason = "source_unverifiable"
        elif utc_now() >= session.deadline_at:
            gap_reason = "deadline_expired"
        elif generation != session.catalog_generation:
            gap_reason = "stale_snapshot"
        elif budget_exhausted:
            gap_reason = "budget_exhausted"
        else:
            gap_reason = "policy_unavailable"
        frontier.finish_investigator_session(
            state.case_id, event_id, outcome="gap", reason_code=gap_reason
        )

    def _expire_event_frontier_session(
        self,
        state: InvestigationState,
        frontier: SearchFrontierRepository,
        event_id: str,
    ) -> InvestigationState:
        prior_turns = frontier.investigator_turns(state.case_id, event_id)
        if prior_turns:
            last_outcome = frontier.read_investigator_turn_outcome(prior_turns[-1].turn_id)
            if last_outcome is None:
                raise ValueError("expired attention has an unaccounted turn")
            with self.store.transaction():
                source_missing = (
                    frontier.read_event(event_id).source_state == "missing_unverifiable"
                )
                frontier.close_investigator_session_in_transaction(
                    FrontierInvestigatorTurnClosureIntentV1(
                        event_id=event_id,
                        case_id=state.case_id,
                        final_turn_id=prior_turns[-1].turn_id,
                        outcome="gap",
                        reason_code=(
                            "source_unverifiable" if source_missing else "deadline_expired"
                        ),
                    )
                )
        else:
            self._close_unstarted_frontier_session(state, frontier, event_id, budget_exhausted=True)
        return self._save(
            state.model_copy(
                update={
                    "warnings": self._warnings(state, "Event frontier attention deadline expired.")
                }
            ),
            "frontier_event_gap",
            "Unresolved event references remain explicit after attention expiry.",
        )

    def _close_unverifiable_event_session(
        self,
        state: InvestigationState,
        frontier: SearchFrontierRepository,
        event_id: str,
    ) -> InvestigationState:
        turns = frontier.investigator_turns(state.case_id, event_id)
        if turns:
            last_outcome = frontier.read_investigator_turn_outcome(turns[-1].turn_id)
            if last_outcome is None:
                raise ValueError("unverifiable event has an unaccounted attention turn")
            with self.store.transaction():
                frontier.close_investigator_session_in_transaction(
                    FrontierInvestigatorTurnClosureIntentV1(
                        event_id=event_id,
                        case_id=state.case_id,
                        final_turn_id=turns[-1].turn_id,
                        outcome="gap",
                        reason_code="source_unverifiable",
                    )
                )
        else:
            frontier.finish_investigator_session(
                state.case_id,
                event_id,
                outcome="gap",
                reason_code="source_unverifiable",
            )
        return self._save(
            state.model_copy(
                update={
                    "warnings": self._warnings(
                        state, "Event frontier source is no longer verifiable."
                    )
                }
            ),
            "frontier_event_gap",
            "Source loss left event attention unresolved without a model call.",
        )

    def _event_frontier_turn(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
        owner_started_version: int,
    ) -> tuple[InvestigationState, tuple[EvidenceContext, ...], bool]:
        """Spend at most one durable event-attention slot, then yield to collection.

        This first active slice only ranks already stored, case-local evidence.
        A failed reference closes the attention session with an explicit gap; it
        never grants a model probe authority or silently skips a catalog page.
        """

        ranker = self.frontier_ranker
        knowledge = self.knowledge
        if ranker is None or knowledge is None:
            return state, context, False
        initial_state, initial_context = state, context
        frontier = SearchFrontierRepository(self.store)
        case_turns_remaining = frontier.investigator_case_turns_remaining(state.case_id)
        session = frontier.active_investigator_session(state.case_id)
        if session is None:
            if self._remaining_ms(state) <= 100:
                return state, context, False
            pending = frontier.pending_investigator_triggers(state.case_id, limit=1)
            if not pending:
                events = frontier.pending_investigator_events(state.case_id, limit=1)
                if not events:
                    return state, context, False
                intake = frontier.intake_investigator_event_status(
                    state.case_id, events[0].event_id
                )
                if intake.status == "backpressured":
                    state = self._save(
                        state.model_copy(
                            update={
                                "warnings": self._warnings(
                                    state, "Frontier event intake is at capacity."
                                )
                            }
                        ),
                        "frontier_event_gap",
                        "The event remains durable for later attention.",
                    )
                    return state, context, True
                pending = frontier.pending_investigator_triggers(state.case_id, limit=1)
            if not pending:
                return state, context, False
            session = frontier.start_investigator_session(
                state.case_id, pending[0].event_id, decision_budget=8
            )

        if utc_now() >= min(session.deadline_at, state.deadline_at):
            state = self._expire_event_frontier_session(state, frontier, session.event_id)
            return state, context, True

        if frontier.read_event(session.event_id).source_state == "missing_unverifiable":
            state = self._close_unverifiable_event_session(state, frontier, session.event_id)
            return state, context, True

        if case_turns_remaining == 0:
            exhausted_turns = frontier.investigator_turns(state.case_id, session.event_id)
            if exhausted_turns:
                if frontier.read_investigator_turn_outcome(exhausted_turns[-1].turn_id) is None:
                    return state, context, True
                return (
                    self._close_budgeted_frontier_session(state, frontier, session.event_id),
                    context,
                    True,
                )
            self._close_unstarted_frontier_session(
                state, frontier, session.event_id, budget_exhausted=True
            )
            state = self._save(
                state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state, "Event frontier case turn capacity is exhausted."
                        )
                    }
                ),
                "frontier_event_gap",
                "Event attention ended without a new turn because the case cap is exhausted.",
            )
            return state, context, True

        retriever = EvidenceRetriever(self.store)
        generation = retriever.discover(
            EvidenceCatalogQuery(case_id=state.case_id, limit=1)
        ).case_evidence_generation
        versions = RelevantVersionsV1(
            objective=1, evidence=generation, graph=knowledge.pack.version
        )
        prior_turns = frontier.investigator_turns(state.case_id, session.event_id)
        if prior_turns and prior_turns[-1].catalog_generation != generation:
            # The ordinary loop's packet predates this case append. Rebuild it
            # from stored facts before freezing the next focused-context digest.
            context = self.context(str(state.case_id), state=state)
            initial_context = context
        prior_outcome = (
            frontier.read_investigator_turn_outcome(prior_turns[-1].turn_id)
            if prior_turns
            else None
        )
        if prior_turns and prior_outcome is None:
            # Only an expired reservation or a newer owner may reconcile it.
            return state, context, True
        if prior_turns and len(prior_turns) >= session.decision_budget:
            return (
                self._close_budgeted_frontier_session(state, frontier, session.event_id),
                context,
                True,
            )
        cursor_before = prior_outcome.cursor_after if prior_outcome is not None else None
        cursor_after = cursor_before
        pending_ids = prior_outcome.remaining_item_ids if prior_outcome is not None else ()
        offered_ids: tuple[str, ...] = ()
        reissue_lineage: tuple[FrontierPendingRefreshV3, ...] = ()
        candidate_registry = None
        candidate_refs: tuple[AdmittedCandidateRefV1, ...] = ()
        if self._attempts_consumed(state) < state.max_probes:
            registry, needs = self.runtime.general_candidate_catalog(state.case_id)
            issued = tuple(
                record
                for need in needs[:8]
                if not isinstance(
                    (record := registry.issue(state.case_id, state.state_version, need)),
                    CandidateGap,
                )
                and record.cost_ms <= self._remaining_ms(state)
            )
            if issued:
                candidate_registry = registry
                candidate_refs = tuple(
                    AdmittedCandidateRefV1.model_validate(
                        record.model_dump(mode="json", exclude={"schema_version"})
                    )
                    for record in issued
                )
        pending_measure_ids = tuple(
            item_id
            for item_id in pending_ids
            if frontier.readback(item_id).reference.kind == "measure"
        )

        def candidate_identity(candidate_id: str) -> tuple[str, ...] | None:
            # Match the same immutable measurement across epochs, including its
            # exact sources. Probe ID alone cannot distinguish targets or windows.
            row = self.store.connection.execute(
                "SELECT probe_id,manifest_version,manifest_sha256,invocation_sha256,"
                "observable,target_handle,source_evidence_id,source_evidence_sha256,"
                "dependency_bindings_json,dependency_sha256,cost_ms,resource_class,"
                "safety_class,description FROM case_measurement_candidates "
                "WHERE case_id=? AND candidate_id=?",
                (str(state.case_id), candidate_id),
            ).fetchone()
            return None if row is None else tuple(str(value) for value in row)

        successors: dict[str, AdmittedCandidateRefV1] = {}
        unavailable_pending = len(pending_measure_ids) > 2
        for item_id in pending_measure_ids:
            predecessor_id = frontier.readback(item_id).reference.candidate_id
            identity = None if predecessor_id is None else candidate_identity(predecessor_id)
            matches = tuple(
                ref
                for ref in candidate_refs
                if identity is not None and candidate_identity(ref.candidate_id) == identity
            )
            if len(matches) != 1:
                unavailable_pending = True
            else:
                successors[item_id] = matches[0]
        retained_refs = tuple(successors.values())
        retained_ids = {ref.candidate_id for ref in retained_refs}
        candidate_refs = (
            *retained_refs,
            *(ref for ref in candidate_refs if ref.candidate_id not in retained_ids),
        )[: min(2, 8 - len(pending_ids) + len(pending_measure_ids))]
        eligible_ids: tuple[EvidenceId, ...] = ()
        catalog_entries: tuple[EvidenceCatalogEntry, ...] = ()
        page_gap: str | None = (
            "frontier_pending_source_unavailable" if unavailable_pending else None
        )
        refresh_pending = False
        if (
            page_gap is None
            and prior_outcome is not None
            and prior_turns[-1].catalog_generation != generation
        ):
            previous_versions = prior_turns[-1].current_versions
            refresh_pending = bool(pending_ids) and (
                previous_versions.objective == versions.objective
                and previous_versions.graph == versions.graph
                and previous_versions.evidence is not None
                and versions.evidence is not None
                and previous_versions.evidence < versions.evidence
            )
            if refresh_pending:
                # A new generation can insert records ahead of the old cursor.
                # Keep the historical cursor only as the predecessor boundary;
                # the refreshed tail must restart discovery from the head.
                cursor_after = None
            else:
                page_gap = "frontier_catalog_changed"
        if pending_ids and page_gap is None:
            references = tuple(frontier.readback(item_id).reference for item_id in pending_ids)
            if any(
                (ref.kind != "retrieve_evidence" or ref.evidence_id is None)
                and not (
                    prior_turns
                    and isinstance(prior_turns[-1], FrontierInvestigatorTurnV3)
                    and ref.kind == "measure"
                    and ref.candidate_id is not None
                )
                for ref in references
            ):
                page_gap = (
                    "frontier_catalog_changed"
                    if refresh_pending
                    else "frontier_pending_source_unavailable"
                )
                refresh_pending = False
                cursor_after = cursor_before
            else:
                exact_ids = tuple(
                    ref.evidence_id for ref in references if ref.evidence_id is not None
                )
                if exact_ids:
                    try:
                        exact_page = retriever.describe_exact(
                            EvidenceCatalogExactQuery(
                                case_id=state.case_id,
                                evidence_ids=exact_ids,
                                expected_generation=generation,
                                observed_from=state.incident_start,
                                observed_until=state.incident_end,
                                current_collection_start=state.created_at,
                            )
                        )
                    except ValueError as error:
                        if str(error) == "exact catalog generation changed":
                            return state, context, True
                        if str(error) != "exact catalog reference unavailable":
                            raise
                        page_gap = (
                            "frontier_catalog_changed"
                            if refresh_pending
                            else "frontier_pending_source_unavailable"
                        )
                        refresh_pending = False
                        cursor_after = cursor_before
                    else:
                        catalog_entries = exact_page.entries
        elif page_gap is None:
            try:
                page = discover_retrieval_page(
                    case_id=state.case_id,
                    retriever=retriever,
                    expected_generation=generation,
                    cursor=cursor_before,
                    visible_evidence_ids=tuple(
                        EvidenceId(root=value)
                        for value in tuple(
                            dict.fromkeys(
                                str(item.evidence_id)
                                for item in context
                                if item.case_scope == "current_case"
                            )
                        )[:256]
                    ),
                    incident_start=state.incident_start,
                    incident_end=state.incident_end,
                    current_collection_start=state.created_at,
                    page_limit=8 - len(candidate_refs),
                )
            except ValueError as error:
                if str(error) != "retrieval catalog generation changed":
                    raise
                return state, context, True
            cursor_after = page.cursor_after
            eligible_ids = tuple(item.evidence_id for item in page.eligible_entries)
            catalog_entries = page.entries
            if eligible_ids and not candidate_refs:
                try:
                    offered_ids = tuple(
                        item.item_id
                        for item in frontier.upsert_retrieval_page(
                            state.case_id,
                            eligible_ids,
                            versions,
                            expected_generation=generation,
                        )
                    )
                except FrontierItemCapacityError:
                    # No page cursor is consumed if even one reference cannot fit.
                    cursor_after = cursor_before
                    eligible_ids = ()
                    page_gap = "frontier_item_capacity_exhausted"
                except ValueError as error:
                    if str(error) != "retrieval page generation is stale":
                        raise
                    return state, context, True

        if candidate_refs and page_gap is None:
            # Existing pending choices own their slots. New measurements use
            # only remaining capacity and do not displace retained references.
            available_slots = 8 - len(pending_ids) - len(eligible_ids)
            candidate_refs = candidate_refs[: len(pending_measure_ids) + available_slots]
            try:
                mixed_items = frontier.upsert_mixed_page(
                    state.case_id,
                    eligible_ids,
                    tuple(ref.candidate_id for ref in candidate_refs),
                    versions,
                    expected_generation=generation,
                    candidate_epoch=state.state_version,
                )
            except FrontierItemCapacityError:
                page_gap = (
                    "frontier_pending_source_unavailable"
                    if pending_measure_ids
                    else "frontier_item_capacity_exhausted"
                )
                cursor_after = cursor_before
                eligible_ids = ()
                refresh_pending = False
            except ValueError as error:
                if str(error) == "mixed page generation is stale":
                    return state, context, True
                if str(error) not in {
                    "mixed turn candidate is unregistered or stale",
                    "mixed turn candidate source binding changed",
                    "mixed turn candidate has already been admitted",
                }:
                    raise
                page_gap = "frontier_pending_source_unavailable"
                cursor_after = cursor_before
                eligible_ids = ()
                refresh_pending = False
            else:
                measure_by_candidate = {
                    item.reference.candidate_id: item
                    for item in mixed_items
                    if item.reference.kind == "measure"
                }
                reissue_lineage = tuple(
                    FrontierPendingRefreshV3(
                        predecessor_item_id=item_id,
                        successor_item_id=measure_by_candidate[
                            successors[item_id].candidate_id
                        ].item_id,
                    )
                    for item_id in pending_measure_ids
                )
                successor_ids = {link.successor_item_id for link in reissue_lineage}
                offered_ids = tuple(
                    item.item_id for item in mixed_items if item.item_id not in successor_ids
                )
        if page_gap is not None or not candidate_refs:
            candidate_refs = ()
            candidate_registry = None
            if pending_measure_ids:
                page_gap = "frontier_pending_source_unavailable"
                reissue_lineage = ()
                offered_ids = ()
                eligible_ids = ()
                cursor_after = cursor_before
                refresh_pending = False
        if pending_measure_ids and not reissue_lineage and page_gap is None:
            page_gap = "frontier_pending_source_unavailable"
            cursor_after = cursor_before
            refresh_pending = False

        stale_pending_measurement_gap = page_gap == "frontier_pending_source_unavailable" and bool(
            pending_measure_ids
        )

        mixed_turn = bool(candidate_refs) or (
            bool(prior_turns) and isinstance(prior_turns[-1], FrontierInvestigatorTurnV3)
        )
        packet_receipt_id: str | None = None
        if candidate_refs:
            source_ids_list: list[EvidenceId] = []
            for ref in candidate_refs:
                source_row = self.store.connection.execute(
                    "SELECT source_evidence_id,dependency_bindings_json "
                    "FROM case_measurement_candidates WHERE case_id=? AND candidate_id=?",
                    (str(state.case_id), ref.candidate_id),
                ).fetchone()
                if source_row is None:
                    raise ValueError("registered mixed candidate source is unavailable")
                source_ids_list.append(EvidenceId(root=str(source_row[0])))
                source_ids_list.extend(
                    EvidenceId(root=str(binding["evidence_id"]))
                    for binding in json.loads(str(source_row[1]))
                )
            source_ids = tuple(dict.fromkeys(source_ids_list))
            packet_receipt_id = (
                FrontierPacketReceiptRepository(self.store)
                .freeze(
                    case_id=state.case_id,
                    epoch_state_version=state.state_version,
                    evidence_ids=source_ids,
                    expected_generation=generation,
                )
                .receipt_id
            )

        deadline = min(
            state.deadline_at,
            session.deadline_at,
            utc_now() + timedelta(seconds=4 if mixed_turn else 1.5),
        )
        if deadline <= utc_now() + timedelta(milliseconds=50):
            return state, context, True
        focused_digest = self._frontier_context_digest(context)
        reservation_pending_ids = (
            pending_ids
            if refresh_pending and mixed_turn
            else tuple(
                next(
                    (
                        link.successor_item_id
                        for link in reissue_lineage
                        if link.predecessor_item_id == item_id
                    ),
                    item_id,
                )
                for item_id in pending_ids
            )
        )
        try:
            turn = frontier.reserve_investigator_turn(
                state.case_id,
                session.event_id,
                owner_started_version=owner_started_version,
                expected_checkpoint_version=state.state_version,
                current_versions=versions,
                focused_context_sha256=focused_digest,
                catalog_generation=generation,
                cursor_before=cursor_before,
                cursor_after=cursor_after,
                offered_refs=(),
                pending_tail=(),
                offered_item_ids=offered_ids,
                pending_item_ids=reservation_pending_ids,
                eligible_evidence_ids=eligible_ids,
                turn_deadline_at=deadline,
                refresh_pending=refresh_pending and not mixed_turn,
                mixed_candidate_epoch=state.state_version if mixed_turn else None,
                packet_receipt_id=packet_receipt_id,
                reissue_lineage=reissue_lineage,
                auto_reissue_retrieval=refresh_pending and mixed_turn,
                mixed_stale_pending_gap=stale_pending_measurement_gap,
            )
        except FrontierItemCapacityError:
            if not refresh_pending:
                raise
            # The failed reservation rolled back every successor and old-item
            # transition. Record a stale unresolved gap; never reuse old IDs.
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state, "Event frontier pending refresh lacked item capacity."
                    )
                }
            )
            page_gap = "frontier_catalog_changed"
            cursor_after = cursor_before
            try:
                turn = frontier.reserve_investigator_turn(
                    state.case_id,
                    session.event_id,
                    owner_started_version=owner_started_version,
                    expected_checkpoint_version=state.state_version,
                    current_versions=versions,
                    focused_context_sha256=focused_digest,
                    catalog_generation=generation,
                    cursor_before=cursor_before,
                    cursor_after=cursor_after,
                    offered_refs=(),
                    pending_tail=(),
                    offered_item_ids=(),
                    pending_item_ids=pending_ids,
                    eligible_evidence_ids=(),
                    turn_deadline_at=deadline,
                    mixed_candidate_epoch=state.state_version if mixed_turn else None,
                    packet_receipt_id=packet_receipt_id,
                )
            except ValueError as error:
                if str(error) == "investigator source unverifiable":
                    state = self._close_unverifiable_event_session(
                        state, frontier, session.event_id
                    )
                    return state, context, True
                if str(error) == "investigator turn deadline is invalid":
                    if utc_now() >= min(session.deadline_at, state.deadline_at):
                        state = self._expire_event_frontier_session(
                            state, frontier, session.event_id
                        )
                    return state, context, True
                if str(error) != "investigator catalog generation is stale":
                    raise
                return state, context, True
        except ValueError as error:
            if str(error) == "investigator source unverifiable":
                state = self._close_unverifiable_event_session(state, frontier, session.event_id)
                return state, context, True
            if str(error) == "investigator turn deadline is invalid":
                if utc_now() >= min(session.deadline_at, state.deadline_at):
                    state = self._expire_event_frontier_session(state, frontier, session.event_id)
                return state, context, True
            if str(error) != "investigator catalog generation is stale":
                raise
            return state, context, True
        pending_ids = turn.pending_item_ids
        cursor_after = turn.cursor_after
        item_ids = (*pending_ids, *offered_ids)
        refs_by_id = {ref.candidate_id: ref for ref in candidate_refs}
        if not stale_pending_measurement_gap:
            candidate_refs = tuple(
                refs_by_id[candidate_id]
                for item_id in item_ids
                if (candidate_id := frontier.readback(item_id).reference.candidate_id) is not None
            )
        selected_item_id: str | None = None
        selected_evidence_id: EvidenceId | None = None
        selected_measurement: AdmittedCandidateRefV1 | None = None
        selected_snapshot_id: str | None = None
        transition: FrontierInvestigatorItemTransitionV1 | None = None
        call: ProviderCall | None = None
        failure = page_gap
        if failure is None and item_ids:
            frozen_items = tuple(frontier.readback(item_id) for item_id in item_ids)
            if any(item.status is not FrontierStatus.REQUESTED for item in frozen_items):
                failure = "frontier_reference_already_terminal"
            else:
                # Historical retrieval-only pages retain FIFO; a mixed turn
                # ranks all frozen alternatives with bounded deferral aging.
                items = (
                    frozen_items
                    if mixed_turn
                    else frozen_items[:1]
                    if pending_ids
                    else frozen_items
                )
                started_at = utc_now()
                started = time.monotonic()
                try:
                    step = run_frontier_step(
                        case_id=state.case_id,
                        items=items,
                        versions=versions,
                        symptom=state.objective,
                        hypothesis_briefs=tuple(
                            item.statement[:240] for item in state.hypotheses[:8]
                        ),
                        deadline_at=deadline,
                        provider=ranker.provider,
                        model_weight_sha256=ranker.model_weight_sha256,
                        catalog_entries=tuple(
                            entry
                            for entry in catalog_entries
                            if str(entry.evidence_id)
                            in {
                                str(item.reference.evidence_id)
                                for item in items
                                if item.reference.evidence_id is not None
                            }
                        ),
                        candidate_refs=candidate_refs,
                        candidate_registry=candidate_registry,
                        candidate_epoch=state.state_version,
                        store=self.store,
                        retriever=retriever,
                        frontier=frontier,
                        ranker=ranker,
                        evidence_packets=tuple(
                            SemanticPacketRefV1.model_validate(packet)
                            for packet in evidence_packets(context)[:24]
                        ),
                        packet_receipt_id=packet_receipt_id,
                        defer_retrieval_satisfaction=True,
                    )
                    call = ProviderCall(
                        role="catalog_attention",
                        provider_id=ranker.provider.provider_id,
                        provider_version=ranker.provider.provider_version,
                        state_version=state.state_version,
                        started_at=started_at,
                        elapsed_ms=(time.monotonic() - started) * 1000,
                        degraded=step.ranking.model_abstained,
                        detail="event_frontier_retrieval",
                    )
                    if (
                        step.retrieval is not None
                        and step.retrieval.status is FrontierStatus.RUNNING
                        and step.retrieval.evidence is not None
                    ):
                        selected_item_id = step.selected.item_id
                        selected_evidence_id = step.retrieval.evidence.evidence_id
                    elif step.measurement is not None and step.snapshot_id is not None:
                        selected_item_id = step.selected.item_id
                        selected_measurement = step.measurement
                        selected_snapshot_id = step.snapshot_id
                    else:
                        failure = "frontier_selection_unavailable"
                except (RuntimeError, ValueError):
                    failure = "frontier_policy_unavailable"

        if selected_item_id is not None and selected_evidence_id is not None:
            tentative = state.model_copy(
                update={
                    "fast_catalog_generation": generation,
                    "fast_catalog_selected_ids": tuple(
                        dict.fromkeys((selected_evidence_id, *state.fast_catalog_selected_ids))
                    )[:8],
                }
            )
            expanded = self.context(str(state.case_id), state=tentative)
            current_generation = retriever.discover(
                EvidenceCatalogQuery(case_id=state.case_id, limit=1)
            ).case_evidence_generation
            if (
                str(selected_evidence_id) not in {str(item.evidence_id) for item in expanded}
                or current_generation != generation
                or self._frontier_context_digest(self.context(str(state.case_id), state=state))
                != focused_digest
            ):
                failure = (
                    "frontier_catalog_changed"
                    if current_generation != generation
                    else "frontier_focused_delivery_changed"
                )
                transition = FrontierInvestigatorItemTransitionV1(
                    item_id=selected_item_id,
                    expected_status=FrontierStatus.RUNNING,
                    terminal_status=FrontierStatus.OBSOLETE,
                    reason="focused_delivery_changed",
                )
            else:
                transition = FrontierInvestigatorItemTransitionV1(
                    item_id=selected_item_id,
                    expected_status=FrontierStatus.RUNNING,
                    terminal_status=FrontierStatus.SATISFIED,
                    reason="focused_delivery_confirmed",
                )
                state = tentative
                context = expanded

        if failure is None and utc_now() >= turn.deadline_at:
            failure = "frontier_turn_deadline_expired"
            if selected_item_id is not None:
                transition = FrontierInvestigatorItemTransitionV1(
                    item_id=selected_item_id,
                    expected_status=(
                        FrontierStatus.CLAIMED
                        if selected_measurement is not None
                        else FrontierStatus.RUNNING
                    ),
                    terminal_status=FrontierStatus.OBSOLETE,
                    reason="deadline_expired_before_delivery",
                )
                state, context = initial_state, initial_context

        # The event's source is part of the attention claim, even when the
        # selected catalog row itself is still present. Never turn a vanished
        # source into a success, a benign empty page, or a provider failure.
        if frontier.read_event(session.event_id).source_state == "missing_unverifiable":
            failure = "frontier_source_unverifiable"
            if selected_item_id is not None:
                transition = FrontierInvestigatorItemTransitionV1(
                    item_id=selected_item_id,
                    expected_status=(
                        FrontierStatus.CLAIMED
                        if selected_measurement is not None
                        else FrontierStatus.RUNNING
                    ),
                    terminal_status=FrontierStatus.OBSOLETE,
                    reason="source_unverifiable_before_delivery",
                )
            state, context = initial_state, initial_context

        if (
            failure is None
            and selected_item_id is not None
            and selected_measurement is not None
            and selected_snapshot_id is not None
            and candidate_registry is not None
            and isinstance(turn, FrontierInvestigatorTurnV3)
        ):
            admitted_state = self._save(
                state.model_copy(
                    update={
                        "provider_calls": (
                            *state.provider_calls,
                            *((call,) if call is not None else ()),
                        )[-128:]
                    }
                ),
                "event_frontier_measurement_admitted",
                "Selected registered read-only measurement admitted for one worker launch.",
                frontier_measurement_admission=FrontierMeasurementAdmissionIntent(
                    turn_id=turn.turn_id,
                    selected_item_id=selected_item_id,
                    snapshot_id=selected_snapshot_id,
                    candidate_id=selected_measurement.candidate_id,
                    invocation_sha256=selected_measurement.invocation_sha256,
                    task_id=f"probe-0-{selected_measurement.probe_id}",
                    cost_ms=selected_measurement.cost_ms,
                    registry=candidate_registry,
                ),
            )
            outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
            if (
                outcome is None
                or not isinstance(outcome, FrontierInvestigatorTurnOutcomeV3)
                or outcome.launch_continuation_id is None
                or outcome.dispatch_admission_id is None
            ):
                raise ValueError("mixed measurement admission outcome is unavailable")
            proposal = ProbeProposal(
                probe_id=selected_measurement.probe_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
                estimated_cost_ms=selected_measurement.cost_ms,
                resource_class=selected_measurement.resource_class,
                safety_class=selected_measurement.safety_class,
                dedupe_key=f"candidate:{selected_measurement.candidate_id}",
            )
            worker_failure: str | None = None
            try:
                result = self.runtime.execute_candidate_measurement(
                    self._opened(admitted_state, (proposal,)),
                    selected_measurement.candidate_id,
                    selected_snapshot_id,
                    launch_continuation_id=outcome.launch_continuation_id,
                )
            except Exception as error:
                # Host access may already have started. Read the admission
                # terminal below, mark uncertainty, and never retry the token.
                result = None
                worker_failure = type(error).__name__
            admission = CandidateDispatchAdmissionRepository(self.store).readback(
                outcome.dispatch_admission_id
            )
            linked = admission.outcome_status == "linked"
            terminal = (
                self._frontier_execution_outcome(
                    admission.execution_id,
                    state.case_id,
                    selected_measurement.candidate_id,
                )
                if linked
                else FrontierStatus.INTERRUPTED
            )
            current = frontier.readback(selected_item_id)
            if linked and current.status is FrontierStatus.ADMITTED:
                current = frontier.transition(
                    selected_item_id,
                    FrontierStatus.ADMITTED,
                    FrontierStatus.RUNNING,
                    "candidate_execution_started",
                )
            if current.status in {
                FrontierStatus.CLAIMED,
                FrontierStatus.ADMITTED,
                FrontierStatus.RUNNING,
            }:
                frontier.transition(
                    selected_item_id,
                    current.status,
                    terminal,
                    "candidate_execution_" + terminal.value if linked else "candidate_uncertain",
                )
            if linked:
                self._project(str(state.case_id))
            updated = admitted_state.model_copy(
                update={
                    "completed_probe_ids": tuple(
                        dict.fromkeys(
                            (*admitted_state.completed_probe_ids, selected_measurement.probe_id)
                        )
                    ),
                    "interrupted_probe_ids": (
                        admitted_state.interrupted_probe_ids
                        if terminal is FrontierStatus.SATISFIED
                        else tuple(
                            dict.fromkeys(
                                (
                                    *admitted_state.interrupted_probe_ids,
                                    selected_measurement.probe_id,
                                )
                            )
                        )
                    ),
                    "warnings": (
                        admitted_state.warnings
                        if terminal is FrontierStatus.SATISFIED
                        else self._warnings(
                            admitted_state,
                            f"Event-selected measurement worker interrupted: {worker_failure}."
                            if worker_failure is not None
                            else f"Event-selected measurement was denied: {result.reason}"
                            if isinstance(result, ObservabilityGap)
                            else (
                                "Event-selected measurement did not satisfy the question "
                                "and was not replayed."
                            ),
                        )
                    ),
                    "round_count": admitted_state.round_count + 1,
                }
            )
            saved = self._save(
                updated,
                "event_frontier_measurement_collected"
                if terminal is FrontierStatus.SATISFIED
                else "event_frontier_measurement_unsatisfied",
                "Registered measurement reached a persisted terminal or explicit uncertainty.",
                frontier_session_closure=(
                    FrontierInvestigatorTurnClosureIntentV1(
                        event_id=session.event_id,
                        case_id=state.case_id,
                        final_turn_id=turn.turn_id,
                        outcome="gap",
                        reason_code="budget_exhausted",
                    )
                    if turn.ordinal >= session.decision_budget
                    or frontier.investigator_case_turns_remaining(state.case_id) == 0
                    else None
                ),
            )
            return saved, self.context(str(saved.case_id), state=saved), True

        if failure is not None:
            outcome = "gap"
            reason_code = (
                "source_unverifiable"
                if failure == "frontier_source_unverifiable"
                else "stale_context"
                if failure in {"frontier_catalog_changed", "frontier_pending_source_unavailable"}
                else "deadline_expired"
                if failure == "frontier_turn_deadline_expired"
                else "policy_unavailable"
            )
            state = state.model_copy(
                update={"warnings": self._warnings(state, f"Event frontier gap: {failure}.")}
            )
            selected_item_ids: tuple[str, ...] = ()
        elif selected_item_id is not None:
            outcome = "focused_delivery"
            reason_code = "focused_context_delivered"
            selected_item_ids = (selected_item_id,)
        else:
            outcome = "no_new_fact"
            reason_code = "all_facts_already_visible"
            selected_item_ids = ()
        completion_type = (
            FrontierInvestigatorTurnCompletionV3
            if isinstance(turn, FrontierInvestigatorTurnV3)
            else FrontierInvestigatorTurnCompletionV1
        )
        completion = completion_type(
            turn_id=turn.turn_id,
            case_id=state.case_id,
            outcome=outcome,
            reason_code=reason_code,
            frontier_item_ids=selected_item_ids,
            remaining_item_ids=tuple(
                item_id for item_id in item_ids if item_id not in selected_item_ids
            ),
            cursor_after=cursor_after,
            focused_context_sha256=focused_digest,
        )
        refresh_tail_unfinished = bool(getattr(turn, "pending_refresh_lineage", ()))
        if not refresh_tail_unfinished:
            for previous in reversed(prior_turns):
                if previous.offered_item_ids:
                    break
                if getattr(previous, "pending_refresh_lineage", ()):
                    refresh_tail_unfinished = True
                    break
        has_more = bool(completion.remaining_item_ids or completion.cursor_after) or (
            bool(pending_ids) and cursor_after is None and refresh_tail_unfinished
        )
        case_turn_count = self.store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_investigator_turns WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        budget_exhausted = turn.ordinal >= session.decision_budget or (
            case_turn_count is not None and int(case_turn_count[0]) >= 32
        )
        closure = None
        if outcome == "gap":
            closure = FrontierInvestigatorTurnClosureIntentV1(
                event_id=session.event_id,
                case_id=state.case_id,
                final_turn_id=turn.turn_id,
                outcome="gap",
                reason_code=reason_code,
            )
        elif not has_more:
            closure = FrontierInvestigatorTurnClosureIntentV1(
                event_id=session.event_id,
                case_id=state.case_id,
                final_turn_id=turn.turn_id,
                outcome=outcome,
                reason_code=reason_code,
            )
        elif budget_exhausted:
            closure = FrontierInvestigatorTurnClosureIntentV1(
                event_id=session.event_id,
                case_id=state.case_id,
                final_turn_id=turn.turn_id,
                outcome="gap",
                reason_code="budget_exhausted",
            )
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state, "Event frontier turn budget ended with unresolved references."
                    )
                }
            )
        if call is not None:
            state = state.model_copy(
                update={"provider_calls": (*state.provider_calls, call)[-128:]}
            )
        try:
            state = self._save(
                state,
                "event_frontier_turn",
                "Bounded event attention recorded with exact stored-evidence custody.",
                frontier_turn_completion=completion,
                frontier_item_transition=transition,
                frontier_session_closure=closure,
            )
        except ValueError as error:
            race_reasons: dict[
                str, Literal["deadline_expired", "stale_context", "source_unverifiable"]
            ] = {
                "investigator completion deadline expired": "deadline_expired",
                "investigator completion catalog generation is stale": "stale_context",
                "investigator source unverifiable": "source_unverifiable",
                "investigator source unverifiable requires explicit gap": "source_unverifiable",
            }
            race_reason = race_reasons.get(str(error))
            if race_reason is None or (
                completion.outcome not in {"focused_delivery", "no_new_fact"}
                and race_reason != "source_unverifiable"
            ):
                raise
            # The rejected transaction rolled back the selected-item transition
            # and checkpoint. Preserve every unresolved reference as a gap.
            state, context = initial_state, initial_context
            state = state.model_copy(
                update={
                    "warnings": self._warnings(
                        state, f"Event frontier gap: frontier_{race_reason}_before_commit."
                    )
                }
            )
            state = self._save(
                state,
                "event_frontier_turn",
                "Reserved attention became stale before focused delivery committed.",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                    turn_id=turn.turn_id,
                    case_id=state.case_id,
                    outcome="gap",
                    reason_code=race_reason,
                    remaining_item_ids=item_ids,
                    cursor_after=cursor_after,
                    focused_context_sha256=focused_digest,
                ),
                frontier_item_transition=(
                    FrontierInvestigatorItemTransitionV1(
                        item_id=selected_item_id,
                        expected_status=FrontierStatus.RUNNING,
                        terminal_status=FrontierStatus.OBSOLETE,
                        reason="delivery_changed_before_commit",
                    )
                    if selected_item_id is not None
                    else None
                ),
                frontier_session_closure=FrontierInvestigatorTurnClosureIntentV1(
                    event_id=session.event_id,
                    case_id=state.case_id,
                    final_turn_id=turn.turn_id,
                    outcome="gap",
                    reason_code=race_reason,
                ),
            )
        return state, context, True

    def _frontier_retrieval(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> tuple[InvestigationState, tuple[EvidenceContext, ...], bool]:
        """Rank exact case retrieval, observed graph branches, and deep review.

        Measurement candidates are deliberately absent here. Their registry can
        attest a target and window, but only the separate candidate-dispatch
        admission path may authorize and account for their execution.
        """

        ranker = self.frontier_ranker
        if ranker is None or self.knowledge is None or self._remaining_ms(state) <= 100:
            return state, context, False
        reserved = tuple(
            dict.fromkeys(
                (
                    *(item.evidence_id for item in state.requested_details),
                    *state.requested_evidence_ids,
                )
            )
        )
        if len(reserved) >= 8:
            return state, context, False
        deadline = min(state.deadline_at, utc_now() + timedelta(seconds=1.5))
        if deadline <= utc_now() + timedelta(milliseconds=50):
            return state, context, False
        started_at = utc_now()
        started = time.monotonic()
        retriever = EvidenceRetriever(self.store)
        frontier = SearchFrontierRepository(self.store)
        step: FrontierPolicyStepV1 | None = None
        try:
            generation = retriever.discover(
                EvidenceCatalogQuery(case_id=state.case_id, limit=1)
            ).case_evidence_generation
            versions = RelevantVersionsV1(
                # A case objective is immutable. Checkpoint writes are not
                # objective revisions and must not churn frontier identities.
                objective=1,
                evidence=generation,
                graph=self.knowledge.pack.version,
            )
            packet = self.knowledge.focused_packet(
                objective=state.objective,
                hypothesis_briefs=tuple(item.statement for item in state.hypotheses[:3]),
                max_relations=6,
                max_chars=6_000,
            )
            visible_ids = tuple(
                dict.fromkeys(
                    item.evidence_id for item in context if item.case_scope == "current_case"
                )
            )[:64]
            visible = set(visible_ids)
            scoped_records: dict[EvidenceId, bool] = {}

            def current_incident_record(evidence_id: EvidenceId) -> bool:
                if evidence_id not in scoped_records:
                    row = self.store.evidence(
                        case_id=str(state.case_id), evidence_id=str(evidence_id)
                    )
                    record = (
                        EvidenceRecord.model_validate_json(row.record_json)
                        if row is not None
                        else None
                    )
                    scoped_records[evidence_id] = bool(
                        record is not None
                        and record.case_id == state.case_id
                        and record.evidence_id == evidence_id
                        and record.statement_kind is StatementKind.OBSERVED_FACT
                        and (
                            state.incident_start <= record.observed_at <= state.incident_end
                            or record.captured_at >= state.created_at
                        )
                    )
                return scoped_records[evidence_id]

            relation_repository = EvidenceRelationRepository(self.store)
            branch_relations = tuple(
                (relation.relation_id, relation.relation_version)
                for relation in relation_repository.prioritized_relations(
                    evidence_ids=visible_ids, limit=64
                )
                if relation.memory_layer is MemoryLayer.MACHINE
                and relation.assertion_status is AssertionStatus.OBSERVED
                and relation.is_valid_at(utc_now())
                and relation.evidence_ids
                and any(evidence_id not in visible for evidence_id in relation.evidence_ids)
                and all(
                    current_incident_record(evidence_id) for evidence_id in relation.evidence_ids
                )
            )[:4]
            discovered = seed_frontier_discovery(
                case_id=state.case_id,
                retriever=retriever,
                frontier=frontier,
                versions=versions,
                candidates=(),
                knowledge=packet,
                packet_evidence_ids=visible_ids,
                source_store=self.store,
                branch_relations=branch_relations,
                consult_deep=not self._has_deep_work(),
                page_limit=32,
                max_pages=4,
                max_items=32,
            )
            requested = tuple(
                item for item in discovered.items if item.status is FrontierStatus.REQUESTED
            )
            if not requested:
                return state, context, False
            entries: dict[EvidenceId, EvidenceCatalogEntry] = {}
            cursor = None
            for _ in range(4):
                page = retriever.discover(
                    EvidenceCatalogQuery(case_id=state.case_id, cursor=cursor, limit=32)
                )
                if page.case_evidence_generation != generation:
                    raise ValueError("frontier catalog changed during source readback")
                entries.update((entry.evidence_id, entry) for entry in page.entries)
                cursor = page.next_cursor
                if cursor is None:
                    break
            items = tuple(
                item
                for item in requested
                if item.reference.kind in {"review_branch", "consult_deep"}
                or (
                    item.reference.evidence_id in entries
                    and (
                        state.incident_start
                        <= entries[item.reference.evidence_id].observed_at
                        <= state.incident_end
                        or entries[item.reference.evidence_id].captured_at >= state.created_at
                    )
                )
            )[:8]
            if not items:
                return state, context, False
            step = run_frontier_step(
                case_id=state.case_id,
                items=items,
                versions=versions,
                symptom=state.objective,
                hypothesis_briefs=tuple(item.statement[:240] for item in state.hypotheses[:8]),
                deadline_at=deadline,
                provider=ranker.provider,
                model_weight_sha256=ranker.model_weight_sha256,
                catalog_entries=tuple(
                    entries[item.reference.evidence_id]
                    for item in items
                    if item.reference.evidence_id is not None
                ),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=state.state_version,
                store=self.store,
                retriever=retriever,
                frontier=frontier,
                ranker=ranker,
                evidence_packets=tuple(
                    SemanticPacketRefV1.model_validate(item)
                    for item in evidence_packets(context)[:24]
                ),
                defer_retrieval_satisfaction=True,
            )
            call = ProviderCall(
                role="catalog_attention",
                provider_id=ranker.provider.provider_id,
                provider_version=ranker.provider.provider_version,
                state_version=state.state_version,
                started_at=started_at,
                elapsed_ms=(time.monotonic() - started) * 1000,
                degraded=step.ranking.model_abstained,
                detail=(
                    "frontier_" + step.ranking.degraded_reason
                    if step.ranking.degraded_reason is not None
                    else "frontier_laya"
                ),
            )
            branch_item_id: str | None = None
            if step.deep_question_id is not None:
                state, task_sha = self._queue_deep_review(state, context, step.deep_question_id)
                if task_sha is None:
                    frontier.transition(
                        step.selected.item_id,
                        FrontierStatus.CLAIMED,
                        FrontierStatus.OBSOLETE,
                        "deep_review_not_admitted",
                    )
                    return state, context, False
                frontier.transition(
                    step.selected.item_id,
                    FrontierStatus.CLAIMED,
                    FrontierStatus.ADMITTED,
                    "deep_review_admitted",
                )
                frontier.transition(
                    step.selected.item_id,
                    FrontierStatus.ADMITTED,
                    FrontierStatus.RUNNING,
                    "deep_review_running",
                )
                state = self._save(
                    state.model_copy(
                        update={"provider_calls": (*state.provider_calls, call)[-128:]}
                    ),
                    "frontier_deep_handoff",
                    f"Question {step.deep_question_id}: frozen deep task {task_sha}",
                )
                if self._last_deep_admission is not None:
                    self._close_deep_frontier(self._last_deep_admission)
                return state, context, False
            if step.branch_relation is not None:
                branch = process_claimed_branch(
                    case_id=state.case_id,
                    selected=step.selected,
                    branch_relation=step.branch_relation,
                    current_packet_evidence_ids=visible_ids,
                    expected_versions=versions,
                    store=self.store,
                    retriever=retriever,
                    frontier=frontier,
                )
                if branch.status is not FrontierStatus.RUNNING or branch.evidence is None:
                    return state, context, False
                branch_item_id = branch.item_id
                selected_id = branch.evidence.evidence_id
            elif (
                step.retrieval is not None
                and step.retrieval.status is FrontierStatus.RUNNING
                and step.retrieval.evidence is not None
            ):
                selected_id = step.retrieval.evidence.evidence_id
            else:
                return state, context, False
            selected = tuple(dict.fromkeys((selected_id, *state.fast_catalog_selected_ids)))[:8]
            tentative = state.model_copy(
                update={
                    "schema_version": 5,
                    "fast_catalog_generation": generation,
                    "fast_catalog_selected_ids": selected,
                }
            )
            expanded = self.context(str(state.case_id), state=tentative)
            delivered = str(selected_id) in {str(item.evidence_id) for item in expanded}
            current_generation = retriever.discover(
                EvidenceCatalogQuery(case_id=state.case_id, limit=1)
            ).case_evidence_generation
            if not delivered or current_generation != generation:
                if branch_item_id is not None:
                    frontier.transition(
                        branch_item_id,
                        FrontierStatus.RUNNING,
                        FrontierStatus.OBSOLETE,
                        "focused_delivery_changed",
                    )
                raise ValueError("frontier retrieval was not delivered in a stable case packet")
            state = self._save(
                tentative.model_copy(
                    update={
                        "provider_calls": (*state.provider_calls, call)[-128:],
                    }
                ),
                "frontier_branch_retrieved" if branch_item_id else "frontier_retrieved",
                "Exact stored case evidence selected by bounded frontier attention.",
            )
            if branch_item_id is not None or step.retrieval is not None:
                frontier.transition(
                    branch_item_id or step.selected.item_id,
                    FrontierStatus.RUNNING,
                    FrontierStatus.SATISFIED,
                    "focused_delivery_confirmed",
                )
            return state, expanded, True
        except Exception as error:
            if step is not None:
                claimed = frontier.readback(step.selected.item_id)
                if claimed.status in {
                    FrontierStatus.CLAIMED,
                    FrontierStatus.ADMITTED,
                    FrontierStatus.RUNNING,
                }:
                    frontier.transition(
                        claimed.item_id,
                        claimed.status,
                        FrontierStatus.OBSOLETE,
                        "frontier_policy_failed_before_delivery",
                    )
            state = self._save(
                state.model_copy(
                    update={
                        "warnings": self._warnings(
                            state,
                            f"Frontier attention unavailable: {type(error).__name__}.",
                        )
                    }
                ),
                "frontier_fallback",
                "Frontier selection failed closed; ordinary catalog and probe routing remain.",
            )
            return state, context, False

    def _catalog_attention(
        self,
        state: InvestigationState,
        context: tuple[EvidenceContext, ...],
    ) -> tuple[InvestigationState, tuple[EvidenceContext, ...], bool]:
        """Let a bounded fast ranker select IDs, then load only persisted facts.

        The metadata page is an index, never an observation. A generation change
        during inference invalidates the whole selection before it reaches either
        brain's evidence context.
        """

        assert self.catalog_attention is not None
        if not self._retrieval_omitted_evidence(context):
            return state, context, False
        reserved = tuple(
            dict.fromkeys(
                (
                    *(item.evidence_id for item in state.requested_details),
                    *state.requested_evidence_ids,
                )
            )
        )
        if len(reserved) >= 8:
            # The deep brain's exact requests own all packet priority slots.
            # Defer metadata ranking until one is released; no model time or
            # seen marker should be spent on an undeliverable suggestion.
            return state, context, False
        deadline = min(state.deadline_at, utc_now() + timedelta(seconds=1.5))
        if deadline <= utc_now() + timedelta(milliseconds=50):
            return state, context, False
        retriever = EvidenceRetriever(self.store)
        query = EvidenceCatalogQuery(
            case_id=state.case_id,
            observed_from=state.incident_start,
            observed_until=state.incident_end,
            current_collection_start=state.created_at,
            limit=64,
        )
        generation = retriever.discover(
            query.model_copy(update={"limit": 1})
        ).case_evidence_generation
        if (
            state.fast_catalog_generation is not None
            and state.fast_catalog_generation != generation
        ):
            state = self._save(
                state.model_copy(
                    update={
                        "fast_catalog_generation": generation,
                        "fast_catalog_cursor": None,
                        "fast_catalog_seen_ids": (),
                        "fast_catalog_selected_ids": (),
                    }
                ),
                "catalog_reset",
                "Case evidence changed; prior metadata attention was discarded.",
            )
            context = self.context(str(state.case_id), state=state)
        seen = state.fast_catalog_seen_ids if state.fast_catalog_generation == generation else ()
        selected = (
            state.fast_catalog_selected_ids if state.fast_catalog_generation == generation else ()
        )
        cursor = state.fast_catalog_cursor if state.fast_catalog_generation == generation else None
        original_cursor = cursor
        visible = {str(item.evidence_id) for item in context}
        seen_keys = {str(item) for item in seen}
        # Stratify one bounded attention window across up to four catalog pages.
        # A cursor advances only when its first page has been exposed in full;
        # the seen set prevents repeats while later pages remain reachable.
        entries_list: list[EvidenceCatalogEntry] = []
        next_cursor = cursor
        first_page_available: tuple[EvidenceId, ...] = ()
        first_page_next_cursor = None
        for page_index, quota in enumerate((8, 6, 4, 2)):
            page = retriever.discover(query.model_copy(update={"cursor": next_cursor}))
            if page.case_evidence_generation != generation:
                return state, context, True
            available = tuple(
                item
                for item in page.entries
                if str(item.evidence_id) not in visible and str(item.evidence_id) not in seen_keys
            )
            chosen = available[:quota]
            entries_list.extend(chosen)
            if page_index == 0:
                first_page_available = tuple(item.evidence_id for item in available)
                first_page_next_cursor = page.next_cursor
            next_cursor = page.next_cursor
            if next_cursor is None:
                break
        entries = tuple(entries_list)
        if not entries:
            if next_cursor is not None and state.fast_catalog_cursor != next_cursor:
                state = self._save(
                    state.model_copy(
                        update={
                            "schema_version": 5,
                            "fast_catalog_generation": generation,
                            "fast_catalog_cursor": next_cursor,
                            "fast_catalog_seen_ids": seen,
                            "fast_catalog_selected_ids": selected,
                        }
                    ),
                    "catalog_advanced",
                    "No unseen metadata in four catalog pages; advanced the bounded cursor.",
                )
            return state, context, False
        # Metadata is untrusted and can be long even when each field is valid.
        # Fit the typed byte cap without letting a long summary crash the case.
        while entries:
            try:
                request = CatalogAttentionRequest.from_page(
                    case_id=state.case_id,
                    page=EvidenceCatalogPage(
                        entries=entries,
                        case_evidence_generation=generation,
                    ),
                    visible_evidence_ids=(),
                    deadline_at=deadline,
                    attention_goal=state.objective[:240],
                )
                break
            except ValueError:
                entries = entries[:-1]
        else:
            return state, context, False
        if {str(item) for item in first_page_available} <= {
            str(item.evidence_id) for item in entries
        }:
            cursor = first_page_next_cursor
        started_at = utc_now()
        started = time.monotonic()
        provider_id = type(self.catalog_attention).__name__[:80]
        failure: str | None = None
        ranked: tuple[EvidenceId, ...] = ()
        degraded = False
        try:
            response = self.catalog_attention.rank_catalog(request).validate_against(request)
            degraded = response.degraded
            ranked = response.ranked_evidence_ids
        except Exception as error:
            failure = type(error).__name__
            degraded = True
        # A writer may append evidence while the ranker runs. Never act on an
        # ID ordering from that obsolete snapshot, even if the ID still exists.
        stale = (
            retriever.discover(query.model_copy(update={"limit": 1})).case_evidence_generation
            != generation
        )
        if stale:
            ranked = ()
            degraded = True
            failure = "stale catalog generation"
        elif not degraded and ranked:
            tentative = state.model_copy(
                update={
                    "schema_version": 5,
                    "fast_catalog_generation": generation,
                    "fast_catalog_seen_ids": tuple(
                        dict.fromkeys((*seen, *(item.evidence_id for item in entries)))
                    )[-128:],
                    "fast_catalog_selected_ids": tuple(dict.fromkeys((*ranked, *selected)))[:8],
                }
            )
            expanded = self.context(str(state.case_id), state=tentative)
            delivered = {str(item.evidence_id) for item in expanded}
            if (
                retriever.discover(query.model_copy(update={"limit": 1})).case_evidence_generation
                != generation
            ):
                ranked = ()
                degraded = True
                failure = "stale catalog generation"
            else:
                if ranked and all(str(item) in delivered for item in ranked):
                    selected = tuple(dict.fromkeys((*ranked, *selected)))[:8]
                    context = expanded
                else:
                    failure = "ranked evidence did not fit the bounded packet"
                    degraded = True
        next_state = state.model_copy(
            update={
                "schema_version": 5,
                "fast_catalog_generation": generation,
                "fast_catalog_cursor": cursor if not degraded else original_cursor,
                "fast_catalog_seen_ids": tuple(
                    dict.fromkeys((*seen, *(item.evidence_id for item in entries)))
                )[-128:]
                if not degraded
                else (() if stale else seen),
                "fast_catalog_selected_ids": selected if not stale else (),
                "provider_calls": (
                    *state.provider_calls,
                    ProviderCall(
                        role="catalog_attention",
                        provider_id=provider_id,
                        provider_version="1",
                        state_version=state.state_version,
                        started_at=started_at,
                        elapsed_ms=(time.monotonic() - started) * 1000,
                        degraded=degraded,
                        detail=failure[:120] if failure else None,
                    ),
                )[-128:],
                "warnings": self._warnings(
                    state,
                    f"Catalog attention rejected {failure}."
                    if failure
                    else "Catalog attention degraded; exact evidence was not selected.",
                )
                if degraded
                else state.warnings,
            }
        )
        with self.store.transaction() as transaction:
            transaction.append_coordinator_event(
                case_id=str(state.case_id),
                kind="provider",
                fields={
                    "role": "catalog_attention",
                    "attempted_provider_id": provider_id,
                    "effective_provider_id": provider_id if not degraded else "none",
                    "failed": degraded,
                },
            )
        saved = self._save(
            next_state,
            "catalog_attention",
            f"Metadata rank loaded {len(ranked)} exact case observations."
            if not degraded
            else f"Metadata rank rejected: {failure or 'provider degraded'}.",
        )
        return (
            saved,
            context,
            degraded and failure != "ranked evidence did not fit the bounded packet",
        )

    def _save(
        self,
        state: InvestigationState,
        event: str,
        detail: str,
        *,
        frontier_turn_completion: (
            FrontierInvestigatorTurnCompletionV1 | FrontierInvestigatorTurnCompletionV3 | None
        ) = None,
        frontier_item_transition: FrontierInvestigatorItemTransitionV1 | None = None,
        frontier_session_closure: FrontierInvestigatorTurnClosureIntentV1 | None = None,
        frontier_measurement_admission: FrontierMeasurementAdmissionIntent | None = None,
    ) -> InvestigationState:
        if (
            frontier_turn_completion is None
            and frontier_item_transition is None
            and frontier_session_closure is None
            and frontier_measurement_admission is None
        ):
            return self.repository.save(
                state, expected_version=state.state_version, event=event, detail=detail
            )
        return self.repository.save(
            state,
            expected_version=state.state_version,
            event=event,
            detail=detail,
            frontier_turn_completion=frontier_turn_completion,
            frontier_item_transition=frontier_item_transition,
            frontier_session_closure=frontier_session_closure,
            frontier_measurement_admission=frontier_measurement_admission,
        )

    @staticmethod
    def _warnings(state: InvestigationState, message: str) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*state.warnings, message)))[-64:]

    @staticmethod
    def _fingerprint(context: tuple[EvidenceContext, ...]) -> str:
        # A new failed/denied/unsupported record updates coverage and remains
        # visible to the user, but it cannot by itself distinguish root causes.
        # Clock-inconsistent facts also cannot be counted as investigative gain.
        # Summaries and repeated equivalent records are presentation/retrieval
        # changes, not new observations. This remains a novelty fallback, not
        # a verified uncertainty-resolution ledger.
        payload = sorted(
            {
                json.dumps(
                    (item.probe_id, item.status.value, item.facts),
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
            }
        )
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def _opened(state: InvestigationState, proposals: tuple[ProbeProposal, ...]) -> OpenedCase:
        selected_ids = {proposal.probe_id for proposal in proposals}
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
                        depends_on=tuple(
                            dependency for dependency in p.depends_on if dependency in selected_ids
                        ),
                    )
                    for p in proposals
                ),
                total_cost_ms=sum(p.estimated_cost_ms for p in proposals),
                skipped_fresh=(),
                skipped_budget=(),
                skipped_low_value=(),
            ),
        )
