"""Execute a case plan and atomically persist normalized evidence and audit data."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
import warnings
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from systemsense.application.candidate_catalog import (
    general_measurement_candidate_catalog,
    process_pressure_candidate_catalog,
)
from systemsense.application.case_service import CaseService, OpenedCase
from systemsense.application.fair_model_turns import FairModelTurns, ModelTurnRegistration
from systemsense.application.targets import (
    InventoryProcessBinding,
    ProcessTargetBinding,
    ProcessTargetRepository,
    TargetSelectionError,
)
from systemsense.audit import AuditChain, AuditOutcome
from systemsense.decision.contracts import DecisionRequest, PermissionClass, ProbeCapability
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.domain.cases import CaseKind, CaseStatus
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import (
    CaseId,
    EntityId,
    EvidenceId,
    ExecutionId,
    JsonValue,
    stable_source_id,
)
from systemsense.domain.inventory import InventoryFact
from systemsense.domain.probes import (
    MeasurementNeed,
    Privilege,
    ProbeInvocation,
    ProbeManifest,
    SafetyClass,
)
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.redaction import Redactor
from systemsense.orchestration.invocations import (
    MeasurementRegistry,
    ObservabilityGap,
    RegisteredMeasurement,
    RegisteredTarget,
)
from systemsense.orchestration.planner import PlannedProbe
from systemsense.orchestration.probe_capacity_ledger import (
    DurableProbeLedger,
    LedgerBudget,
    LedgerUnavailable,
)
from systemsense.orchestration.probes import (
    ProbeObservation,
    ProbeRun,
    ProbeRunner,
    ProbeRunStatus,
)
from systemsense.orchestration.scheduler import (
    BlockingTaskOfferQueue,
    BoundedScheduler,
    HostWorkArbiter,
    ResourceBudget,
    ResourceClass,
    Task,
    TaskContext,
    TaskResult,
    TaskStatus,
)
from systemsense.packs.runtime import TargetPressureParametersV1
from systemsense.policy import PolicyDenied
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import (
    CandidateDispatchAdmission,
    CandidateDispatchAdmissionRepository,
)
from systemsense.storage.case_candidates import CandidateGap, CaseCandidateRegistry
from systemsense.storage.decision_snapshots import ProbeManifestRef
from systemsense.storage.followup_admissions import (
    FollowupAdmission,
    FollowupAdmissionRepository,
)
from systemsense.storage.presented_read_set import PresentedReadSetV1
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore, StaleCaseStateError

_HOST_ENTITY_ID = EntityId(
    root=f"entity_{hashlib.sha256(b'systemsense.local-host').hexdigest()[:32]}"
)


@dataclass(frozen=True, slots=True)
class PersistedProbeResult:
    """One committed parent execution visible to an owner-thread follow-up policy."""

    task_id: str
    case_id: str
    epoch_state_version: int
    probe_id: str
    execution_id: ExecutionId
    evidence_generation: int
    trigger_evidence_sha256: str
    frontier_event_id: str | None = None


@dataclass(frozen=True, slots=True)
class _OfferContext:
    trigger_execution_id: str
    task_id: str
    candidate_probe_id: str
    decision_snapshot_id: str | None

    def audit_fields(self) -> dict[str, JsonValue]:
        return {
            "trigger_execution_id": self.trigger_execution_id,
            "task_id": self.task_id,
            "candidate_probe_id": self.candidate_probe_id,
            "decision_snapshot_id": self.decision_snapshot_id or "",
        }


# Model callbacks take fair, bounded turns across cases in this interpreter.
# GPU admission and cross-process ownership remain separate concerns.
_FAIR_MODEL_TURNS = FairModelTurns(max_registered=16)

_DEFAULT_PROBE_BUDGET = ResourceBudget(
    global_limit=4,
    per_resource={
        ResourceClass.DISK: 1,
        ResourceClass.GPU: 1,
        ResourceClass.INFERENCE: 1,
    },
)
# Non-Windows default runtimes share this budget only within the interpreter.
_SHARED_PROBE_ARBITER = HostWorkArbiter(_DEFAULT_PROBE_BUDGET)
_DURABLE_PROBE_ARBITERS: dict[str, HostWorkArbiter] = {}
_DURABLE_PROBE_ARBITERS_LOCK = threading.Lock()


def default_probe_arbiter(store: SQLiteStore) -> HostWorkArbiter:
    """Share one durable probe budget among Windows default runtimes."""
    if sys.platform != "win32":
        return _SHARED_PROBE_ARBITER
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data or not Path(local_app_data).is_absolute():
        raise LedgerUnavailable("absolute LOCALAPPDATA is required for probe capacity")
    ledger_dir = Path(local_app_data) / "SystemSense"
    try:
        ledger_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise LedgerUnavailable("probe capacity ledger unavailable") from error
    ledger_path = (ledger_dir / "host-probe-capacity-v1.sqlite3").resolve()
    with _DURABLE_PROBE_ARBITERS_LOCK:
        arbiter = _DURABLE_PROBE_ARBITERS.get(str(ledger_path))
        if arbiter is None:
            ledger = DurableProbeLedger(
                ledger_path,
                LedgerBudget(
                    global_limit=_DEFAULT_PROBE_BUDGET.global_limit,
                    per_resource={
                        resource.value: limit
                        for resource, limit in _DEFAULT_PROBE_BUDGET.per_resource.items()
                    },
                    max_pending=_DEFAULT_PROBE_BUDGET.max_tasks,
                ),
                schema_hash="systemsense-registered-isolated-probes-v1",
            )
            arbiter = HostWorkArbiter(_DEFAULT_PROBE_BUDGET, ledger=ledger)
            _DURABLE_PROBE_ARBITERS[str(ledger_path)] = arbiter
    return arbiter


def default_probe_scheduler(store: SQLiteStore) -> BoundedScheduler:
    return BoundedScheduler(
        budget=_DEFAULT_PROBE_BUDGET,
        host_arbiter=default_probe_arbiter(store),
    )


@dataclass(frozen=True, slots=True)
class FollowupSelection:
    """A catalog ID and optional frozen decision, never probe parameters."""

    probe_id: str
    decision_snapshot_id: str | None = None
    presented_read_set: PresentedReadSetV1 | None = None
    unprotected_historical_count: int = 0


@dataclass(frozen=True, slots=True)
class CandidateFollowupSelection:
    """An exact locally registered candidate selected from a frozen request."""

    probe_id: str
    candidate_id: str
    decision_snapshot_id: str


def _valid_followup_selection(value: object) -> bool:
    """Check the runtime boundary even if a provider ignores its type contract."""

    if not isinstance(value, FollowupSelection):
        return False
    probe_id: object = object.__getattribute__(value, "probe_id")
    snapshot_id: object = object.__getattribute__(value, "decision_snapshot_id")
    read_set: object = object.__getattribute__(value, "presented_read_set")
    historical_count: object = object.__getattribute__(value, "unprotected_historical_count")
    return (
        isinstance(probe_id, str)
        and (snapshot_id is None or (isinstance(snapshot_id, str) and len(snapshot_id) <= 80))
        and (read_set is None or isinstance(read_set, PresentedReadSetV1))
        and (isinstance(historical_count, int) and 0 <= historical_count <= 256)
    )


def _sqlite_writer_busy(error: sqlite3.OperationalError) -> bool:
    code: object = getattr(error, "sqlite_errorcode", None)
    return isinstance(code, int) and (code & 0xFF) in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }


def _process_binding_still_current(
    store: SQLiteStore,
    case_id: CaseId,
    binding: ProcessTargetBinding | InventoryProcessBinding,
) -> bool:
    repository = ProcessTargetRepository(store)
    if isinstance(binding, InventoryProcessBinding):
        current = repository.resolve_process_candidate_for_sampling(case_id, binding.candidate_id)
        # Validation time advances between owner and worker; the source identity
        # and exact PID/creation binding must not.
        return current.model_dump(exclude={"validated_at"}) == binding.model_dump(
            exclude={"validated_at"}
        )
    return repository.resolve_process_target_for_sampling(case_id) == binding


class DiagnosticRuntime:
    """Complete case creation, execution, normalization, and persistence."""

    def __init__(
        self,
        *,
        store: SQLiteStore,
        case_service: CaseService,
        probe_runner: ProbeRunner,
        redactor: Redactor | None = None,
        scheduler: BoundedScheduler | None = None,
    ) -> None:
        self._store = store
        self._case_service = case_service
        self._probe_runner = probe_runner
        self._redactor = redactor or Redactor()
        self._scheduler = scheduler if scheduler is not None else default_probe_scheduler(store)

    def probe_manifest(self, probe_id: str) -> ProbeManifest | None:
        """Resolve one registered manifest for private decision snapshot provenance."""

        return self._probe_runner.manifest(probe_id)

    def candidate_catalog(
        self, case_id: CaseId, *, store: SQLiteStore | None = None
    ) -> tuple[CaseCandidateRegistry, tuple[MeasurementNeed, ...]]:
        """Expose only application-registered, inventory-bound read-only choices."""

        return process_pressure_candidate_catalog(
            self._store if store is None else store, self._probe_runner, case_id
        )

    def general_candidate_catalog(
        self, case_id: CaseId, *, store: SQLiteStore | None = None
    ) -> tuple[CaseCandidateRegistry, tuple[MeasurementNeed, ...]]:
        """Expose case-bound, parameter-free host measurements for general cases."""
        return general_measurement_candidate_catalog(
            self._store if store is None else store, self._probe_runner, case_id
        )

    def admit_persisted_candidate_followup(
        self,
        parent: PersistedProbeResult,
        *,
        candidate_id: str,
        snapshot_id: str,
        task_id: str,
    ) -> CandidateDispatchAdmission:
        """Reserve an exact, parent-bound candidate before any worker launch.

        This is admission only. A scheduler must still claim once and execute
        through the registered probe boundary using the returned identity.
        """

        case_id = CaseId(root=parent.case_id)
        row = self._store.connection.execute(
            "SELECT probe_id FROM case_measurement_candidates "
            "WHERE candidate_id=? AND case_id=? AND epoch_state_version=?",
            (candidate_id, parent.case_id, parent.epoch_state_version),
        ).fetchone()
        if row is None:
            raise ValueError("candidate follow-up is not registered in the parent epoch")
        probe_id = str(row[0])
        if probe_id == "application.target_pressure":
            registry, _ = self.candidate_catalog(case_id)
        elif probe_id in {"pressure.sample", "gpu.telemetry.sample"}:
            registry, _ = self.general_candidate_catalog(case_id)
        else:
            raise ValueError("candidate follow-up probe is not an admitted local catalog")
        resolved = registry.resolve(case_id, parent.epoch_state_version, candidate_id)
        if isinstance(resolved, CandidateGap) or resolved.candidate.probe_id != probe_id:
            raise ValueError("candidate follow-up source or target is unavailable")
        return CandidateDispatchAdmissionRepository(
            self._store, registry=registry
        ).admit_after_parent(
            snapshot_id=snapshot_id,
            candidate_id=candidate_id,
            case_id=case_id,
            epoch_state_version=parent.epoch_state_version,
            task_id=task_id,
            invocation_sha256=resolved.candidate.invocation_sha256,
            cost_ms=resolved.candidate.cost_ms,
            trigger_execution_id=str(parent.execution_id),
            trigger_evidence_sha256=parent.trigger_evidence_sha256,
        )

    def open_case(
        self,
        *,
        kind: CaseKind,
        symptom: str,
        target_traits: tuple[str, ...],
        created_at: UtcDateTime,
        budget_ms: int,
        max_probes: int,
    ) -> OpenedCase:
        opened = self._case_service.open_case(
            kind=kind,
            symptom=symptom,
            target_traits=frozenset(target_traits),
            created_at=created_at,
            budget_ms=budget_ms,
            max_probes=max_probes,
        )
        self.execute_plan(opened)
        with self._store.transaction() as transaction:
            state_version = transaction.transition_case(
                case_id=str(opened.case.case_id),
                expected_state_version=opened.case.state_version,
                status=CaseStatus.READY.value,
            )
        return OpenedCase(
            case=opened.case.model_copy(
                update={"status": CaseStatus.READY, "state_version": state_version}
            ),
            plan=opened.plan,
            deadline_at=opened.deadline_at,
        )

    def execute_plan(
        self,
        opened: OpenedCase,
        *,
        cancel_event: threading.Event | None = None,
        on_persisted: Callable[[ProbeRun], None] | None = None,
        decision_snapshot_id: str | None = None,
        followup_capabilities: tuple[ProbeCapability, ...] = (),
        offer_followup: Callable[[PersistedProbeResult], FollowupSelection | None] | None = None,
        async_offer_followup: (
            Callable[
                [PersistedProbeResult, SQLiteStore],
                FollowupSelection | CandidateFollowupSelection | None,
            ]
            | None
        ) = None,
        diagnostic_admissions_by_instance: Mapping[str, str] | None = None,
    ) -> tuple[TaskResult, ...]:
        """Execute one plan, persisting each completion on the owning thread.

        Follow-up capabilities are application-owned catalog entries, not model
        output. The provider callback may select only their registered IDs.
        """
        if (offer_followup is not None and async_offer_followup is not None) or bool(
            followup_capabilities
        ) != (offer_followup is not None or async_offer_followup is not None):
            raise ValueError("follow-up catalog and callback must be supplied together")
        return self._execute_plan(
            opened,
            cancel_event=cancel_event,
            on_persisted=on_persisted,
            decision_snapshot_id=decision_snapshot_id,
            parameters_by_probe={},
            audit_binding={},
            followup_capabilities=followup_capabilities,
            offer_followup=offer_followup,
            async_offer_followup=async_offer_followup,
            diagnostic_admissions_by_instance=diagnostic_admissions_by_instance,
        )

    def execute_bound_target_pressure(
        self,
        opened: OpenedCase,
        *,
        cancel_event: threading.Event | None = None,
    ) -> tuple[TaskResult, ...]:
        """Run only the selected process probe from a revalidated case binding."""
        if len(opened.plan.probes) != 1 or opened.plan.probes[0].probe_id != (
            "application.target_pressure"
        ):
            raise ValueError("bound target execution requires only application.target_pressure")
        current_case = self._store.case(str(opened.case.case_id))
        if (
            current_case is None
            or current_case.state_version != opened.case.state_version
            or current_case.status != CaseStatus.COLLECTING.value
        ):
            raise ValueError("target execution case is no longer collecting at this version")
        try:
            binding = ProcessTargetRepository(self._store).resolve_process_target_for_sampling(
                opened.case.case_id
            )
        except TargetSelectionError as error:
            now = datetime.now(UTC)
            unavailable = ProbeRun(
                execution_id=ExecutionId.new(),
                probe_id="application.target_pressure",
                status=ProbeRunStatus.UNAVAILABLE,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                error=f"Bound process target unavailable: {error}",
            )
            return self._execute_plan(
                opened,
                cancel_event=cancel_event,
                on_persisted=None,
                decision_snapshot_id=None,
                parameters_by_probe={},
                audit_binding={"target_binding_status": "unavailable"},
                preflight_runs={"application.target_pressure": unavailable},
            )
        if opened.case.state_version < binding.case_state_version:
            raise ValueError("target binding is newer than the execution case version")
        parameters: dict[str, JsonValue] = {
            "pid": binding.pid,
            "creation_time": binding.creation_time.isoformat(),
        }
        return self._execute_plan(
            opened,
            cancel_event=cancel_event,
            on_persisted=None,
            decision_snapshot_id=None,
            parameters_by_probe={"application.target_pressure": parameters},
            audit_binding={
                "target_candidate_id": binding.candidate_id,
                "target_evidence_id": str(binding.evidence_id),
                "target_evidence_sha256": binding.evidence_sha256,
            },
        )

    def execute_measurement_need(
        self,
        opened: OpenedCase,
        need: MeasurementNeed,
        *,
        cancel_event: threading.Event | None = None,
        on_persisted: Callable[[ProbeRun], None] | None = None,
        decision_snapshot_id: str | None = None,
    ) -> tuple[TaskResult, ...] | ObservabilityGap:
        """Admit one exact selected-process need, never a model-supplied PID.

        This is the first typed production capability. Other needs remain
        explicit observability gaps until an adapter is registered for them.
        """
        probe_id = "application.target_pressure"
        if need.capability_id != probe_id:
            return ObservabilityGap(need=need, reason="capability has no admitted runtime adapter")
        if len(opened.plan.probes) != 1 or opened.plan.probes[0].probe_id != probe_id:
            return ObservabilityGap(need=need, reason="capability is not in the current case plan")
        current_case = self._store.case(str(opened.case.case_id))
        if (
            current_case is None
            or current_case.state_version != opened.case.state_version
            or current_case.status != CaseStatus.COLLECTING.value
        ):
            return ObservabilityGap(need=need, reason="case plan is no longer collecting")
        manifest = self._probe_runner.manifest(probe_id)
        if manifest is None:
            return ObservabilityGap(need=need, reason="capability is no longer registered")
        if manifest.input_model != TargetPressureParametersV1.__name__:
            return ObservabilityGap(need=need, reason="measurement registration is incompatible")
        try:
            binding = ProcessTargetRepository(self._store).resolve_process_target_for_sampling(
                opened.case.case_id
            )
        except TargetSelectionError:
            return ObservabilityGap(need=need, reason="selected process target is unavailable")
        if opened.case.state_version < binding.case_state_version:
            return ObservabilityGap(need=need, reason="selected process binding is newer than plan")
        try:
            registry = MeasurementRegistry(
                (
                    RegisteredMeasurement(
                        manifest=manifest,
                        parameter_model=TargetPressureParametersV1,
                        observable=probe_id,
                        targets=(
                            RegisteredTarget(
                                handle=binding.candidate_id,
                                parameters={
                                    "pid": binding.pid,
                                    "creation_time": binding.creation_time.isoformat(),
                                },
                            ),
                        ),
                    ),
                )
            )
            invocation = registry.resolve(need)
        except ValueError:
            return ObservabilityGap(need=need, reason="measurement registration is invalid")
        if isinstance(invocation, ObservabilityGap):
            return invocation
        try:
            return self._execute_plan(
                opened,
                cancel_event=cancel_event,
                on_persisted=on_persisted,
                decision_snapshot_id=decision_snapshot_id,
                parameters_by_probe={probe_id: invocation.parameters},
                audit_binding={
                    "target_candidate_id": binding.candidate_id,
                    "target_evidence_id": str(binding.evidence_id),
                    "target_evidence_sha256": binding.evidence_sha256,
                    "measurement_invocation_id": invocation.dedupe_key,
                },
                bound_target_binding=binding,
                bound_target_invocation=invocation,
            )
        except TargetSelectionError:
            return ObservabilityGap(
                need=need, reason="selected process target changed before execution"
            )

    def execute_candidate_measurement(
        self,
        opened: OpenedCase,
        candidate_id: str,
        snapshot_id: str,
        *,
        cancel_event: threading.Event | None = None,
        launch_continuation_id: str | None = None,
    ) -> tuple[TaskResult, ...] | ObservabilityGap:
        """Admit one frozen choice before scheduling; claim once before host access."""

        planned_probe_id = opened.plan.probes[0].probe_id if len(opened.plan.probes) == 1 else ""
        need = MeasurementNeed(
            capability_id=planned_probe_id or "application.target_pressure",
            observable=planned_probe_id or "application.target_pressure",
        )
        probe_id = need.capability_id
        if len(opened.plan.probes) != 1 or probe_id not in {
            "application.target_pressure",
            "pressure.sample",
            "gpu.telemetry.sample",
        }:
            return ObservabilityGap(need=need, reason="candidate has no current single-probe plan")
        current_case = self._store.case(str(opened.case.case_id))
        if (
            current_case is None
            or current_case.status != CaseStatus.COLLECTING.value
            or current_case.state_version != opened.case.state_version
        ):
            return ObservabilityGap(need=need, reason="candidate collection epoch is stale")
        manifest = self._probe_runner.manifest(probe_id)
        expected_model = (
            TargetPressureParametersV1.__name__
            if probe_id == "application.target_pressure"
            else "NoParametersV1"
        )
        if manifest is None or manifest.input_model != expected_model:
            return ObservabilityGap(need=need, reason="candidate probe registration changed")
        admission: CandidateDispatchAdmission | None = None
        try:
            registry, _ = (
                self.candidate_catalog(opened.case.case_id)
                if probe_id == "application.target_pressure"
                else self.general_candidate_catalog(opened.case.case_id)
                if launch_continuation_id is None
                else general_measurement_candidate_catalog(
                    self._store,
                    self._probe_runner,
                    opened.case.case_id,
                    for_existing_admission=True,
                )
            )
            continuation = (
                None
                if launch_continuation_id is None
                else CandidateDispatchAdmissionRepository(self._store).readback_launch_continuation(
                    launch_continuation_id
                )
            )
            if continuation is None:
                resolved = registry.resolve(
                    opened.case.case_id, opened.case.state_version, candidate_id
                )
            else:
                admission = CandidateDispatchAdmissionRepository(self._store).readback(
                    continuation.admission_id
                )
                if (
                    continuation.case_id != opened.case.case_id
                    or continuation.resulting_checkpoint_version != opened.case.state_version
                    or admission.candidate_id != candidate_id
                    or admission.snapshot_id != snapshot_id
                ):
                    raise ValueError("candidate launch continuation differs from plan")
                resolved = registry.resolve_for_continuation(
                    opened.case.case_id,
                    admission.epoch_state_version,
                    candidate_id,
                    admission.admission_id,
                    continuation.continuation_id,
                )
            if isinstance(resolved, CandidateGap):
                return ObservabilityGap(
                    need=need, reason=f"candidate unavailable: {resolved.reason}"
                )
            invocation = resolved.invocation
            if invocation.probe_id != probe_id or (
                (invocation.target_handle is None)
                != (probe_id in {"pressure.sample", "gpu.telemetry.sample"})
            ):
                return ObservabilityGap(need=need, reason="candidate invocation is unsupported")
            binding = (
                ProcessTargetRepository(self._store).resolve_process_candidate_for_sampling(
                    opened.case.case_id, invocation.target_handle
                )
                if invocation.target_handle is not None
                else None
            )
            prepared = self._probe_runner.prepare_invocation(
                probe_id, invocation.parameters, expected_version=invocation.probe_version
            )
            if prepared.parameters != invocation.parameters:
                return ObservabilityGap(need=need, reason="candidate probe parameters changed")
            task_id = f"probe-0-{opened.plan.probes[0].plan_instance_id}"
            if continuation is None:
                admissions = CandidateDispatchAdmissionRepository(self._store, registry=registry)
                admission = admissions.admit(
                    snapshot_id=snapshot_id,
                    candidate_id=candidate_id,
                    case_id=opened.case.case_id,
                    epoch_state_version=opened.case.state_version,
                    task_id=task_id,
                    invocation_sha256=resolved.candidate.invocation_sha256,
                    cost_ms=resolved.candidate.cost_ms,
                )
            if admission is None or admission.task_id != task_id:
                raise ValueError("candidate launch task differs from admitted task")
            if continuation is None and snapshot_id.startswith("frontier_decision_snapshot_"):
                snapshot = CandidateDecisionSnapshotRepository(self._store).readback_frontier(
                    snapshot_id
                )
                SearchFrontierRepository(self._store).transition(
                    snapshot.selected_item_id,
                    FrontierStatus.CLAIMED,
                    FrontierStatus.ADMITTED,
                    "candidate_admitted",
                )
        except (TargetSelectionError, PolicyDenied, ValueError) as error:
            return ObservabilityGap(need=need, reason=f"candidate dispatch rejected: {error}")
        try:
            return self._execute_plan(
                opened,
                cancel_event=cancel_event,
                on_persisted=None,
                decision_snapshot_id=None,
                parameters_by_probe={probe_id: invocation.parameters},
                audit_binding={
                    "candidate_id": candidate_id,
                    "candidate_admission_id": admission.admission_id,
                    "candidate_snapshot_id": snapshot_id,
                    **(
                        {
                            "target_evidence_id": str(binding.evidence_id),
                            "target_evidence_sha256": binding.evidence_sha256,
                        }
                        if binding is not None
                        else {}
                    ),
                },
                bound_target_binding=binding,
                bound_target_invocation=invocation,
                candidate_admission=admission,
                candidate_resource_class=resolved.candidate.resource_class,
                candidate_launch_continuation_id=launch_continuation_id,
            )
        except TargetSelectionError:
            # The durable intent remains unclaimed and cannot be replayed.
            return ObservabilityGap(need=need, reason="candidate target changed after admission")

    def _execute_plan(
        self,
        opened: OpenedCase,
        *,
        cancel_event: threading.Event | None,
        on_persisted: Callable[[ProbeRun], None] | None,
        decision_snapshot_id: str | None,
        parameters_by_probe: Mapping[str, dict[str, JsonValue]],
        audit_binding: Mapping[str, JsonValue],
        preflight_runs: Mapping[str, ProbeRun] | None = None,
        bound_target_binding: ProcessTargetBinding | InventoryProcessBinding | None = None,
        bound_target_invocation: ProbeInvocation | None = None,
        candidate_admission: CandidateDispatchAdmission | None = None,
        candidate_resource_class: ResourceClass | None = None,
        candidate_launch_continuation_id: str | None = None,
        followup_capabilities: tuple[ProbeCapability, ...] = (),
        offer_followup: Callable[[PersistedProbeResult], FollowupSelection | None] | None = None,
        async_offer_followup: (
            Callable[
                [PersistedProbeResult, SQLiteStore],
                FollowupSelection | CandidateFollowupSelection | None,
            ]
            | None
        ) = None,
        diagnostic_admissions_by_instance: Mapping[str, str] | None = None,
    ) -> tuple[TaskResult, ...]:
        if bound_target_binding is not None and bound_target_invocation is None:
            raise ValueError("bound target binding and invocation must be supplied together")
        if (
            bound_target_binding is None
            and bound_target_invocation is not None
            and (candidate_admission is None or bound_target_invocation.target_handle is not None)
        ):
            raise ValueError("parameter-free candidate requires an admitted no-target invocation")
        if candidate_admission is not None and (
            bound_target_invocation is None
            or candidate_resource_class is None
            or len(opened.plan.probes) != 1
        ):
            raise ValueError("candidate admission requires one exact bound invocation")
        if (offer_followup is not None and async_offer_followup is not None) or bool(
            followup_capabilities
        ) != (offer_followup is not None or async_offer_followup is not None):
            raise ValueError("follow-up catalog and callback must be supplied together")
        if len(followup_capabilities) > 8:
            raise ValueError("follow-up catalog exceeds the bounded first-slice limit")
        # The evaluation package also exports recorder helpers that import
        # Investigator; delay this optional storage edge until the runtime is
        # fully initialized to avoid a package import cycle.
        from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

        diagnostic_admissions = dict(diagnostic_admissions_by_instance or {})
        planned_by_instance = {planned.plan_instance_id: planned for planned in opened.plan.probes}
        if len(diagnostic_admissions) > 8 or len(set(diagnostic_admissions.values())) != len(
            diagnostic_admissions
        ):
            raise ValueError("diagnostic admission mapping is invalid or exceeds bound")
        for instance_id, admission_id in diagnostic_admissions.items():
            planned = planned_by_instance.get(instance_id)
            manifest = None if planned is None else self._probe_runner.manifest(planned.probe_id)
            admission = DiagnosticIntentRepository(self._store).readback(admission_id)
            parameters = {} if planned is None else parameters_by_probe.get(planned.probe_id, {})
            manifest_digest = (
                None
                if manifest is None
                else hashlib.sha256(
                    json.dumps(
                        manifest.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest()
            )
            parameters_digest = hashlib.sha256(
                json.dumps(
                    parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
            ).hexdigest()
            invocation_digest = hashlib.sha256(
                json.dumps(
                    {
                        "probe_id": admission.probe_id,
                        "probe_version": admission.probe_version,
                        "parameters": parameters,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            if (
                planned is None
                or manifest is None
                or admission.case_id != opened.case.case_id
                or admission.epoch_state_version != opened.case.state_version
                or admission.plan_instance_id != instance_id
                or admission.probe_id != planned.probe_id
                or admission.probe_version != manifest.version
                or planned.invocation is not None
                or admission.manifest_sha256 != manifest_digest
                or admission.parameters_sha256 != parameters_digest
                or admission.invocation_sha256 != invocation_digest
            ):
                raise ValueError("diagnostic admission does not match the planned probe")
        followup_catalog: dict[str, ProbeCapability] = {}
        for capability in followup_capabilities:
            manifest = self._probe_runner.manifest(capability.probe_id)
            exact_candidate = (
                capability.probe_id
                in {"application.target_pressure", "pressure.sample", "gpu.telemetry.sample"}
                and manifest is not None
                and manifest.input_model
                == (
                    TargetPressureParametersV1.__name__
                    if capability.probe_id == "application.target_pressure"
                    else "NoParametersV1"
                )
            )
            if (
                capability.probe_id in followup_catalog
                or manifest is None
                or (not exact_candidate and manifest.input_model != "NoParametersV1")
                or manifest.safety.privilege is not Privilege.STANDARD
                or manifest.safety.safety_class not in {SafetyClass.R0, SafetyClass.R1}
                or manifest.safety.safety_class is not capability.safety_class
                or manifest.safety.target_state_effect != "none"
                or manifest.safety.outbound_network
                or capability.permission_class is not PermissionClass.READ_ONLY
                or (not exact_candidate and capability.target_handles)
                or (not exact_candidate and capability.observable_ids)
                or (not exact_candidate and capability.supports_window)
                or capability.resource_class
                is not (
                    ResourceClass.PROCESS
                    if capability.probe_id == "application.target_pressure"
                    else _resource_class(manifest.category)
                )
            ):
                raise ValueError("follow-up capability is not a registered broad read-only probe")
            if not exact_candidate:
                invocation = self._probe_runner.prepare_invocation(
                    capability.probe_id, {}, expected_version=manifest.version
                )
                if (
                    invocation.parameters
                    or invocation.target_handle is not None
                    or invocation.window
                ):
                    raise ValueError("follow-up capability is not parameter-free")
            followup_catalog[capability.probe_id] = capability
        if bound_target_binding is not None and bound_target_invocation is not None:
            current_case = self._store.case(str(opened.case.case_id))
            if (
                current_case is None
                or current_case.state_version != opened.case.state_version
                or current_case.status != CaseStatus.COLLECTING.value
                or not _process_binding_still_current(
                    self._store, opened.case.case_id, bound_target_binding
                )
            ):
                raise TargetSelectionError("selected process target changed before execution")
        preflight: dict[str, ProbeRun] = {}
        canonical_parameters: dict[str, dict[str, JsonValue]] = {}
        manifest_by_instance: dict[str, ProbeManifest | None] = {}
        tasks: list[Task] = []
        task_id_by_instance = {
            planned.plan_instance_id: f"probe-{index}-{planned.plan_instance_id}"
            for index, planned in enumerate(opened.plan.probes)
        }
        if len(task_id_by_instance) != len(opened.plan.probes):
            raise ValueError("plan instance IDs must be unique before execution")
        if candidate_admission is not None and candidate_admission.task_id not in (
            task_id_by_instance.values()
        ):
            raise ValueError("candidate admission task differs from plan")
        for planned in opened.plan.probes:
            instance_id = planned.plan_instance_id
            manifest = self._probe_runner.manifest(planned.probe_id)
            manifest_by_instance[instance_id] = manifest
            parameters = (
                planned.invocation.parameters
                if planned.invocation is not None
                else parameters_by_probe.get(planned.probe_id, {})
            )
            invocation: ProbeInvocation | None = None
            if preflight_runs is not None and planned.probe_id in preflight_runs:
                preflight[instance_id] = preflight_runs[planned.probe_id]
                canonical_parameters[instance_id] = {}
            else:
                try:
                    if (
                        planned.probe_id == "application.target_pressure"
                        and planned.invocation is not None
                    ):
                        raise PolicyDenied("target pressure requires the bound process flow")
                    invocation = self._probe_runner.prepare_invocation(
                        planned.probe_id,
                        parameters,
                        expected_version=(
                            planned.invocation.probe_version
                            if planned.invocation is not None
                            else 0
                            if manifest is None
                            else manifest.version
                        ),
                        target_handle=(
                            planned.invocation.target_handle
                            if planned.invocation is not None
                            else None
                        ),
                        window=None if planned.invocation is None else planned.invocation.window,
                        observable=(
                            None if planned.invocation is None else planned.invocation.observable
                        ),
                    )
                    if planned.invocation is not None and invocation != planned.invocation:
                        raise PolicyDenied("planned invocation differs from registered parameters")
                    if bound_target_invocation is not None:
                        if (
                            planned.probe_id != bound_target_invocation.probe_id
                            or invocation.parameters != bound_target_invocation.parameters
                            or invocation.probe_version != bound_target_invocation.probe_version
                            or invocation.observable != bound_target_invocation.observable
                        ):
                            raise TargetSelectionError(
                                "bound invocation differs from registered probe"
                            )
                        invocation = bound_target_invocation
                    canonical_parameters[instance_id] = invocation.parameters
                except PolicyDenied as error:
                    now = datetime.now(UTC)
                    preflight[instance_id] = ProbeRun(
                        execution_id=ExecutionId.new(),
                        probe_id=planned.probe_id,
                        status=ProbeRunStatus.DENIED,
                        started_at=now,
                        finished_at=now,
                        elapsed_ms=0,
                        error=f"Probe invocation denied: {error}",
                    )
                    canonical_parameters[instance_id] = {}
            tasks.append(
                Task(
                    task_id=task_id_by_instance[instance_id],
                    action=lambda context, item_id=instance_id, prepared=invocation: (
                        preflight[item_id]
                        if item_id in preflight
                        else self._run_admitted_invocation(
                            opened,
                            cast("ProbeInvocation", prepared),
                            context,
                            bound_target_binding=bound_target_binding,
                            candidate_admission=candidate_admission,
                            candidate_launch_continuation_id=candidate_launch_continuation_id,
                        )
                    ),
                    accept_result=lambda value: (
                        isinstance(value, ProbeRun)
                        and value.status is ProbeRunStatus.OK
                        and value.observation is not None
                    ),
                    dependencies=tuple(
                        task_id_by_instance[dependency] for dependency in planned.depends_on
                    ),
                    resource=(
                        candidate_resource_class
                        if candidate_resource_class is not None
                        else _resource_class(
                            "orchestration" if manifest is None else manifest.category
                        )
                    ),
                    priority=max(0, round(planned.value * 100)),
                    invocation=invocation,
                    isolated_probe=(
                        invocation is not None
                        and instance_id not in preflight
                        and planned.probe_id in self._probe_runner.isolated_probe_ids
                    ),
                    state_version=opened.case.state_version,
                    timeout_seconds=(
                        None if manifest is None else manifest.limits.timeout_ms / 1000
                    ),
                )
            )

        # Reserve every diagnostic question once, atomically, before any
        # collector can start. A committed claim is never replayed after a
        # crash because the probe may have run before its result was stored.
        diagnostic_claims: dict[str, str] = {}
        if diagnostic_admissions:
            if any(instance_id in preflight for instance_id in diagnostic_admissions):
                raise ValueError("diagnostic admission cannot use a preflight result")
            with self._store.transaction():
                repository = DiagnosticIntentRepository(self._store)
                for instance_id, admission_id in diagnostic_admissions.items():
                    diagnostic_claims[instance_id] = repository.claim_dispatch(
                        admission_id
                    ).claim_id
        diagnostic_task_ids = {
            task_id_by_instance[instance_id] for instance_id in diagnostic_admissions
        }

        def verified_audit(store: SQLiteStore) -> AuditChain:
            return AuditChain.from_verified_entries(
                store.audit_entries(case_id=str(opened.case.case_id)),
                checkpoint=store.audit_checkpoint(case_id=str(opened.case.case_id)),
                redactor=self._redactor,
            )

        planned_by_task = {
            task_id_by_instance[planned.plan_instance_id]: planned for planned in opened.plan.probes
        }
        admitted_by_task: dict[str, FollowupAdmission] = {}
        candidate_by_task: dict[str, CandidateDispatchAdmission] = {}
        candidate_invocation_by_task: dict[str, ProbeInvocation] = {}
        snapshot_by_task: dict[str, str | None] = {}
        binding_by_task: dict[str, dict[str, JsonValue]] = {}
        persisted_by_task: dict[str, PersistedProbeResult] = {}
        frontier_event_by_task: dict[str, str | None] = {}
        generation_by_task: dict[str, int] = {}
        digest_by_task: dict[str, str] = {}
        frontier = SearchFrontierRepository(self._store)
        staged_followup: (
            tuple[
                Task,
                PlannedProbe,
                ProbeManifest,
                ProbeInvocation,
                PersistedProbeResult,
                str,
                str | None,
                int,
                PresentedReadSetV1 | None,
                int,
            ]
            | None
        ) = None
        staged_candidate: (
            tuple[
                Task,
                PlannedProbe,
                ProbeManifest,
                ProbeInvocation,
                PersistedProbeResult,
                CandidateFollowupSelection,
            ]
            | None
        ) = None
        known_invocation_keys = {
            task.invocation.dedupe_key for task in tasks if task.invocation is not None
        }
        admitted_parents: set[str] = set()
        rejected_parents: set[str] = set()
        sync_legacy_decided = False
        pending_rejections: deque[tuple[PersistedProbeResult, str]] = deque()
        baseline_task_ids = {task.task_id for task in tasks}
        completed_baseline: set[str] = set()
        active_followup_task_ids: set[str] = set()
        active_workers = 0
        pending_parents: deque[PersistedProbeResult] = deque()
        active_model_parent: PersistedProbeResult | None = None
        pending_factories = 0
        terminalized = False
        terminal_gap_ids: set[str] = set()
        external_offer_context: _OfferContext | None = None
        worker_lock = threading.Lock()
        external_offers = (
            BlockingTaskOfferQueue(max_pending=8) if async_offer_followup is not None else None
        )
        model_turns = _FAIR_MODEL_TURNS

        def close_if_idle_locked() -> None:
            if (
                external_offers is not None
                and len(completed_baseline) == len(baseline_task_ids)
                and not active_followup_task_ids
                and not pending_parents
                and active_workers == 0
                and pending_factories == 0
            ):
                external_offers.close()

        def complete_pending_factory() -> None:
            nonlocal pending_factories
            with worker_lock:
                if pending_factories > 0:
                    pending_factories -= 1
                close_if_idle_locked()

        def persist_worker_offer_gap(
            parent: PersistedProbeResult, reason_code: str, candidate_probe_id: str
        ) -> None:
            # The owner queue cannot accept a callback in this path. A separate
            # IMMEDIATE transaction verifies the latest chain before recording
            # the exact lost offer. No one-shot measurement is replayed.
            for attempt in range(4):
                transaction_started = False
                try:
                    with SQLiteStore(self._store.path, busy_timeout_ms=200) as gap_store:
                        with gap_store.transaction() as transaction:
                            transaction_started = True
                            now = datetime.now(UTC)
                            entry = verified_audit(gap_store).append(
                                event_id=f"followup_queue_gap_{parent.execution_id}",
                                case_id=opened.case.case_id,
                                probe_id="systemsense.followup",
                                outcome=AuditOutcome.UNAVAILABLE,
                                occurred_at=now,
                                parameters={
                                    "reason_code": reason_code,
                                    "trigger_execution_id": str(parent.execution_id),
                                    "candidate_probe_id": candidate_probe_id,
                                },
                            )
                            transaction.append_audit(
                                event_id=entry.event_id,
                                case_id=parent.case_id,
                                event_json=entry.model_dump_json(),
                                created_at=now.isoformat(),
                                occurred_at=now.isoformat(),
                                persisted_at=datetime.now(UTC).isoformat(),
                            )
                    return
                except sqlite3.OperationalError as error:
                    if transaction_started or not _sqlite_writer_busy(error) or attempt == 3:
                        raise
                    time.sleep(0.05)

        def durable_or_pending_offer_gap(
            parent: PersistedProbeResult, reason_code: str, candidate_probe_id: str
        ) -> None:
            try:
                persist_worker_offer_gap(parent, reason_code, candidate_probe_id)
            except Exception as error:
                # The atomic source outbox event remains pending for reconciliation.
                # Never replay this worker's one-shot measurement here.
                warnings.warn(
                    "Adaptive follow-up gap audit unavailable; pending outbox retained "
                    f"for {parent.execution_id}: {type(error).__name__}",
                    RuntimeWarning,
                    stacklevel=2,
                )

        def record_terminal_gap_once(
            parent: PersistedProbeResult, reason_code: str, candidate_probe_id: str = ""
        ) -> None:
            execution_id = str(parent.execution_id)
            with worker_lock:
                if (
                    execution_id in terminal_gap_ids
                    or execution_id in admitted_parents
                    or execution_id in rejected_parents
                ):
                    return
                terminal_gap_ids.add(execution_id)
            durable_or_pending_offer_gap(parent, reason_code, candidate_probe_id)

        def current_epoch() -> int:
            case = self._store.case(str(opened.case.case_id))
            return (
                opened.case.state_version
                if case is not None
                and case.status == CaseStatus.COLLECTING.value
                and case.state_version == opened.case.state_version
                else -1
            )

        def persist(result: TaskResult) -> None:
            if pending_rejections:
                flush_rejection()
            if result.status is TaskStatus.DEDUPLICATED:
                return
            if (offer_followup is not None or async_offer_followup is not None) and (
                result.status is TaskStatus.STALE or current_epoch() < 0
            ):
                # A stale epoch cannot acquire an old-case measurement or a
                # follow-up outcome. Its unlinked admission remains uncertain.
                return
            task_candidate = candidate_by_task.get(result.task_id, candidate_admission)
            if task_candidate is not None and (
                result.status is TaskStatus.STALE or current_epoch() < 0
            ):
                # A worker may have claimed before another owner advanced the
                # epoch. Keep the one-shot intent uncertain, with no stale run.
                return
            if result.task_id in diagnostic_task_ids and (
                result.status is TaskStatus.STALE or current_epoch() < 0
            ):
                # The one-shot claim remains consumed. Final reconciliation
                # records an explicit interrupted result without host access.
                return
            planned = planned_by_task[result.task_id]
            probe_id = planned.probe_id
            instance_id = planned.plan_instance_id
            run = _probe_run(result, probe_id=probe_id)
            if task_candidate is not None:
                candidate_repository = CandidateDispatchAdmissionRepository(self._store)
                intent = candidate_repository.readback(task_candidate.admission_id)
                if intent.claimed_at is None or intent.claimed_at > run.started_at:
                    # No collector result can be attributed to this dispatch.
                    # The exact admission still consumes one slot/cost and is
                    # reported as uncertain; a fabricated probe execution
                    # would double count the attempt and distort coverage.
                    return
                if (
                    candidate_launch_continuation_id is not None
                    and result.task_id not in candidate_by_task
                ):
                    continuation = candidate_repository.readback_launch_continuation(
                        candidate_launch_continuation_id
                    )
                    if continuation.consumed_at is None:
                        # The old-epoch claim is uncertain, but no worker passed
                        # the N+1 launch fence and no collector run can be linked.
                        return
            manifest = manifest_by_instance[instance_id]
            category = "orchestration" if manifest is None else manifest.category
            parameters_json = json.dumps(
                canonical_parameters.get(instance_id, {}),
                sort_keys=True,
                separators=(",", ":"),
            )
            admission = admitted_by_task.get(result.task_id)
            with self._store.transaction() as transaction:
                try:
                    transaction.require_case_state(
                        case_id=str(opened.case.case_id),
                        expected_state_version=opened.case.state_version,
                    )
                except StaleCaseStateError:
                    if task_candidate is None and result.task_id not in diagnostic_task_ids:
                        raise
                    return
                audit_entry = verified_audit(self._store).append(
                    event_id=f"probe_{run.execution_id}",
                    case_id=opened.case.case_id,
                    probe_id=probe_id,
                    outcome=_audit_outcome(run.status),
                    occurred_at=run.finished_at,
                    parameters={
                        "elapsed_ms": run.elapsed_ms,
                        "tree_exit_status": run.tree_exit_status,
                        "plan_instance_id": instance_id,
                        "parameters_sha256": hashlib.sha256(
                            parameters_json.encode("utf-8")
                        ).hexdigest(),
                        **binding_by_task.get(result.task_id, audit_binding),
                        **(
                            {"diagnostic_claim_id": diagnostic_claims[instance_id]}
                            if instance_id in diagnostic_claims
                            else {}
                        ),
                    },
                    error=run.error,
                )
                transaction.record_probe_execution(
                    execution_id=str(run.execution_id),
                    case_id=str(opened.case.case_id),
                    probe_id=run.probe_id,
                    probe_version=0 if manifest is None else manifest.version,
                    status=run.status.value,
                    parameters_json=parameters_json,
                    started_at=run.started_at.isoformat(),
                    finished_at=run.finished_at.isoformat(),
                    state_version=(
                        task_candidate.epoch_state_version
                        if task_candidate is not None
                        else opened.case.state_version
                    ),
                    tree_exit_status=run.tree_exit_status,
                    followup_admission_id=(None if admission is None else admission.admission_id),
                )
                candidate_invocation = candidate_invocation_by_task.get(
                    result.task_id, bound_target_invocation
                )
                if task_candidate is not None and candidate_invocation is not None:
                    CandidateDispatchAdmissionRepository(self._store).link_execution(
                        task_candidate.admission_id,
                        str(run.execution_id),
                        candidate_invocation,
                    )
                snapshot_id = snapshot_by_task.get(result.task_id, decision_snapshot_id)
                if snapshot_id is not None and admission is None and task_candidate is None:
                    transaction.link_decision_execution(
                        snapshot_id=snapshot_id,
                        execution_id=str(run.execution_id),
                    )
                evidence_id: EvidenceId | None = None
                if run.status is ProbeRunStatus.OK and run.observation is not None:
                    evidence_id = self._persist_observation(
                        transaction=transaction,
                        opened=opened,
                        run=run,
                        category=category,
                        probe_version=1 if manifest is None else manifest.version,
                        captured_at=run.finished_at,
                    )
                else:
                    self._persist_coverage(
                        transaction=transaction,
                        opened=opened,
                        run=run,
                        category=category,
                        probe_version=0 if manifest is None else manifest.version,
                        captured_at=run.finished_at,
                    )
                generation_row = self._store.connection.execute(
                    "SELECT generation FROM evidence_case_generations WHERE case_id=?",
                    (str(opened.case.case_id),),
                ).fetchone()
                generation = 0 if generation_row is None else int(generation_row[0])
                generation_by_task[result.task_id] = generation
                event = frontier.append_result_event(
                    opened.case.case_id,
                    source_evidence_id=evidence_id,
                    source_execution_id=run.execution_id,
                    versions=RelevantVersionsV1(
                        objective=opened.case.state_version,
                        evidence=generation,
                    ),
                )
                frontier_event_by_task[result.task_id] = (
                    event.event_id if isinstance(event, FrontierEventV1) else None
                )
                if evidence_id is not None:
                    digest_by_task[result.task_id] = FollowupAdmissionRepository(
                        self._store
                    ).parent_evidence_digest(str(opened.case.case_id), str(run.execution_id))
                transaction.append_audit(
                    event_id=audit_entry.event_id,
                    case_id=str(opened.case.case_id),
                    event_json=audit_entry.model_dump_json(),
                    created_at=run.finished_at.isoformat(),
                    occurred_at=run.finished_at.isoformat(),
                    persisted_at=datetime.now(UTC).isoformat(),
                )
                if (diagnostic_admission_id := diagnostic_admissions.get(instance_id)) is not None:
                    try:
                        diagnostic_repository = DiagnosticIntentRepository(self._store)
                        diagnostic_repository.link_execution(
                            diagnostic_admission_id, str(run.execution_id)
                        )
                        diagnostic_repository.evaluate(diagnostic_admission_id)
                    except (ValueError, sqlite3.IntegrityError) as error:
                        # Persist the observation even if its optional diagnostic
                        # question loses custody. If the admitted source itself
                        # vanished, persist an explicit unknown terminal so a
                        # restart cannot mistake the question for a live test.
                        if isinstance(error, ValueError):
                            try:
                                DiagnosticIntentRepository(self._store).record_custody_gap(
                                    diagnostic_admission_id
                                )
                            except ValueError:
                                pass
                        warnings.warn(
                            f"Diagnostic execution link unavailable: {type(error).__name__}",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                if admission is not None:
                    FollowupAdmissionRepository(self._store).link_execution(
                        admission_id=admission.admission_id,
                        execution_id=str(run.execution_id),
                    )
            if run.status is ProbeRunStatus.OK and run.observation is not None:
                if (generation := generation_by_task.get(result.task_id)) is not None:
                    persisted_by_task[result.task_id] = PersistedProbeResult(
                        task_id=result.task_id,
                        case_id=str(opened.case.case_id),
                        epoch_state_version=opened.case.state_version,
                        probe_id=probe_id,
                        execution_id=run.execution_id,
                        evidence_generation=generation,
                        trigger_evidence_sha256=digest_by_task[result.task_id],
                        frontier_event_id=frontier_event_by_task.get(result.task_id),
                    )
            if on_persisted is not None:
                on_persisted(run)

        def flush_rejection() -> bool:
            """Retry only an uncommitted audit lock; never replay an admission."""

            while pending_rejections:
                parent, reason_code = pending_rejections[0]
                for attempt in range(3):
                    appended_to_chain = False
                    try:
                        with self._store.transaction() as transaction:
                            now = datetime.now(UTC)
                            entry = verified_audit(self._store).append(
                                event_id=f"followup_rejected_{parent.execution_id}",
                                case_id=opened.case.case_id,
                                probe_id="systemsense.followup",
                                outcome=AuditOutcome.DENIED,
                                occurred_at=now,
                                parameters={
                                    "trigger_execution_id": str(parent.execution_id),
                                    "reason_code": reason_code,
                                },
                            )
                            appended_to_chain = True
                            transaction.append_audit(
                                event_id=entry.event_id,
                                case_id=parent.case_id,
                                event_json=entry.model_dump_json(),
                                created_at=now.isoformat(),
                                occurred_at=now.isoformat(),
                                persisted_at=datetime.now(UTC).isoformat(),
                            )
                    except sqlite3.OperationalError as error:
                        if (
                            appended_to_chain
                            or not _sqlite_writer_busy(error)
                            or self._store.connection.in_transaction
                        ):
                            raise
                        if attempt < 2:
                            time.sleep(0.02)
                    else:
                        pending_rejections.popleft()
                        break
                else:
                    return False
            return True

        def reject_followup(parent: PersistedProbeResult, reason_code: str) -> None:
            """Record one bounded advisory gap without discarding baseline results."""

            if str(parent.execution_id) in rejected_parents:
                return
            rejected_parents.add(str(parent.execution_id))
            pending_rejections.append((parent, reason_code))
            if not flush_rejection():
                warnings.warn(
                    "Follow-up rejection audit delayed by SQLite writer lock",
                    RuntimeWarning,
                    stacklevel=2,
                )

        def prepare_followup(
            parent: PersistedProbeResult,
            selection: FollowupSelection | CandidateFollowupSelection,
        ) -> tuple[Task, ...]:
            nonlocal staged_followup, staged_candidate
            if (
                str(parent.execution_id) in admitted_parents
                or str(parent.execution_id) in rejected_parents
            ):
                return ()
            if staged_followup is not None or staged_candidate is not None:
                reject_followup(parent, "offer_preparation_conflict")
                return ()
            if isinstance(selection, CandidateFollowupSelection):
                if (
                    (parent.probe_id, selection.probe_id)
                    not in {
                        ("application.snapshot", "application.target_pressure"),
                        ("core.resources", "pressure.sample"),
                        ("local_ai.snapshot", "gpu.telemetry.sample"),
                    }
                    or selection.probe_id not in followup_catalog
                    or len(tasks) + len(admitted_by_task) + len(candidate_by_task) + 1
                    > self._scheduler.max_tasks
                ):
                    reject_followup(parent, "invalid_candidate_selection")
                    return ()
                manifest = self._probe_runner.manifest(selection.probe_id)
                expected_model = (
                    TargetPressureParametersV1.__name__
                    if selection.probe_id == "application.target_pressure"
                    else "NoParametersV1"
                )
                if manifest is None or manifest.input_model != expected_model:
                    reject_followup(parent, "candidate_catalog_changed")
                    return ()
                try:
                    registry, _ = (
                        self.candidate_catalog(opened.case.case_id)
                        if selection.probe_id == "application.target_pressure"
                        else self.general_candidate_catalog(opened.case.case_id)
                    )
                    resolved = registry.resolve(
                        opened.case.case_id, parent.epoch_state_version, selection.candidate_id
                    )
                    if (
                        isinstance(resolved, CandidateGap)
                        or resolved.candidate.probe_id != selection.probe_id
                    ):
                        raise ValueError("candidate source unavailable")
                    CandidateDecisionSnapshotRepository(self._store).verify_selection(
                        selection.decision_snapshot_id,
                        opened.case.case_id,
                        parent.epoch_state_version,
                        selection.candidate_id,
                        resolved.candidate.invocation_sha256,
                    )
                except ValueError:
                    reject_followup(parent, "candidate_selection_stale")
                    return ()
                invocation = resolved.invocation
                if invocation.dedupe_key in known_invocation_keys:
                    reject_followup(parent, "duplicate_work")
                    return ()
                instance_id = f"candidate-followup-{parent.execution_id}"
                task_id = f"probe-{instance_id}"
                planned = PlannedProbe(
                    probe_id=selection.probe_id,
                    instance_id=instance_id,
                    invocation=invocation,
                    cost_ms=resolved.candidate.cost_ms,
                    value=followup_catalog[selection.probe_id].baseline_priority,
                    reason="persisted_exact_candidate_followup",
                )
                task = Task(
                    task_id=task_id,
                    action=lambda context, prepared=invocation: self._run_admitted_invocation(
                        opened,
                        prepared,
                        context,
                        bound_target_binding=None,
                        candidate_admission=candidate_by_task[context.task_id],
                    ),
                    accept_result=lambda value: (
                        isinstance(value, ProbeRun)
                        and value.status is ProbeRunStatus.OK
                        and value.observation is not None
                    ),
                    dependencies=(parent.task_id,),
                    resource=resolved.candidate.resource_class,
                    priority=max(
                        0, round(followup_catalog[selection.probe_id].baseline_priority * 100)
                    ),
                    invocation=invocation,
                    isolated_probe=selection.probe_id in self._probe_runner.isolated_probe_ids,
                    state_version=opened.case.state_version,
                    timeout_seconds=manifest.limits.timeout_ms / 1000,
                )
                staged_candidate = (task, planned, manifest, invocation, parent, selection)
                return (task,)
            if not _valid_followup_selection(selection):
                reject_followup(parent, "invalid_selection")
                return ()
            snapshot_id = selection.decision_snapshot_id
            if async_offer_followup is not None and (
                snapshot_id is None or selection.presented_read_set is None
            ):
                # A provider-selected asynchronous child must be bound to the
                # exact frozen model request and presented evidence. The
                # legacy synchronous deterministic callback alone may use a
                # synthetic non-training request digest.
                reject_followup(parent, "missing_snapshot_or_read_set")
                return ()
            capability = followup_catalog.get(selection.probe_id)
            if capability is None:
                reject_followup(parent, "invalid_selection")
                return ()
            if len(tasks) + len(admitted_by_task) + 1 > self._scheduler.max_tasks:
                reject_followup(parent, "graph_limit")
                return ()
            manifest = self._probe_runner.manifest(capability.probe_id)
            if manifest is None:
                reject_followup(parent, "catalog_changed")
                return ()
            try:
                invocation = self._probe_runner.prepare_invocation(
                    capability.probe_id, {}, expected_version=manifest.version
                )
            except (PolicyDenied, ValueError):
                reject_followup(parent, "catalog_changed")
                return ()
            if invocation.parameters or invocation.target_handle is not None or invocation.window:
                reject_followup(parent, "catalog_changed")
                return ()
            if invocation.dedupe_key in known_invocation_keys:
                reject_followup(parent, "duplicate_work")
                return ()
            if snapshot_id is None:
                request_payload = {
                    "schema_version": 1,
                    "kind": "deterministic_followup_non_training",
                    "case_id": parent.case_id,
                    "epoch_state_version": parent.epoch_state_version,
                    "trigger_execution_id": str(parent.execution_id),
                    "evidence_generation": parent.evidence_generation,
                    "candidate_probe_ids": sorted(followup_catalog),
                }
                request_sha256 = hashlib.sha256(
                    json.dumps(
                        request_payload,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
            else:
                snapshot_row = self._store.connection.execute(
                    "SELECT case_id,state_version,request_json,request_sha256,"
                    "candidate_probe_ids_json,probe_manifest_refs_json "
                    "FROM decision_snapshots WHERE snapshot_id=?",
                    (snapshot_id,),
                ).fetchone()
                if (
                    snapshot_row is None
                    or str(snapshot_row[0]) != parent.case_id
                    or int(snapshot_row[1]) != parent.epoch_state_version
                ):
                    reject_followup(parent, "invalid_snapshot")
                    return ()
                try:
                    request_json = str(snapshot_row[2])
                    frozen = DecisionRequest.model_validate_json(request_json)
                    candidates = tuple(json.loads(str(snapshot_row[4])))
                    refs = tuple(
                        ProbeManifestRef(**item) for item in json.loads(str(snapshot_row[5]))
                    )
                except (TypeError, ValueError):
                    reject_followup(parent, "invalid_snapshot")
                    return ()
                if (
                    hashlib.sha256(request_json.encode("utf-8")).hexdigest() != str(snapshot_row[3])
                    or frozen.case_id != opened.case.case_id
                    or frozen.state_version != parent.epoch_state_version
                    or candidates != tuple(item.probe_id for item in frozen.available_probes)
                    or tuple(ref.probe_id for ref in refs) != candidates
                ):
                    reject_followup(parent, "invalid_snapshot")
                    return ()
                if selection.presented_read_set is not None:
                    contexts = frozen.attention_context or frozen.evidence_context
                    current_ids = {
                        str(item.evidence_id)
                        for item in contexts
                        if item.case_scope == "current_case"
                    }
                    packet_ids = tuple(
                        dict.fromkeys(
                            item["evidence_id"]
                            for item in LayaDecisionProvider.evidence_fragments_for_laya(frozen)
                        )
                    )
                    expected_ids = tuple(item for item in packet_ids if item in current_ids)
                    if tuple(
                        str(item.evidence_id) for item in selection.presented_read_set.entries
                    ) != expected_ids or selection.unprotected_historical_count != sum(
                        item not in current_ids for item in packet_ids
                    ):
                        reject_followup(parent, "invalid_read_set")
                        return ()
                elif async_offer_followup is not None:
                    reject_followup(parent, "missing_read_set")
                    return ()
                frozen_capability = next(
                    (
                        item
                        for item in frozen.available_probes
                        if item.probe_id == capability.probe_id
                    ),
                    None,
                )
                frozen_ref = next(
                    (item for item in refs if item.probe_id == capability.probe_id), None
                )
                if frozen_capability != capability or frozen_ref != ProbeManifestRef.from_manifest(
                    capability.probe_id, manifest
                ):
                    reject_followup(parent, "invalid_snapshot")
                    return ()
                request_sha256 = str(snapshot_row[3])
            instance_id = f"followup-{parent.execution_id}"
            task_id = f"probe-{instance_id}"
            planned = PlannedProbe(
                probe_id=capability.probe_id,
                instance_id=instance_id,
                invocation=invocation,
                cost_ms=capability.cost_ms,
                value=capability.baseline_priority,
                reason="persisted_read_only_followup",
            )
            task = Task(
                task_id=task_id,
                action=lambda context, prepared=invocation: self._run_followup_invocation(
                    opened, prepared, context
                ),
                accept_result=lambda value: (
                    isinstance(value, ProbeRun)
                    and value.status is ProbeRunStatus.OK
                    and value.observation is not None
                ),
                dependencies=(parent.task_id,),
                resource=capability.resource_class,
                priority=max(0, round(capability.baseline_priority * 100)),
                invocation=invocation,
                isolated_probe=capability.probe_id in self._probe_runner.isolated_probe_ids,
                state_version=opened.case.state_version,
                timeout_seconds=manifest.limits.timeout_ms / 1000,
            )
            staged_followup = (
                task,
                planned,
                manifest,
                invocation,
                parent,
                request_sha256,
                snapshot_id,
                capability.cost_ms,
                selection.presented_read_set,
                selection.unprotected_historical_count,
            )
            return (task,)

        def offer_after_persist(result: TaskResult) -> tuple[Task, ...]:
            nonlocal sync_legacy_decided
            if offer_followup is None or sync_legacy_decided:
                return ()
            parent = persisted_by_task.get(result.task_id)
            if parent is None:
                return ()
            sync_legacy_decided = True
            try:
                selection = offer_followup(parent)
            except Exception:
                reject_followup(parent, "provider_error")
                return ()
            return () if selection is None else prepare_followup(parent, selection)

        def admit_offered(offered: tuple[Task, ...]) -> bool:
            nonlocal staged_followup, staged_candidate, external_offer_context
            if staged_candidate is not None:
                task, planned, manifest, invocation, parent, selection = staged_candidate
                if offered != (task,):
                    raise ValueError("candidate scheduler offer differs from prepared task")
                try:
                    candidate_intent = self.admit_persisted_candidate_followup(
                        parent,
                        candidate_id=selection.candidate_id,
                        snapshot_id=selection.decision_snapshot_id,
                        task_id=task.task_id,
                    )
                except ValueError:
                    staged_candidate = None
                    reject_followup(parent, "candidate_admission_rejected")
                    if external_offers is not None:
                        complete_pending_factory()
                        external_offer_context = None
                    return False
                except sqlite3.OperationalError as error:
                    if not _sqlite_writer_busy(error) or self._store.connection.in_transaction:
                        raise
                    row = self._store.connection.execute(
                        "SELECT admission_id FROM candidate_dispatch_admissions "
                        "WHERE case_id=? AND epoch_state_version=? AND task_id=?",
                        (parent.case_id, parent.epoch_state_version, task.task_id),
                    ).fetchone()
                    if row is not None:
                        raise RuntimeError(
                            "candidate admission commit outcome is uncertain"
                        ) from error
                    staged_candidate = None
                    reject_followup(parent, "candidate_admission_busy")
                    if external_offers is not None:
                        complete_pending_factory()
                        external_offer_context = None
                    return False
                planned_by_task[task.task_id] = planned
                manifest_by_instance[planned.plan_instance_id] = manifest
                canonical_parameters[planned.plan_instance_id] = invocation.parameters
                candidate_by_task[task.task_id] = candidate_intent
                candidate_invocation_by_task[task.task_id] = invocation
                snapshot_by_task[task.task_id] = selection.decision_snapshot_id
                binding_by_task[task.task_id] = {
                    "candidate_admission_id": candidate_intent.admission_id,
                    "trigger_execution_id": str(parent.execution_id),
                    "measurement_invocation_id": invocation.dedupe_key,
                }
                known_invocation_keys.add(invocation.dedupe_key)
                staged_candidate = None
                admitted_parents.add(str(parent.execution_id))
                if external_offers is not None:
                    with worker_lock:
                        active_followup_task_ids.add(task.task_id)
                if parent.frontier_event_id is not None:
                    try:
                        frontier.ack_event(parent.frontier_event_id)
                    except Exception as error:
                        warnings.warn(
                            f"Candidate outbox ACK remains pending: {type(error).__name__}",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                if external_offers is not None:
                    complete_pending_factory()
                    external_offer_context = None
                return True
            if staged_followup is None or offered != (staged_followup[0],):
                raise ValueError("follow-up scheduler offer differs from prepared task")
            (
                task,
                planned,
                manifest,
                invocation,
                parent,
                request_sha256,
                snapshot_id,
                cost_ms,
                presented_read_set,
                historical_count,
            ) = staged_followup
            try:
                admission = FollowupAdmissionRepository(self._store).admit(
                    case_id=parent.case_id,
                    epoch_state_version=parent.epoch_state_version,
                    trigger_execution_id=str(parent.execution_id),
                    expected_evidence_generation=parent.evidence_generation,
                    expected_trigger_evidence_sha256=parent.trigger_evidence_sha256,
                    request_sha256=request_sha256,
                    decision_snapshot_id=snapshot_id,
                    invocation=invocation,
                    task_id=task.task_id,
                    estimated_cost_ms=cost_ms,
                    presented_read_set=presented_read_set,
                    unprotected_historical_count=historical_count,
                )
            except ValueError:
                staged_followup = None
                reject_followup(parent, "admission_rejected")
                if external_offers is not None:
                    complete_pending_factory()
                    external_offer_context = None
                return False
            except sqlite3.OperationalError as error:
                if not _sqlite_writer_busy(error) or self._store.connection.in_transaction:
                    raise
                # Prove that no intent committed before treating the lock as a
                # clean rejection. An ambiguous committed intent is never retried.
                row = self._store.connection.execute(
                    "SELECT admission_id FROM collection_followup_admissions "
                    "WHERE case_id=? AND epoch_state_version=? AND task_id=?",
                    (parent.case_id, parent.epoch_state_version, task.task_id),
                ).fetchone()
                if row is not None:
                    raise RuntimeError("follow-up admission commit outcome is uncertain") from error
                staged_followup = None
                reject_followup(parent, "admission_busy")
                if external_offers is not None:
                    complete_pending_factory()
                    external_offer_context = None
                return False
            planned_by_task[task.task_id] = planned
            manifest_by_instance[planned.plan_instance_id] = manifest
            canonical_parameters[planned.plan_instance_id] = invocation.parameters
            admitted_by_task[task.task_id] = admission
            snapshot_by_task[task.task_id] = snapshot_id
            binding_by_task[task.task_id] = {
                "followup_admission_id": admission.admission_id,
                "trigger_execution_id": admission.trigger_execution_id,
                "request_sha256": admission.request_sha256,
                "measurement_invocation_id": invocation.dedupe_key,
            }
            known_invocation_keys.add(invocation.dedupe_key)
            staged_followup = None
            admitted_parents.add(str(parent.execution_id))
            if external_offers is not None:
                with worker_lock:
                    active_followup_task_ids.add(task.task_id)
            if parent.frontier_event_id is not None:
                try:
                    frontier.ack_event(parent.frontier_event_id)
                except Exception as error:
                    # Admission already committed. ACK is only outbox custody;
                    # aborting here would orphan a one-shot admitted task.
                    warnings.warn(
                        f"Follow-up outbox ACK remains pending: {type(error).__name__}",
                        RuntimeWarning,
                        stacklevel=2,
                    )
            if external_offers is not None:
                complete_pending_factory()
                external_offer_context = None
            return True

        def offer_after_persist_async(result: TaskResult) -> tuple[Task, ...]:
            nonlocal active_workers, pending_factories
            offers = external_offers
            callback = async_offer_followup
            assert offers is not None and callback is not None
            parent = persisted_by_task.get(result.task_id)
            with worker_lock:
                if result.task_id in baseline_task_ids:
                    completed_baseline.add(result.task_id)
                active_followup_task_ids.discard(result.task_id)
            eligible = (
                parent is not None
                and not (cancel_event is not None and cancel_event.is_set())
                and datetime.now(UTC) < opened.deadline_at
            )
            if eligible:
                assert parent is not None
                overflow_parent: PersistedProbeResult | None = None
                with worker_lock:
                    if len(pending_parents) < 8:
                        pending_parents.append(parent)
                    else:
                        overflow_parent = parent
                if overflow_parent is not None:
                    reject_followup(overflow_parent, "model_capacity")

            def enqueue(
                factory: Callable[[], tuple[Task, ...]],
                source: PersistedProbeResult,
                candidate_probe_id: str,
            ) -> None:
                nonlocal pending_factories
                with worker_lock:
                    pending_factories += 1

                def guarded_factory() -> tuple[Task, ...]:
                    with worker_lock:
                        stopped = terminalized
                    if stopped:
                        complete_pending_factory()
                        record_terminal_gap_once(
                            source, "case_stopped_before_offer", candidate_probe_id
                        )
                        return ()
                    return factory()

                if not offers.offer_factory(guarded_factory):
                    complete_pending_factory()
                    record_terminal_gap_once(
                        source,
                        "case_stopped_before_offer" if terminalized else "offer_queue_unavailable",
                        candidate_probe_id,
                    )
                    warnings.warn(
                        "Adaptive follow-up offer queue is full or closed",
                        RuntimeWarning,
                        stacklevel=2,
                    )

            def enqueue_rejection(source: PersistedProbeResult, reason_code: str) -> None:
                def reject_on_owner(
                    frozen_parent: PersistedProbeResult = source,
                    frozen_reason: str = reason_code,
                ) -> tuple[Task, ...]:
                    reject_followup(frozen_parent, frozen_reason)
                    complete_pending_factory()
                    return ()

                enqueue(reject_on_owner, source, "")

            def infer(registration: ModelTurnRegistration) -> None:
                nonlocal active_workers, active_model_parent
                try:
                    while True:
                        with worker_lock:
                            if not pending_parents:
                                break
                            selected_parent = pending_parents.popleft()
                            active_model_parent = selected_parent
                        try:
                            attempt = registration.acquire(
                                deadline_at=opened.deadline_at,
                                cancel_event=cancel_event,
                            )
                            if attempt.status != "acquired":
                                record_terminal_gap_once(
                                    selected_parent, f"model_turn_{attempt.status}"
                                )
                                continue
                            assert attempt.lease is not None
                            skip_reason: str | None = None
                            selection: FollowupSelection | CandidateFollowupSelection | None = None
                            with attempt.lease:
                                if cancel_event is not None and cancel_event.is_set():
                                    skip_reason = "model_turn_cancelled"
                                elif datetime.now(UTC) >= opened.deadline_at:
                                    skip_reason = "model_turn_expired"
                                else:
                                    with SQLiteStore(self._store.path) as worker_store:
                                        selection = callback(selected_parent, worker_store)
                            if skip_reason is not None:
                                record_terminal_gap_once(selected_parent, skip_reason)
                                continue
                            if cancel_event is not None and cancel_event.is_set():
                                record_terminal_gap_once(
                                    selected_parent, "model_turn_cancelled_after_callback"
                                )
                            elif datetime.now(UTC) >= opened.deadline_at:
                                record_terminal_gap_once(
                                    selected_parent, "model_turn_expired_after_callback"
                                )
                            elif selection is not None:

                                def prepare_on_owner(
                                    frozen_parent: PersistedProbeResult = selected_parent,
                                    frozen_selection: FollowupSelection
                                    | CandidateFollowupSelection = selection,
                                ) -> tuple[Task, ...]:
                                    nonlocal external_offer_context
                                    external_offer_context = _OfferContext(
                                        trigger_execution_id=str(frozen_parent.execution_id),
                                        task_id=f"probe-followup-{frozen_parent.execution_id}",
                                        candidate_probe_id=frozen_selection.probe_id,
                                        decision_snapshot_id=frozen_selection.decision_snapshot_id,
                                    )
                                    prepared = prepare_followup(frozen_parent, frozen_selection)
                                    if not prepared:
                                        complete_pending_factory()
                                        external_offer_context = None
                                    return prepared

                                enqueue(prepare_on_owner, selected_parent, selection.probe_id)
                        except Exception as error:
                            warnings.warn(
                                f"Adaptive follow-up worker failed: {type(error).__name__}",
                                RuntimeWarning,
                                stacklevel=2,
                            )
                            enqueue_rejection(selected_parent, "provider_error")
                        finally:
                            with worker_lock:
                                if active_model_parent is selected_parent:
                                    active_model_parent = None
                finally:
                    registration.close()
                    restart_registration: ModelTurnRegistration | None = None
                    abandoned: tuple[PersistedProbeResult, ...] = ()
                    with worker_lock:
                        active_workers -= 1
                        if pending_parents and active_workers == 0:
                            restart_registration = model_turns.register(str(ExecutionId.new()))
                            if restart_registration is not None:
                                active_workers += 1
                            else:
                                abandoned = tuple(pending_parents)
                                pending_parents.clear()
                        close_if_idle_locked()
                    for item in abandoned:
                        durable_or_pending_offer_gap(item, "model_capacity", "")
                    if restart_registration is not None:
                        start_inference_worker(restart_registration)

            def start_inference_worker(registration: ModelTurnRegistration) -> None:
                nonlocal active_workers
                try:
                    threading.Thread(
                        target=infer,
                        args=(registration,),
                        name="systemsense-followup",
                        daemon=True,
                    ).start()
                except RuntimeError as error:
                    # Thread creation failed after reserving one worker. Close
                    # the registration and audit all queued parents.
                    with worker_lock:
                        active_workers -= 1
                        abandoned = tuple(pending_parents)
                        pending_parents.clear()
                        close_if_idle_locked()
                    registration.close()
                    for item in abandoned:
                        durable_or_pending_offer_gap(item, "worker_start_failed", "")
                    warnings.warn(
                        f"Adaptive follow-up worker could not start: {type(error).__name__}",
                        RuntimeWarning,
                        stacklevel=2,
                    )

            worker_registration: ModelTurnRegistration | None = None
            rejected: tuple[PersistedProbeResult, ...] = ()
            with worker_lock:
                if pending_parents and active_workers == 0:
                    worker_registration = model_turns.register(str(ExecutionId.new()))
                    if worker_registration is not None:
                        active_workers += 1
                    else:
                        rejected = tuple(pending_parents)
                        pending_parents.clear()
            # Registry exhaustion retains the outbox event and audits a gap.
            for item in rejected:
                reject_followup(item, "model_capacity")
            if worker_registration is not None:
                start_inference_worker(worker_registration)
            with worker_lock:
                close_if_idle_locked()
            return ()

        def record_offer_error(error: Exception) -> None:
            nonlocal external_offer_context
            complete_pending_factory()
            error_context = (
                external_offer_context.audit_fields() if external_offer_context is not None else {}
            )
            external_offer_context = None
            now = datetime.now(UTC)
            with self._store.transaction() as transaction:
                entry = verified_audit(self._store).append(
                    event_id=f"followup_offer_error_{ExecutionId.new()}",
                    case_id=opened.case.case_id,
                    probe_id="systemsense.followup",
                    outcome=AuditOutcome.FAILED,
                    occurred_at=now,
                    parameters={
                        "reason_code": "offer_factory_error",
                        "error_type": type(error).__name__,
                        "admission_custody": "uncertain",
                        **error_context,
                    },
                )
                transaction.append_audit(
                    event_id=entry.event_id,
                    case_id=str(opened.case.case_id),
                    event_json=entry.model_dump_json(),
                    created_at=now.isoformat(),
                    occurred_at=now.isoformat(),
                    persisted_at=datetime.now(UTC).isoformat(),
                )
            warnings.warn(
                f"Adaptive follow-up offer failed: {type(error).__name__}",
                RuntimeWarning,
                stacklevel=2,
            )

        if external_offers is None:
            # Preserve the pre-extension scheduler contract for ordinary plans
            # and read-only bound-target flows with custom scheduler adapters.
            results = self._scheduler.run_blocking(
                tasks,
                case_deadline_at=opened.deadline_at,
                state_version=(
                    current_epoch
                    if offer_followup is not None or diagnostic_admissions
                    else opened.case.state_version
                ),
                cancel_event=cancel_event,
                on_result=persist,
                offer_after_result=(offer_after_persist if offer_followup is not None else None),
                on_admitted=admit_offered if followup_catalog else None,
            )
        else:
            try:
                results = self._scheduler.run_blocking(
                    tasks,
                    case_deadline_at=opened.deadline_at,
                    state_version=current_epoch,
                    cancel_event=cancel_event,
                    on_result=persist,
                    offer_after_result=offer_after_persist_async,
                    on_admitted=admit_offered,
                    external_offers=external_offers,
                    on_offer_error=record_offer_error,
                )
            finally:
                # The scheduler stops draining offers at deadline/cancellation
                # or exception. Close that custody boundary before reconciling.
                with worker_lock:
                    terminalized = True
                    queued_parents = tuple(pending_parents)
                    pending_parents.clear()
                    in_flight_parent = active_model_parent
                external_offers.close()
                for prepare in external_offers.drain():
                    prepare()
                if staged_followup is not None:
                    unadmitted_parent = staged_followup[4]
                    staged_followup = None
                    reject_followup(unadmitted_parent, "case_stopped_before_admission")
                    complete_pending_factory()
                if staged_candidate is not None:
                    unadmitted_parent = staged_candidate[4]
                    staged_candidate = None
                    reject_followup(unadmitted_parent, "case_stopped_before_admission")
                    complete_pending_factory()
                for queued_parent in queued_parents:
                    record_terminal_gap_once(queued_parent, "case_stopped_before_model_turn")
                if in_flight_parent is not None:
                    record_terminal_gap_once(in_flight_parent, "case_stopped_during_model_turn")
        if pending_rejections and not flush_rejection():
            warnings.warn(
                "Follow-up rejection audit could not be persisted before return",
                RuntimeWarning,
                stacklevel=2,
            )
        # A one-shot claim with no persisted result is consumed, not replayed.
        # The collector might have run before cancellation or a process failure.
        for diagnostic_admission_id in diagnostic_admissions.values():
            try:
                with self._store.transaction():
                    diagnostic_repository = DiagnosticIntentRepository(self._store)
                    if diagnostic_repository.terminal(diagnostic_admission_id) is not None:
                        continue
                    if diagnostic_repository.execution_link(diagnostic_admission_id) is None:
                        diagnostic_repository.interrupt(
                            diagnostic_admission_id, reason="dispatch_outcome_unknown"
                        )
                    else:
                        diagnostic_repository.evaluate(diagnostic_admission_id)
            except ValueError as error:
                try:
                    with self._store.transaction():
                        DiagnosticIntentRepository(self._store).record_custody_gap(
                            diagnostic_admission_id
                        )
                except ValueError:
                    pass
                warnings.warn(
                    f"Diagnostic result remains uncertain: {type(error).__name__}",
                    RuntimeWarning,
                    stacklevel=2,
                )
        return results

    def _run_followup_invocation(
        self, opened: OpenedCase, invocation: ProbeInvocation, context: TaskContext
    ) -> ProbeRun:
        """Recheck the case from the worker's own connection before host access."""

        started = datetime.now(UTC)
        try:
            with SQLiteStore(self._store.path) as worker_store:
                case = worker_store.case(str(opened.case.case_id))
                if (
                    case is None
                    or case.state_version != opened.case.state_version
                    or case.status != CaseStatus.COLLECTING.value
                ):
                    raise ValueError("follow-up collection epoch changed while queued")
        except ValueError:
            status = ProbeRunStatus.UNAVAILABLE
            detail = "Follow-up collection epoch unavailable at execution"
        except Exception as error:
            status = ProbeRunStatus.FAILED
            detail = f"Local case-store revalidation failed: {type(error).__name__}"
        else:
            return self._probe_runner.run_invocation(
                invocation,
                deadline_at=context.deadline_at,
                cancellation=context.cancellation,
                host_slot=context.host_slot,
            )
        finished = datetime.now(UTC)
        return ProbeRun(
            execution_id=ExecutionId.new(),
            probe_id=invocation.probe_id,
            status=status,
            started_at=started,
            finished_at=finished,
            elapsed_ms=(finished - started).total_seconds() * 1000,
            error=detail,
        )

    def _run_admitted_invocation(
        self,
        opened: OpenedCase,
        invocation: ProbeInvocation,
        context: TaskContext,
        *,
        bound_target_binding: ProcessTargetBinding | InventoryProcessBinding | None,
        candidate_admission: CandidateDispatchAdmission | None = None,
        candidate_launch_continuation_id: str | None = None,
    ) -> ProbeRun:
        if candidate_admission is None and bound_target_binding is None:
            return self._probe_runner.run_invocation(
                invocation,
                deadline_at=context.deadline_at,
                cancellation=context.cancellation,
                host_slot=context.host_slot,
            )
        # The scheduler may queue this task after the case-side admission. Use
        # a separate same-thread SQLite connection, not the coordinator's
        # thread-affine connection, before touching the selected OS process.
        started = datetime.now(UTC)
        try:
            with SQLiteStore(self._store.path) as worker_store:
                current_case = worker_store.case(str(opened.case.case_id))
                if (
                    current_case is None
                    or current_case.state_version != opened.case.state_version
                    or current_case.status != CaseStatus.COLLECTING.value
                    or (
                        bound_target_binding is not None
                        and not _process_binding_still_current(
                            worker_store, opened.case.case_id, bound_target_binding
                        )
                    )
                ):
                    raise TargetSelectionError("selected process binding changed while queued")
                if candidate_admission is not None:
                    worker_registry, _ = (
                        process_pressure_candidate_catalog(
                            worker_store, self._probe_runner, opened.case.case_id
                        )
                        if invocation.probe_id == "application.target_pressure"
                        else general_measurement_candidate_catalog(
                            worker_store,
                            self._probe_runner,
                            opened.case.case_id,
                            for_existing_admission=True,
                        )
                    )
                    resolved = (
                        worker_registry.resolve_for_claim(
                            opened.case.case_id,
                            opened.case.state_version,
                            candidate_admission.candidate_id,
                            candidate_admission.admission_id,
                        )
                        if candidate_launch_continuation_id is None
                        else worker_registry.resolve_for_continuation(
                            opened.case.case_id,
                            candidate_admission.epoch_state_version,
                            candidate_admission.candidate_id,
                            candidate_admission.admission_id,
                            candidate_launch_continuation_id,
                        )
                    )
                    if (
                        isinstance(resolved, CandidateGap)
                        or resolved.invocation != invocation
                        or resolved.candidate.invocation_sha256
                        != candidate_admission.invocation_sha256
                    ):
                        raise ValueError("candidate source or invocation changed while queued")
                    worker_admissions = CandidateDispatchAdmissionRepository(
                        worker_store, registry=worker_registry
                    )
                    if candidate_launch_continuation_id is None:
                        worker_admissions.claim_for_worker(
                            candidate_admission.admission_id,
                            case_id=opened.case.case_id,
                            epoch_state_version=opened.case.state_version,
                            task_id=context.task_id,
                            invocation_sha256=candidate_admission.invocation_sha256,
                        )
                    else:
                        worker_admissions.consume_launch_continuation(
                            candidate_launch_continuation_id,
                            case_id=opened.case.case_id,
                            task_id=context.task_id,
                            invocation_sha256=candidate_admission.invocation_sha256,
                        )
                    if (
                        candidate_launch_continuation_id is None
                        and candidate_admission.snapshot_id.startswith(
                            "frontier_decision_snapshot_"
                        )
                    ):
                        snapshot = CandidateDecisionSnapshotRepository(
                            worker_store
                        ).readback_frontier(candidate_admission.snapshot_id)
                        SearchFrontierRepository(worker_store).transition(
                            snapshot.selected_item_id,
                            FrontierStatus.ADMITTED,
                            FrontierStatus.RUNNING,
                            "worker_claimed",
                        )
        except TargetSelectionError:
            status = ProbeRunStatus.UNAVAILABLE
            error_summary = "Selected process target unavailable at execution"
        except ValueError:
            status = ProbeRunStatus.UNAVAILABLE
            error_summary = "Candidate dispatch admission unavailable at execution"
        except Exception as error:
            # A corrupt/unopenable case store is an internal measurement
            # failure, not evidence that the selected target went missing.
            status = ProbeRunStatus.FAILED
            error_summary = f"Local case-store revalidation failed: {type(error).__name__}"
        else:
            # ProbeRunner.run rechecks the registered parameter schema and policy;
            # the collector separately rechecks live PID and creation identity.
            return self._probe_runner.run(
                invocation.probe_id,
                invocation.parameters,
                deadline_at=context.deadline_at,
                cancellation=context.cancellation,
                host_slot=context.host_slot,
            )
        finished = datetime.now(UTC)
        if candidate_admission is not None:
            # A failed pre-claim revalidation is not a claimed execution. A
            # successful claim occurred before any collector starts.
            started = finished
        return ProbeRun(
            execution_id=ExecutionId.new(),
            probe_id=invocation.probe_id,
            status=status,
            started_at=started,
            finished_at=finished,
            elapsed_ms=(finished - started).total_seconds() * 1000,
            error=error_summary,
        )

    def _persist_observation(
        self,
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        category: str,
        probe_version: int,
        captured_at: UtcDateTime,
    ) -> EvidenceId:
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        assert run.observation is not None
        observation = self._redact_observation(run.observation)
        observed_at = observation.observed_at
        time_basis = (
            "collector_upper_bound"
            if observation.time_quality == "bounded_interval"
            else "collector_observed"
        )
        collector = CollectorReference(
            id=run.probe_id,
            version=probe_version,
            execution_id=run.execution_id,
        )
        source_id = stable_source_id(
            "systemsense.probe",
            {
                "probe_id": run.probe_id,
                "probe_version": collector.version,
            },
        )
        source = EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": run.probe_id},
        )
        record = EvidenceRecord(
            evidence_id=EvidenceId.new(),
            case_id=opened.case.case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=observed_at,
            captured_at=captured_at,
            source=source,
            collector=collector,
            summary=observation.summary,
            facts=tuple(
                EvidenceFact(name=name, value=value)
                for name, value in sorted(observation.facts.items())
            ),
            extraction=Extraction(
                confidence=1.0,
                parser="builtin.probe",
                parser_version=1,
            ),
            limitations=observation.limitations,
            sensitivity=_sensitivity(category),
        )
        inventory = InventoryFact(
            entity_id=_HOST_ENTITY_ID,
            category=category,
            name=run.probe_id,
            value=observation.facts,
            source=source,
            collector=collector,
            observed_at=observed_at,
            captured_at=captured_at,
            extraction=record.extraction,
            freshness_ttl_seconds=_freshness_ttl(category),
            sensitivity=_sensitivity(category),
            limitations=observation.limitations,
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(record.evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=observed_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(run.execution_id),
            dedupe_key=f"execution:{run.execution_id}",
            time_basis=time_basis,
            time_quality=observation.time_quality,
        )
        transaction.upsert_inventory(
            category=inventory.category,
            fact_key=f"{inventory.entity_id}:{inventory.name}",
            record_json=inventory.model_dump_json(),
            observed_at=observed_at.isoformat(),
            captured_at=captured_at.isoformat(),
            time_basis=time_basis,
            time_quality=observation.time_quality,
        )
        if run.probe_id == "incident.events":
            self._persist_incident_event_children(
                transaction=transaction,
                opened=opened,
                run=run,
                observation=observation,
                collector=collector,
                captured_at=captured_at,
            )
        return record.evidence_id

    def _persist_incident_event_children(
        self,
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        observation: ProbeObservation,
        collector: CollectorReference,
        captured_at: UtcDateTime,
    ) -> None:
        from systemsense.platform.windows.deep_collectors import IncidentProfileEvent
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        raw_events = observation.facts.get("events")
        if not isinstance(raw_events, list):
            self._persist_child_coverage(
                transaction=transaction,
                opened=opened,
                run=run,
                captured_at=captured_at,
                status=CoverageStatus.FAILED,
                reason="incident event facts were not a list",
            )
            return
        invalid = 0
        for raw_event in raw_events[:512]:
            try:
                event = IncidentProfileEvent.model_validate(raw_event)
                source = EvidenceSource(
                    type="windows.eventlog",
                    source_id=event.source_id,
                    locator={
                        "channel": event.channel,
                        "provider": event.provider,
                        "event_id": event.event_id,
                        "record_id": event.record_id,
                    },
                )
                facts = (
                    EvidenceFact(name="profile", value=event.profile),
                    EvidenceFact(name="provider", value=event.provider),
                    EvidenceFact(name="event_id", value=event.event_id),
                    EvidenceFact(name="record_id", value=event.record_id),
                    EvidenceFact(name="level", value=event.level),
                    EvidenceFact(name="event_data", value=cast("JsonValue", event.event_data)),
                )
                if event.rendered_message is not None:
                    facts = (
                        *facts,
                        EvidenceFact(name="rendered_message", value=event.rendered_message),
                    )
                child = EvidenceRecord(
                    evidence_id=EvidenceId.new(),
                    case_id=opened.case.case_id,
                    statement_kind=StatementKind.OBSERVED_FACT,
                    observed_at=event.observed_at,
                    captured_at=captured_at,
                    source=source,
                    collector=collector,
                    summary=(
                        f"{event.channel} event {event.event_id} from {event.provider} "
                        f"matched the {event.profile} incident profile"
                    ),
                    facts=facts,
                    extraction=Extraction(
                        confidence=1.0,
                        parser="builtin.incident_event_profile",
                        parser_version=1,
                    ),
                    limitations=("selected from a bounded fixed-profile Event Log query",),
                    sensitivity=Sensitivity.PERSONAL,
                )
            except (TypeError, ValueError):
                invalid += 1
                continue
            transaction.insert_evidence(
                case_id=str(opened.case.case_id),
                evidence_id=str(child.evidence_id),
                source_id=event.source_id,
                record_json=child.model_dump_json(),
                observed_at=event.observed_at.isoformat(),
                captured_at=captured_at.isoformat(),
                execution_id=str(run.execution_id),
                dedupe_key=f"execution:{run.execution_id}:event:{event.source_id}",
                time_basis="source_event",
                time_quality="exact",
            )
        omitted = max(0, len(raw_events) - 512)
        if invalid or omitted:
            details: list[str] = []
            if invalid:
                details.append(f"{invalid} malformed event records were rejected")
            if omitted:
                details.append(f"{omitted} event records exceeded the 512-record child limit")
            self._persist_child_coverage(
                transaction=transaction,
                opened=opened,
                run=run,
                captured_at=captured_at,
                status=CoverageStatus.FAILED if invalid else CoverageStatus.TRUNCATED,
                reason="; ".join(details),
            )

    @staticmethod
    def _persist_child_coverage(
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        captured_at: UtcDateTime,
        status: CoverageStatus,
        reason: str,
    ) -> None:
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        coverage = CoverageRecord(
            evidence_id=EvidenceId.new(),
            case_id=opened.case.case_id,
            category="events.child",
            status=status,
            captured_at=captured_at,
            reason=reason,
            execution_id=run.execution_id,
        )
        source_id = stable_source_id(
            "systemsense.probe.coverage",
            {
                "probe_id": run.probe_id,
                "execution_id": str(run.execution_id),
                "scope": "event_children",
            },
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(coverage.evidence_id),
            source_id=source_id,
            record_json=coverage.model_dump_json(),
            observed_at=captured_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(run.execution_id),
            dedupe_key=f"execution:{run.execution_id}:events-child-coverage",
            time_basis="probe_attempt_finish",
            time_quality="exact",
        )

    def _persist_coverage(
        self,
        *,
        transaction: object,
        opened: OpenedCase,
        run: ProbeRun,
        category: str,
        probe_version: int,
        captured_at: UtcDateTime,
    ) -> None:
        from systemsense.storage.sqlite_store import StoreTransaction

        assert isinstance(transaction, StoreTransaction)
        coverage = CoverageRecord(
            evidence_id=EvidenceId.new(),
            case_id=opened.case.case_id,
            category=category,
            status=_coverage_status(run.status),
            captured_at=captured_at,
            reason=(None if run.error is None else self._redactor.redact_text(run.error).text)
            or f"probe ended with {run.status.value}",
            execution_id=run.execution_id,
        )
        source_id = stable_source_id(
            "systemsense.probe.coverage",
            {
                "probe_id": run.probe_id,
                "probe_version": probe_version,
            },
        )
        transaction.insert_evidence(
            case_id=str(opened.case.case_id),
            evidence_id=str(coverage.evidence_id),
            source_id=source_id,
            record_json=coverage.model_dump_json(),
            observed_at=captured_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(run.execution_id),
            dedupe_key=f"execution:{run.execution_id}",
            time_basis="probe_attempt_finish",
            time_quality="exact",
        )

    def _redact_observation(self, observation: ProbeObservation) -> ProbeObservation:
        return ProbeObservation(
            summary=self._redactor.redact_text(observation.summary).text,
            facts={
                name: self._redact_json(name, value) for name, value in observation.facts.items()
            },
            limitations=tuple(
                self._redactor.redact_text(item).text for item in observation.limitations
            ),
            observed_at=observation.observed_at,
            captured_at=observation.captured_at,
            time_quality=observation.time_quality,
        )

    def _redact_json(self, field_name: str, value: JsonValue) -> JsonValue:
        if isinstance(value, str):
            return self._redactor.redact_field(field_name, value)
        if isinstance(value, list):
            return [self._redact_json(field_name, item) for item in value]
        if isinstance(value, dict):
            return {name: self._redact_json(name, item) for name, item in value.items()}
        return cast("JsonValue", value)


def _audit_outcome(status: ProbeRunStatus) -> AuditOutcome:
    return {
        ProbeRunStatus.OK: AuditOutcome.ALLOWED,
        ProbeRunStatus.DENIED: AuditOutcome.DENIED,
        ProbeRunStatus.UNAVAILABLE: AuditOutcome.UNAVAILABLE,
        ProbeRunStatus.FAILED: AuditOutcome.FAILED,
        ProbeRunStatus.TIMED_OUT: AuditOutcome.TIMED_OUT,
        ProbeRunStatus.TRUNCATED: AuditOutcome.TRUNCATED,
        ProbeRunStatus.CANCELLED: AuditOutcome.CANCELLED,
    }[status]


def _coverage_status(status: ProbeRunStatus) -> CoverageStatus:
    return {
        ProbeRunStatus.OK: CoverageStatus.COVERED,
        ProbeRunStatus.DENIED: CoverageStatus.DENIED,
        ProbeRunStatus.UNAVAILABLE: CoverageStatus.UNAVAILABLE,
        ProbeRunStatus.FAILED: CoverageStatus.FAILED,
        ProbeRunStatus.TIMED_OUT: CoverageStatus.FAILED,
        ProbeRunStatus.TRUNCATED: CoverageStatus.TRUNCATED,
        ProbeRunStatus.CANCELLED: CoverageStatus.UNAVAILABLE,
    }[status]


def _freshness_ttl(category: str) -> int:
    return 300 if category in {"core", "application", "network", "performance"} else 3600


def _sensitivity(category: str) -> Sensitivity:
    if category in {"application", "storage", "network", "events", "performance"}:
        return Sensitivity.PERSONAL
    return Sensitivity.SYSTEM_METADATA


def _resource_class(category: str) -> ResourceClass:
    if category in {"network"}:
        return ResourceClass.NETWORK
    if category in {"servicing", "storage", "events"}:
        return ResourceClass.DISK
    if category in {"local_ai"}:
        return ResourceClass.GPU
    if category in {"application", "devices", "power", "security"}:
        return ResourceClass.PROCESS
    return ResourceClass.CPU


def _probe_run(result: TaskResult, *, probe_id: str) -> ProbeRun:
    if result.status in {TaskStatus.SUCCEEDED, TaskStatus.FAILED} and isinstance(
        result.value, ProbeRun
    ):
        if result.value.status is ProbeRunStatus.OK and result.value.observation is None:
            return result.value.model_copy(
                update={
                    "status": ProbeRunStatus.FAILED,
                    "error": "probe reported success without an observation",
                }
            )
        return result.value
    now = datetime.now(UTC)
    finished = result.finished_at or now
    status = {
        TaskStatus.TIMED_OUT: ProbeRunStatus.TIMED_OUT,
        TaskStatus.CANCELLED: ProbeRunStatus.CANCELLED,
        TaskStatus.BLOCKED: ProbeRunStatus.UNAVAILABLE,
        TaskStatus.STALE: ProbeRunStatus.UNAVAILABLE,
        TaskStatus.FAILED: ProbeRunStatus.FAILED,
        TaskStatus.SUCCEEDED: ProbeRunStatus.FAILED,
        TaskStatus.DEDUPLICATED: ProbeRunStatus.UNAVAILABLE,
    }[result.status]
    return ProbeRun(
        execution_id=ExecutionId.new(),
        probe_id=probe_id,
        status=status,
        started_at=result.started_at or finished,
        finished_at=finished,
        elapsed_ms=result.duration_ms,
        error=result.error or f"scheduler ended with {result.status.value}",
    )
