"""Immutable case-scoped choices for registered read-only measurements.

This registry does not execute probes or reserve dispatch authority. Models see
only CandidateRecord metadata; exact invocations remain private to local code.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, cast
from uuid import uuid4

from pydantic import BaseModel, Field

from systemsense.decision.contracts import PermissionClass
from systemsense.domain.evidence import EvidenceRecord, FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.probes import (
    MeasurementNeed,
    Privilege,
    ProbeInvocation,
    ProbeManifest,
    SafetyClass,
)
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.orchestration.invocations import (
    MeasurementRegistry,
    ObservabilityGap,
    RegisteredMeasurement,
    RegisteredTarget,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.sqlite_store import SQLiteStore

_ID = re.compile(r"cand_v1_[0-9a-f]{32}\Z")
_MAX_PER_EPOCH = 128


class CandidateGapReason(StrEnum):
    UNKNOWN = "unknown_candidate"
    STALE_CASE = "stale_case"
    UNREGISTERED = "unregistered_need"
    INVALID_BINDING = "invalid_binding"
    SOURCE_STALE = "source_stale"
    SOURCE_CHANGED = "source_changed"
    TARGET_CHANGED = "target_changed"
    MANIFEST_CHANGED = "manifest_changed"
    WINDOW_INELIGIBLE = "window_ineligible"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CATALOG_FULL = "catalog_full"


class CandidateGap(FrozenModel):
    """Typed refusal; no broad scan or alternate target is implied."""

    case_id: CaseId
    candidate_id: str | None = None
    reason: CandidateGapReason


class CandidateRecord(FrozenModel):
    """Model-safe reference only; it contains no selectors or parameters."""

    schema_version: Literal[1] = 1
    candidate_id: str = Field(pattern=r"^cand_v1_[0-9a-f]{32}$")
    probe_id: str
    description: str = Field(min_length=1, max_length=240)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    invocation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cost_ms: int = Field(gt=0, le=120_000)
    resource_class: ResourceClass
    safety_class: SafetyClass
    permission_class: PermissionClass = PermissionClass.READ_ONLY


@dataclass(frozen=True, slots=True)
class CandidateResolution:
    """Eligibility readback, never a dispatch or replay permit."""

    candidate: CandidateRecord
    invocation: ProbeInvocation
    dispatch_authorized: Literal[False] = False


@dataclass(frozen=True, slots=True)
class CandidateTargetBinding:
    """Application-owned inventory handle and typed parameters, never model text."""

    handle: str
    parameters: dict[str, JsonValue]
    source_evidence_id: EvidenceId | None = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateRegistration:
    """Trusted local catalog entry for one probe/observable."""

    manifest: ProbeManifest
    parameter_model: type[BaseModel]
    observable: str
    description: str
    cost_ms: int
    resource_class: ResourceClass
    source_evidence_id: EvidenceId
    freshness_ttl_seconds: int
    targets: tuple[CandidateTargetBinding, ...] = ()
    dependency_evidence_ids: tuple[EvidenceId, ...] = ()
    supports_window: bool = False
    max_window_lookback_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class _EvidenceBinding:
    evidence_id: EvidenceId
    digest: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _Prepared:
    registration: CandidateRegistration
    invocation: ProbeInvocation
    target: CandidateTargetBinding | None
    source: _EvidenceBinding
    dependencies: tuple[_EvidenceBinding, ...]
    manifest_sha256: str
    description: str
    expires_at: datetime
    binding_sha256: str


TargetRevalidator = Callable[[CaseId, CandidateTargetBinding, ProbeInvocation], bool]
ManifestLookup = Callable[[str], ProbeManifest | None]


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest_sha256(manifest: ProbeManifest) -> str:
    return _sha256(_canonical(manifest.model_dump(mode="json")))


def _invocation_json(invocation: ProbeInvocation) -> str:
    return _canonical(invocation.model_dump(mode="json"))


def _utc(value: str) -> datetime:
    return ensure_utc(datetime.fromisoformat(value))


class CaseCandidateRegistry:
    """Mint and resolve only exact, fresh local measurement candidates."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        registrations: tuple[CandidateRegistration, ...],
        manifest_lookup: ManifestLookup,
        revalidate_target: TargetRevalidator | None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._lookup = manifest_lookup
        self._revalidate_target = revalidate_target
        self._clock = clock
        self._registrations: dict[tuple[str, str], CandidateRegistration] = {}
        self._measurements: dict[tuple[str, str], MeasurementRegistry] = {}
        for registration in registrations:
            manifest = registration.manifest
            key = (manifest.probe_id, registration.observable)
            if (
                key in self._registrations
                or manifest.input_model != registration.parameter_model.__name__
                or manifest.safety.safety_class not in {SafetyClass.R0, SafetyClass.R1}
                or manifest.safety.privilege is not Privilege.STANDARD
                or manifest.safety.target_state_effect != "none"
                or manifest.safety.outbound_network
                or not 1 <= registration.cost_ms <= 120_000
                or not 1 <= registration.freshness_ttl_seconds <= 86_400
                or not 1 <= len(registration.description) <= 240
                or len(registration.targets) > 64
                or len(registration.dependency_evidence_ids) > 16
                or len(set(registration.dependency_evidence_ids))
                != len(registration.dependency_evidence_ids)
                or (
                    registration.max_window_lookback_seconds is not None
                    and not 1 <= registration.max_window_lookback_seconds <= 604_800
                )
            ):
                raise ValueError("candidate registration is not bounded and read-only")
            if len({item.handle for item in registration.targets}) != len(registration.targets):
                raise ValueError("candidate target handles must be unique")
            self._registrations[key] = registration
            self._measurements[key] = MeasurementRegistry(
                (
                    RegisteredMeasurement(
                        manifest=registration.manifest,
                        parameter_model=registration.parameter_model,
                        observable=registration.observable,
                        supports_window=registration.supports_window,
                        targets=tuple(
                            RegisteredTarget(handle=target.handle, parameters=target.parameters)
                            for target in registration.targets
                        ),
                    ),
                )
            )

    def issue(
        self, case_id: CaseId, epoch_state_version: int, need: MeasurementNeed
    ) -> CandidateRecord | CandidateGap:
        """Idempotently mint a fresh exact candidate; no machine action occurs."""

        now = ensure_utc(self._clock())
        with self._store.transaction():
            prepared = self._prepare(case_id, epoch_state_version, need, now)
            if isinstance(prepared, CandidateGap):
                return prepared
            row = self._store.connection.execute(
                "SELECT candidate_id FROM case_measurement_candidates "
                "WHERE case_id=? AND epoch_state_version=? AND binding_sha256=?",
                (str(case_id), epoch_state_version, prepared.binding_sha256),
            ).fetchone()
            if row is not None:
                candidate_id = str(row[0])
                resolved = self._resolve_locked(case_id, epoch_state_version, candidate_id, now)
                if isinstance(resolved, CandidateGap):
                    return resolved
                return resolved.candidate
            count = self._store.connection.execute(
                "SELECT COUNT(*) FROM case_measurement_candidates "
                "WHERE case_id=? AND epoch_state_version=?",
                (str(case_id), epoch_state_version),
            ).fetchone()
            assert count is not None
            if int(count[0]) >= _MAX_PER_EPOCH:
                return self._gap(case_id, None, CandidateGapReason.CATALOG_FULL)
            candidate_id = f"cand_v1_{uuid4().hex}"
            invocation_json = _invocation_json(prepared.invocation)
            invocation_sha256 = _sha256(invocation_json)
            dependency_json = _canonical(
                [
                    {
                        "evidence_id": str(item.evidence_id),
                        "sha256": item.digest,
                        "expires_at": item.expires_at.isoformat(),
                    }
                    for item in prepared.dependencies
                ]
            )
            self._store.connection.execute(
                "INSERT INTO case_measurement_candidates ("
                "candidate_id,schema_version,case_id,epoch_state_version,probe_id,"
                "manifest_version,manifest_sha256,invocation_json,invocation_sha256,"
                "observable,target_handle,source_evidence_id,source_evidence_sha256,"
                "dependency_bindings_json,dependency_sha256,binding_sha256,cost_ms,"
                "resource_class,safety_class,description,issued_at,expires_at) "
                "VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    candidate_id,
                    str(case_id),
                    epoch_state_version,
                    prepared.invocation.probe_id,
                    prepared.registration.manifest.version,
                    prepared.manifest_sha256,
                    invocation_json,
                    invocation_sha256,
                    prepared.invocation.observable,
                    prepared.invocation.target_handle,
                    str(prepared.source.evidence_id),
                    prepared.source.digest,
                    dependency_json,
                    _sha256(dependency_json),
                    prepared.binding_sha256,
                    prepared.registration.cost_ms,
                    prepared.registration.resource_class.value,
                    prepared.registration.manifest.safety.safety_class.value,
                    prepared.description,
                    now.isoformat(),
                    prepared.expires_at.isoformat(),
                ),
            )
            return self._record(candidate_id, prepared)

    def resolve(
        self, case_id: CaseId, epoch_state_version: int, candidate_id: str
    ) -> CandidateResolution | CandidateGap:
        """Revalidate eligibility; dispatcher must still admit before host access."""

        now = ensure_utc(self._clock())
        with self._store.read_snapshot():
            return self._resolve_locked(case_id, epoch_state_version, candidate_id, now)

    def resolve_for_claim(
        self,
        case_id: CaseId,
        epoch_state_version: int,
        candidate_id: str,
        admission_id: str,
    ) -> CandidateResolution | CandidateGap:
        """Recheck an already budgeted candidate without reserving a second slot."""

        now = ensure_utc(self._clock())
        with self._store.read_snapshot():
            row = self._store.connection.execute(
                "SELECT 1 FROM candidate_dispatch_admissions WHERE admission_id=? "
                "AND candidate_id=? AND case_id=? AND epoch_state_version=?",
                (admission_id, candidate_id, str(case_id), epoch_state_version),
            ).fetchone()
            if row is None:
                return self._gap(case_id, candidate_id, CandidateGapReason.UNKNOWN)
            return self._resolve_locked(
                case_id,
                epoch_state_version,
                candidate_id,
                now,
                require_new_budget=False,
            )

    def readback(self, case_id: CaseId, epoch_state_version: int) -> tuple[CandidateRecord, ...]:
        """Historical metadata only; call resolve to determine present eligibility."""

        rows = self._store.connection.execute(
            "SELECT candidate_id,probe_id,description,manifest_sha256,"
            "invocation_sha256,cost_ms,resource_class,safety_class "
            "FROM case_measurement_candidates WHERE case_id=? AND epoch_state_version=? "
            "ORDER BY issued_at,candidate_id",
            (str(case_id), epoch_state_version),
        ).fetchall()
        return tuple(
            CandidateRecord(
                candidate_id=str(row[0]),
                probe_id=str(row[1]),
                description=str(row[2]),
                manifest_sha256=str(row[3]),
                invocation_sha256=str(row[4]),
                cost_ms=int(row[5]),
                resource_class=ResourceClass(str(row[6])),
                safety_class=SafetyClass(str(row[7])),
            )
            for row in rows
        )

    def _resolve_locked(
        self,
        case_id: CaseId,
        epoch: int,
        candidate_id: str,
        now: datetime,
        *,
        require_new_budget: bool = True,
    ) -> CandidateResolution | CandidateGap:
        if _ID.fullmatch(candidate_id) is None:
            return self._gap(case_id, candidate_id, CandidateGapReason.UNKNOWN)
        row = self._store.connection.execute(
            "SELECT schema_version,probe_id,manifest_version,manifest_sha256,"
            "invocation_json,invocation_sha256,observable,target_handle,source_evidence_id,"
            "source_evidence_sha256,dependency_bindings_json,dependency_sha256,binding_sha256,"
            "cost_ms,resource_class,safety_class,description,issued_at,expires_at "
            "FROM case_measurement_candidates "
            "WHERE candidate_id=? AND case_id=? AND epoch_state_version=?",
            (candidate_id, str(case_id), epoch),
        ).fetchone()
        if row is None:
            return self._gap(case_id, candidate_id, CandidateGapReason.UNKNOWN)
        if self._checkpoint(case_id, epoch, now) is None:
            return self._gap(case_id, candidate_id, CandidateGapReason.STALE_CASE)
        try:
            invocation_json = str(row[4])
            invocation = ProbeInvocation.model_validate_json(invocation_json)
            issued_at = _utc(str(row[17]))
            expires_at = _utc(str(row[18]))
            dependency_rows: object = json.loads(str(row[10]))
            if not isinstance(dependency_rows, list):
                raise ValueError("dependency bindings are not a list")
            dependency_rows = cast("list[object]", dependency_rows)
        except (TypeError, ValueError):
            return self._gap(case_id, candidate_id, CandidateGapReason.INVALID_BINDING)
        registration = self._registrations.get((str(row[1]), str(row[6])))
        if registration is None:
            return self._gap(case_id, candidate_id, CandidateGapReason.UNREGISTERED)
        if (
            int(row[0]) != 1
            or invocation.probe_id != str(row[1])
            or invocation.probe_version != int(row[2])
            or invocation.observable != str(row[6])
            or invocation.target_handle != row[7]
            or _sha256(invocation_json) != str(row[5])
            or _sha256(str(row[10])) != str(row[11])
            or not issued_at <= now < expires_at
        ):
            return self._gap(case_id, candidate_id, CandidateGapReason.INVALID_BINDING)
        current = self._lookup(registration.manifest.probe_id)
        if (
            current is None
            or _manifest_sha256(current) != str(row[3])
            or _manifest_sha256(registration.manifest) != str(row[3])
        ):
            return self._gap(case_id, candidate_id, CandidateGapReason.MANIFEST_CHANGED)
        need = MeasurementNeed(
            capability_id=invocation.probe_id,
            observable=invocation.observable,
            target_handle=invocation.target_handle,
            window=invocation.window,
        )
        prepared = self._prepare(case_id, epoch, need, now)
        if isinstance(prepared, CandidateGap):
            return prepared
        if (
            prepared.invocation != invocation
            or prepared.manifest_sha256 != str(row[3])
            or str(prepared.source.evidence_id) != str(row[8])
            or prepared.source.digest != str(row[9])
            or prepared.binding_sha256 != str(row[12])
            or prepared.registration.cost_ms != int(row[13])
            or prepared.registration.resource_class.value != str(row[14])
            or prepared.registration.manifest.safety.safety_class.value != str(row[15])
            or prepared.description != str(row[16])
            or prepared.expires_at != expires_at
            or len(prepared.dependencies) != len(dependency_rows)
        ):
            return self._gap(case_id, candidate_id, CandidateGapReason.SOURCE_CHANGED)
        expected_dependencies = [
            {
                "evidence_id": str(item.evidence_id),
                "sha256": item.digest,
                "expires_at": item.expires_at.isoformat(),
            }
            for item in prepared.dependencies
        ]
        if dependency_rows != expected_dependencies:
            return self._gap(case_id, candidate_id, CandidateGapReason.SOURCE_CHANGED)
        if require_new_budget and not self._budget_ok(case_id, epoch, registration.cost_ms):
            return self._gap(case_id, candidate_id, CandidateGapReason.BUDGET_EXHAUSTED)
        return CandidateResolution(
            candidate=self._record(candidate_id, prepared), invocation=invocation
        )

    def _prepare(
        self, case_id: CaseId, epoch: int, need: MeasurementNeed, now: datetime
    ) -> _Prepared | CandidateGap:
        checkpoint = self._checkpoint(case_id, epoch, now)
        if checkpoint is None:
            return self._gap(case_id, None, CandidateGapReason.STALE_CASE)
        key = (need.capability_id, need.observable)
        registration = self._registrations.get(key)
        if registration is None:
            return self._gap(case_id, None, CandidateGapReason.UNREGISTERED)
        current = self._lookup(registration.manifest.probe_id)
        manifest_sha256 = _manifest_sha256(registration.manifest)
        if current is None or _manifest_sha256(current) != manifest_sha256:
            return self._gap(case_id, None, CandidateGapReason.MANIFEST_CHANGED)
        if need.window is not None and (
            not registration.supports_window
            or registration.max_window_lookback_seconds is None
            or need.window.end > now
            or now - need.window.end > timedelta(seconds=registration.max_window_lookback_seconds)
        ):
            return self._gap(case_id, None, CandidateGapReason.WINDOW_INELIGIBLE)
        target = next(
            (item for item in registration.targets if item.handle == need.target_handle), None
        )
        if need.target_handle is not None and target is None:
            return self._gap(case_id, None, CandidateGapReason.UNREGISTERED)
        try:
            resolved = self._measurements[key].resolve(need)
        except ValueError:
            return self._gap(case_id, None, CandidateGapReason.INVALID_BINDING)
        if isinstance(resolved, ObservabilityGap):
            return self._gap(case_id, None, CandidateGapReason.UNREGISTERED)
        invocation = resolved
        if target is not None:
            if self._revalidate_target is None:
                return self._gap(case_id, None, CandidateGapReason.TARGET_CHANGED)
            try:
                valid_target = self._revalidate_target(case_id, target, invocation)
            except Exception:
                valid_target = False
            if not valid_target:
                return self._gap(case_id, None, CandidateGapReason.TARGET_CHANGED)
        source_id = (
            target.source_evidence_id
            if target is not None and target.source_evidence_id is not None
            else registration.source_evidence_id
        )
        source = self._evidence_binding(case_id, epoch, source_id, registration, now)
        if source is None:
            return self._gap(case_id, None, CandidateGapReason.SOURCE_STALE)
        dependencies: list[_EvidenceBinding] = []
        for dependency_id in registration.dependency_evidence_ids:
            dependency = self._evidence_binding(case_id, epoch, dependency_id, registration, now)
            if dependency is None:
                return self._gap(case_id, None, CandidateGapReason.SOURCE_STALE)
            dependencies.append(dependency)
        expires_at = min(
            source.expires_at,
            *(item.expires_at for item in dependencies),
            _utc(cast("str", checkpoint["deadline_at"])),
        )
        if now >= expires_at:
            return self._gap(case_id, None, CandidateGapReason.SOURCE_STALE)
        description = (
            target.description
            if target is not None and target.description
            else registration.description
        )
        if need.window is not None:
            description = (
                f"{description} in {need.window.start:%Y-%m-%d %H:%M}-{need.window.end:%H:%M} UTC"
            )
        if not 1 <= len(description) <= 240:
            return self._gap(case_id, None, CandidateGapReason.INVALID_BINDING)
        invocation_sha256 = _sha256(_invocation_json(invocation))
        dependency_payload = [
            {
                "evidence_id": str(item.evidence_id),
                "sha256": item.digest,
                "expires_at": item.expires_at.isoformat(),
            }
            for item in dependencies
        ]
        binding_sha256 = _sha256(
            _canonical(
                {
                    "schema_version": 1,
                    "case_id": str(case_id),
                    "epoch_state_version": epoch,
                    "manifest_sha256": manifest_sha256,
                    "invocation_sha256": invocation_sha256,
                    "source_evidence_id": str(source.evidence_id),
                    "source_evidence_sha256": source.digest,
                    "source_expires_at": source.expires_at.isoformat(),
                    "dependencies": dependency_payload,
                    "cost_ms": registration.cost_ms,
                    "resource_class": registration.resource_class.value,
                    "safety_class": registration.manifest.safety.safety_class.value,
                    "description": description,
                }
            )
        )
        return _Prepared(
            registration=registration,
            invocation=invocation,
            target=target,
            source=source,
            dependencies=tuple(dependencies),
            manifest_sha256=manifest_sha256,
            description=description,
            expires_at=expires_at,
            binding_sha256=binding_sha256,
        )

    def _evidence_binding(
        self,
        case_id: CaseId,
        epoch: int,
        evidence_id: EvidenceId,
        registration: CandidateRegistration,
        now: datetime,
    ) -> _EvidenceBinding | None:
        row = self._store.connection.execute(
            "SELECT record_json,source_id,execution_id,observed_at,captured_at,"
            "time_basis,time_quality "
            "FROM evidence WHERE case_id=? AND evidence_id=?",
            (str(case_id), str(evidence_id)),
        ).fetchone()
        if row is None:
            return None
        raw = str(row[0])
        try:
            record = EvidenceRecord.model_validate_json(raw)
            observed_at = _utc(str(row[3]))
            captured_at = _utc(str(row[4]))
        except ValueError:
            return None
        if (
            record.case_id != case_id
            or record.evidence_id != evidence_id
            or record.statement_kind is not StatementKind.OBSERVED_FACT
            or record.source.source_id != str(row[1])
            or str(record.collector.execution_id) != str(row[2])
            or record.observed_at != observed_at
            or record.captured_at != captured_at
            or observed_at > captured_at
            or observed_at > now
            or captured_at > now
            or (str(row[5]), str(row[6]))
            not in {
                ("collector_upper_bound", "bounded_interval"),
                ("collector_observed", "exact"),
                ("collector_captured", "exact"),
                ("source_observed", "exact"),
                ("source_event", "exact"),
            }
        ):
            return None
        execution = self._store.connection.execute(
            "SELECT probe_id,probe_version,status,state_version,started_at,finished_at "
            "FROM probe_executions WHERE case_id=? AND execution_id=?",
            (str(case_id), str(row[2])),
        ).fetchone()
        if (
            execution is None
            or str(execution[0]) != record.collector.id
            or int(execution[1]) != record.collector.version
            or str(execution[2]) != "ok"
            or int(execution[3]) > epoch
            or execution[4] is None
            or execution[5] is None
            or not _utc(str(execution[4])) <= _utc(str(execution[5])) <= captured_at
        ):
            return None
        expires_at = min(observed_at, captured_at) + timedelta(
            seconds=registration.freshness_ttl_seconds
        )
        if now >= expires_at:
            return None
        return _EvidenceBinding(evidence_id=evidence_id, digest=_sha256(raw), expires_at=expires_at)

    def _checkpoint(self, case_id: CaseId, epoch: int, now: datetime) -> dict[str, object] | None:
        case = self._store.case(str(case_id))
        if case is None or case.status != "collecting" or case.state_version != epoch:
            return None
        row = self._store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(case_id),)
        ).fetchone()
        if row is None:
            return None
        try:
            checkpoint: object = json.loads(str(row[0]))
            if not isinstance(checkpoint, dict):
                return None
            parsed = cast("dict[str, object]", checkpoint)
            deadline = _utc(str(parsed["deadline_at"]))
        except (KeyError, TypeError, ValueError):
            return None
        if (
            parsed.get("case_id") != str(case_id)
            or parsed.get("state_version") != epoch
            or parsed.get("status") != "running"
            or now >= deadline
        ):
            return None
        return parsed

    def _budget_ok(self, case_id: CaseId, epoch: int, cost_ms: int) -> bool:
        checkpoint = self._checkpoint(case_id, epoch, ensure_utc(self._clock()))
        if checkpoint is None:
            return False
        try:
            budget_ms = int(cast("int", checkpoint["budget_ms"]))
            spent_cost_ms = int(cast("int", checkpoint["spent_cost_ms"]))
            max_probes = int(cast("int", checkpoint["max_probes"]))
            unrecorded = int(cast("int", checkpoint["unrecorded_attempt_count"]))
            completed = set(cast("list[str]", checkpoint["completed_probe_ids"]))
            pending = set(cast("list[str]", checkpoint["pending_probe_ids"]))
            interrupted = set(cast("list[str]", checkpoint["interrupted_probe_ids"]))
        except (KeyError, TypeError, ValueError):
            return False
        if min(budget_ms, max_probes) <= 0 or min(spent_cost_ms, unrecorded) < 0:
            return False
        history_rows = self._store.connection.execute(
            "SELECT probe_id FROM probe_executions WHERE case_id=?", (str(case_id),)
        ).fetchall()
        history_ids = {str(row[0]) for row in history_rows}
        unknown = (completed | pending).difference(history_ids, interrupted)
        admitted = self._store.connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(estimated_cost_ms),0) "
            "FROM collection_followup_admissions AS a "
            "LEFT JOIN collection_followup_execution_links AS l "
            "ON l.admission_id=a.admission_id "
            "WHERE a.case_id=? AND a.epoch_state_version=? AND l.admission_id IS NULL",
            (str(case_id), epoch),
        ).fetchone()
        candidate_unlinked = self._store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions AS a "
            "LEFT JOIN candidate_decision_execution_links AS l "
            "ON l.snapshot_id=a.snapshot_id AND l.candidate_id=a.candidate_id "
            "WHERE a.case_id=? AND l.execution_id IS NULL",
            (str(case_id),),
        ).fetchone()
        candidate_cost = self._store.connection.execute(
            "SELECT COALESCE(SUM(cost_ms),0) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        assert (
            admitted is not None and candidate_unlinked is not None and candidate_cost is not None
        )
        return (
            len(history_rows)
            + len(unknown)
            + unrecorded
            + int(admitted[0])
            + int(candidate_unlinked[0])
            + 1
            <= max_probes
            and spent_cost_ms + int(admitted[1]) + int(candidate_cost[0]) + cost_ms <= budget_ms
        )

    @staticmethod
    def _record(candidate_id: str, prepared: _Prepared) -> CandidateRecord:
        return CandidateRecord(
            candidate_id=candidate_id,
            probe_id=prepared.invocation.probe_id,
            description=prepared.description,
            manifest_sha256=prepared.manifest_sha256,
            invocation_sha256=_sha256(_invocation_json(prepared.invocation)),
            cost_ms=prepared.registration.cost_ms,
            resource_class=prepared.registration.resource_class,
            safety_class=prepared.registration.manifest.safety.safety_class,
        )

    @staticmethod
    def _gap(case_id: CaseId, candidate_id: str | None, reason: CandidateGapReason) -> CandidateGap:
        return CandidateGap(case_id=case_id, candidate_id=candidate_id, reason=reason)
