"""Application-owned candidate catalogs for bounded read-only sampling."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime, timedelta

from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, stable_source_id
from systemsense.domain.probes import MeasurementNeed, MeasurementWindow, ProbeInvocation
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.evidence.redaction import Redactor
from systemsense.orchestration.probes import ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import (
    LiveSampleWindowParametersV1,
    NoParameters,
    TargetPressureParametersV1,
)
from systemsense.platform.windows.deep_collectors import ComponentStatus, NvidiaTelemetrySnapshot
from systemsense.storage.case_candidates import (
    CandidateRegistration,
    CandidateTargetBinding,
    CaseCandidateRegistry,
)
from systemsense.storage.sqlite_store import SQLiteStore

_PROBE_ID = "application.target_pressure"
_GENERAL_PROBE_ID = "pressure.sample"
_GENERAL_SOURCE_ID = "core.resources"
_GPU_PROBE_ID = "gpu.telemetry.sample"
_GPU_SOURCE_ID = "local_ai.snapshot"
_GPU_SAMPLE_BOUND_NOTE = "nvidia-smi sample instant is unknown within the bounded query interval"
_GENERAL_FRESHNESS_SECONDS = 300
_SAFE_EXECUTABLE_NAME = re.compile(r"[A-Za-z0-9_.+-]{1,80}\Z")


class NoParametersV1(NoParameters):
    """Catalog schema name for the built-in parameter-free probe manifest."""


def _description_for_process(name: str, pid: int, redactor: Redactor) -> str:
    scrubbed = redactor.redact_text(name)
    if scrubbed.replacements or _SAFE_EXECUTABLE_NAME.fullmatch(scrubbed.text) is None:
        return f"Read bounded pressure for inventory process PID {pid}"
    return f"Read bounded pressure for {scrubbed.text} (PID {pid})"


def _current_general_source(
    store: SQLiteStore,
    case_id: CaseId,
    now: datetime,
    *,
    admitted_source: EvidenceId | None = None,
) -> EvidenceId | None:
    """Select one exact baseline observation, with no alternate source fallback."""
    source_clause = " AND e.evidence_id=?" if admitted_source is not None else ""
    row = store.connection.execute(
        "SELECT e.evidence_id,e.record_json,e.observed_at,e.captured_at,x.status,"
        "e.execution_id,e.source_id,e.time_basis,e.time_quality,x.probe_version,"
        "x.started_at,x.finished_at "
        "FROM evidence AS e JOIN probe_executions AS x "
        "ON x.case_id=e.case_id AND x.execution_id=e.execution_id "
        f"WHERE e.case_id=? AND x.probe_id=?{source_clause} "
        "ORDER BY e.captured_at DESC,e.evidence_id DESC LIMIT 1",
        (
            (str(case_id), _GENERAL_SOURCE_ID, str(admitted_source))
            if admitted_source is not None
            else (str(case_id), _GENERAL_SOURCE_ID)
        ),
    ).fetchone()
    if row is None or str(row[4]) != "ok":
        return None
    try:
        record = EvidenceRecord.model_validate_json(str(row[1]))
        observed_at = ensure_utc(datetime.fromisoformat(str(row[2])))
        captured_at = ensure_utc(datetime.fromisoformat(str(row[3])))
        started_at = ensure_utc(datetime.fromisoformat(str(row[10])))
        finished_at = ensure_utc(datetime.fromisoformat(str(row[11])))
    except ValueError:
        return None
    expected_source_id = stable_source_id(
        "systemsense.probe",
        {"probe_id": _GENERAL_SOURCE_ID, "probe_version": record.collector.version},
    )
    if (
        record.case_id != case_id
        or str(record.evidence_id) != str(row[0])
        or record.statement_kind is not StatementKind.OBSERVED_FACT
        or record.collector.id != _GENERAL_SOURCE_ID
        or str(record.collector.execution_id) != str(row[5])
        or record.source.type != "systemsense.probe"
        or record.source.locator != {"probe_id": _GENERAL_SOURCE_ID}
        or record.source.source_id != expected_source_id
        or record.source.source_id != str(row[6])
        or (str(row[7]), str(row[8]))
        not in {
            ("collector_observed", "exact"),
            ("collector_captured", "exact"),
            ("collector_upper_bound", "bounded_interval"),
        }
        or record.collector.version != int(row[9])
        or record.observed_at != observed_at
        or record.captured_at != captured_at
        or started_at > finished_at
        or finished_at > captured_at
        or not observed_at <= captured_at <= now
        or now >= observed_at + timedelta(seconds=_GENERAL_FRESHNESS_SECONDS)
    ):
        return None
    return record.evidence_id


def _attempted_for_source(
    store: SQLiteStore,
    case_id: CaseId,
    source_id: EvidenceId,
    probe_id: str,
    window: MeasurementWindow | None = None,
) -> bool:
    # A live interval is a case-level observation identity. A fresher baseline
    # may justify a *new* interval, but cannot authorize replay of this one.
    source_clause = " AND c.source_evidence_id=?" if window is None else ""
    admitted = store.connection.execute(
        "SELECT c.invocation_json FROM candidate_dispatch_admissions AS a "
        "JOIN case_measurement_candidates AS c ON c.candidate_id=a.candidate_id "
        "WHERE a.case_id=? AND c.case_id=? AND c.probe_id=? "
        f"{source_clause}",
        (
            (str(case_id), str(case_id), probe_id, str(source_id))
            if window is None
            else (str(case_id), str(case_id), probe_id)
        ),
    ).fetchall()
    expected_window = None if window is None else window.model_dump(mode="json")
    if any(json.loads(str(row[0])).get("window") == expected_window for row in admitted):
        # Admission may have reached the host before a crash. Reissuing the
        # same no-window need under a newer checkpoint is not a safe retry.
        return True
    execution_source_clause = (
        " AND finished_at >= (SELECT captured_at FROM evidence WHERE case_id=? AND evidence_id=?)"
        if window is None
        else ""
    )
    rows = store.connection.execute(
        "SELECT parameters_json FROM probe_executions WHERE case_id=? AND probe_id=? "
        f"{execution_source_clause}",
        (
            (str(case_id), probe_id, str(case_id), str(source_id))
            if window is None
            else (str(case_id), probe_id)
        ),
    ).fetchall()
    expected_parameters = (
        {}
        if window is None
        else {
            "window_start": window.start.isoformat(),
            "window_end": window.end.isoformat(),
        }
    )
    return any(json.loads(str(row[0])) == expected_parameters for row in rows)


def _current_gpu_source(
    store: SQLiteStore,
    case_id: CaseId,
    now: datetime,
    *,
    admitted_source: EvidenceId | None = None,
) -> EvidenceId | None:
    """Require a fresh successful native NVIDIA observation, not GPU-name text."""
    source_clause = " AND e.evidence_id=?" if admitted_source is not None else ""
    parameters = (
        (str(case_id), _GPU_SOURCE_ID, str(admitted_source))
        if admitted_source is not None
        else (str(case_id), _GPU_SOURCE_ID)
    )
    row = store.connection.execute(
        "SELECT e.evidence_id,e.record_json,e.observed_at,e.captured_at,e.source_id,"
        "e.execution_id,e.time_basis,e.time_quality,x.status,x.probe_version,"
        "x.parameters_json,x.started_at,x.finished_at "
        "FROM evidence AS e JOIN probe_executions AS x "
        "ON x.case_id=e.case_id AND x.execution_id=e.execution_id "
        f"WHERE e.case_id=? AND x.probe_id=?{source_clause} "
        "ORDER BY e.captured_at DESC,e.evidence_id DESC LIMIT 1",
        parameters,
    ).fetchone()
    if row is None or str(row[8]) != "ok" or str(row[10]) != "{}":
        return None
    try:
        record = EvidenceRecord.model_validate_json(str(row[1]))
        observed_at = ensure_utc(datetime.fromisoformat(str(row[2])))
        captured_at = ensure_utc(datetime.fromisoformat(str(row[3])))
        started_at = ensure_utc(datetime.fromisoformat(str(row[11])))
        finished_at = ensure_utc(datetime.fromisoformat(str(row[12])))
        facts = {fact.name: fact.value for fact in record.facts}
        if len(facts) != len(record.facts):
            return None
        telemetry = NvidiaTelemetrySnapshot.model_validate(facts.get("nvidia_telemetry"))
        source_started_at = ensure_utc(datetime.fromisoformat(str(facts["collection_started_at"])))
        source_completed_at = ensure_utc(
            datetime.fromisoformat(str(facts["collection_completed_at"]))
        )
    except (KeyError, TypeError, ValueError):
        return None
    expected_source_id = stable_source_id(
        "systemsense.probe",
        {"probe_id": _GPU_SOURCE_ID, "probe_version": record.collector.version},
    )
    gpu_ids = tuple(gpu.uuid.strip().casefold() for gpu in telemetry.gpus)
    if (
        record.case_id != case_id
        or str(record.evidence_id) != str(row[0])
        or record.statement_kind is not StatementKind.OBSERVED_FACT
        or record.collector.id != _GPU_SOURCE_ID
        or record.collector.version != int(row[9])
        or str(record.collector.execution_id) != str(row[5])
        or record.source.type != "systemsense.probe"
        or record.source.locator != {"probe_id": _GPU_SOURCE_ID}
        or record.source.source_id != expected_source_id
        or record.source.source_id != str(row[4])
        or record.extraction.parser != "builtin.probe"
        or record.extraction.parser_version != 1
        or record.extraction.confidence != 1.0
        or (str(row[6]), str(row[7])) != ("collector_upper_bound", "bounded_interval")
        or record.observed_at != observed_at
        or record.captured_at != captured_at
        or telemetry.sample_started_at is None
        or not started_at <= source_started_at <= telemetry.sample_started_at
        or not telemetry.sample_started_at <= telemetry.captured_at
        or not telemetry.captured_at <= source_completed_at == observed_at
        or not observed_at <= finished_at <= captured_at
        or not observed_at <= captured_at <= now
        or now >= observed_at + timedelta(seconds=_GENERAL_FRESHNESS_SECONDS)
        or telemetry.status is not ComponentStatus.AVAILABLE
        or telemetry.limitation != _GPU_SAMPLE_BOUND_NOTE
        or not gpu_ids
        or any(not uuid for uuid in gpu_ids)
        or len(gpu_ids) != len(set(gpu_ids))
    ):
        return None
    return record.evidence_id


def _admitted_gpu_source(store: SQLiteStore, case_id: CaseId) -> EvidenceId | None:
    rows = store.connection.execute(
        "SELECT c.source_evidence_id FROM candidate_dispatch_admissions AS a "
        "JOIN case_measurement_candidates AS c ON c.candidate_id=a.candidate_id "
        "WHERE a.case_id=? AND c.case_id=? AND c.probe_id=? LIMIT 2",
        (str(case_id), str(case_id), _GPU_PROBE_ID),
    ).fetchall()
    if len(rows) != 1:
        return None
    try:
        return EvidenceId(root=str(rows[0][0]))
    except ValueError:
        return None


def _admitted_window_binding(
    store: SQLiteStore, case_id: CaseId, candidate_id: str
) -> tuple[str, EvidenceId, MeasurementWindow | None] | None:
    row = store.connection.execute(
        "SELECT c.probe_id,c.source_evidence_id,c.invocation_json "
        "FROM candidate_dispatch_admissions AS a "
        "JOIN case_measurement_candidates AS c ON c.candidate_id=a.candidate_id "
        "WHERE a.case_id=? AND c.case_id=? AND c.candidate_id=?",
        (str(case_id), str(case_id), candidate_id),
    ).fetchone()
    if row is None:
        return None
    try:
        invocation = ProbeInvocation.model_validate_json(str(row[2]))
        if invocation.probe_id != str(row[0]):
            return None
        return str(row[0]), EvidenceId(root=str(row[1])), invocation.window
    except ValueError:
        return None


def _gpu_attempted_in_case(store: SQLiteStore, case_id: CaseId) -> bool:
    """One passive GPU series per case, even if inventory refreshes later."""
    return (
        store.connection.execute(
            "SELECT 1 FROM candidate_dispatch_admissions AS a "
            "JOIN case_measurement_candidates AS c ON c.candidate_id=a.candidate_id "
            "WHERE a.case_id=? AND c.case_id=? AND c.probe_id=? LIMIT 1",
            (str(case_id), str(case_id), _GPU_PROBE_ID),
        ).fetchone()
        is not None
        or store.connection.execute(
            "SELECT 1 FROM probe_executions WHERE case_id=? AND probe_id=? LIMIT 1",
            (str(case_id), _GPU_PROBE_ID),
        ).fetchone()
        is not None
    )


def general_pressure_candidate_catalog(
    store: SQLiteStore,
    runner: ProbeRunner,
    case_id: CaseId,
    *,
    for_existing_admission: bool = False,
    observation_window: MeasurementWindow | None = None,
    clock: Callable[[], datetime] = utc_now,
) -> tuple[CaseCandidateRegistry, tuple[MeasurementNeed, ...]]:
    """Offer a new choice, or reconstruct an old one only for worker claim."""
    now = ensure_utc(clock())
    source_id = _current_general_source(store, case_id, now)
    manifest = runner.manifest(_GENERAL_PROBE_ID)
    registrations: tuple[CandidateRegistration, ...] = ()
    needs: tuple[MeasurementNeed, ...] = ()
    eligible_source = (
        source_id is not None
        and manifest is not None
        and manifest.input_model == LiveSampleWindowParametersV1.__name__
    )
    attempted = (
        _attempted_for_source(store, case_id, source_id, _GENERAL_PROBE_ID, observation_window)
        if eligible_source and source_id is not None
        else False
    )
    if eligible_source and (for_existing_admission or not attempted):
        assert source_id is not None and manifest is not None
        registrations = (
            CandidateRegistration(
                manifest=manifest,
                parameter_model=LiveSampleWindowParametersV1,
                observable=_GENERAL_PROBE_ID,
                description="Read bounded host CPU, memory, and disk pressure samples",
                cost_ms=10_000,
                resource_class=ResourceClass.CPU,
                source_evidence_id=source_id,
                freshness_ttl_seconds=_GENERAL_FRESHNESS_SECONDS,
                supports_window=True,
                live_window=True,
            ),
        )
        if not attempted:
            needs = (
                MeasurementNeed(
                    capability_id=_GENERAL_PROBE_ID,
                    observable=_GENERAL_PROBE_ID,
                    window=observation_window,
                ),
            )
    return (
        CaseCandidateRegistry(
            store,
            registrations=registrations,
            manifest_lookup=runner.manifest,
            revalidate_target=None,
            clock=clock,
        ),
        needs,
    )


def general_measurement_candidate_catalog(
    store: SQLiteStore,
    runner: ProbeRunner,
    case_id: CaseId,
    *,
    for_existing_admission: bool = False,
    for_existing_candidate_id: str | None = None,
    observation_window: MeasurementWindow | None = None,
    clock: Callable[[], datetime] = utc_now,
) -> tuple[CaseCandidateRegistry, tuple[MeasurementNeed, ...]]:
    """Finite pressure and NVIDIA choices bound to separate exact baseline sources."""
    now = ensure_utc(clock())
    if for_existing_candidate_id is not None and not for_existing_admission:
        raise ValueError("exact candidate reconstruction requires an existing admission")
    exact_binding = (
        _admitted_window_binding(store, case_id, for_existing_candidate_id)
        if for_existing_candidate_id is not None
        else None
    )
    if for_existing_candidate_id is not None and exact_binding is None:
        return CaseCandidateRegistry(
            store,
            registrations=(),
            manifest_lookup=runner.manifest,
            revalidate_target=None,
            clock=clock,
        ), ()
    if exact_binding is not None:
        observation_window = exact_binding[2]
    registrations: list[CandidateRegistration] = []
    needs: list[MeasurementNeed] = []
    admitted_gpu_source = (
        exact_binding[1]
        if exact_binding is not None and exact_binding[0] == _GPU_PROBE_ID
        else _admitted_gpu_source(store, case_id)
        if for_existing_admission and exact_binding is None
        else None
    )
    gpu_source = (
        _current_gpu_source(store, case_id, now, admitted_source=admitted_gpu_source)
        if not for_existing_admission or admitted_gpu_source is not None
        else None
    )
    for probe_id, source_id, description, cost_ms, resource in (
        (
            _GENERAL_PROBE_ID,
            _current_general_source(
                store,
                case_id,
                now,
                admitted_source=(
                    exact_binding[1]
                    if exact_binding is not None and exact_binding[0] == _GENERAL_PROBE_ID
                    else None
                ),
            )
            if exact_binding is None or exact_binding[0] == _GENERAL_PROBE_ID
            else None,
            "Read bounded host CPU, memory, and disk pressure samples",
            10_000,
            ResourceClass.CPU,
        ),
        (
            _GPU_PROBE_ID,
            gpu_source,
            "Read bounded NVIDIA utilization, memory, thermal, power, and clock samples",
            2_500,
            ResourceClass.GPU,
        ),
    ):
        if exact_binding is not None and probe_id != exact_binding[0]:
            continue
        manifest = runner.manifest(probe_id)
        if (
            source_id is None
            or manifest is None
            or manifest.input_model != LiveSampleWindowParametersV1.__name__
        ):
            continue
        attempted = (
            _gpu_attempted_in_case(store, case_id)
            if probe_id == _GPU_PROBE_ID and observation_window is None
            else _attempted_for_source(store, case_id, source_id, probe_id, observation_window)
        )
        if attempted and not for_existing_admission:
            continue
        registrations.append(
            CandidateRegistration(
                manifest=manifest,
                parameter_model=LiveSampleWindowParametersV1,
                observable=probe_id,
                description=description,
                cost_ms=cost_ms,
                resource_class=resource,
                source_evidence_id=source_id,
                freshness_ttl_seconds=_GENERAL_FRESHNESS_SECONDS,
                supports_window=True,
                live_window=True,
            )
        )
        if not attempted and not for_existing_admission:
            needs.append(
                MeasurementNeed(
                    capability_id=probe_id, observable=probe_id, window=observation_window
                )
            )
    return (
        CaseCandidateRegistry(
            store,
            registrations=tuple(registrations),
            manifest_lookup=runner.manifest,
            revalidate_target=None,
            clock=clock,
        ),
        tuple(needs),
    )


def process_pressure_candidate_catalog(
    store: SQLiteStore,
    runner: ProbeRunner,
    case_id: CaseId,
    *,
    clock: Callable[[], datetime] = utc_now,
) -> tuple[CaseCandidateRegistry, tuple[MeasurementNeed, ...]]:
    """Enumerate only fresh case-inventory targets; no candidate is a dispatch grant.

    The return value contains private typed needs for local issue/admission. The
    fast brain sees only the registry's later model-safe CandidateRecord values.
    """
    targets = ProcessTargetRepository(store, clock=clock)
    inventory = targets.list_process_candidates(case_id)
    manifest = runner.manifest(_PROBE_ID)
    if manifest is None:
        raise ValueError("registered process-pressure probe is unavailable")
    redactor = Redactor()
    bindings = tuple(
        CandidateTargetBinding(
            handle=item.candidate_id,
            parameters={"pid": item.pid, "creation_time": item.creation_time.isoformat()},
            source_evidence_id=item.evidence_id,
            description=_description_for_process(item.name, item.pid, redactor),
        )
        for item in inventory.candidates
    )

    def revalidate(
        requested_case: CaseId,
        target: CandidateTargetBinding,
        invocation: ProbeInvocation,
    ) -> bool:
        if requested_case != case_id or target.source_evidence_id != inventory.evidence_id:
            return False
        try:
            current = targets.resolve_process_candidate_for_sampling(requested_case, target.handle)
            parameters = TargetPressureParametersV1.model_validate(invocation.parameters)
        except (TargetSelectionError, ValueError):
            return False
        return (
            invocation.target_handle == target.handle
            and current.evidence_id == inventory.evidence_id
            and current.pid == parameters.pid
            and current.creation_time == parameters.creation_time
        )

    registry = CaseCandidateRegistry(
        store,
        registrations=(
            CandidateRegistration(
                manifest=manifest,
                parameter_model=TargetPressureParametersV1,
                observable=_PROBE_ID,
                description="Read bounded pressure for an inventory-derived process",
                cost_ms=10_000,
                resource_class=ResourceClass.PROCESS,
                source_evidence_id=inventory.evidence_id,
                freshness_ttl_seconds=300,
                targets=bindings,
            ),
        ),
        manifest_lookup=runner.manifest,
        revalidate_target=revalidate,
        clock=clock,
    )
    needs = tuple(
        MeasurementNeed(
            capability_id=_PROBE_ID,
            observable=_PROBE_ID,
            target_handle=item.candidate_id,
        )
        for item in inventory.candidates
    )
    return registry, needs
