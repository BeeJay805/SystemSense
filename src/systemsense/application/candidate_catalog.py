"""Application-owned candidate catalogs for bounded read-only sampling."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timedelta

from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId, stable_source_id
from systemsense.domain.probes import MeasurementNeed, ProbeInvocation
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.evidence.redaction import Redactor
from systemsense.orchestration.probes import ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import NoParameters, TargetPressureParametersV1
from systemsense.storage.case_candidates import (
    CandidateRegistration,
    CandidateTargetBinding,
    CaseCandidateRegistry,
)
from systemsense.storage.sqlite_store import SQLiteStore

_PROBE_ID = "application.target_pressure"
_GENERAL_PROBE_ID = "pressure.sample"
_GENERAL_SOURCE_ID = "core.resources"
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
    store: SQLiteStore, case_id: CaseId, now: datetime
) -> EvidenceId | None:
    """Select one exact baseline observation, with no alternate source fallback."""
    row = store.connection.execute(
        "SELECT e.evidence_id,e.record_json,e.observed_at,e.captured_at,x.status,"
        "e.execution_id,e.source_id,e.time_basis,e.time_quality,x.probe_version,"
        "x.started_at,x.finished_at "
        "FROM evidence AS e JOIN probe_executions AS x "
        "ON x.case_id=e.case_id AND x.execution_id=e.execution_id "
        "WHERE e.case_id=? AND x.probe_id=? "
        "ORDER BY e.captured_at DESC,e.evidence_id DESC LIMIT 1",
        (str(case_id), _GENERAL_SOURCE_ID),
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


def _pressure_already_sampled(store: SQLiteStore, case_id: CaseId, source_id: EvidenceId) -> bool:
    row = store.connection.execute(
        "SELECT 1 FROM probe_executions WHERE case_id=? AND probe_id=? "
        "AND status='ok' AND parameters_json='{}' AND finished_at >= "
        "(SELECT observed_at FROM evidence WHERE case_id=? AND evidence_id=?) LIMIT 1",
        (str(case_id), _GENERAL_PROBE_ID, str(case_id), str(source_id)),
    ).fetchone()
    return row is not None


def general_pressure_candidate_catalog(
    store: SQLiteStore,
    runner: ProbeRunner,
    case_id: CaseId,
    *,
    clock: Callable[[], datetime] = utc_now,
) -> tuple[CaseCandidateRegistry, tuple[MeasurementNeed, ...]]:
    """Offer one parameter-free host-pressure sample from a fresh case baseline."""
    now = ensure_utc(clock())
    source_id = _current_general_source(store, case_id, now)
    manifest = runner.manifest(_GENERAL_PROBE_ID)
    registrations: tuple[CandidateRegistration, ...] = ()
    needs: tuple[MeasurementNeed, ...] = ()
    if (
        source_id is not None
        and manifest is not None
        and manifest.input_model == NoParametersV1.__name__
        and not _pressure_already_sampled(store, case_id, source_id)
    ):
        registrations = (
            CandidateRegistration(
                manifest=manifest,
                parameter_model=NoParametersV1,
                observable=_GENERAL_PROBE_ID,
                description="Read bounded host CPU, memory, and disk pressure samples",
                cost_ms=10_000,
                resource_class=ResourceClass.CPU,
                source_evidence_id=source_id,
                freshness_ttl_seconds=_GENERAL_FRESHNESS_SECONDS,
            ),
        )
        needs = (MeasurementNeed(capability_id=_GENERAL_PROBE_ID, observable=_GENERAL_PROBE_ID),)
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
