"""Application-owned, inventory-bound candidate catalog for read-only process sampling."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime

from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import MeasurementNeed, ProbeInvocation
from systemsense.domain.time import utc_now
from systemsense.evidence.redaction import Redactor
from systemsense.orchestration.probes import ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import TargetPressureParametersV1
from systemsense.storage.case_candidates import (
    CandidateRegistration,
    CandidateTargetBinding,
    CaseCandidateRegistry,
)
from systemsense.storage.sqlite_store import SQLiteStore

_PROBE_ID = "application.target_pressure"
_SAFE_EXECUTABLE_NAME = re.compile(r"[A-Za-z0-9_.+-]{1,80}\Z")


def _description_for_process(name: str, pid: int, redactor: Redactor) -> str:
    scrubbed = redactor.redact_text(name)
    if scrubbed.replacements or _SAFE_EXECUTABLE_NAME.fullmatch(scrubbed.text) is None:
        return f"Read bounded pressure for inventory process PID {pid}"
    return f"Read bounded pressure for {scrubbed.text} (PID {pid})"


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
