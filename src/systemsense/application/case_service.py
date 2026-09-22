"""Open persisted cases and produce their deterministic initial probe plans."""

from datetime import timedelta

from pydantic import ValidationError

from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    CaseTimeWindowBasis,
    DiagnosticCase,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.inventory import InventoryFact
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.orchestration.planner import (
    CasePlan,
    CasePlanner,
    CasePlanningRequest,
)
from systemsense.storage.sqlite_store import SQLiteStore


class OpenedCase(FrozenModel):
    case: DiagnosticCase
    plan: CasePlan
    deadline_at: UtcDateTime


class CaseService:
    def __init__(self, store: SQLiteStore, planner: CasePlanner) -> None:
        self._store = store
        self._planner = planner

    def open_case(
        self,
        *,
        kind: CaseKind,
        symptom: str,
        target_traits: frozenset[str],
        created_at: UtcDateTime,
        budget_ms: int,
        max_probes: int = 32,
    ) -> OpenedCase:
        diagnostic_case = DiagnosticCase(
            case_id=CaseId.new(),
            kind=kind,
            status=CaseStatus.COLLECTING,
            symptom=symptom,
            created_at=created_at,
            time_window=CaseTimeWindow(
                start=created_at - timedelta(minutes=15),
                end=created_at + timedelta(minutes=5),
                basis=CaseTimeWindowBasis.CASE_OPEN_DERIVED,
            ),
        )
        deadline_at = utc_now() + timedelta(milliseconds=budget_ms)
        plan = self._planner.plan(
            CasePlanningRequest(
                symptom=diagnostic_case.symptom,
                target_traits=target_traits,
                fresh_probe_ids=self._fresh_probe_ids(created_at),
                budget_ms=budget_ms,
                max_probes=max_probes,
                case_id=diagnostic_case.case_id,
                state_version=diagnostic_case.state_version,
                correlation_id=f"planning:{diagnostic_case.case_id}",
                deadline_at=deadline_at,
            )
        )
        self._store.create_case(
            case_id=str(diagnostic_case.case_id),
            kind=diagnostic_case.kind.value,
            symptom=diagnostic_case.symptom,
            created_at=diagnostic_case.created_at.isoformat(),
            status=diagnostic_case.status.value,
            state_version=diagnostic_case.state_version,
            time_window_start=diagnostic_case.time_window.start.isoformat(),
            time_window_end=diagnostic_case.time_window.end.isoformat(),
            time_window_basis=diagnostic_case.time_window.basis.value,
        )
        return OpenedCase(
            case=diagnostic_case,
            plan=plan,
            deadline_at=deadline_at,
        )

    def _fresh_probe_ids(self, at: UtcDateTime) -> frozenset[str]:
        probe_ids: set[str] = set()
        for row in self._store.inventory_page(limit=500):
            try:
                fact = InventoryFact.model_validate_json(row.record_json)
            except ValidationError:
                continue
            if not fact.is_stale(at):
                probe_ids.add(fact.collector.id)
        return frozenset(probe_ids)
