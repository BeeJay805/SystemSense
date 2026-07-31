"""Open persisted cases and produce their deterministic initial probe plans."""

from datetime import timedelta

from pydantic import ValidationError

from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    DiagnosticCase,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.inventory import InventoryFact
from systemsense.domain.time import UtcDateTime
from systemsense.orchestration.planner import (
    CasePlan,
    CasePlanningRequest,
    DeterministicPlanner,
)
from systemsense.storage.sqlite_store import SQLiteStore


class OpenedCase(FrozenModel):
    case: DiagnosticCase
    plan: CasePlan


class CaseService:
    def __init__(self, store: SQLiteStore, planner: DeterministicPlanner) -> None:
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
            ),
        )
        plan = self._planner.plan(
            CasePlanningRequest(
                symptom=diagnostic_case.symptom,
                target_traits=target_traits,
                fresh_probe_ids=self._fresh_probe_ids(created_at),
                budget_ms=budget_ms,
                max_probes=max_probes,
            )
        )
        self._store.create_case(
            case_id=str(diagnostic_case.case_id),
            kind=diagnostic_case.kind.value,
            symptom=diagnostic_case.symptom,
            created_at=diagnostic_case.created_at.isoformat(),
        )
        return OpenedCase(case=diagnostic_case, plan=plan)

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
