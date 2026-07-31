from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from systemsense.application.case_service import CaseService
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.domain.cases import CaseKind, CaseStatus
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
    SelfWrite,
)
from systemsense.mcp_server import default_case_runtime
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRunner,
)
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_CATEGORIES = ("core", "application", "devices", "network", "servicing", "local_ai")


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _definition(category: str, *, fails: bool = False) -> ProbeDefinition:
    probe_id = f"{category}.snapshot"

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if fails:
            raise RuntimeError("fixture unavailable")
        return ProbeObservation(
            summary=f"Collected {category} snapshot",
            facts={"category": category, "value": 1},
        )

    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id=probe_id,
            version=1,
            implementation_id=f"builtin.{probe_id}",
            question=f"What is the current {category} state?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
                self_writes=(
                    SelfWrite.AUDIT_RECORD,
                    SelfWrite.EVIDENCE_RECORD,
                ),
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(
                timeout_ms=1_000,
                max_output_bytes=32_768,
                max_records=64,
            ),
            category=category,
        ),
        parameter_model=NoParameters,
        handler=collect,
        isolated=False,
    )


def _runtime(store: SQLiteStore, *, failing_category: str | None = None) -> DiagnosticRuntime:
    definitions = tuple(
        _definition(category, fails=category == failing_category) for category in _CATEGORIES
    )
    planner = DeterministicPlanner(
        candidates=tuple(
            ProbeCandidate(
                probe_id=definition.manifest.probe_id,
                cost_ms=10,
                value=1.0,
                common=True,
            )
            for definition in definitions
        )
    )
    return DiagnosticRuntime(
        store=store,
        case_service=CaseService(store, planner),
        probe_runner=ProbeRunner(definitions=definitions),
    )


def test_case_executes_registered_plan_and_populates_evidence_inventory_audit(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = _runtime(store).open_case(
            kind=CaseKind.GENERAL,
            symptom="broad fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=16,
        )

        assert opened.case.status is CaseStatus.READY
        assert store.record_counts() == {
            "evidence": 6,
            "inventory_current": 6,
            "inventory_history": 6,
            "audit_events": 6,
        }
        assert store.inventory_categories() == set(_CATEGORIES)
        assert store.audit_count(case_id=str(opened.case.case_id)) == 6


def test_failed_probe_becomes_coverage_and_is_still_audited(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = _runtime(store, failing_category="devices").open_case(
            kind=CaseKind.GENERAL,
            symptom="failure fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=16,
        )

        assert opened.case.status is CaseStatus.READY
        assert store.coverage_count(case_id=str(opened.case.case_id)) == 1
        assert store.record_counts()["inventory_current"] == 5
        assert store.audit_count(case_id=str(opened.case.case_id)) == 6


def test_default_common_bundle_collects_live_normalized_core_evidence(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = default_case_runtime(store).open_case(
            kind=CaseKind.GENERAL,
            symptom="general system health",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=8,
        )
        rows = store.evidence_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=10,
        )

        assert opened.case.status is CaseStatus.READY
        assert len(rows) == 2
        assert store.inventory_categories() == {"core"}
        assert store.audit_count(case_id=str(opened.case.case_id)) == 2
