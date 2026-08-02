import json
from datetime import UTC, datetime, timedelta
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


def _definition(
    category: str,
    *,
    fails: bool = False,
    limitations: tuple[str, ...] = (),
) -> ProbeDefinition:
    probe_id = f"{category}.snapshot"

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if fails:
            raise RuntimeError("fixture unavailable")
        return ProbeObservation(
            summary=f"Collected {category} snapshot",
            facts={"category": category, "value": 1},
            limitations=limitations,
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
            "evidence": 12,
            "inventory_current": 6,
            "inventory_history": 6,
            "audit_events": 6,
        }
        assert store.inventory_categories() == set(_CATEGORIES)
        assert store.audit_count(case_id=str(opened.case.case_id)) == 6


def test_successful_probes_persist_explicit_covered_source_states(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = _runtime(store).open_case(
            kind=CaseKind.GENERAL,
            symptom="broad fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=16,
        )
        rows = store.coverage_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=10,
        )

        assert len(rows) == 6
        records = [json.loads(row.record_json) for row in rows]
        assert {record["status"] for record in records} == {"covered"}
        assert {record["collector_id"] for record in records} == {
            f"{category}.snapshot" for category in _CATEGORIES
        }


def test_successful_probe_with_limitations_is_explicitly_partial(tmp_path: Path) -> None:
    definition = _definition("network", limitations=("DNS registry was not collected",))
    planner = DeterministicPlanner(
        candidates=(
            ProbeCandidate(
                probe_id="network.snapshot",
                cost_ms=10,
                value=1.0,
                common=True,
            ),
        )
    )
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(definitions=(definition,)),
        )
        opened = runtime.open_case(
            kind=CaseKind.NETWORK,
            symptom="network fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=8,
        )
        row = store.coverage_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=1,
        )[0]
        record = json.loads(row.record_json)

    assert record["status"] == "partial"
    assert record["limitations"] == ["DNS registry was not collected"]


def test_fresh_inventory_is_materialized_as_cited_evidence_in_the_new_case(
    tmp_path: Path,
) -> None:
    definition = _definition("devices")
    planner = DeterministicPlanner(
        candidates=(
            ProbeCandidate(
                probe_id="devices.snapshot",
                cost_ms=10,
                value=1.0,
                symptom_terms=frozenset({"device"}),
            ),
        )
    )
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(definitions=(definition,)),
        )
        first = runtime.open_case(
            kind=CaseKind.DEVICES_AUDIO,
            symptom="device fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=8,
        )
        second = runtime.open_case(
            kind=CaseKind.DEVICES_AUDIO,
            symptom="device fixture",
            target_traits=(),
            created_at=_NOW + timedelta(minutes=1),
            budget_ms=1_000,
            max_probes=8,
        )
        rows = store.evidence_page(
            case_id=str(second.case.case_id),
            offset=0,
            limit=10,
        )

        assert first.plan.probe_ids == ("devices.snapshot",)
        assert second.plan.probe_ids == ()
        assert second.plan.skipped_fresh == ("devices.snapshot",)
        assert len(rows) == 1
        cached = json.loads(rows[0].record_json)
        assert cached["collector"]["id"] == "devices.snapshot"
        assert any("Reused fresh inventory" in item for item in cached["limitations"])


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
        assert store.coverage_count(case_id=str(opened.case.case_id)) == 6
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
