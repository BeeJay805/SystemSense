from datetime import UTC, datetime
from pathlib import Path

import pytest

from systemsense.application.case_service import CaseService
from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindowBasis
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceSource,
    Extraction,
    Sensitivity,
)
from systemsense.domain.ids import EntityId, ExecutionId
from systemsense.domain.inventory import InventoryFact
from systemsense.orchestration.planner import (
    CasePlan,
    CasePlanningRequest,
    DeterministicPlanner,
    PlannedProbe,
    ProbeCandidate,
)
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_plan_rejects_ambiguous_duplicate_probe_instances() -> None:
    with pytest.raises(ValueError, match="instance"):
        CasePlan(
            probes=(
                PlannedProbe(probe_id="core.system", cost_ms=1, value=1.0, reason="first"),
                PlannedProbe(probe_id="core.system", cost_ms=1, value=1.0, reason="second"),
            ),
            total_cost_ms=2,
            skipped_fresh=(),
            skipped_budget=(),
            skipped_low_value=(),
        )


def test_plan_keeps_distinct_instances_and_resolves_dependencies_by_instance() -> None:
    plan = CasePlan(
        probes=(
            PlannedProbe(
                probe_id="core.system", instance_id="first", cost_ms=1, value=1.0, reason="a"
            ),
            PlannedProbe(
                probe_id="core.system",
                instance_id="second",
                cost_ms=1,
                value=1.0,
                reason="b",
                depends_on=("first",),
            ),
        ),
        total_cost_ms=2,
        skipped_fresh=(),
        skipped_budget=(),
        skipped_low_value=(),
    )

    assert plan.probe_ids == ("core.system", "core.system")
    assert [probe.plan_instance_id for probe in plan.probes] == ["first", "second"]


def _planner() -> DeterministicPlanner:
    return DeterministicPlanner(
        candidates=(
            ProbeCandidate(
                probe_id="core.system",
                cost_ms=50,
                value=1.0,
                common=True,
            ),
            ProbeCandidate(
                probe_id="core.resources",
                cost_ms=50,
                value=1.0,
                common=True,
            ),
            ProbeCandidate(
                probe_id="application.wer",
                cost_ms=300,
                value=0.9,
                symptom_terms=frozenset({"crash", "stopped working"}),
                target_traits=frozenset({"application"}),
            ),
            ProbeCandidate(
                probe_id="network.connections",
                cost_ms=200,
                value=0.7,
                symptom_terms=frozenset({"network", "connection"}),
                target_traits=frozenset({"network"}),
            ),
            ProbeCandidate(
                probe_id="expensive.low_value",
                cost_ms=900,
                value=0.1,
                symptom_terms=frozenset({"crash"}),
            ),
        ),
        minimum_value=0.2,
    )


def test_plan_includes_common_and_relevant_registered_probes_within_budget() -> None:
    plan = _planner().plan(
        CasePlanningRequest(
            symptom="Application crash and stopped working",
            target_traits=frozenset({"application"}),
            fresh_probe_ids=frozenset(),
            budget_ms=500,
            max_probes=8,
        )
    )

    assert plan.probe_ids == (
        "core.resources",
        "core.system",
        "application.wer",
    )
    assert plan.total_cost_ms == 400
    assert "expensive.low_value" not in plan.probe_ids


def test_fresh_evidence_suppresses_redundant_probe() -> None:
    plan = _planner().plan(
        CasePlanningRequest(
            symptom="Application crash",
            target_traits=frozenset({"application"}),
            fresh_probe_ids=frozenset({"core.system", "application.wer"}),
            budget_ms=500,
            max_probes=8,
        )
    )

    assert plan.probe_ids == ("core.resources", "core.system")
    assert plan.skipped_fresh == ("application.wer",)


def test_case_service_persists_open_case_and_returns_plan(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = CaseService(store, _planner()).open_case(
            kind=CaseKind.APPLICATION,
            symptom="Application crash",
            target_traits=frozenset({"application"}),
            created_at=_NOW,
            budget_ms=500,
        )

        assert opened.case.case_id
        assert opened.case.symptom == "Application crash"
        assert opened.case.time_window.basis is CaseTimeWindowBasis.CASE_OPEN_DERIVED
        assert opened.case.state_version == 0
        assert "application.wer" in opened.plan.probe_ids
        assert store.case_count() == 1
        stored = store.case(str(opened.case.case_id))
        assert stored is not None
        assert stored.status == CaseStatus.COLLECTING.value
        assert stored.state_version == 0
        assert stored.time_window_start == opened.case.time_window.start.isoformat()
        assert stored.time_window_end == opened.case.time_window.end.isoformat()
        assert stored.time_window_basis == CaseTimeWindowBasis.CASE_OPEN_DERIVED.value


def test_case_service_uses_fresh_inventory_to_skip_optional_probe(tmp_path: Path) -> None:
    fact = InventoryFact(
        entity_id=EntityId.new(),
        category="application",
        name="application.wer",
        value={"status": "captured"},
        source=EvidenceSource(
            type="systemsense.probe",
            source_id="src_" + ("a" * 64),
            locator={"probe_id": "application.wer"},
        ),
        collector=CollectorReference(
            id="application.wer",
            version=1,
            execution_id=ExecutionId.new(),
        ),
        observed_at=_NOW,
        captured_at=_NOW,
        extraction=Extraction(
            confidence=1.0,
            parser="builtin.probe",
            parser_version=1,
        ),
        freshness_ttl_seconds=300,
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        with store.transaction() as transaction:
            transaction.upsert_inventory(
                category=fact.category,
                fact_key=f"{fact.entity_id}:{fact.name}",
                record_json=fact.model_dump_json(),
                observed_at=fact.observed_at.isoformat(),
            )

        opened = CaseService(store, _planner()).open_case(
            kind=CaseKind.APPLICATION,
            symptom="Application crash",
            target_traits=frozenset({"application"}),
            created_at=_NOW,
            budget_ms=500,
        )

        assert opened.plan.probe_ids == ("core.resources", "core.system")
        assert opened.plan.skipped_fresh == ("application.wer",)
