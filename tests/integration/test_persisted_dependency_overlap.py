"""A predeclared dependent may start after durable parent evidence, not batch drain."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from systemsense.application.case_service import CaseService
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.domain.cases import CaseKind
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.orchestration.planner import CasePlan, CasePlanningRequest, PlannedProbe
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRun,
    ProbeRunner,
)
from systemsense.orchestration.scheduler import BoundedScheduler, ResourceBudget, ResourceClass
from systemsense.storage.sqlite_store import SQLiteStore


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _DependencyPlanner:
    def plan(self, request: CasePlanningRequest) -> CasePlan:
        del request
        return CasePlan(
            probes=(
                PlannedProbe(
                    probe_id="fixture.slow.snapshot", cost_ms=10, value=1, reason="independent"
                ),
                PlannedProbe(
                    probe_id="fixture.parent.snapshot", cost_ms=10, value=1, reason="prerequisite"
                ),
                PlannedProbe(
                    probe_id="fixture.child.snapshot",
                    cost_ms=10,
                    value=1,
                    reason="follow-up",
                    depends_on=("fixture.parent.snapshot",),
                ),
            ),
            total_cost_ms=30,
            skipped_fresh=(),
            skipped_budget=(),
            skipped_low_value=(),
        )


def _definition(
    name: str,
    category: str,
    handler: Callable[[dict[str, JsonValue]], ProbeObservation],
) -> ProbeDefinition:
    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id=f"fixture.{name}.snapshot",
            version=1,
            implementation_id=f"builtin.fixture.{name}.snapshot",
            question=f"Inspect fixture {name}",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=8_000, max_output_bytes=8_192, max_records=10),
            category=category,
        ),
        parameter_model=_NoParameters,
        handler=handler,
        isolated=False,
    )


def _observation(name: str) -> ProbeObservation:
    now = datetime.now(UTC)
    return ProbeObservation(
        summary=f"{name} completed",
        facts={"stage": name},
        observed_at=now,
        captured_at=now,
    )


def test_predeclared_child_sees_parent_commit_while_independent_probe_runs(
    tmp_path: Path,
) -> None:
    database = tmp_path / "case.db"
    slow_started = threading.Event()
    child_started = threading.Event()
    slow_finished = threading.Event()
    owner_thread = threading.get_ident()
    persisted: list[str] = []

    def slow(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        slow_started.set()
        if not child_started.wait(timeout=5):
            raise RuntimeError("dependent did not start before unrelated probe finished")
        slow_finished.set()
        return _observation("slow")

    def parent(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if not slow_started.wait(timeout=5):
            raise RuntimeError("unrelated slow probe was not in flight")
        return _observation("parent")

    def child(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert not slow_finished.is_set()
        # The collector owns its own read connection; the application store's
        # SQLite connection remains on the scheduler/persistence thread.
        with sqlite3.connect(database, timeout=2) as reader:
            rows = reader.execute(
                "SELECT p.execution_id, e.evidence_id FROM probe_executions AS p "
                "JOIN evidence AS e ON e.execution_id = p.execution_id "
                "WHERE p.probe_id = 'fixture.parent.snapshot' AND p.status = 'ok'"
            ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] and rows[0][1]
        child_started.set()
        return _observation("child")

    definitions = (
        _definition("slow", "network", slow),
        _definition("parent", "application", parent),
        _definition("child", "application", child),
    )
    with SQLiteStore(database) as store:
        cases = CaseService(store, _DependencyPlanner())
        runtime = DiagnosticRuntime(
            store=store,
            case_service=cases,
            probe_runner=ProbeRunner(definitions=definitions),
            scheduler=BoundedScheduler(
                budget=ResourceBudget(
                    global_limit=2,
                    per_resource={ResourceClass.NETWORK: 1, ResourceClass.PROCESS: 1},
                )
            ),
        )
        opened = cases.open_case(
            kind=CaseKind.GENERAL,
            symptom="fixture dependency overlap",
            target_traits=frozenset(),
            created_at=datetime.now(UTC),
            budget_ms=12_000,
            max_probes=3,
        )

        def on_persisted(run: ProbeRun) -> None:
            assert threading.get_ident() == owner_thread
            persisted.append(run.probe_id)

        results = runtime.execute_plan(opened, on_persisted=on_persisted)

        assert child_started.is_set()
        assert slow_finished.is_set()
        assert all(result.satisfies_dependency for result in results)
        assert persisted.index("fixture.parent.snapshot") < persisted.index(
            "fixture.child.snapshot"
        )
        assert store.probe_execution_count(case_id=str(opened.case.case_id)) == 3
