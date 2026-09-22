import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from systemsense.application import runtime as runtime_module
from systemsense.application.bootstrap import default_case_runtime
from systemsense.application.case_service import CaseService
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.domain.cases import CaseKind, CaseStatus
from systemsense.domain.coverage import CoverageRecord
from systemsense.domain.evidence import EvidenceRecord, Sensitivity
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
    SelfWrite,
)
from systemsense.orchestration.planner import (
    CasePlan,
    CasePlanningRequest,
    DeterministicPlanner,
    PlannedProbe,
    ProbeCandidate,
)
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRunner,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_EVENT_TIME = _NOW - timedelta(minutes=2)
_COLLECTION_START = _NOW + timedelta(minutes=10)
_COLLECTION_FINISH = _COLLECTION_START + timedelta(seconds=2)
_CATEGORIES = ("core", "application", "devices", "network", "servicing", "local_ai")


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def probe_definition(category: str, *, fails: bool = False) -> ProbeDefinition:
    probe_id = f"{category}.snapshot"

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if fails:
            raise RuntimeError("fixture unavailable")
        return ProbeObservation(
            summary=f"Collected {category} snapshot",
            facts={"category": category, "value": 1},
            observed_at=_NOW,
            captured_at=_NOW,
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
        probe_definition(category, fails=category == failing_category) for category in _CATEGORIES
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


def _incident_runtime(
    store: SQLiteStore,
    *,
    events: list[JsonValue],
) -> DiagnosticRuntime:
    base = probe_definition("events")

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        return ProbeObservation(
            summary="Collected fixed incident event profile",
            facts={"events": events, "channel_status": {"System": "available"}},
            observed_at=_COLLECTION_FINISH,
            captured_at=_COLLECTION_FINISH,
        )

    definition = ProbeDefinition(
        manifest=base.manifest.model_copy(
            update={
                "probe_id": "incident.events",
                "implementation_id": "builtin.incident.events",
                "category": "events",
            }
        ),
        parameter_model=base.parameter_model,
        handler=collect,
        isolated=False,
    )
    planner = DeterministicPlanner(
        candidates=(
            ProbeCandidate(
                probe_id="incident.events",
                cost_ms=10,
                value=1.0,
                common=True,
                resource_class=ResourceClass.DISK,
            ),
        )
    )
    return DiagnosticRuntime(
        store=store,
        case_service=CaseService(store, planner),
        probe_runner=ProbeRunner(definitions=(definition,)),
    )


def test_runtime_classifies_broad_probe_resources_without_overlapping_disk_work() -> None:
    resource_class = runtime_module._resource_class  # pyright: ignore[reportPrivateUsage]

    assert resource_class("storage") is ResourceClass.DISK
    assert resource_class("events") is ResourceClass.DISK
    assert resource_class("power") is ResourceClass.PROCESS
    assert resource_class("security") is ResourceClass.PROCESS


def test_incident_event_children_keep_source_time_provenance_and_personal_sensitivity(
    tmp_path: Path,
) -> None:
    source_id = f"src_{'a' * 64}"
    event: JsonValue = {
        "profile": "hardware",
        "channel": "System",
        "provider": "Microsoft-Windows-WHEA-Logger",
        "event_id": 18,
        "record_id": 123,
        "level": 2,
        "observed_at": _EVENT_TIME.isoformat(),
        "event_data": {"ErrorSource": "Machine Check Exception"},
        "rendered_message": "A hardware error was reported.",
        "source_id": source_id,
    }
    with SQLiteStore(tmp_path / "incident.db") as store:
        opened = _incident_runtime(store, events=[event]).open_case(
            kind=CaseKind.GENERAL,
            symptom="unexpected restart",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=1,
        )
        rows = store.evidence_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=10,
        )

    records = [EvidenceRecord.model_validate_json(row.record_json) for row in rows]
    parent = next(record for record in records if record.source.type == "systemsense.probe")
    child = next(record for record in records if record.source.type == "windows.eventlog")
    assert parent.observed_at == _COLLECTION_FINISH
    assert parent.sensitivity is Sensitivity.PERSONAL
    assert child.observed_at == _EVENT_TIME
    assert child.captured_at >= _COLLECTION_FINISH
    assert child.source.source_id == source_id
    assert child.source.locator == {
        "channel": "System",
        "event_id": 18,
        "provider": "Microsoft-Windows-WHEA-Logger",
        "record_id": 123,
    }
    assert child.collector.id == "incident.events"
    assert child.extraction.parser == "builtin.incident_event_profile"
    assert child.sensitivity is Sensitivity.PERSONAL


def test_malformed_incident_child_creates_separate_failed_coverage(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "incident-malformed.db") as store:
        opened = _incident_runtime(store, events=[{"profile": "hardware"}]).open_case(
            kind=CaseKind.GENERAL,
            symptom="malformed event fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=1,
        )
        coverage_rows = store.coverage_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=10,
        )

    assert len(coverage_rows) == 1
    coverage = CoverageRecord.model_validate_json(coverage_rows[0].record_json)
    assert coverage.category == "events.child"
    assert coverage.status.value == "failed"


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
        assert opened.case.state_version == 1
        persisted_case = store.case(str(opened.case.case_id))
        assert persisted_case is not None
        assert persisted_case.status == CaseStatus.READY.value
        assert persisted_case.state_version == 1
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


def test_failed_probe_redacts_coverage_reason_and_audit_error(tmp_path: Path) -> None:
    definition = probe_definition("fixture.secret")

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        raise RuntimeError(r"db_password=super-secret at C:\Users\Alice\Desktop\dump.txt")

    definition = definition.__class__(
        manifest=definition.manifest,
        parameter_model=definition.parameter_model,
        handler=collect,
        isolated=False,
    )
    planner = DeterministicPlanner(
        candidates=(
            ProbeCandidate(
                probe_id=definition.manifest.probe_id,
                cost_ms=10,
                value=1.0,
                common=True,
            ),
        )
    )

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(definitions=(definition,)),
        ).open_case(
            kind=CaseKind.GENERAL,
            symptom="redaction fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=1,
        )
        coverage_row = store.coverage_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=1,
        )[0]
        with sqlite3.connect(tmp_path / "systemsense.db") as connection:
            audit_json = str(
                connection.execute(
                    "SELECT event_json FROM audit_events WHERE case_id = ?",
                    (str(opened.case.case_id),),
                ).fetchone()[0]
            )

    coverage_json = coverage_row.record_json
    for persisted in (coverage_json, audit_json):
        assert "super-secret" not in persisted
        assert r"C:\Users\Alice" not in persisted
    coverage = CoverageRecord.model_validate_json(coverage_json)
    assert coverage.reason is not None
    assert "<redacted-secret>" in coverage.reason
    assert "<redacted-user-path>" in coverage.reason


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


def test_runtime_does_not_use_case_open_time_for_observation_capture_or_audit(
    tmp_path: Path,
) -> None:
    class ProbeClock:
        def __init__(self) -> None:
            self._values = iter(
                (
                    _COLLECTION_START,
                    _COLLECTION_START,
                    _COLLECTION_FINISH,
                )
            )

        def __call__(self) -> datetime:
            return next(self._values)

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        return ProbeObservation(
            summary="event captured after case opened",
            facts={"value": 1},
            observed_at=_EVENT_TIME,
            captured_at=_NOW,
        )

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        definition = probe_definition("fixture.timestamp")
        definition = definition.__class__(
            manifest=definition.manifest,
            parameter_model=definition.parameter_model,
            handler=collect,
            isolated=False,
        )
        planner = DeterministicPlanner(
            candidates=(
                ProbeCandidate(
                    probe_id=definition.manifest.probe_id,
                    cost_ms=10,
                    value=1.0,
                    common=True,
                ),
            )
        )
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(
                definitions=(definition,),
                now=ProbeClock(),
            ),
        )

        opened = runtime.open_case(
            kind=CaseKind.GENERAL,
            symptom="timestamp fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=1,
        )
        row = store.evidence_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=1,
        )[0]
        record = EvidenceRecord.model_validate_json(row.record_json)
        with sqlite3.connect(tmp_path / "systemsense.db") as connection:
            audit_row = connection.execute(
                """
                SELECT event_json, created_at, occurred_at, persisted_at
                FROM audit_events
                WHERE case_id = ?
                """,
                (str(opened.case.case_id),),
            ).fetchone()
            inventory_row = connection.execute(
                """
                SELECT observed_at, captured_at, time_basis, time_quality
                FROM inventory_current
                WHERE category = ?
                """,
                ("fixture.timestamp",),
            ).fetchone()

    assert record.observed_at == _EVENT_TIME
    assert record.captured_at == _COLLECTION_FINISH
    assert row.observed_at == _EVENT_TIME.isoformat()
    assert row.captured_at == _COLLECTION_FINISH.isoformat()
    assert row.execution_id is not None
    assert row.time_basis == "collector_observed"
    assert row.time_quality == "exact"
    assert record.observed_at != opened.case.created_at
    assert record.captured_at != opened.case.created_at
    assert audit_row is not None
    assert datetime.fromisoformat(str(audit_row[1])) == _COLLECTION_FINISH
    assert datetime.fromisoformat(str(audit_row[2])) == _COLLECTION_FINISH
    assert datetime.fromisoformat(str(audit_row[3])) >= _COLLECTION_FINISH
    assert (
        datetime.fromisoformat(str(json.loads(audit_row[0])["occurred_at"])) == _COLLECTION_FINISH
    )
    assert inventory_row is not None
    assert datetime.fromisoformat(str(inventory_row[0])) == _EVENT_TIME
    assert datetime.fromisoformat(str(inventory_row[1])) == _COLLECTION_FINISH
    assert inventory_row[2:] == ("collector_observed", "exact")


def test_runtime_coverage_uses_probe_finish_time(tmp_path: Path) -> None:
    class ProbeClock:
        def __init__(self) -> None:
            self._values = iter(
                (
                    _COLLECTION_START,
                    _COLLECTION_START,
                    _COLLECTION_FINISH,
                    _COLLECTION_FINISH,
                )
            )

        def __call__(self) -> datetime:
            return next(self._values)

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        definition = probe_definition("fixture.coverage", fails=True)
        planner = DeterministicPlanner(
            candidates=(
                ProbeCandidate(
                    probe_id=definition.manifest.probe_id,
                    cost_ms=10,
                    value=1.0,
                    common=True,
                ),
            )
        )
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(
                definitions=(definition,),
                now=ProbeClock(),
            ),
        )

        opened = runtime.open_case(
            kind=CaseKind.GENERAL,
            symptom="coverage timestamp fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=1,
        )
        coverage_row = store.coverage_page(
            case_id=str(opened.case.case_id),
            offset=0,
            limit=1,
        )[0]
        coverage = CoverageRecord.model_validate_json(coverage_row.record_json)

    assert coverage.captured_at == _COLLECTION_FINISH
    assert coverage.captured_at != opened.case.created_at


def test_runtime_executes_independent_probes_in_bounded_parallel_and_journals_attempts(
    tmp_path: Path,
) -> None:
    barrier = threading.Barrier(2)
    activity_lock = threading.Lock()
    active = 0
    peak_active = 0

    def definition(number: int) -> ProbeDefinition:
        probe_id = f"fixture.parallel-{number}"

        def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            nonlocal active, peak_active
            observed_at = datetime.now(UTC)
            with activity_lock:
                active += 1
                peak_active = max(peak_active, active)
            try:
                barrier.wait(timeout=0.5)
                time.sleep(0.03)
            finally:
                with activity_lock:
                    active -= 1
            return ProbeObservation(
                summary=f"parallel probe {number}",
                facts={"number": number},
                observed_at=observed_at,
                captured_at=datetime.now(UTC),
            )

        return ProbeDefinition(
            manifest=ProbeManifest(
                probe_id=probe_id,
                version=1,
                implementation_id=f"builtin.{probe_id}",
                question="Can independent probes overlap?",
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
                    max_records=8,
                ),
                category="fixture",
            ),
            parameter_model=NoParameters,
            handler=collect,
            isolated=False,
        )

    definitions = (definition(1), definition(2))
    planner = DeterministicPlanner(
        candidates=tuple(
            ProbeCandidate(
                probe_id=item.manifest.probe_id,
                cost_ms=100,
                value=1.0,
                common=True,
            )
            for item in definitions
        )
    )
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(definitions=definitions),
        )

        opened = runtime.open_case(
            kind=CaseKind.GENERAL,
            symptom="parallel fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=2,
        )

        assert peak_active == 2
        assert store.probe_execution_count(case_id=str(opened.case.case_id)) == 2
        assert store.record_counts()["evidence"] == 2


def test_runtime_honors_provider_probe_dependencies(tmp_path: Path) -> None:
    prerequisite_finished = threading.Event()
    execution_order: list[str] = []

    first = probe_definition("fixture.first")
    second = probe_definition("fixture.second")

    def collect_first(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        time.sleep(0.03)
        execution_order.append("first")
        prerequisite_finished.set()
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary="prerequisite",
            facts={"step": 1},
            observed_at=observed_at,
            captured_at=observed_at,
        )

    def collect_second(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if not prerequisite_finished.is_set():
            raise RuntimeError("dependency ran before prerequisite completed")
        execution_order.append("second")
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary="dependent",
            facts={"step": 2},
            observed_at=observed_at,
            captured_at=observed_at,
        )

    definitions = (
        first.__class__(
            manifest=first.manifest,
            parameter_model=first.parameter_model,
            handler=collect_first,
            isolated=False,
        ),
        second.__class__(
            manifest=second.manifest,
            parameter_model=second.parameter_model,
            handler=collect_second,
            isolated=False,
        ),
    )

    class DependencyPlanner:
        def plan(self, request: CasePlanningRequest) -> CasePlan:
            del request
            return CasePlan(
                probes=(
                    PlannedProbe(
                        probe_id="fixture.first.snapshot",
                        cost_ms=10,
                        value=1.0,
                        reason="prerequisite",
                    ),
                    PlannedProbe(
                        probe_id="fixture.second.snapshot",
                        cost_ms=10,
                        value=1.0,
                        reason="dependent",
                        depends_on=("fixture.first.snapshot",),
                    ),
                ),
                total_cost_ms=20,
                skipped_fresh=(),
                skipped_budget=(),
                skipped_low_value=(),
            )

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, DependencyPlanner()),
            probe_runner=ProbeRunner(definitions=definitions),
        ).open_case(
            kind=CaseKind.GENERAL,
            symptom="dependency fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=1_000,
            max_probes=2,
        )

        assert execution_order == ["first", "second"]
        assert store.probe_execution_count(case_id=str(opened.case.case_id)) == 2
        assert store.coverage_count(case_id=str(opened.case.case_id)) == 0


def test_planning_and_collection_share_one_case_deadline(tmp_path: Path) -> None:
    collected = threading.Event()
    definition = probe_definition("fixture.shared-deadline")

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        collected.set()
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary="must not run after the case deadline",
            facts={"ran": True},
            observed_at=observed_at,
            captured_at=observed_at,
        )

    definition = definition.__class__(
        manifest=definition.manifest,
        parameter_model=definition.parameter_model,
        handler=collect,
        isolated=False,
    )

    class SlowPlanner:
        def plan(self, request: CasePlanningRequest) -> CasePlan:
            time.sleep(0.03)
            return CasePlan(
                probes=(
                    PlannedProbe(
                        probe_id=definition.manifest.probe_id,
                        cost_ms=1,
                        value=1.0,
                        reason="deadline regression",
                    ),
                ),
                total_cost_ms=1,
                skipped_fresh=(),
                skipped_budget=(),
                skipped_low_value=(),
            )

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, SlowPlanner()),
            probe_runner=ProbeRunner(definitions=(definition,)),
        ).open_case(
            kind=CaseKind.GENERAL,
            symptom="shared deadline fixture",
            target_traits=(),
            created_at=_NOW,
            budget_ms=5,
            max_probes=1,
        )

        assert opened.deadline_at < datetime.now(UTC)
        assert not collected.is_set()
        assert store.coverage_count(case_id=str(opened.case.case_id)) == 1
