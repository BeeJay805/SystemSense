"""The target probe receives parameters only from a revalidated case binding."""

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application import runtime as runtime_module
from systemsense.application.case_service import CaseService
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.application.targets import ProcessTargetBinding, TargetSelectionError
from systemsense.domain.cases import CaseKind
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.time import utc_now
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.packs.runtime import TargetPressureParametersV1, default_probe_runner
from systemsense.storage.sqlite_store import SQLiteStore


def _runtime(
    store: SQLiteStore, captured: list[dict[str, JsonValue]]
) -> tuple[DiagnosticRuntime, CaseService]:
    manifest = default_probe_runner().manifest("application.target_pressure")
    assert manifest is not None

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        captured.append(parameters)
        sampled_at = utc_now()
        return ProbeObservation(
            summary="Selected process sampled",
            facts={"target_pid": parameters["pid"]},
            observed_at=sampled_at,
            captured_at=sampled_at,
        )

    runner = ProbeRunner(
        definitions=(
            ProbeDefinition(
                manifest=manifest,
                parameter_model=TargetPressureParametersV1,
                handler=collect,
                isolated=False,
            ),
        )
    )
    service = CaseService(
        store,
        DeterministicPlanner(
            candidates=(
                ProbeCandidate(
                    probe_id="application.target_pressure",
                    cost_ms=100,
                    value=1.0,
                    common=True,
                ),
            )
        ),
    )
    return DiagnosticRuntime(store=store, case_service=service, probe_runner=runner), service


def test_bound_target_runtime_persists_exact_parameters_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        assert tuple(item.probe_id for item in opened.plan.probes) == (
            "application.target_pressure",
        )
        binding = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )

        def resolve(_repository: object, case_id: object) -> ProcessTargetBinding:
            assert case_id == opened.case.case_id
            return binding

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )
        runtime.execute_bound_target_pressure(opened)

        assert len(captured) == 1
        assert captured[0]["pid"] == 4242
        assert datetime.fromisoformat(str(captured[0]["creation_time"])) == (binding.creation_time)
        execution = store.connection.execute(
            "SELECT status, parameters_json FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone()
        assert execution is not None
        assert execution[0] == "ok"
        assert json.loads(str(execution[1])) == {
            "pid": 4242,
            "creation_time": binding.creation_time.isoformat().replace("+00:00", "Z"),
        }
        audit = store.audit_entries(case_id=str(opened.case.case_id))
        assert len(audit) == 1
        assert audit[0].parameters["target_candidate_id"] == binding.candidate_id
        assert audit[0].parameters["target_evidence_id"] == str(binding.evidence_id)
        assert audit[0].parameters["target_evidence_sha256"] == binding.evidence_sha256
        assert (
            audit[0].parameters["parameters_sha256"]
            == hashlib.sha256(str(execution[1]).encode("utf-8")).hexdigest()
        )
        assert store.evidence_page(case_id=str(opened.case.case_id), offset=0, limit=10)


def test_general_plan_cannot_supply_target_parameters(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=utc_now(),
            budget_ms=5000,
            max_probes=1,
        )
        runtime.execute_plan(opened)
        assert captured == []
        row = store.connection.execute(
            "SELECT status, parameters_json FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone()
        assert row == ("denied", "{}")


def test_stale_case_version_is_rejected_before_bound_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=utc_now(),
            budget_ms=5000,
            max_probes=1,
        )
        store.connection.execute(
            "UPDATE cases SET state_version = 1 WHERE case_id = ?",
            (str(opened.case.case_id),),
        )

        def should_not_resolve(_repository: object, _case_id: object) -> None:
            raise AssertionError("stale plan must not resolve or sample a target")

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            should_not_resolve,
        )
        with pytest.raises(ValueError, match="no longer collecting"):
            runtime.execute_bound_target_pressure(opened)
        assert captured == []


def test_expired_binding_records_coverage_without_sampling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=utc_now(),
            budget_ms=5000,
            max_probes=1,
        )

        def expired(_repository: object, _case_id: object) -> None:
            raise TargetSelectionError("application snapshot is stale")

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            expired,
        )
        runtime.execute_bound_target_pressure(opened)
        assert captured == []
        row = store.connection.execute(
            "SELECT status, parameters_json FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone()
        assert row == ("unavailable", "{}")
        assert store.coverage_page(case_id=str(opened.case.case_id), offset=0, limit=10)
        audit = store.audit_entries(case_id=str(opened.case.case_id))
        assert audit[0].parameters["target_binding_status"] == "unavailable"
        assert audit[0].outcome == "unavailable"
