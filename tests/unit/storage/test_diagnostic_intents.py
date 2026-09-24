"""Durable diagnostic questions bind actual execution and source-owned results."""

import hashlib
import importlib.util
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from typing import Any, cast

import pytest

from systemsense.application.investigation_state import InvestigationState, InvestigationStatus
from systemsense.audit import AuditChain, AuditOutcome
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.probes import MeasurementWindow
from systemsense.domain.time import utc_now
from systemsense.evaluation.progress import PredicateScope, PredictedOutcome
from systemsense.evaluation.progress import TestIntent as Intent
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


def test_diagnostic_intent_repository_is_available() -> None:
    assert importlib.util.find_spec("systemsense.storage.diagnostic_intents") is not None


GUID = "00000000-0000-0000-0000-000000000001"


def _state(store: SQLiteStore) -> InvestigationState:
    now = utc_now()
    state = InvestigationState(
        case_id=CaseId.new(),
        objective="Check this WLAN interface",
        created_at=now,
        updated_at=now,
        deadline_at=now + timedelta(minutes=5),
        incident_start=now - timedelta(minutes=1),
        incident_end=now + timedelta(minutes=1),
        budget_ms=10000,
        status=InvestigationStatus.RUNNING,
    )
    repository = InvestigationRepository(store)
    repository.create(state)
    return repository.save(state, expected_version=0, event="running", detail="Started")


def _persist(
    store: SQLiteStore,
    state: InvestigationState,
    *,
    plan: str = "plan.wifi",
    association: str = "connected",
    started_before: bool = False,
    version: int = 3,
    claim_id: str | None = None,
) -> EvidenceRecord:
    now = utc_now()
    execution = ExecutionId.new()
    snapshot: dict[str, JsonValue] = {
        "source_id": "src_" + "a" * 64,
        "captured_at": now.isoformat(),
        "wifi_observed_at": now.isoformat(),
        "wifi_status": "available",
        "wifi_interfaces": [
            {"interface_guid": GUID, "description": "Wi-Fi", "association_state": association}
        ],
        "omitted_wifi_count": 0,
        "addresses_observed_at": now.isoformat(),
        "addresses_status": "unsupported",
        "adapters": [],
        "omitted_adapter_count": 0,
        "routes_observed_at": now.isoformat(),
        "routes_status": "unsupported",
        "default_routes": [],
        "omitted_route_count": 0,
        "proxy_observed_at": now.isoformat(),
        "proxy_status": "unsupported",
        "proxy": None,
        "wlan_events_observed_at": now.isoformat(),
        "wlan_events_status": "unsupported",
        "recent_failures": [],
        "omitted_failure_count": 0,
        "status": "partial",
    }
    record = EvidenceRecord.model_validate(
        {
            "evidence_id": str(EvidenceId.new()),
            "case_id": str(state.case_id),
            "statement_kind": "observed_fact",
            "observed_at": now,
            "captured_at": now,
            "source": {
                "type": "systemsense.probe",
                "source_id": stable_source_id(
                    "systemsense.probe",
                    {"probe_id": "network.connectivity", "probe_version": version},
                ),
                "locator": {"probe_id": "network.connectivity"},
            },
            "collector": {
                "id": "network.connectivity",
                "version": version,
                "execution_id": str(execution),
            },
            "summary": "WLAN snapshot",
            "facts": [{"name": "connectivity_detail", "value": snapshot}],
            "extraction": {"confidence": 1, "parser": "builtin.probe", "parser_version": 1},
            "sensitivity": "system_metadata",
        }
    )
    chain = AuditChain.from_verified_entries(
        store.audit_entries(case_id=str(state.case_id)),
        checkpoint=store.audit_checkpoint(case_id=str(state.case_id)),
    )
    audit = chain.append(
        event_id=f"probe_{execution}",
        case_id=state.case_id,
        probe_id="network.connectivity",
        outcome=AuditOutcome.ALLOWED,
        occurred_at=now,
        parameters={
            "plan_instance_id": plan,
            "parameters_sha256": hashlib.sha256(b"{}").hexdigest(),
            **({"diagnostic_claim_id": claim_id} if claim_id is not None else {}),
        },
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution),
            case_id=str(state.case_id),
            probe_id="network.connectivity",
            probe_version=version,
            status="ok",
            parameters_json="{}",
            started_at=(now - timedelta(minutes=2) if started_before else now).isoformat(),
            finished_at=now.isoformat(),
            state_version=state.state_version,
        )
        transaction.insert_evidence(
            case_id=str(state.case_id),
            evidence_id=str(record.evidence_id),
            source_id=record.source.source_id,
            record_json=record.model_dump_json(),
            captured_at=now.isoformat(),
            observed_at=now.isoformat(),
            execution_id=str(execution),
            dedupe_key=f"execution:{execution}",
        )
        transaction.append_audit(
            event_id=audit.event_id,
            case_id=str(state.case_id),
            event_json=audit.model_dump_json(),
            created_at=now.isoformat(),
        )
    return record


def _intent(state: InvestigationState) -> Intent:
    return Intent(
        intent_id="test.wifi",
        branch_id="branch.wifi",
        probe_id="network.connectivity",
        uncertainty_id="uncertainty.wifi",
        scope=PredicateScope(
            case_id=state.case_id,
            target_handle=GUID,
            window=MeasurementWindow(start=state.incident_start, end=state.incident_end),
        ),
        predictions=(
            PredictedOutcome(
                hypothesis_id="wifi.on", predicate_id="network.wifi_associated", expected=True
            ),
            PredictedOutcome(
                hypothesis_id="wifi.off", predicate_id="network.wifi_associated", expected=False
            ),
        ),
    )


def test_durable_terminal_is_idempotent_and_survives_restart(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    path = tmp_path / "case.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        assert admission.probe_version == 3
        with store.transaction():
            claim = repo.claim_dispatch(admission.admission_id)
        result = _persist(store, state, claim_id=claim.claim_id)
        with store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))
            terminal = repo.evaluate(admission.admission_id)
            assert repo.evaluate(admission.admission_id) == terminal
        assert terminal.status == "evaluated"
        assert terminal.evaluation is not None and terminal.evaluation.observed is True
        assert terminal.evaluation.evidence_ids == (result.evidence_id,)
        assert repo.pending(state.case_id) == ()
    with SQLiteStore(path) as store:
        repo = DiagnosticIntentRepository(store)
        assert repo.readback(admission.admission_id) == admission
        assert repo.terminal(admission.admission_id) == terminal


@pytest.mark.parametrize("defect", ["case", "plan", "version", "before"])
def test_execution_cannot_escape_admission(tmp_path: Path, defect: str) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with store.transaction():
            claim = repo.claim_dispatch(admission.admission_id)
        result = _persist(
            store,
            _state(store) if defect == "case" else state,
            plan="wrong" if defect == "plan" else "plan.wifi",
            started_before=defect == "before",
            version=1 if defect == "version" else 3,
            claim_id=claim.claim_id,
        )
        with pytest.raises(ValueError), store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))


def test_admission_and_terminal_roll_back_and_require_transaction(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state)
        repo = DiagnosticIntentRepository(store)
        with pytest.raises(ValueError, match="transaction"):
            repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with pytest.raises(RuntimeError), store.transaction():
            repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
            raise RuntimeError("crash")
        assert repo.pending(state.case_id) == ()
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with pytest.raises(RuntimeError), store.transaction():
            repo.interrupt(admission.admission_id, reason="worker_interrupted")
            raise RuntimeError("checkpoint failed")
        assert repo.terminal(admission.admission_id) is None
        with store.transaction():
            terminal = repo.interrupt(admission.admission_id, reason="worker_interrupted")
        assert terminal.execution_id is None and terminal.status == "interrupted"
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute("UPDATE diagnostic_intent_admissions SET record_json='{}'")
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute("DELETE FROM diagnostic_intent_terminals")


def test_stale_duplicate_and_cross_case_source_admission_rejected(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state)
        other = _state(store)
        repo = DiagnosticIntentRepository(store)
        for target, version in [(state, state.state_version - 1), (other, other.state_version)]:
            with pytest.raises(ValueError), store.transaction():
                repo.admit(
                    _intent(target),
                    expected_state_version=version,
                    source_evidence_id=source.evidence_id,
                    plan_instance_id="plan.wifi",
                    parameters={},
                )
        with store.transaction():
            repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )


@pytest.mark.parametrize("association,expected", [("disconnected", False), ("associating", None)])
def test_false_and_unknown_results_are_preserved(
    tmp_path: Path,
    association: str,
    expected: bool | None,
) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with store.transaction():
            claim = repo.claim_dispatch(admission.admission_id)
        result = _persist(store, state, association=association, claim_id=claim.claim_id)
        with store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))
            terminal = repo.evaluate(admission.admission_id)
        assert terminal.evaluation is not None and terminal.evaluation.observed is expected
        assert terminal.status == ("unknown" if expected is None else "evaluated")
        assert terminal.reason == (
            "predicate_unknown" if expected is None else "predicate_evaluated"
        )
        with pytest.raises((ValueError, sqlite3.IntegrityError)), store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))


def test_backdated_snapshot_is_not_a_prospective_result(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with store.transaction():
            claim = repo.claim_dispatch(admission.admission_id)
        result = _persist(store, state, claim_id=claim.claim_id)
        raw = result.model_dump(mode="json")
        raw["facts"][0]["value"]["wifi_observed_at"] = source.observed_at.isoformat()
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (json.dumps(raw), str(result.evidence_id)),
        )
        with store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))
        with store.transaction():
            terminal = repo.evaluate(admission.admission_id)
        assert terminal.status == "unknown" and terminal.evaluation is None
        assert terminal.reason == "source_precedes_admission"


def test_digest_readback_rejects_source_and_terminal_tampering(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state)
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
            repo.interrupt(admission.admission_id, reason="worker_interrupted")
        store.connection.execute("DROP TRIGGER diagnostic_terminals_no_update")
        store.connection.execute(
            "UPDATE diagnostic_intent_terminals SET record_sha256=?", ("0" * 64,)
        )
        with pytest.raises(ValueError, match="corrupt"):
            repo.terminal(admission.admission_id)
        changed = source.model_copy(update={"summary": "Changed stored source"})
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (changed.model_dump_json(), str(source.evidence_id)),
        )
        with pytest.raises(ValueError, match="source changed"):
            repo.readback(admission.admission_id)


def test_admission_cannot_use_future_source_observation(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state)
        future = utc_now() + timedelta(days=1)
        changed = source.model_copy(update={"observed_at": future, "captured_at": future})
        store.connection.execute(
            "UPDATE evidence SET record_json=?,observed_at=?,captured_at=? WHERE evidence_id=?",
            (
                changed.model_dump_json(),
                future.isoformat(),
                future.isoformat(),
                str(source.evidence_id),
            ),
        )
        store.connection.execute(
            "UPDATE probe_executions SET finished_at=? WHERE execution_id=?",
            (future.isoformat(), str(source.collector.execution_id)),
        )
        repo = DiagnosticIntentRepository(store)
        with pytest.raises(ValueError), store.transaction():
            repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )


@pytest.mark.parametrize("defect", ["wifi_status", "omitted_wifi_count", "details_status"])
def test_partial_target_source_is_not_admitted(tmp_path: Path, defect: str) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state)
        raw = source.model_dump(mode="json")
        snapshot = raw["facts"][0]["value"]
        if defect == "details_status":
            snapshot["wifi_interfaces"][0]["details_status"] = "permission_denied"
        else:
            snapshot[defect] = 1 if defect == "omitted_wifi_count" else "partial"
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (json.dumps(raw), str(source.evidence_id)),
        )
        repo = DiagnosticIntentRepository(store)
        with pytest.raises(ValueError), store.transaction():
            repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )


def test_corrupt_result_is_a_terminal_unknown_with_visible_custody_limitation(
    tmp_path: Path,
) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with store.transaction():
            claim = repo.claim_dispatch(admission.admission_id)
        result = _persist(store, state, claim_id=claim.claim_id)
        store.connection.execute(
            "UPDATE evidence SET record_json='{}' WHERE evidence_id=?", (str(result.evidence_id),)
        )
        with store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))
            terminal = repo.evaluate(admission.admission_id)
            assert repo.evaluate(admission.admission_id) == terminal
        assert terminal.status == "unknown" and terminal.evaluation is None
        assert terminal.reason == "source_unverifiable"
        assert terminal.rejected_evidence_ids == (result.evidence_id,)
        assert repo.pending(state.case_id) == ()
        with pytest.raises((ValueError, sqlite3.IntegrityError)), store.transaction():
            repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )


def test_failed_execution_and_missing_observation_close_without_false_progress(
    tmp_path: Path,
) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    for execution_status in ("failed", "ok"):
        with SQLiteStore(tmp_path / f"{execution_status}.db") as store:
            state = _state(store)
            source = _persist(store, state, plan="baseline")
            repo = DiagnosticIntentRepository(store)
            with store.transaction():
                admission = repo.admit(
                    _intent(state),
                    expected_state_version=state.state_version,
                    source_evidence_id=source.evidence_id,
                    plan_instance_id="plan.wifi",
                    parameters={},
                )
            with store.transaction():
                claim = repo.claim_dispatch(admission.admission_id)
            result = _persist(store, state, claim_id=claim.claim_id)
            store.connection.execute(
                "DELETE FROM evidence WHERE evidence_id=?", (str(result.evidence_id),)
            )
            store.connection.execute(
                "UPDATE probe_executions SET status=? WHERE execution_id=?",
                (execution_status, str(result.collector.execution_id)),
            )
            with store.transaction():
                repo.link_execution(admission.admission_id, str(result.collector.execution_id))
                terminal = repo.evaluate(admission.admission_id)
                assert repo.evaluate(admission.admission_id) == terminal
            assert terminal.status == ("failed" if execution_status == "failed" else "unknown")
            assert terminal.evaluation is None or terminal.evaluation.observed is None


@pytest.mark.parametrize("fails,advance_epoch", [(False, False), (True, False), (False, True)])
def test_real_runtime_binds_actual_execution_before_terminal_evaluation(
    tmp_path: Path,
    fails: bool,
    advance_epoch: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.application.case_service import CaseService, OpenedCase
    from systemsense.application.runtime import DiagnosticRuntime
    from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindow, DiagnosticCase
    from systemsense.orchestration.planner import CasePlan, DeterministicPlanner, PlannedProbe
    from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
    from systemsense.orchestration.scheduler import BoundedScheduler, TaskResult
    from systemsense.packs.runtime import default_probe_definitions
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "runtime.db") as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        registered = next(
            d for d in default_probe_definitions() if d.manifest.probe_id == "network.connectivity"
        )
        collector_calls: list[str] = []

        def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            collector_calls.append("collected")
            if fails:
                raise RuntimeError("fixture WLAN collection unavailable")
            now = utc_now()
            snapshot = cast(dict[str, JsonValue], source.facts[0].value).copy()
            for key in snapshot:
                if key.endswith("observed_at") or key == "captured_at":
                    snapshot[key] = now.isoformat()
            return ProbeObservation(
                summary="Registered WLAN observation",
                facts={"connectivity_detail": snapshot},
                observed_at=now,
                captured_at=now,
            )

        scheduler = BoundedScheduler()
        runtime = DiagnosticRuntime(
            store=store,
            scheduler=scheduler,
            case_service=CaseService(store, DeterministicPlanner(candidates=())),
            probe_runner=ProbeRunner(
                definitions=(
                    ProbeDefinition(
                        manifest=registered.manifest,
                        parameter_model=registered.parameter_model,
                        handler=collect,
                        isolated=False,
                    ),
                )
            ),
        )
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        opened = OpenedCase(
            case=DiagnosticCase(
                case_id=state.case_id,
                kind=CaseKind.NETWORK,
                status=CaseStatus.COLLECTING,
                symptom=state.objective,
                created_at=state.created_at,
                state_version=state.state_version,
                time_window=CaseTimeWindow(start=state.incident_start, end=state.incident_end),
            ),
            plan=CasePlan(
                probes=(
                    PlannedProbe(
                        probe_id="network.connectivity",
                        instance_id="plan.wifi",
                        cost_ms=100,
                        value=1,
                        reason="Registered test",
                    ),
                ),
                total_cost_ms=100,
                skipped_fresh=(),
                skipped_budget=(),
                skipped_low_value=(),
            ),
            deadline_at=state.deadline_at,
        )
        if advance_epoch:
            original_schedule = scheduler.run_blocking

            def run_after_transition(*args: Any, **kwargs: Any) -> tuple[TaskResult, ...]:
                assert repo.dispatch_claim(admission.admission_id) is not None
                InvestigationRepository(store).save(
                    state,
                    expected_version=state.state_version,
                    event="case_changed_while_queued",
                    detail="New case epoch before worker launch",
                )
                return original_schedule(*args, **kwargs)

            monkeypatch.setattr(scheduler, "run_blocking", run_after_transition)
        runtime.execute_plan(
            opened, diagnostic_admissions_by_instance={"plan.wifi": admission.admission_id}
        )
        if advance_epoch:
            assert collector_calls == []
            assert store.probe_execution_count(case_id=str(state.case_id)) == 1
            assert repo.execution_link(admission.admission_id) is None
            terminal = repo.terminal(admission.admission_id)
            assert terminal is not None and terminal.status == "interrupted"
            assert terminal.reason == "dispatch_outcome_unknown"
            assert terminal.execution_id is None and terminal.evaluation is None
            with pytest.raises(ValueError, match="claimed"):
                runtime.execute_plan(
                    opened, diagnostic_admissions_by_instance={"plan.wifi": admission.admission_id}
                )
            assert collector_calls == []
            assert store.probe_execution_count(case_id=str(state.case_id)) == 1
            return
        link = repo.execution_link(admission.admission_id)
        assert link is not None and link.execution_id != str(source.collector.execution_id)
        automatic_terminal = repo.terminal(admission.admission_id)
        assert automatic_terminal is not None
        with store.transaction():
            terminal = repo.evaluate(admission.admission_id)
        assert terminal == automatic_terminal
        assert terminal.execution_id == link.execution_id
        assert terminal.status == ("failed" if fails else "evaluated")
        if not fails:
            assert terminal.evaluation is not None and terminal.evaluation.observed is True
        count = store.probe_execution_count(case_id=str(state.case_id))
        with pytest.raises(ValueError, match="claimed"):
            runtime.execute_plan(
                opened, diagnostic_admissions_by_instance={"plan.wifi": admission.admission_id}
            )
        assert store.probe_execution_count(case_id=str(state.case_id)) == count


def test_original_source_loss_has_durable_non_evidentiary_terminal(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    path = tmp_path / "case.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        source = _persist(store, state)
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with pytest.raises(ValueError), store.transaction():
            repo.record_custody_gap(admission.admission_id)
        store.connection.execute(
            "DELETE FROM evidence WHERE evidence_id=?", (str(source.evidence_id),)
        )
        with store.transaction():
            terminal = repo.record_custody_gap(admission.admission_id)
        assert terminal.status == "unknown" and terminal.evaluation is None
        assert terminal.reason == "admission_source_unverifiable"
        assert terminal.execution_id is None
        assert terminal.rejected_evidence_ids == (source.evidence_id,)
        with pytest.raises(ValueError):
            repo.readback(admission.admission_id)
    with SQLiteStore(path) as store:
        repo = DiagnosticIntentRepository(store)
        assert repo.terminal(admission.admission_id) == terminal
        assert repo.pending(state.case_id) == ()


def test_dispatch_claim_is_one_shot_transactional_and_restart_visible(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    path = tmp_path / "claim.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        source = _persist(store, state)
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        with pytest.raises(ValueError, match="transaction"):
            repo.claim_dispatch(admission.admission_id)
        with pytest.raises(RuntimeError), store.transaction():
            repo.claim_dispatch(admission.admission_id)
            raise RuntimeError("abort before dispatch")
        assert repo.dispatch_claim(admission.admission_id) is None
        with store.transaction():
            claim = repo.claim_dispatch(admission.admission_id)
        with pytest.raises(ValueError, match="claimed"), store.transaction():
            repo.claim_dispatch(admission.admission_id)
        assert claim.claimed_at >= admission.admitted_at
        assert claim.plan_instance_id == admission.plan_instance_id
    with SQLiteStore(path) as store:
        repo = DiagnosticIntentRepository(store)
        assert repo.dispatch_claim(admission.admission_id) == claim
        assert repo.pending(state.case_id) == (admission,)
        assert repo.execution_link(admission.admission_id) is None
        with pytest.raises(ValueError, match="claimed"), store.transaction():
            repo.claim_dispatch(admission.admission_id)
        with store.transaction():
            terminal = repo.interrupt(admission.admission_id, reason="dispatch_outcome_unknown")
        assert terminal.status == "interrupted"
        with pytest.raises(ValueError), store.transaction():
            repo.claim_dispatch(admission.admission_id)
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute(
                "UPDATE diagnostic_intent_dispatch_claims SET record_json='{}'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute("DELETE FROM diagnostic_intent_dispatch_claims")


def test_stale_case_epoch_cannot_claim_dispatch(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "claim.db") as store:
        state = _state(store)
        source = _persist(store, state)
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        InvestigationRepository(store).save(
            state,
            expected_version=state.state_version,
            event="changed",
            detail="New objective epoch",
        )
        with pytest.raises(ValueError, match="stale"), store.transaction():
            repo.claim_dispatch(admission.admission_id)


def test_competing_connections_cannot_both_claim_dispatch(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    path = tmp_path / "claim.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        source = _persist(store, state)
        with store.transaction():
            admission = DiagnosticIntentRepository(store).admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
    barrier = Barrier(2)

    def attempt() -> str:
        with SQLiteStore(path) as connection:
            repo = DiagnosticIntentRepository(connection)
            barrier.wait(timeout=5)
            try:
                with connection.transaction():
                    repo.claim_dispatch(admission.admission_id)
                return "claimed"
            except ValueError:
                return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt), pool.submit(attempt)]
        assert sorted(future.result(timeout=10) for future in futures) == ["claimed", "rejected"]


@pytest.mark.parametrize("defect", ["missing_claim", "wrong_audit_claim", "before_claim"])
def test_execution_requires_its_own_preceding_dispatch_claim(tmp_path: Path, defect: str) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "claim.db") as store:
        state = _state(store)
        source = _persist(store, state)
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
        claim_id = None
        if defect != "missing_claim":
            with store.transaction():
                claim = repo.claim_dispatch(admission.admission_id)
            claim_id = (
                "diagnostic_claim_" + "0" * 32 if defect == "wrong_audit_claim" else claim.claim_id
            )
        result = _persist(store, state, claim_id=claim_id)
        if defect == "before_claim":
            store.connection.execute(
                "UPDATE probe_executions SET started_at=? WHERE execution_id=?",
                (admission.admitted_at.isoformat(), str(result.collector.execution_id)),
            )
        with pytest.raises(ValueError), store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))


@pytest.mark.parametrize(
    "disposition",
    [
        "pending",
        "evaluated",
        "tampered_link",
        "tampered_claim",
        "tampered_execution",
    ],
)
def test_linked_admission_source_loss_recovers_only_with_intact_custody(
    tmp_path: Path,
    disposition: str,
) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    path = tmp_path / "linked-source-loss.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
            claim = repo.claim_dispatch(admission.admission_id)
        result = _persist(store, state, claim_id=claim.claim_id)
        with store.transaction():
            repo.link_execution(admission.admission_id, str(result.collector.execution_id))
        original_terminal = None
        if disposition == "evaluated":
            with store.transaction():
                original_terminal = repo.evaluate(admission.admission_id)
            assert original_terminal.evaluation is not None
            assert original_terminal.evaluation.observed is True
        store.connection.execute(
            "DELETE FROM evidence WHERE evidence_id=?", (str(source.evidence_id),)
        )
        if disposition == "tampered_link":
            store.connection.execute("DROP TRIGGER diagnostic_links_no_update")
            store.connection.execute(
                "UPDATE diagnostic_intent_execution_links SET record_sha256=?", ("0" * 64,)
            )
        elif disposition == "tampered_claim":
            store.connection.execute("DROP TRIGGER diagnostic_claims_no_update")
            store.connection.execute(
                "UPDATE diagnostic_intent_dispatch_claims SET record_sha256=?", ("0" * 64,)
            )
        elif disposition == "tampered_execution":
            store.connection.execute(
                "UPDATE probe_executions SET probe_version=1 WHERE execution_id=?",
                (str(result.collector.execution_id),),
            )
        with pytest.raises(ValueError):
            repo.readback(admission.admission_id)
        with pytest.raises(ValueError), store.transaction():
            repo.evaluate(admission.admission_id)
        if disposition == "pending":
            with store.transaction():
                terminal = repo.record_custody_gap(admission.admission_id)
                assert repo.record_custody_gap(admission.admission_id) == terminal
            assert terminal.status == "unknown" and terminal.evaluation is None
            assert terminal.reason == "admission_source_unverifiable"
            assert terminal.execution_id == str(result.collector.execution_id)
            assert terminal.sources == ()
            assert terminal.rejected_evidence_ids == (source.evidence_id,)
        else:
            with pytest.raises(ValueError), store.transaction():
                repo.record_custody_gap(admission.admission_id)
            rows = store.connection.execute(
                "SELECT record_json FROM diagnostic_intent_terminals WHERE admission_id=?",
                (admission.admission_id,),
            ).fetchall()
            if disposition == "evaluated":
                assert original_terminal is not None and len(rows) == 1
                assert json.loads(rows[0][0]) == original_terminal.model_dump(mode="json")
            else:
                assert rows == []
    with SQLiteStore(path) as store:
        repo = DiagnosticIntentRepository(store)
        if disposition == "pending":
            restored = repo.terminal(admission.admission_id)
            assert restored is not None and restored.status == "unknown"
            assert restored.execution_id == str(result.collector.execution_id)
            assert restored.evaluation is None and repo.pending(state.case_id) == ()
        elif disposition == "evaluated":
            with pytest.raises(ValueError):
                repo.terminal(admission.admission_id)


@pytest.mark.parametrize(
    "linked,source_lost", [(False, False), (False, True), (True, False), (True, True)]
)
def test_restart_recovers_consumed_claims_without_redispatch(
    tmp_path: Path,
    linked: bool,
    source_lost: bool,
) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    path = tmp_path / "recovery.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        source = _persist(store, state, plan="baseline")
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
            claim = repo.claim_dispatch(admission.admission_id)
        execution_id = None
        if linked:
            result = _persist(store, state, claim_id=claim.claim_id)
            execution_id = str(result.collector.execution_id)
            with store.transaction():
                repo.link_execution(admission.admission_id, execution_id)
        if source_lost:
            store.connection.execute(
                "DELETE FROM evidence WHERE evidence_id=?", (str(source.evidence_id),)
            )
        before = store.probe_execution_count(case_id=str(state.case_id))
    with SQLiteStore(path) as store:
        # The exclusive application owner normally advances the case epoch on resume.
        repository = InvestigationRepository(store)
        recovered_state = repository.load(str(state.case_id))
        repository.save(
            recovered_state,
            expected_version=recovered_state.state_version,
            event="resumed",
            detail="Exclusive owner recovered case",
        )
        repo = DiagnosticIntentRepository(store)
        with pytest.raises(ValueError, match="transaction"):
            repo.recover_consumed(state.case_id)
        with store.transaction():
            terminals = repo.recover_consumed(state.case_id)
        assert len(terminals) == 1
        terminal = terminals[0]
        assert terminal.admission_id == admission.admission_id
        assert terminal.execution_id == execution_id
        expected = "unknown" if source_lost else ("evaluated" if linked else "interrupted")
        assert terminal.status == expected
        if source_lost:
            assert terminal.reason == "admission_source_unverifiable"
            assert terminal.evaluation is None
        elif not linked:
            assert terminal.reason == "dispatch_outcome_unknown"
        with store.transaction():
            assert repo.recover_consumed(state.case_id) == ()
        assert store.probe_execution_count(case_id=str(state.case_id)) == before
        assert repo.pending(state.case_id) == ()
        with pytest.raises(ValueError), store.transaction():
            repo.claim_dispatch(admission.admission_id)


def test_recovery_does_not_consume_unclaimed_admission(tmp_path: Path) -> None:
    from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository

    with SQLiteStore(tmp_path / "recovery.db") as store:
        state = _state(store)
        source = _persist(store, state)
        repo = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = repo.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
            assert repo.recover_consumed(state.case_id) == ()
        assert repo.pending(state.case_id) == (admission,)
        assert repo.dispatch_claim(admission.admission_id) is None
