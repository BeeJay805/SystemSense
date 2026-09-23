"""A PDF investigation waits for an observed process choice before target sampling."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.targets import ProcessTargetRepository
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContextStatus
from systemsense.orchestration.probes import ProbeDefinition, ProbeRunner
from systemsense.packs.runtime import TargetPressureParametersV1, default_probe_runner
from systemsense.storage.sqlite_store import SQLiteStore


def _application_snapshot(store: SQLiteStore, case_id: CaseId, at: datetime) -> None:
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "application.snapshot", "probe_version": 1}
    )
    created = at - timedelta(minutes=1)
    facts: dict[str, JsonValue] = {
        "collection_started_at": (at - timedelta(seconds=1)).isoformat(),
        "collection_completed_at": at.isoformat(),
        "collection_status": "available",
        "omitted_counts": {"processes": 0, "services": 0, "startup": 0},
        "processes": [
            {
                "pid": 4242,
                "ppid": 1,
                "name": "viewer.exe",
                "creation_time": created.isoformat(),
                "identity": f"4242@{created.isoformat()}",
            }
        ],
    }
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=at,
        captured_at=at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "application.snapshot"},
        ),
        collector=CollectorReference(
            id="application.snapshot", version=1, execution_id=execution_id
        ),
        summary="Application topology",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="application.snapshot",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(at - timedelta(seconds=1)).isoformat(),
            finished_at=at.isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=at.isoformat(),
            captured_at=at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )


def _precollected_pdf_investigator(store: SQLiteStore) -> tuple[Investigator, CaseId]:
    investigator = default_investigator(store)
    state = investigator.create(objective="This PDF viewer is slow")
    _application_snapshot(store, state.case_id, state.created_at)
    investigator.repository.save(
        state.model_copy(update={"completed_probe_ids": ("application.snapshot",)}),
        expected_version=state.state_version,
        event="precollected",
        detail="fixture snapshot",
    )
    return investigator, state.case_id


def test_pdf_run_waits_for_process_selection_and_generic_resume_cannot_bypass(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "pdf-wait.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)

        waiting = investigator.run(str(case_id))

        assert waiting.status is InvestigationStatus.AWAITING_TARGET
        assert waiting.outcome is InvestigationOutcome.AWAITING_TARGET
        assert waiting.completed_probe_ids == ("application.snapshot",)
        assert waiting.assessment is None
        assert not waiting.provider_calls
        with pytest.raises(ValueError, match="target"):
            investigator.resume(str(case_id))
        with pytest.raises(ValueError, match="binding"):
            investigator.resume_after_target(str(case_id))
        inventory = ProcessTargetRepository(store).list_process_candidates(case_id)
        assert len(inventory.candidates) == 1
        ProcessTargetRepository(store).bind_process_target(
            case_id, inventory.candidates[0].candidate_id
        )
        with pytest.raises(ValueError, match="target"):
            investigator.resume(str(case_id))

        queued = investigator.resume_after_target(str(case_id))

        assert queued.status is InvestigationStatus.QUEUED
        assert queued.outcome is InvestigationOutcome.INVESTIGATING
        assert queued.completed_probe_ids == ("application.snapshot",)


def _waiting_with_binding(investigator: Investigator, case_id: CaseId) -> None:
    waiting = investigator.run(str(case_id))
    assert waiting.status is InvestigationStatus.AWAITING_TARGET
    targets = ProcessTargetRepository(investigator.store)
    inventory = targets.list_process_candidates(case_id)
    targets.bind_process_target(case_id, inventory.candidates[0].candidate_id)
    investigator.resume_after_target(str(case_id))


def test_resumed_pdf_samples_only_bound_target_and_failure_is_not_diagnosis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "pdf-failed-probe.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def unavailable(parameters: dict[str, JsonValue]):
            calls.append(parameters)
            raise RuntimeError("counter unavailable")

        monkeypatch.setattr(
            investigator.runtime,
            "_probe_runner",
            ProbeRunner(
                definitions=(
                    ProbeDefinition(
                        manifest=manifest,
                        parameter_model=TargetPressureParametersV1,
                        handler=unavailable,
                        isolated=False,
                    ),
                )
            ),
        )

        finished = investigator.run(str(case_id))

        assert len(calls) == 1
        assert calls[0]["pid"] == 4242
        assert finished.completed_probe_ids == (
            "application.snapshot",
            "application.target_pressure",
        )
        assert not finished.pending_probe_ids
        assert finished.assessment is None
        assert finished.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
        context = investigator.context(str(case_id))
        assert any(
            item.probe_id == "performance.coverage" and item.status is EvidenceContextStatus.FAILED
            for item in context
        ), [(item.probe_id, item.status) for item in context]
        completed_version = finished.state_version
        with pytest.raises(ValueError, match="not awaiting"):
            investigator.resume_after_target(str(case_id))
        assert investigator.repository.load(str(case_id)).state_version == completed_version


def test_interrupted_pending_target_is_not_replayed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-interrupted.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        queued = investigator.repository.load(str(case_id))
        investigator.repository.save(
            queued.model_copy(update={"pending_probe_ids": ("application.target_pressure",)}),
            expected_version=queued.state_version,
            event="test_crash",
            detail="target may have been observed before worker crashed",
        )

        def must_not_replay(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("uncertain prior target attempt must not repeat")

        investigator.runtime.execute_bound_target_pressure = must_not_replay  # type: ignore[method-assign]
        finished = investigator.run(str(case_id))

        assert "application.target_pressure" in finished.completed_probe_ids
        assert not finished.pending_probe_ids
        assert any("not automatically repeated" in warning for warning in finished.warnings)
        assert finished.assessment is None
        assert finished.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION


def test_pdf_case_with_too_small_budget_does_not_await_unrunnable_target(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-low-budget.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        limited = investigator.repository.save(
            state.model_copy(
                update={
                    "budget_ms": 5_000,
                    "deadline_at": utc_now() + timedelta(milliseconds=1),
                }
            ),
            expected_version=state.state_version,
            event="test_budget",
            detail="target collection cost exceeds configured case budget",
        )

        finished = investigator.run(str(case_id))

        assert limited.completed_probe_ids == ("application.snapshot",)
        assert finished.status is not InvestigationStatus.AWAITING_TARGET
        assert finished.outcome is not InvestigationOutcome.AWAITING_TARGET
        assert any("10-second case budget" in warning for warning in finished.warnings)
        assert "application.target_pressure" not in finished.completed_probe_ids
