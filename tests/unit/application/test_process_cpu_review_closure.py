"""Synthetic regressions for narrowly reviewed process CPU completion."""

import json
from datetime import timedelta
from pathlib import Path
from typing import Never

import pytest

from systemsense.application.deep_worker import (
    DeepMailboxRepository,
    DeepWorkerResultV1,
    FrozenDeepTaskV1,
    freeze_deep_task,
)
from systemsense.application.investigation_state import InvestigationState
from systemsense.application.investigator import Investigator, _narrow_current_process_cpu_question
from systemsense.application.targets import ProcessTargetBinding, ProcessTargetRepository
from systemsense.decision.contracts import ProbeProposal
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContext
from systemsense.platform.windows.deep_collectors import (
    TargetPressureSample,
    TargetPressureSnapshot,
    TargetPressureStatus,
)
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.presented_read_set import capture_presented_read_set
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_generic_process_frontier_selection import (
    _generic_case,
    _set_frontier_owner,
)
from tests.unit.application.test_process_presence_review import IDENTITY

# Private test fixture: synthetic persisted records only, no host/model invocation.
# pyright: reportPrivateUsage=false
OBJECTIVE = "Is viewer.exe monopolizing a core during a short sample?"
SUMMARY = "The bounded target sample was reviewed; cause remains unknown."
ACTIVITY_OBJECTIVE = (
    "The local viewer.exe application is lagging. "
    "What can you verify about its current activity, and what remains unknown?"
)


@pytest.mark.parametrize(
    "objective",
    (
        ACTIVITY_OBJECTIVE,
        "Is viewer.exe busy right now?",
        "Can you measure viewer.exe current activity?",
    ),
)
def test_present_activity_question_can_use_a_bounded_target_sample(objective: str) -> None:
    assert _narrow_current_process_cpu_question(objective) == "viewer.exe"


@pytest.mark.parametrize(
    "objective",
    (
        "Why is viewer.exe lagging? What is it doing now?",
        "What was viewer.exe doing earlier, and is it busy now?",
        "Compare viewer.exe memory and network activity now.",
        "Was viewer.exe busy all day?",
    ),
)
def test_broad_activity_question_cannot_close_on_a_cpu_sample(objective: str) -> None:
    assert _narrow_current_process_cpu_question(objective) is None


@pytest.mark.parametrize(
    "objective",
    [
        "What CPU architecture is viewer.exe using now?",
        "Which processor core is viewer.exe running on currently?",
        "What is the current processor affinity of viewer.exe?",
    ],
)
def test_cpu_usage_sample_cannot_answer_cpu_identity_or_affinity(objective: str) -> None:
    assert _narrow_current_process_cpu_question(objective) is None


def test_cpu_scope_words_come_from_question_not_executable_name() -> None:
    assert _narrow_current_process_cpu_question("Is cpu.exe running currently?") is None
    assert (
        _narrow_current_process_cpu_question("What is memory.exe's current CPU use?")
        == "memory.exe"
    )


def _pressure_case(
    store: SQLiteStore,
    *,
    objective: str = OBJECTIVE,
    identity_mismatch: str | None = None,
    partial: bool = False,
    sample_mismatch: str | None = None,
) -> tuple[Investigator, InvestigationState, ProcessTargetBinding, EvidenceId]:
    app, state = _generic_case(store, max_probes=4, objective=objective)
    binding = ProcessTargetRepository(store).bind_exact_process_name(state.case_id, "viewer.exe")
    started = state.created_at + timedelta(seconds=1)
    ended = started + timedelta(seconds=3)
    captured = ended + timedelta(milliseconds=10)
    manifest = app.runtime.probe_manifest("application.target_pressure")
    assert manifest is not None
    execution_id = ExecutionId.new()
    evidence_id = EvidenceId.new()
    status = TargetPressureStatus.PARTIAL if partial else TargetPressureStatus.AVAILABLE
    target_pid = binding.pid + (1 if identity_mismatch == "pid" else 0)
    target_birth = binding.creation_time + (
        timedelta(seconds=1) if identity_mismatch == "birth" else timedelta(0)
    )
    baseline = TargetPressureSample(
        query_started_at=started - timedelta(seconds=1)
        if sample_mismatch == "baseline_outside_window"
        else started,
        observed_at=started + timedelta(milliseconds=10),
        status=(
            TargetPressureStatus.PARTIAL
            if sample_mismatch == "baseline_status"
            else TargetPressureStatus.AVAILABLE
        ),
        delta_status="baseline",
        name=binding.name,
    )
    measured = tuple(
        TargetPressureSample(
            query_started_at=started + timedelta(seconds=1, milliseconds=5)
            if sample_mismatch == "overlapping_queries" and index == 2
            else started + timedelta(seconds=index),
            observed_at=started + timedelta(seconds=index, milliseconds=10),
            status=(
                TargetPressureStatus.PARTIAL
                if sample_mismatch == "measured_status" and index == 2
                else status
            ),
            delta_status="measured",
            name=(
                "other.exe" if sample_mismatch == "measured_name" and index == 2 else binding.name
            ),
            cpu_percent=(None if sample_mismatch == "measured_units" and index == 2 else 6.25),
            cpu_logical_cores=(None if sample_mismatch == "measured_units" and index == 2 else 1.0),
        )
        for index in (1, 2)
    )
    ordered_samples = (baseline, *measured)
    if sample_mismatch == "measured_order":
        ordered_samples = (baseline, *reversed(measured))
    pressure = TargetPressureSnapshot(
        schema_version=2,
        logical_cpu_count=16,
        target_pid=target_pid,
        target_creation_time=target_birth,
        window_started_at=started,
        window_ended_at=ended,
        captured_at=ended,
        samples=ordered_samples,
        limitations=("first sample is a counter baseline", "samples are separate instants"),
        status=status,
    )
    source_id = stable_source_id(
        "systemsense.probe",
        {"probe_id": "application.target_pressure", "probe_version": manifest.version},
    )
    raw_pressure = pressure.model_dump(mode="json")
    if sample_mismatch == "coerced_cpu_count":
        raw_pressure["logical_cpu_count"] = "16"
    if sample_mismatch == "coerced_pid":
        raw_pressure["target_pid"] = str(target_pid)
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=state.case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=ended,
        captured_at=captured,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "application.target_pressure"},
        ),
        collector=CollectorReference(
            id="application.target_pressure", version=manifest.version, execution_id=execution_id
        ),
        summary="Synthetic exact-identity, bounded process CPU sample.",
        facts=(EvidenceFact(name="target_pressure", value=raw_pressure),),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as tx:
        tx.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(state.case_id),
            probe_id="application.target_pressure",
            probe_version=manifest.version,
            status="ok",
            parameters_json=json.dumps(
                {"pid": target_pid, "creation_time": target_birth.isoformat()}
            ),
            started_at=started.isoformat(),
            finished_at=captured.isoformat(),
            state_version=state.state_version,
        )
        tx.insert_evidence(
            case_id=str(state.case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=ended.isoformat(),
            captured_at=captured.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )
    state = state.model_copy(
        update={
            "completed_probe_ids": ("application.snapshot", "application.target_pressure"),
        }
    )
    return app, state, binding, evidence_id


def _apply_sol_review(
    store: SQLiteStore,
    app: Investigator,
    state: InvestigationState,
    *,
    used: bool = True,
    considered: bool = True,
    applied: bool = True,
    degraded: bool = False,
) -> InvestigationState:
    context = app.context(str(state.case_id), state=state)
    snapshot = next(item for item in context if item.probe_id == "application.snapshot")
    pressure = next(item for item in context if item.probe_id == "application.target_pressure")
    request = ReasoningRequest(
        schema_version=3,
        case_id=state.case_id,
        state_version=state.state_version,
        correlation_id="synthetic-cpu-review",
        deadline_at=state.deadline_at,
        objective=state.objective,
        evidence_ids=(snapshot.evidence_id, pressure.evidence_id),
        evidence_context=context,
        available_probes=app._case_capabilities(state),
        completed_probe_ids=frozenset(state.completed_probe_ids),
        budget_ms=30_000,
        max_probes=4,
    )
    task = freeze_deep_task(
        request,
        capture_presented_read_set(store, state.case_id, tuple(x.evidence_id for x in context)),
        provider_identity=IDENTITY,
        hypothesis_revision=0,
    )
    response = ReasoningResponse(
        schema_version=3,
        provider=IDENTITY,
        case_id=state.case_id,
        state_version=state.state_version,
        correlation_id=request.correlation_id,
        deadline_at=state.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary=SUMMARY,
        degraded=degraded,
        considered_evidence_ids=(snapshot.evidence_id, pressure.evidence_id) if considered else (),
        hypotheses=(
            Hypothesis(
                hypothesis_id="bounded_cpu",
                statement="The measured target CPU level is scoped to this sample only.",
                status=HypothesisStatus.UNRESOLVED,
                supporting_evidence_ids=(pressure.evidence_id,) if used else (),
            ),
        ),
    )
    response.validate_against(request)
    now = max(utc_now(), pressure.captured_at + timedelta(milliseconds=1))
    result = DeepWorkerResultV1(
        case_id=state.case_id,
        request_sha256=task.request_sha256,
        provider_identity=IDENTITY,
        status="completed",
        started_at=now,
        finished_at=now,
        elapsed_ms=1,
        response=response,
    )
    mailbox = DeepMailboxRepository(store)
    assert mailbox.admit(task)
    assert mailbox.finish(task, "applied" if applied else "rejected", result=result)
    return state.model_copy(update={"summary": SUMMARY, "summary_source": "advisory_async"})


def test_valid_applied_review_closes_bounded_sample_and_preserves_sol_summary(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cpu-valid.db") as store:
        store.initialize()
        app, state, _binding, _pressure_id = _pressure_case(store)
        state = _apply_sol_review(store, app, state)
        result = app._complete_reviewed_loopback_task(state, None)
        assert result is not None
        assert result.summary == SUMMARY
        assert result.summary_source == "advisory_async"
        assert result.assessment is not None
        assert result.assessment.root_cause_proven is False
        assert set(map(str, result.assessment.evidence_ids)) == {
            str(item.evidence_id)
            for item in app.context(str(state.case_id), state=state)
            if item.probe_id in {"application.snapshot", "application.target_pressure"}
        }


def test_valid_review_closes_present_activity_without_claiming_the_lag_cause(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "activity-valid.db") as store:
        store.initialize()
        app, state, _binding, _pressure_id = _pressure_case(store, objective=ACTIVITY_OBJECTIVE)
        state = _apply_sol_review(store, app, state)
        result = app._complete_reviewed_loopback_task(state, None)
        assert result is not None
        assert result.summary == SUMMARY
        assert result.assessment is not None
        assert result.assessment.root_cause_proven is False


@pytest.mark.parametrize(
    (
        "objective",
        "used",
        "considered",
        "applied",
        "degraded",
        "pending",
        "mismatch",
        "partial",
        "sample_mismatch",
    ),
    [
        (OBJECTIVE, False, True, True, False, False, None, False, None),  # cited only
        (OBJECTIVE, True, False, True, False, False, None, False, None),  # not considered
        (OBJECTIVE, True, True, False, False, False, None, False, None),  # rejected mailbox item
        (OBJECTIVE, True, True, True, True, False, None, False, None),  # degraded response
        (OBJECTIVE, True, True, True, False, True, None, False, None),  # unresolved request
        ("Why is viewer.exe using a core?", True, True, True, False, False, None, False, None),
        ("Was viewer.exe using a core earlier?", True, True, True, False, False, None, False, None),
        (
            "Is viewer.exe causing system slowness with CPU?",
            True,
            True,
            True,
            False,
            False,
            None,
            False,
            None,
        ),
        (
            "Is viewer.exe using a core continuously?",
            True,
            True,
            True,
            False,
            False,
            None,
            False,
            None,
        ),
        (
            "What are viewer.exe's current CPU and memory levels?",
            True,
            True,
            True,
            False,
            False,
            None,
            False,
            None,
        ),
        (
            "What was viewer.exe's CPU during yesterday's sample?",
            True,
            True,
            True,
            False,
            False,
            None,
            False,
            None,
        ),
        (
            "Compare viewer.exe CPU with the network and disk now",
            True,
            True,
            True,
            False,
            False,
            None,
            False,
            None,
        ),
        (OBJECTIVE, True, True, True, False, False, "pid", False, None),
        (OBJECTIVE, True, True, True, False, False, "birth", False, None),
        (OBJECTIVE, True, True, True, False, False, None, True, None),  # partial collection
        (OBJECTIVE, True, True, True, False, False, None, False, "baseline_status"),
        (OBJECTIVE, True, True, True, False, False, None, False, "measured_status"),
        (OBJECTIVE, True, True, True, False, False, None, False, "measured_name"),
        (OBJECTIVE, True, True, True, False, False, None, False, "measured_units"),
        (OBJECTIVE, True, True, True, False, False, None, False, "measured_order"),
        (OBJECTIVE, True, True, True, False, False, None, False, "baseline_outside_window"),
        (OBJECTIVE, True, True, True, False, False, None, False, "overlapping_queries"),
        (OBJECTIVE, True, True, True, False, False, None, False, "coerced_cpu_count"),
        (OBJECTIVE, True, True, True, False, False, None, False, "coerced_pid"),
    ],
)
def test_cpu_closure_withholds_broad_unreviewed_or_invalid_measurements(
    tmp_path: Path,
    objective: str,
    used: bool,
    considered: bool,
    applied: bool,
    degraded: bool,
    pending: bool,
    mismatch: str | None,
    partial: bool,
    sample_mismatch: str | None,
) -> None:
    with SQLiteStore(tmp_path / "cpu-negative.db") as store:
        store.initialize()
        app, state, _binding, _pressure_id = _pressure_case(
            store,
            objective=objective,
            identity_mismatch=mismatch,
            partial=partial,
            sample_mismatch=sample_mismatch,
        )
        state = _apply_sol_review(
            store, app, state, used=used, considered=considered, applied=applied, degraded=degraded
        )
        if pending:
            state = state.model_copy(update={"pending_probe_ids": ("application.target_pressure",)})
        assert app._complete_reviewed_loopback_task(state, None) is None


def test_active_deep_work_blocks_completion_but_not_readiness(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cpu-active.db") as store:
        store.initialize()
        app, state, _binding, _pressure_id = _pressure_case(store)
        state = _apply_sol_review(store, app, state)
        row = store.connection.execute(
            "SELECT task_json FROM deep_mailbox WHERE case_id=? AND status='applied'",
            (str(state.case_id),),
        ).fetchone()
        assert row is not None
        app._deep_task = FrozenDeepTaskV1.model_validate_json(str(row[0]))
        assert app._scoped_measurements_ready_for_review(state)
        assert app._complete_reviewed_loopback_task(state, None) is None


def test_valid_cpu_sample_is_sufficient_to_start_the_first_sol_review(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cpu-ready.db") as store:
        store.initialize()
        app, state, _binding, _pressure_id = _pressure_case(store)
        assert app._scoped_measurements_ready_for_review(state)


@pytest.mark.parametrize("already_reviewed", [False, True])
def test_ready_cpu_sample_reaches_review_before_another_frontier_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, already_reviewed: bool
) -> None:
    with SQLiteStore(tmp_path / "review-before-extra-check.db") as store:
        store.initialize()
        app, state, _binding, _pressure_id = _pressure_case(store)
        _set_frontier_owner(app, select_pressure=True)
        if already_reviewed:
            state = _apply_sol_review(store, app, state)
        state = app.repository.save(
            state,
            expected_version=state.state_version,
            event="synthetic_cpu_ready",
            detail="A registered target measurement is ready for review.",
        )
        reviews: list[str] = []

        def review(
            current: InvestigationState,
            _context: tuple[EvidenceContext, ...],
            **_kwargs: object,
        ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
            reviews.append(str(current.case_id))
            return _apply_sol_review(store, app, current), ()

        def unexpected_work(*_args: object, **_kwargs: object) -> Never:
            raise AssertionError("Extra work started before reviewing the ready measurement")

        monkeypatch.setattr(app, "_reason_with_details", review)
        monkeypatch.setattr(app, "_event_frontier_turn", unexpected_work)
        monkeypatch.setattr(app, "_collect", unexpected_work)
        result = app.run(str(state.case_id))
        assert result.outcome is not None and result.outcome.value == "supported_explanation"
        assert result.assessment is not None
        assert len(reviews) == (0 if already_reviewed else 1)
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone() == (2,)
