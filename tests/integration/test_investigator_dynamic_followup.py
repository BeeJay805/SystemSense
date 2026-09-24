"""A fast-brain follow-up can overlap the remaining baseline work in one case epoch."""

import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
)
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.contracts import ProbeCapability
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.provider import FastDecisionProvider
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.inference.laya_runtime import LayaAttentionResult
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import (
    BoundedScheduler,
    ResourceClass,
    StateVersion,
    Task,
    TaskGraph,
    TaskResult,
)
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.decision_snapshots import DecisionSnapshotRepository
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


class NoParametersV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _definition(
    probe_id: str,
    category: str,
    collect: Callable[[dict[str, JsonValue]], ProbeObservation],
) -> ProbeDefinition:
    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id=probe_id,
            version=1,
            implementation_id=f"builtin.{probe_id}",
            question=f"What is the {probe_id} state?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=3000, max_output_bytes=32768, max_records=64),
            category=category,
        ),
        parameter_model=NoParametersV1,
        handler=collect,
        isolated=False,
    )


def _investigator(
    store: SQLiteStore,
    *,
    decision: FastDecisionProvider,
    slow_started: threading.Event,
    child_finished: threading.Event,
    collected: list[str],
    scheduler: BoundedScheduler | None = None,
    extra_count: int = 0,
    fail_child: bool = False,
) -> Investigator:
    def slow(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        slow_started.set()
        assert child_finished.wait(timeout=10), "follow-up did not overlap slow baseline work"
        collected.append("gpu.telemetry.sample")
        now = datetime.now(UTC)
        return ProbeObservation(
            summary="GPU sample", facts={"gpu": 1}, observed_at=now, captured_at=now
        )

    def fast(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert slow_started.wait(timeout=10)
        collected.append("core.system")
        now = datetime.now(UTC)
        return ProbeObservation(
            summary="System sample", facts={"system": 1}, observed_at=now, captured_at=now
        )

    def child(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        collected.append("devices.snapshot")
        child_finished.set()
        if fail_child:
            raise RuntimeError("simulated read-only probe failure")
        now = datetime.now(UTC)
        return ProbeObservation(
            summary="Device sample", facts={"device": 1}, observed_at=now, captured_at=now
        )

    def extra(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = datetime.now(UTC)
        return ProbeObservation(summary="Extra sample", facts={}, observed_at=now, captured_at=now)

    extras = tuple(f"fixture.extra{index}" for index in range(extra_count))
    definitions = (
        _definition("gpu.telemetry.sample", "local_ai", slow),
        _definition("core.system", "core", fast),
        *(_definition(probe_id, "core", extra) for probe_id in extras),
        _definition("devices.snapshot", "devices", child),
    )
    capabilities = (
        ProbeCapability(
            probe_id="gpu.telemetry.sample",
            description="GPU state",
            cost_ms=1000,
            resource_class=ResourceClass.GPU,
        ),
        ProbeCapability(
            probe_id="core.system",
            description="System state",
            cost_ms=1000,
            resource_class=ResourceClass.CPU,
        ),
        *(
            ProbeCapability(
                probe_id=probe_id,
                description="Unrelated fixture",
                cost_ms=1000,
                resource_class=ResourceClass.CPU,
            )
            for probe_id in extras
        ),
        ProbeCapability(
            probe_id="devices.snapshot",
            description="Device state",
            keywords=frozenset({"fps"}),
            cost_ms=1000,
            resource_class=ResourceClass.PROCESS,
        ),
    )
    runtime = DiagnosticRuntime(
        store=store,
        case_service=CaseService(
            store,
            DeterministicPlanner(
                candidates=tuple(
                    ProbeCandidate(probe_id=item.probe_id, cost_ms=1000, value=1, common=True)
                    for item in capabilities
                )
            ),
        ),
        probe_runner=ProbeRunner(definitions=definitions),
        scheduler=scheduler,
    )
    return Investigator(
        store=store,
        runtime=runtime,
        capabilities=capabilities,
        decision=decision,
        reasoning=UnavailableReasoningProvider(),
    )


class ChoosingRanker:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[dict[str, str], ...], tuple[dict[str, str], ...]]] = []

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult:
        self.calls.append((evidence, candidates))
        return LayaAttentionResult(
            ranked_probe_ids=tuple(item["probe_id"] for item in candidates),
            considered_probe_ids=tuple(item["probe_id"] for item in candidates),
            ranked_evidence_ids=tuple(item["evidence_id"] for item in evidence),
            considered_evidence_ids=tuple(item["evidence_id"] for item in evidence),
            ranked_attention_page_ids=tuple(item["page_id"] for item in evidence),
            considered_attention_page_ids=tuple(item["page_id"] for item in evidence),
        )


def test_fast_brain_follows_persisted_baseline_evidence_before_slow_probe_finishes(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "choice.db") as store:
        ranker = ChoosingRanker()
        fast_brain = LayaDecisionProvider(ranker=ranker, timeout_seconds=1.5)
        collected: list[str] = []
        investigator = _investigator(
            store,
            decision=fast_brain,
            slow_started=threading.Event(),
            child_finished=threading.Event(),
            collected=collected,
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)

        finished = investigator.run(str(case.case_id))

        assert any(candidates for _, candidates in ranker.calls), ranker.calls
        assert any('"probe_id":"core.system"' in item["description"] for item in ranker.calls[0][0])
        assert store.connection.execute(
            "SELECT 1 FROM collection_followup_admissions WHERE case_id=?", (str(case.case_id),)
        ).fetchone(), (fast_brain.status, ranker.calls, finished.warnings)
        assert set(collected) == {"core.system", "gpu.telemetry.sample", "devices.snapshot"}
        assert "devices.snapshot" in finished.completed_probe_ids
        assert finished.spent_cost_ms == 3000
        admissions = store.connection.execute(
            "SELECT decision_snapshot_id, epoch_state_version FROM collection_followup_admissions "
            "WHERE case_id=?",
            (str(case.case_id),),
        ).fetchall()
        assert len(admissions) == 1
        assert admissions[0][0] is not None
        snapshot = next(
            item
            for item in DecisionSnapshotRepository(store).snapshots(case_id=str(case.case_id))
            if item.snapshot_id == str(admissions[0][0])
        )
        assert snapshot.state_version == int(admissions[0][1])


class FailingRanker:
    def __init__(self) -> None:
        self.calls = 0

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult:
        self.calls += 1
        raise RuntimeError("model unavailable")


class CrashAfterAdmissionScheduler(BoundedScheduler):
    def run_blocking(
        self,
        tasks: TaskGraph | Sequence[Task],
        *,
        case_deadline_at: datetime | None = None,
        cancel_event: threading.Event | None = None,
        state_version: StateVersion = 0,
        on_result: Callable[[TaskResult], None] | None = None,
        offer_after_result: Callable[[TaskResult], Sequence[Task]] | None = None,
        on_admitted: Callable[[tuple[Task, ...]], bool | None] | None = None,
    ) -> tuple[TaskResult, ...]:
        def admit_then_crash(offered: tuple[Task, ...]) -> bool | None:
            assert on_admitted is not None
            accepted = on_admitted(offered)
            if accepted is not False:
                raise RuntimeError("simulated application stop after durable admission")
            return accepted

        return super().run_blocking(
            tasks,
            case_deadline_at=case_deadline_at,
            cancel_event=cancel_event,
            state_version=state_version,
            on_result=on_result,
            offer_after_result=offer_after_result,
            on_admitted=admit_then_crash,
        )


def test_fast_brain_failure_does_not_discard_baseline_results(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "failure.db") as store:
        ranker = FailingRanker()
        fast_brain = LayaDecisionProvider(ranker=ranker, timeout_seconds=1.5)
        collected: list[str] = []
        # Release the slow collector independently because no child is expected.
        child_finished = threading.Event()
        child_finished.set()
        investigator = _investigator(
            store,
            decision=fast_brain,
            slow_started=threading.Event(),
            child_finished=child_finished,
            collected=collected,
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)

        finished = investigator.run(str(case.case_id))

        assert ranker.calls >= 1
        assert {"core.system", "gpu.telemetry.sample"}.issubset(collected)
        assert {"core.system", "gpu.telemetry.sample"}.issubset(finished.completed_probe_ids)
        assert not store.connection.execute(
            "SELECT 1 FROM collection_followup_admissions WHERE case_id=?", (str(case.case_id),)
        ).fetchone()


def test_relevant_catalog_probe_after_first_eight_is_still_offered(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "catalog.db") as store:
        ranker = ChoosingRanker()
        collected: list[str] = []
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ranker, timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=threading.Event(),
            collected=collected,
            extra_count=10,
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)

        finished = investigator.run(str(case.case_id))

        first_candidates = ranker.calls[0][1]
        assert len(first_candidates) == 8
        assert first_candidates[0]["probe_id"] == "devices.snapshot"
        assert "devices.snapshot" in finished.completed_probe_ids
        assert set(collected) == {"core.system", "gpu.telemetry.sample", "devices.snapshot"}


def test_admitted_unlinked_followup_is_counted_once_after_resume(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "crash.db") as store:
        child_finished = threading.Event()
        child_finished.set()
        collected: list[str] = []
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=child_finished,
            collected=collected,
            scheduler=CrashAfterAdmissionScheduler(),
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)

        with pytest.raises(RuntimeError, match="simulated application stop"):
            investigator.run(str(case.case_id))
        repository = InvestigationRepository(store)
        interrupted = repository.load(str(case.case_id))
        repository.save(
            interrupted.model_copy(
                update={
                    "status": InvestigationStatus.INTERRUPTED,
                    "outcome": InvestigationOutcome.INTERRUPTED,
                }
            ),
            expected_version=interrupted.state_version,
            event="interrupted",
            detail="Simulated application recovery.",
        )
        admissions = store.connection.execute(
            "SELECT admission_id FROM collection_followup_admissions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchall()
        assert len(admissions) == 1
        assert not store.connection.execute(
            "SELECT 1 FROM collection_followup_execution_links WHERE admission_id=?",
            (str(admissions[0][0]),),
        ).fetchone()
        investigator.resume(str(case.case_id))
        finished = investigator.run(str(case.case_id))

        execution_count = store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=?", (str(case.case_id),)
        ).fetchone()
        assert execution_count is not None
        assert int(execution_count[0]) + finished.unrecorded_attempt_count + 1 == 3
        assert finished.outcome is InvestigationOutcome.BUDGET_EXHAUSTED
        assert "devices.snapshot" in finished.interrupted_probe_ids
        assert "devices.snapshot" not in collected
        assert (
            len(
                store.connection.execute(
                    "SELECT admission_id FROM collection_followup_admissions WHERE case_id=?",
                    (str(case.case_id),),
                ).fetchall()
            )
            == 1
        )


def test_retained_away_parent_blocks_linked_failed_followup_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "retention.db") as store:
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=threading.Event(),
            collected=[],
            fail_child=True,
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=4)
        original_save = investigator.repository.save

        def interrupt_before_checkpoint(
            state: InvestigationState, *, expected_version: int, event: str, detail: str
        ) -> InvestigationState:
            if event == "baseline_collected":
                raise RuntimeError("simulated application stop before checkpoint")
            return original_save(
                state, expected_version=expected_version, event=event, detail=detail
            )

        monkeypatch.setattr(investigator.repository, "save", interrupt_before_checkpoint)
        with pytest.raises(RuntimeError, match="simulated application stop"):
            investigator.run(str(case.case_id))
        monkeypatch.setattr(investigator.repository, "save", original_save)
        admission = store.connection.execute(
            "SELECT trigger_execution_id FROM collection_followup_admissions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchone()
        assert admission is not None
        execution_count_before = store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id='devices.snapshot'",
            (str(case.case_id),),
        ).fetchone()
        assert execution_count_before is not None and int(execution_count_before[0]) == 1
        store.connection.execute(
            "DELETE FROM evidence WHERE case_id=? AND execution_id=?",
            (str(case.case_id), str(admission[0])),
        )
        repository = InvestigationRepository(store)
        interrupted = repository.load(str(case.case_id))
        repository.save(
            interrupted.model_copy(
                update={
                    "status": InvestigationStatus.INTERRUPTED,
                    "outcome": InvestigationOutcome.INTERRUPTED,
                }
            ),
            expected_version=interrupted.state_version,
            event="interrupted",
            detail="Simulated application recovery after retention.",
        )

        investigator.resume(str(case.case_id))
        finished = investigator.run(str(case.case_id))

        assert "devices.snapshot" in finished.interrupted_probe_ids
        assert any("custody is uncertain" in warning for warning in finished.warnings)
        execution_count_after = store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id='devices.snapshot'",
            (str(case.case_id),),
        ).fetchone()
        assert execution_count_after == execution_count_before
