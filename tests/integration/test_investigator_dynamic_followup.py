"""A fast-brain follow-up can overlap the remaining baseline work in one case epoch."""

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import BaseModel, ConfigDict

from systemsense.application import runtime as runtime_module
from systemsense.application.case_service import CaseService, OpenedCase
from systemsense.application.fair_model_turns import FairModelTurns
from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
)
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import (
    DiagnosticRuntime,
    FollowupSelection,
    PersistedProbeResult,
)
from systemsense.decision.contracts import DecisionRequest, ProbeCapability
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.provider import FastDecisionProvider
from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    CaseTimeWindowBasis,
    DiagnosticCase,
)
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.inference.laya_runtime import LayaAttentionResult
from systemsense.orchestration.planner import (
    CasePlan,
    DeterministicPlanner,
    PlannedProbe,
    ProbeCandidate,
)
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRun,
    ProbeRunner,
)
from systemsense.orchestration.scheduler import (
    BlockingTaskOfferQueue,
    BoundedScheduler,
    ResourceBudget,
    ResourceClass,
    StateVersion,
    Task,
    TaskGraph,
    TaskResult,
)
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.decision_snapshots import (
    DecisionSnapshotRepository,
    ProbeManifestRef,
)
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.presented_read_set import capture_presented_read_set
from systemsense.storage.search_frontier import SearchFrontierRepository
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


class BlockingFirstRanker(ChoosingRanker):
    def __init__(self, entered: threading.Event, release: threading.Event) -> None:
        super().__init__()
        self._entered = entered
        self._release = release

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult:
        if not self.calls:
            self._entered.set()
            assert self._release.wait(timeout=30)
        return super().attend(
            state=state,
            evidence=evidence,
            candidates=candidates,
            timeout_seconds=timeout_seconds,
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
        assert any(not candidates for _, candidates in ranker.calls[1:]), (
            "the admitted child was reoffered after its current-epoch evidence persisted",
            ranker.calls,
        )


def test_failed_fast_worker_thread_start_releases_global_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_start = threading.Thread.start
    failures = 0

    def fail_one_fast_start(thread: threading.Thread) -> None:
        nonlocal failures
        if thread.name == "systemsense-followup" and failures == 0:
            failures += 1
            raise RuntimeError("simulated thread start failure")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_one_fast_start)
    with SQLiteStore(tmp_path / "worker-start.db") as store:
        allow_slow_finish = threading.Event()
        allow_slow_finish.set()
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=allow_slow_finish,
            collected=[],
        )
        first = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)
        investigator.run(str(first.case_id))
        assert failures == 1
        second = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)
        investigator.run(str(second.case_id))
        assert store.connection.execute(
            "SELECT 1 FROM collection_followup_admissions WHERE case_id=?",
            (str(second.case_id),),
        ).fetchone()


def test_delayed_fast_brain_does_not_block_unrelated_result_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_slow = threading.Event()
    slow_persisted = threading.Event()
    saw_overlap = threading.Event()

    class DelayedRanker:
        def attend(
            self,
            *,
            state: dict[str, object],
            evidence: tuple[dict[str, str], ...],
            candidates: tuple[dict[str, str], ...],
            timeout_seconds: float,
        ) -> LayaAttentionResult:
            del state, timeout_seconds
            release_slow.set()
            if slow_persisted.wait(2):
                saw_overlap.set()
            return LayaAttentionResult(
                ranked_probe_ids=tuple(item["probe_id"] for item in candidates),
                considered_probe_ids=tuple(item["probe_id"] for item in candidates),
                ranked_evidence_ids=tuple(item["evidence_id"] for item in evidence),
                considered_evidence_ids=tuple(item["evidence_id"] for item in evidence),
                ranked_attention_page_ids=tuple(item["page_id"] for item in evidence),
                considered_attention_page_ids=tuple(item["page_id"] for item in evidence),
            )

    with SQLiteStore(tmp_path / "delayed.db") as store:
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=DelayedRanker(), timeout_seconds=2.5),
            slow_started=threading.Event(),
            child_finished=release_slow,
            collected=[],
        )
        original = cast(Any, investigator.runtime)._persist_observation

        def record_persistence(**kwargs: Any) -> Any:
            evidence_id = original(**kwargs)
            run = kwargs["run"]
            if isinstance(run, ProbeRun) and run.probe_id == "gpu.telemetry.sample":
                slow_persisted.set()
            return evidence_id

        monkeypatch.setattr(investigator.runtime, "_persist_observation", record_persistence)
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)
        investigator.run(str(case.case_id))
        assert saw_overlap.is_set(), "inference blocked the persistence owner"
        check = store.connection.execute(
            "SELECT c.frozen_generation,c.checked_generation,c.read_set_sha256 "
            "FROM collection_followup_read_set_checks AS c "
            "JOIN collection_followup_admissions AS a ON a.admission_id=c.admission_id "
            "WHERE a.case_id=?",
            (str(case.case_id),),
        ).fetchone()
        assert check is not None, "unrelated result must not stale a focused read set"
        assert int(check[1]) > int(check[0])
        assert len(str(check[2])) == 64


def test_model_cannot_admit_after_nontrigger_presented_evidence_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "presented-change.db"
    extra_id = "ev_" + "e" * 32
    release_slow = threading.Event()
    saw_extra = threading.Event()

    class MutatingRanker:
        def attend(
            self,
            *,
            state: dict[str, object],
            evidence: tuple[dict[str, str], ...],
            candidates: tuple[dict[str, str], ...],
            timeout_seconds: float,
        ) -> LayaAttentionResult:
            del state, timeout_seconds
            if any(item["evidence_id"] == extra_id for item in evidence):
                saw_extra.set()
                with SQLiteStore(database) as other:
                    other.connection.execute(
                        "UPDATE evidence SET captured_at=? WHERE evidence_id=?",
                        (datetime.now(UTC).isoformat(), extra_id),
                    )
            release_slow.set()
            return LayaAttentionResult(
                ranked_probe_ids=tuple(item["probe_id"] for item in candidates),
                considered_probe_ids=tuple(item["probe_id"] for item in candidates),
                ranked_evidence_ids=tuple(item["evidence_id"] for item in evidence),
                considered_evidence_ids=tuple(item["evidence_id"] for item in evidence),
                ranked_attention_page_ids=tuple(item["page_id"] for item in evidence),
                considered_attention_page_ids=tuple(item["page_id"] for item in evidence),
            )

    with SQLiteStore(database) as store:
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=MutatingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=release_slow,
            collected=[],
        )
        original = cast(Any, investigator.runtime)._persist_observation

        def add_nontrigger(**kwargs: Any) -> Any:
            evidence_id = original(**kwargs)
            run = kwargs["run"]
            if isinstance(run, ProbeRun) and run.probe_id == "core.system":
                row = store.connection.execute(
                    "SELECT source_id,record_json,observed_at,captured_at FROM evidence "
                    "WHERE evidence_id=?",
                    (str(evidence_id),),
                ).fetchone()
                assert row is not None
                payload = json.loads(str(row[1]))
                payload["evidence_id"] = extra_id
                payload["summary"] = "Related nontrigger observation"
                store.connection.execute(
                    "INSERT INTO evidence "
                    "(evidence_id,case_id,source_id,record_json,observed_at,captured_at,"
                    "execution_id,dedupe_key,time_basis,time_quality) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        extra_id,
                        str(kwargs["opened"].case.case_id),
                        str(row[0]),
                        json.dumps(payload),
                        str(row[2]),
                        str(row[3]),
                        None,
                        "fixture.nontrigger",
                        "source_observed",
                        "exact",
                    ),
                )
            return evidence_id

        monkeypatch.setattr(investigator.runtime, "_persist_observation", add_nontrigger)
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)
        investigator.run(str(case.case_id))
        assert saw_extra.is_set(), "the changed row must actually have been presented"
        assert not store.connection.execute(
            "SELECT 1 FROM collection_followup_admissions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchone()
        assert any(
            entry.probe_id == "systemsense.followup"
            and entry.parameters.get("reason_code") == "admission_rejected"
            for entry in store.audit_entries(case_id=str(case.case_id))
        )


def test_unavailable_offer_queue_durably_records_exact_parent_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_offer(self: BlockingTaskOfferQueue, factory: Callable[[], tuple[Task, ...]]) -> bool:
        del self, factory
        return False

    monkeypatch.setattr(BlockingTaskOfferQueue, "offer_factory", reject_offer)
    with SQLiteStore(tmp_path / "queue-gap.db") as store:
        release_slow = threading.Event()
        release_slow.set()
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=release_slow,
            collected=[],
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)
        investigator.run(str(case.case_id))
        core_execution = store.connection.execute(
            "SELECT execution_id FROM probe_executions WHERE case_id=? AND probe_id='core.system'",
            (str(case.case_id),),
        ).fetchone()
        assert core_execution is not None
        gaps = [
            entry
            for entry in store.audit_entries(case_id=str(case.case_id))
            if entry.probe_id == "systemsense.followup"
            and entry.parameters.get("reason_code") == "offer_queue_unavailable"
        ]
        assert any(
            entry.parameters.get("trigger_execution_id") == str(core_execution[0]) for entry in gaps
        )
        assert not store.connection.execute(
            "SELECT 1 FROM collection_followup_admissions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchone()


def test_other_case_owning_host_model_slot_records_capacity_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_turns = FairModelTurns(max_registered=1)
    other_case = host_turns.register("other_case")
    assert other_case is not None
    monkeypatch.setattr(runtime_module, "_FAIR_MODEL_TURNS", host_turns)
    try:
        with SQLiteStore(tmp_path / "host-capacity.db") as store:
            release_slow = threading.Event()
            release_slow.set()
            investigator = _investigator(
                store,
                decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
                slow_started=threading.Event(),
                child_finished=release_slow,
                collected=[],
            )
            case = investigator.create(
                objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3
            )
            investigator.run(str(case.case_id))
            assert any(
                entry.probe_id == "systemsense.followup"
                and entry.parameters.get("reason_code") == "model_capacity"
                for entry in store.audit_entries(case_id=str(case.case_id))
            )
            assert not store.connection.execute(
                "SELECT 1 FROM collection_followup_admissions WHERE case_id=?",
                (str(case.case_id),),
            ).fetchone()
    finally:
        other_case.close()


def test_second_case_waits_for_model_turn_then_receives_followup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    turns = FairModelTurns(max_registered=2)
    monkeypatch.setattr(runtime_module, "_FAIR_MODEL_TURNS", turns)
    first_entered = threading.Event()
    release_first = threading.Event()
    failures: list[BaseException] = []
    admitted: dict[str, bool] = {}

    def run_case(name: str, ranker: ChoosingRanker) -> None:
        try:
            with SQLiteStore(tmp_path / f"{name}.db") as store:
                investigator = _investigator(
                    store,
                    decision=LayaDecisionProvider(ranker=ranker, timeout_seconds=1.5),
                    slow_started=threading.Event(),
                    child_finished=threading.Event(),
                    collected=[],
                    scheduler=BoundedScheduler(
                        budget=ResourceBudget(global_limit=4, per_resource={ResourceClass.GPU: 1})
                    ),
                )
                case = investigator.create(
                    objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3
                )
                investigator.run(str(case.case_id))
                admitted[name] = bool(
                    store.connection.execute(
                        "SELECT 1 FROM collection_followup_admissions WHERE case_id=?",
                        (str(case.case_id),),
                    ).fetchone()
                )
                assert not any(
                    entry.parameters.get("reason_code") == "model_capacity"
                    for entry in store.audit_entries(case_id=str(case.case_id))
                )
        except BaseException as error:
            failures.append(error)

    first = threading.Thread(
        target=run_case,
        args=("first", BlockingFirstRanker(first_entered, release_first)),
    )
    second = threading.Thread(target=run_case, args=("second", ChoosingRanker()))
    first.start()
    try:
        assert first_entered.wait(timeout=10)
        second.start()
        limit = time.monotonic() + 5
        while turns.pending_count < 1 and time.monotonic() < limit:
            time.sleep(0.01)
        assert turns.pending_count == 1, (turns.registered_count, failures, admitted)
        assert "second" not in admitted
    finally:
        release_first.set()
        first.join(timeout=15)
        if second.ident is not None:
            second.join(timeout=15)
    assert not first.is_alive() and not second.is_alive()
    assert not failures, failures
    assert admitted == {"first": True, "second": True}
    assert turns.registered_count == 0


def test_waiting_model_turn_expiry_records_exact_parent_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    turns = FairModelTurns(max_registered=2)
    monkeypatch.setattr(runtime_module, "_FAIR_MODEL_TURNS", turns)
    first_entered = threading.Event()
    release_first = threading.Event()
    first_failures: list[BaseException] = []

    def hold_first_case() -> None:
        try:
            with SQLiteStore(tmp_path / "held.db") as store:
                already_finished = threading.Event()
                already_finished.set()
                investigator = _investigator(
                    store,
                    decision=LayaDecisionProvider(
                        ranker=BlockingFirstRanker(first_entered, release_first),
                        timeout_seconds=1.5,
                    ),
                    slow_started=threading.Event(),
                    child_finished=already_finished,
                    collected=[],
                    scheduler=BoundedScheduler(),
                )
                case = investigator.create(
                    objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3
                )
                investigator.run(str(case.case_id))
        except BaseException as error:
            first_failures.append(error)

    first = threading.Thread(target=hold_first_case)
    first.start()
    try:
        assert first_entered.wait(timeout=10)
        with SQLiteStore(tmp_path / "expired.db") as store:
            already_finished = threading.Event()
            already_finished.set()
            ranker = ChoosingRanker()
            investigator = _investigator(
                store,
                decision=LayaDecisionProvider(ranker=ranker, timeout_seconds=1.5),
                slow_started=threading.Event(),
                child_finished=already_finished,
                collected=[],
                scheduler=BoundedScheduler(),
            )
            case = investigator.create(
                objective="Game runs at 12 FPS", budget_ms=3000, max_probes=3
            )
            investigator.run(str(case.case_id))
            assert not ranker.calls, "the waiting case must not run its model"
            executions = store.connection.execute(
                "SELECT execution_id FROM probe_executions WHERE case_id=?",
                (str(case.case_id),),
            ).fetchall()
            execution_ids = {str(row[0]) for row in executions}
            assert execution_ids
            gaps = [
                entry
                for entry in store.audit_entries(case_id=str(case.case_id))
                if entry.probe_id == "systemsense.followup"
            ]
            assert any(
                entry.probe_id == "systemsense.followup"
                and entry.parameters.get("trigger_execution_id") in execution_ids
                and entry.parameters.get("reason_code")
                in {
                    "model_turn_expired",
                    "case_stopped_during_model_turn",
                    "case_stopped_before_model_turn",
                }
                for entry in gaps
            ), [(entry.event_id, entry.parameters) for entry in gaps]
    finally:
        release_first.set()
        first.join(timeout=15)
    assert not first.is_alive()
    assert not first_failures, first_failures
    assert turns.registered_count == 0


def test_model_callback_finishing_after_deadline_records_terminal_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    turns = FairModelTurns(max_registered=1)
    monkeypatch.setattr(runtime_module, "_FAIR_MODEL_TURNS", turns)
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []
    case_ids: list[str] = []
    database = tmp_path / "late-callback.db"

    def run_case() -> None:
        try:
            with SQLiteStore(database) as store:
                already_finished = threading.Event()
                already_finished.set()
                investigator = _investigator(
                    store,
                    decision=LayaDecisionProvider(
                        ranker=BlockingFirstRanker(entered, release), timeout_seconds=1.5
                    ),
                    slow_started=threading.Event(),
                    child_finished=already_finished,
                    collected=[],
                    scheduler=BoundedScheduler(),
                )
                case = investigator.create(
                    objective="Game runs at 12 FPS", budget_ms=3000, max_probes=3
                )
                case_ids.append(str(case.case_id))
                investigator.run(str(case.case_id))
        except BaseException as error:
            failures.append(error)

    owner = threading.Thread(target=run_case)
    owner.start()
    try:
        assert entered.wait(timeout=10)
        owner.join(timeout=8)
        assert not owner.is_alive(), "case deadline must not wait for the advisory model"
    finally:
        release.set()
        owner.join(timeout=5)
    limit = time.monotonic() + 5
    while turns.registered_count and time.monotonic() < limit:
        time.sleep(0.01)
    assert turns.registered_count == 0
    assert not failures, failures
    assert len(case_ids) == 1
    with SQLiteStore(database) as store:
        assert any(
            entry.probe_id == "systemsense.followup"
            and entry.parameters.get("reason_code")
            in {
                "case_stopped_during_model_turn",
                "model_turn_expired_after_callback",
            }
            for entry in store.audit_entries(case_id=case_ids[0])
        )


def test_cancellation_while_waiting_for_model_turn_records_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    turns = FairModelTurns(max_registered=2)
    monkeypatch.setattr(runtime_module, "_FAIR_MODEL_TURNS", turns)
    holder = turns.register("held_turn")
    assert holder is not None
    held = holder.acquire(deadline_at=datetime.now(UTC) + timedelta(seconds=30))
    assert held.status == "acquired" and held.lease is not None
    cancel = threading.Event()
    failures: list[BaseException] = []
    case_ids: list[str] = []
    ranker = ChoosingRanker()
    database = tmp_path / "cancelled-wait.db"

    def run_case() -> None:
        try:
            with SQLiteStore(database) as store:
                already_finished = threading.Event()
                already_finished.set()
                investigator = _investigator(
                    store,
                    decision=LayaDecisionProvider(ranker=ranker, timeout_seconds=1.5),
                    slow_started=threading.Event(),
                    child_finished=already_finished,
                    collected=[],
                    scheduler=BoundedScheduler(),
                )
                case = investigator.create(
                    objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3
                )
                case_ids.append(str(case.case_id))
                investigator.run(str(case.case_id), cancel_event=cancel)
        except BaseException as error:
            failures.append(error)

    owner = threading.Thread(target=run_case)
    owner.start()
    try:
        limit = time.monotonic() + 10
        while turns.pending_count < 1 and time.monotonic() < limit:
            time.sleep(0.01)
        assert turns.pending_count == 1, failures
        cancel.set()
        owner.join(timeout=8)
        assert not owner.is_alive()
    finally:
        cancel.set()
        held.lease.release()
        holder.close()
        owner.join(timeout=5)
    assert not failures, failures
    assert not ranker.calls
    assert len(case_ids) == 1
    with SQLiteStore(database) as store:
        assert any(
            entry.probe_id == "systemsense.followup"
            and entry.parameters.get("reason_code")
            in {
                "model_turn_cancelled",
                "case_stopped_during_model_turn",
            }
            for entry in store.audit_entries(case_id=case_ids[0])
        )
    assert turns.registered_count == 0


def test_deadline_between_offer_preparation_and_admission_is_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_drain = BlockingTaskOfferQueue.drain
    delayed = False

    def delay_prepared_offer(
        self: BlockingTaskOfferQueue,
    ) -> tuple[Callable[[], tuple[Task, ...]], ...]:
        nonlocal delayed
        factories = original_drain(self)
        if not factories or delayed:
            return factories
        limit = time.monotonic() + 2
        while len(factories) < 2 and time.monotonic() < limit:
            time.sleep(0.01)
            factories += original_drain(self)
        assert len(factories) >= 2, "fixture must queue two parent offers"
        delayed = True

        def finish_after_deadline() -> tuple[Task, ...]:
            offered = factories[0]()
            if offered:
                time.sleep(3.2)
            return offered

        return (finish_after_deadline, *factories[1:])

    monkeypatch.setattr(BlockingTaskOfferQueue, "drain", delay_prepared_offer)
    with SQLiteStore(tmp_path / "admission-deadline.db") as store:
        already_finished = threading.Event()
        already_finished.set()
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=already_finished,
            collected=[],
            scheduler=BoundedScheduler(),
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=3000, max_probes=3)
        investigator.run(str(case.case_id))
        assert delayed
        assert not store.connection.execute(
            "SELECT 1 FROM collection_followup_admissions WHERE case_id=?",
            (str(case.case_id),),
        ).fetchone()
        assert any(
            entry.probe_id == "systemsense.followup"
            and entry.parameters.get("reason_code") == "case_stopped_before_admission"
            for entry in store.audit_entries(case_id=str(case.case_id))
        )
        parents = {
            str(row[0])
            for row in store.connection.execute(
                "SELECT execution_id FROM probe_executions WHERE case_id=?",
                (str(case.case_id),),
            ).fetchall()
        }
        terminal = {
            str(entry.parameters.get("trigger_execution_id"))
            for entry in store.audit_entries(case_id=str(case.case_id))
            if entry.probe_id == "systemsense.followup"
            and entry.parameters.get("reason_code")
            in {
                "case_stopped_before_admission",
                "offer_preparation_conflict",
            }
        }
        assert len(parents) >= 2
        assert parents <= terminal


def test_admitted_parent_does_not_receive_false_terminal_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_offer = BlockingTaskOfferQueue.offer_factory
    accepted = threading.Event()
    release_worker = threading.Event()
    held_once = False

    def hold_after_offer(
        self: BlockingTaskOfferQueue, factory: Callable[[], tuple[Task, ...]]
    ) -> bool:
        nonlocal held_once
        offered = original_offer(self, factory)
        if offered and threading.current_thread().name == "systemsense-followup" and not held_once:
            held_once = True
            accepted.set()
            assert release_worker.wait(timeout=10)
        return offered

    monkeypatch.setattr(BlockingTaskOfferQueue, "offer_factory", hold_after_offer)
    cancel = threading.Event()
    failures: list[BaseException] = []
    case_ids: list[str] = []
    database = tmp_path / "admitted-parent.db"

    def run_case() -> None:
        try:
            with SQLiteStore(database) as store:
                already_finished = threading.Event()
                already_finished.set()
                investigator = _investigator(
                    store,
                    decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
                    slow_started=threading.Event(),
                    child_finished=already_finished,
                    collected=[],
                    scheduler=BoundedScheduler(),
                )
                case = investigator.create(
                    objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3
                )
                case_ids.append(str(case.case_id))
                investigator.run(str(case.case_id), cancel_event=cancel)
        except BaseException as error:
            failures.append(error)

    owner = threading.Thread(target=run_case)
    owner.start()
    try:
        assert accepted.wait(timeout=10)
        assert len(case_ids) == 1
        admission_trigger: str | None = None
        limit = time.monotonic() + 10
        while admission_trigger is None and time.monotonic() < limit:
            with SQLiteStore(database) as reader:
                row = reader.connection.execute(
                    "SELECT trigger_execution_id FROM collection_followup_admissions "
                    "WHERE case_id=?",
                    (case_ids[0],),
                ).fetchone()
                admission_trigger = str(row[0]) if row else None
            if admission_trigger is None:
                time.sleep(0.01)
        assert admission_trigger is not None
        cancel.set()
        owner.join(timeout=8)
        assert not owner.is_alive()
    finally:
        cancel.set()
        release_worker.set()
        owner.join(timeout=5)
    assert not failures, failures
    with SQLiteStore(database) as store:
        assert not any(
            entry.probe_id == "systemsense.followup"
            and entry.parameters.get("trigger_execution_id") == admission_trigger
            and entry.parameters.get("reason_code") == "case_stopped_during_model_turn"
            for entry in store.audit_entries(case_id=case_ids[0])
        )


def test_outbox_ack_failure_keeps_admitted_probe_linked_and_nonreplayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_ack(self: SearchFrontierRepository, event_id: str) -> None:
        del self, event_id
        raise RuntimeError("simulated ACK failure")

    monkeypatch.setattr(SearchFrontierRepository, "ack_event", fail_ack)
    with SQLiteStore(tmp_path / "ack-failure.db") as store:
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=threading.Event(),
            collected=[],
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)
        finished = investigator.run(str(case.case_id))
        assert "devices.snapshot" in finished.completed_probe_ids
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM collection_followup_admissions AS a "
                "JOIN collection_followup_execution_links AS l ON l.admission_id=a.admission_id "
                "WHERE a.case_id=?",
                (str(case.case_id),),
            ).fetchone()[0]
            == 1
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
                "AND probe_id='devices.snapshot'",
                (str(case.case_id),),
            ).fetchone()[0]
            == 1
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_event_acks AS a "
                "JOIN search_frontier_events AS e ON e.event_id=a.event_id WHERE e.case_id=?",
                (str(case.case_id),),
            ).fetchone()[0]
            == 0
        )


def test_offer_gap_lock_exhaustion_retains_pending_parent_event_without_worker_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_offer(self: BlockingTaskOfferQueue, factory: Callable[[], tuple[Task, ...]]) -> bool:
        del self, factory
        return False

    original_transaction = SQLiteStore.transaction

    def locked_gap_transaction(self: SQLiteStore) -> Any:
        if (
            threading.current_thread().name == "systemsense-followup"
            and self.busy_timeout_ms() == 200
        ):
            raise sqlite3.OperationalError("database is locked")
        return original_transaction(self)

    monkeypatch.setattr(BlockingTaskOfferQueue, "offer_factory", reject_offer)
    monkeypatch.setattr(SQLiteStore, "transaction", locked_gap_transaction)
    with SQLiteStore(tmp_path / "locked-gap.db") as store:
        release_slow = threading.Event()
        release_slow.set()
        investigator = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            slow_started=threading.Event(),
            child_finished=release_slow,
            collected=[],
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=3)
        with pytest.warns(RuntimeWarning, match="pending outbox retained"):
            investigator.run(str(case.case_id))
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_events AS e "
                "LEFT JOIN search_frontier_event_acks AS a ON a.event_id=e.event_id "
                "WHERE e.case_id=? AND a.event_id IS NULL",
                (str(case.case_id),),
            ).fetchone()[0]
            >= 1
        )


@pytest.mark.parametrize("bind_snapshot", [True, False])
def test_three_fast_parents_and_child_reenter_search_before_unrelated_slow_probe(
    tmp_path: Path,
    bind_snapshot: bool,
) -> None:
    slow_started = threading.Event()
    both_children_done = threading.Event()
    if not bind_snapshot:
        both_children_done.set()
    children: set[str] = set()
    observed: list[str] = []
    offered_parents: list[str] = []

    def collect(probe_id: str) -> Callable[[dict[str, JsonValue]], ProbeObservation]:
        def run(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            if probe_id == "gpu.telemetry.sample":
                slow_started.set()
                assert both_children_done.wait(8), "adaptive children waited for unrelated baseline"
            else:
                assert slow_started.wait(8)
            observed.append(probe_id)
            if probe_id in {"devices.snapshot", "security.snapshot", "network.snapshot"}:
                children.add(probe_id)
                if len(children) == 3:
                    both_children_done.set()
            now = datetime.now(UTC)
            return ProbeObservation(
                summary=probe_id,
                facts={"observed_probe": probe_id},
                observed_at=now,
                captured_at=now,
            )

        return run

    ids = (
        ("gpu.telemetry.sample", "power", ResourceClass.PROCESS),
        ("local_ai.snapshot", "local_ai", ResourceClass.GPU),
        ("core.system", "core", ResourceClass.CPU),
        ("storage.snapshot", "storage", ResourceClass.DISK),
        ("devices.snapshot", "devices", ResourceClass.PROCESS),
        ("security.snapshot", "security", ResourceClass.PROCESS),
        ("network.snapshot", "network", ResourceClass.NETWORK),
        ("application.snapshot", "application", ResourceClass.PROCESS),
    )
    with SQLiteStore(tmp_path / "two-parents.db") as store:
        definitions = tuple(
            _definition(probe_id, category, collect(probe_id)) for probe_id, category, _ in ids
        )
        capabilities = tuple(
            ProbeCapability(
                probe_id=probe_id,
                description=probe_id,
                cost_ms=1000,
                resource_class=resource,
            )
            for probe_id, _, resource in ids
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
        )
        investigator = Investigator(
            store=store,
            runtime=runtime,
            capabilities=capabilities,
            decision=LayaDecisionProvider(ranker=ChoosingRanker(), timeout_seconds=1.5),
            reasoning=UnavailableReasoningProvider(),
        )
        case = investigator.create(objective="Game runs at 12 FPS", budget_ms=20000, max_probes=8)
        baseline_ids = (
            "gpu.telemetry.sample",
            "local_ai.snapshot",
            "core.system",
            "storage.snapshot",
        )
        running = InvestigationRepository(store).save(
            case.model_copy(
                update={
                    "status": InvestigationStatus.RUNNING,
                    "pending_probe_ids": baseline_ids,
                    "spent_cost_ms": 4000,
                }
            ),
            expected_version=case.state_version,
            event="test_collecting",
            detail="four read-only baseline probes",
        )
        opened = OpenedCase(
            case=DiagnosticCase(
                case_id=running.case_id,
                kind=CaseKind.GENERAL,
                status=CaseStatus.COLLECTING,
                symptom=running.objective,
                created_at=running.created_at,
                time_window=CaseTimeWindow(
                    start=running.incident_start,
                    end=running.incident_end,
                    basis=CaseTimeWindowBasis.CASE_OPEN_DERIVED,
                ),
                state_version=running.state_version,
            ),
            deadline_at=running.deadline_at,
            plan=CasePlan(
                probes=tuple(
                    PlannedProbe(probe_id=probe_id, cost_ms=1000, value=1, reason="baseline")
                    for probe_id in baseline_ids
                ),
                total_cost_ms=4000,
                skipped_fresh=(),
                skipped_budget=(),
                skipped_low_value=(),
            ),
        )

        def choose(
            parent: PersistedProbeResult, worker_store: SQLiteStore
        ) -> FollowupSelection | None:
            probe_id = parent.probe_id
            offered_parents.append(probe_id)
            selected = {
                "core.system": "devices.snapshot",
                "local_ai.snapshot": "security.snapshot",
                "storage.snapshot": "network.snapshot",
                "devices.snapshot": "application.snapshot",
            }.get(probe_id)
            if selected is None:
                return None
            if not bind_snapshot:
                return FollowupSelection(probe_id=selected)
            worker = Investigator(
                store=worker_store,
                runtime=runtime,
                capabilities=capabilities,
                decision=investigator.decision,
                reasoning=investigator.reasoning,
            )
            with worker_store.read_snapshot():
                context = worker.context(str(case.case_id))
                request = DecisionRequest(
                    schema_version=3,
                    case_id=case.case_id,
                    state_version=parent.epoch_state_version,
                    correlation_id=f"test:{parent.execution_id}",
                    deadline_at=running.deadline_at,
                    symptom=running.objective,
                    evidence_ids=tuple(item.evidence_id for item in context),
                    evidence_context=context,
                    available_probes=capabilities[4:],
                    budget_ms=1000,
                    max_probes=1,
                )
                visible = {
                    str(item.evidence_id) for item in context if item.case_scope == "current_case"
                }
                packet_ids = tuple(
                    dict.fromkeys(
                        item["evidence_id"]
                        for item in LayaDecisionProvider.evidence_fragments_for_laya(request)
                        if item["evidence_id"] in visible
                    )
                )
                read_set = capture_presented_read_set(
                    worker_store,
                    case.case_id,
                    tuple(EvidenceId(root=item) for item in packet_ids),
                )
                frozen_at = datetime.now(UTC)
            snapshot = DecisionSnapshotRepository(worker_store).capture(
                request,
                request_frozen_at=frozen_at,
                probe_manifest_refs=tuple(
                    ProbeManifestRef.from_manifest(
                        capability.probe_id,
                        runtime.probe_manifest(capability.probe_id),
                    )
                    for capability in capabilities[4:]
                ),
            )
            return FollowupSelection(
                probe_id=selected,
                decision_snapshot_id=snapshot.snapshot_id,
                presented_read_set=read_set,
            )

        runtime.execute_plan(
            opened,
            followup_capabilities=capabilities[4:],
            async_offer_followup=choose,
        )
        admissions = store.connection.execute(
            "SELECT trigger_execution_id,invocation_json FROM collection_followup_admissions "
            "WHERE case_id=? ORDER BY admitted_at",
            (str(case.case_id),),
        ).fetchall()
        if not bind_snapshot:
            assert not admissions
            assert children == set()
            assert "application.snapshot" not in observed
            assert any(
                entry.probe_id == "systemsense.followup"
                and entry.parameters.get("reason_code") == "missing_snapshot_or_read_set"
                for entry in store.audit_entries(case_id=str(case.case_id))
            )
            return
        assert len(admissions) == 4, (observed, offered_parents)
        assert {str(row[0]) for row in admissions} == {
            str(row[0])
            for row in store.connection.execute(
                "SELECT execution_id FROM probe_executions WHERE case_id=? "
                "AND probe_id IN ('core.system','local_ai.snapshot','storage.snapshot',"
                "'devices.snapshot')",
                (str(case.case_id),),
            )
        }
        assert children == {"devices.snapshot", "security.snapshot", "network.snapshot"}
        assert "application.snapshot" in observed
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_events WHERE case_id=?",
                (str(case.case_id),),
            ).fetchone()[0]
            == 8
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_event_acks AS a "
                "JOIN search_frontier_events AS e ON e.event_id=a.event_id WHERE e.case_id=?",
                (str(case.case_id),),
            ).fetchone()[0]
            == 4
        )
        assert observed.index("gpu.telemetry.sample") > max(
            observed.index("devices.snapshot"),
            observed.index("security.snapshot"),
            observed.index("network.snapshot"),
        )


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
        external_offers: BlockingTaskOfferQueue | None = None,
        on_offer_error: Callable[[Exception], None] | None = None,
    ) -> tuple[TaskResult, ...]:
        def admit_then_crash(offered: tuple[Task, ...]) -> bool | None:
            assert on_admitted is not None
            accepted = on_admitted(offered)
            if accepted is not False:
                raise SystemExit("simulated application stop after durable admission")
            return accepted

        return super().run_blocking(
            tasks,
            case_deadline_at=case_deadline_at,
            cancel_event=cancel_event,
            state_version=state_version,
            on_result=on_result,
            offer_after_result=offer_after_result,
            on_admitted=admit_then_crash,
            external_offers=external_offers,
            on_offer_error=on_offer_error,
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

        with pytest.raises(SystemExit, match="simulated application stop"):
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
