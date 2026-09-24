"""The benchmark event projection comes from durable coordinator writes."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock
from time import sleep
from typing import cast

import pytest

from benchmarks.oracle_evidence_binding import CoordinatorEventLogV1
from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    ProbeCapability,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.evaluation.models import (
    EpisodeSpec,
    EvaluationMode,
    MeasurementSource,
    ProviderMeasurement,
)
from systemsense.evaluation.recorder import EpisodeRecorder
from systemsense.evaluation.trace import verify_episode_trace
from systemsense.evaluation.tracking import TrackedDecisionProvider, TrackedReasoningProvider
from systemsense.orchestration.executor import CancellationSignal
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeObservation, ProbeRun, ProbeRunner
from systemsense.orchestration.scheduler import HostWorkSlot
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.runtime_trace import export_coordinator_event_log
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_evaluation_recorder import (
    _definition,  # pyright: ignore[reportPrivateUsage]
    _investigator,  # pyright: ignore[reportPrivateUsage]
)


def _spec() -> EpisodeSpec:
    return EpisodeSpec(
        scenario_id="synthetic.trace",
        objective="Investigate synthetic memory pressure.",
        measurement_source=MeasurementSource.SIMULATION,
        synthetic=True,
        mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
        budget_ms=2000,
        max_rounds=2,
        max_probes=1,
    )


@pytest.mark.parametrize("fails", [False, True])
def test_reopened_case_exports_actual_probe_provider_evidence_and_terminal_events(
    tmp_path: Path, fails: bool
) -> None:
    database = tmp_path / "trace.db"
    with SQLiteStore(database) as store:
        investigator, decision, reasoning = _investigator(store, fails=fails)
        artifact = EpisodeRecorder().record(
            investigator=investigator,
            decision=decision,
            reasoning=reasoning,
            spec=_spec(),
        )
    with SQLiteStore(database) as reopened:
        verify_episode_trace(reopened, artifact)
        with pytest.raises(ValueError, match="coordinator trace does not match episode"):
            verify_episode_trace(
                reopened,
                artifact.model_copy(update={"evidence_count": artifact.evidence_count + 1}),
            )
        linked = reopened.connection.execute(
            "SELECT kind, source_record_id FROM coordinator_events WHERE case_id = ? "
            "ORDER BY sequence",
            (str(artifact.case_id),),
        ).fetchall()
        for kind, source_record_id in linked:
            if kind == "probe":
                assert reopened.probe_execution(str(source_record_id)) is not None
            elif kind in {"evidence", "coverage"}:
                assert (
                    reopened.evidence(
                        case_id=str(artifact.case_id), evidence_id=str(source_record_id)
                    )
                    is not None
                )
        exported = CoordinatorEventLogV1.model_validate(
            export_coordinator_event_log(reopened, str(artifact.case_id))
        )
        events = exported.events
        assert exported.case_id == str(artifact.case_id)
        assert [event.kind for event in events].count("probe") == 1
        assert [event.kind for event in events].count("evidence") == artifact.evidence_count
        assert [event.kind for event in events].count("coverage") == artifact.coverage_count
        assert [event.kind for event in events].count("provider") == (
            artifact.decision.calls + artifact.reasoning.calls
        )
        assert events[-1].kind == "terminal"
        assert events[-1].status == artifact.terminal_status
        assert events[-1].outcome == artifact.terminal_outcome
        assert [event.observed_at for event in events] == sorted(
            event.observed_at for event in events
        )
        state = InvestigationRepository(reopened).load(str(artifact.case_id))
        InvestigationRepository(reopened).save(
            state,
            expected_version=state.state_version,
            event="post_terminal_note",
            detail="No new coordinator work occurred.",
        )
        continued = export_coordinator_event_log(reopened, str(artifact.case_id))
        continued_events = cast(list[dict[str, object]], continued["events"])
        assert sum(event["kind"] == "terminal" for event in continued_events) == 1
        with pytest.raises(Exception, match="immutable"):
            reopened.connection.execute(
                "DELETE FROM coordinator_events WHERE case_id = ?", (str(artifact.case_id),)
            )
        reopened.connection.execute("DELETE FROM cases WHERE case_id = ?", (str(artifact.case_id),))
        assert (
            reopened.connection.execute(
                "SELECT COUNT(*) FROM coordinator_events WHERE case_id = ?",
                (str(artifact.case_id),),
            ).fetchone()[0]
            == 0
        )


def test_failed_decision_attempt_and_effective_fallback_survive_reopen(tmp_path: Path) -> None:
    class FailingDecision:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-failing-decision", provider_version="1", role="fast_decision"
            )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            raise RuntimeError("fixture provider unavailable")

    database = tmp_path / "fallback.db"
    with SQLiteStore(database) as store:
        investigator, _, reasoning = _investigator(store)
        decision = TrackedDecisionProvider(FailingDecision())
        investigator.decision = decision
        artifact = EpisodeRecorder().record(
            investigator=investigator, decision=decision, reasoning=reasoning, spec=_spec()
        )
    with SQLiteStore(database) as reopened:
        verify_episode_trace(reopened, artifact)
        events = CoordinatorEventLogV1.model_validate(
            export_coordinator_event_log(reopened, str(artifact.case_id))
        ).events
        calls = [event for event in events if event.kind == "provider"]
        decision_calls = [event for event in calls if event.role == "decision"]
        assert len(decision_calls) == artifact.decision.calls == 1
        assert decision_calls[0].attempted_provider_id == "fixture-failing-decision"
        assert decision_calls[0].effective_provider_id == "keyword-baseline"
        assert decision_calls[0].failed
        assert artifact.decision.failures == 1
        assert artifact.decision.effective_provider_id == "keyword-baseline"


def test_failed_probe_persistence_rolls_back_trace_and_execution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "rollback.db") as store:
        investigator, _, _ = _investigator(store)
        case_id = str(
            investigator.create(objective="Investigate synthetic memory pressure.").case_id
        )
        stamp = datetime.now(UTC).isoformat()
        with pytest.raises(RuntimeError, match="injected persistence failure"):
            with store.transaction() as transaction:
                transaction.record_probe_execution(
                    execution_id="exec_0123456789abcdef0123456789abcdef",
                    case_id=case_id,
                    probe_id="core.resources",
                    probe_version=1,
                    status="ok",
                    parameters_json="{}",
                    started_at=stamp,
                    finished_at=stamp,
                    state_version=0,
                )
                raise RuntimeError("injected persistence failure")
        assert store.probe_execution_count(case_id=case_id) == 0
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM coordinator_events WHERE case_id = ?", (case_id,)
            ).fetchone()[0]
            == 0
        )


def test_raw_evidence_retention_closes_trace_export_window(tmp_path: Path) -> None:
    database = tmp_path / "retention.db"
    with SQLiteStore(database) as store:
        investigator, decision, reasoning = _investigator(store)
        artifact = EpisodeRecorder().record(
            investigator=investigator, decision=decision, reasoning=reasoning, spec=_spec()
        )
        assert artifact.evidence_count > 0
        assert store.delete_oldest_raw_evidence(limit=1) == 1
    with SQLiteStore(database) as reopened:
        assert (
            reopened.connection.execute(
                "SELECT COUNT(*) FROM coordinator_events WHERE case_id = ?",
                (str(artifact.case_id),),
            ).fetchone()[0]
            > 0
        )
        with pytest.raises(ValueError, match="coordinator evidence event lost source binding"):
            export_coordinator_event_log(reopened, str(artifact.case_id))


def test_recorder_rejects_process_counter_that_disagrees_with_durable_calls(tmp_path: Path) -> None:
    class InflatedDecision(TrackedDecisionProvider):
        def __init__(self) -> None:
            super().__init__(KeywordBaselineDecisionProvider())
            self.reads = 0

        def measurement(self) -> ProviderMeasurement:
            self.reads += 1
            actual = super().measurement()
            if self.reads == 1:
                return actual
            return actual.model_copy(update={"calls": actual.calls + 1})

    with SQLiteStore(tmp_path / "counter-drift.db") as store:
        investigator, _, reasoning = _investigator(store)
        decision = InflatedDecision()
        investigator.decision = decision
        with pytest.raises(
            ValueError, match="provider telemetry disagrees with coordinator journal"
        ):
            EpisodeRecorder().record(
                investigator=investigator, decision=decision, reasoning=reasoning, spec=_spec()
            )


def test_recovered_case_never_emits_a_second_terminal_or_a_misleading_export(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "recovered.db") as store:
        investigator, _, _ = _investigator(store)
        created = investigator.create(objective="Investigate synthetic memory pressure.")
        repo = InvestigationRepository(store)
        interrupted = repo.save(
            created.model_copy(
                update={
                    "status": InvestigationStatus.INTERRUPTED,
                    "outcome": InvestigationOutcome.INTERRUPTED,
                }
            ),
            expected_version=created.state_version,
            event="interrupted",
            detail="Recovery marked the case interrupted.",
        )
        resumed = repo.save(
            interrupted.model_copy(
                update={
                    "status": InvestigationStatus.RUNNING,
                    "outcome": InvestigationOutcome.INVESTIGATING,
                }
            ),
            expected_version=interrupted.state_version,
            event="resumed",
            detail="The case resumed.",
        )
        repo.save(
            resumed.model_copy(
                update={
                    "status": InvestigationStatus.COMPLETE,
                    "outcome": InvestigationOutcome.BUDGET_EXHAUSTED,
                }
            ),
            expected_version=resumed.state_version,
            event="stopped",
            detail="The case stopped.",
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM coordinator_events WHERE case_id = ? AND kind = 'terminal'",
                (str(created.case_id),),
            ).fetchone()[0]
            == 1
        )
        with pytest.raises(ValueError, match="terminal differs"):
            export_coordinator_event_log(store, str(created.case_id))


def test_trace_writer_rejects_fields_that_override_journal_identity(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "forged.db") as store:
        investigator, _, _ = _investigator(store)
        case_id = str(investigator.create(objective="Investigate memory pressure.").case_id)
        with pytest.raises(ValueError, match="fields"):
            with store.transaction() as transaction:
                transaction.append_coordinator_event(
                    case_id=case_id,
                    kind="provider",
                    fields={"event_id": "forged"},
                )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM coordinator_events WHERE case_id = ?", (case_id,)
            ).fetchone()[0]
            == 0
        )


def test_coordinator_rejected_provider_counts_as_failed_after_reopen(tmp_path: Path) -> None:
    class WrongIdentityDecision:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-decision", provider_version="1", role="fast_decision"
            )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            response = KeywordBaselineDecisionProvider().decide(request)
            return response.model_copy(
                update={
                    "provider": ProviderIdentity(
                        provider_id="untrusted-response",
                        provider_version="1",
                        role="fast_decision",
                    )
                }
            )

    database = tmp_path / "rejected.db"
    with SQLiteStore(database) as store:
        investigator, _, reasoning = _investigator(store)
        decision = TrackedDecisionProvider(WrongIdentityDecision())
        investigator.decision = decision
        artifact = EpisodeRecorder().record(
            investigator=investigator, decision=decision, reasoning=reasoning, spec=_spec()
        )
    with SQLiteStore(database) as reopened:
        verify_episode_trace(reopened, artifact)
        assert artifact.decision.calls == 1
        assert artifact.decision.failures == 1
        assert artifact.decision.effective_provider_id == "keyword-baseline"
        provider = next(
            event
            for event in CoordinatorEventLogV1.model_validate(
                export_coordinator_event_log(reopened, str(artifact.case_id))
            ).events
            if event.kind == "provider" and event.role == "decision"
        )
        assert provider.failed is True
        assert provider.attempted_provider_id == "fixture-decision"


def test_parallel_probe_start_order_survives_reversed_completion(tmp_path: Path) -> None:
    first_started = Event()
    second_started = Event()
    clock_lock = Lock()
    last_timestamp = datetime.min.replace(tzinfo=UTC)

    def distinct_now() -> datetime:
        nonlocal last_timestamp
        with clock_lock:
            last_timestamp = max(datetime.now(UTC), last_timestamp + timedelta(microseconds=1))
            return last_timestamp

    def observation(name: str) -> ProbeObservation:
        now = datetime.now(UTC)
        return ProbeObservation(
            summary=f"Synthetic {name} observation.",
            facts={name: "observed"},
            observed_at=now,
            captured_at=now,
        )

    def collect_resources(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        first_started.set()
        assert second_started.wait(timeout=1)
        sleep(0.05)
        return observation("resources")

    def collect_system(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        second_started.set()
        return observation("system")

    class OrderedProbeRunner(ProbeRunner):
        def run(
            self,
            probe_id: str,
            parameters: dict[str, JsonValue],
            *,
            deadline_at: UtcDateTime | None = None,
            cancellation: CancellationSignal | None = None,
            host_slot: HostWorkSlot | None = None,
        ) -> ProbeRun:
            assert host_slot is not None
            if probe_id == "core.system":
                assert first_started.wait(timeout=1)
            return super().run(
                probe_id,
                parameters,
                deadline_at=deadline_at,
                cancellation=cancellation,
                host_slot=host_slot,
            )

    original = _definition()
    resources = replace(original, handler=collect_resources)
    system = replace(
        original,
        manifest=original.manifest.model_copy(
            update={
                "probe_id": "core.system",
                "implementation_id": "builtin.core.system",
                "category": "core",
            }
        ),
        handler=collect_system,
    )
    database = tmp_path / "parallel.db"
    with SQLiteStore(database) as store:
        planner = DeterministicPlanner(
            candidates=(
                ProbeCandidate(probe_id="core.resources", cost_ms=10, value=1, common=True),
                ProbeCandidate(probe_id="core.system", cost_ms=10, value=1, common=True),
            )
        )
        decision = TrackedDecisionProvider(KeywordBaselineDecisionProvider())
        reasoning = TrackedReasoningProvider(DeterministicReasoningProvider())
        investigator = Investigator(
            store=store,
            runtime=DiagnosticRuntime(
                store=store,
                case_service=CaseService(store, planner),
                probe_runner=OrderedProbeRunner(definitions=(resources, system), now=distinct_now),
            ),
            capabilities=tuple(
                ProbeCapability(
                    probe_id=probe_id,
                    description="synthetic parallel observation",
                    common=True,
                    cost_ms=10,
                    resource_class=ResourceClass.CPU,
                )
                for probe_id in ("core.resources", "core.system")
            ),
            decision=decision,
            reasoning=reasoning,
        )
        artifact = EpisodeRecorder().record(
            investigator=investigator,
            decision=decision,
            reasoning=reasoning,
            spec=_spec().model_copy(update={"max_probes": 2}),
        )
        rows = store.connection.execute(
            "SELECT probe_id FROM probe_executions WHERE case_id = ? "
            "ORDER BY started_at, execution_id",
            (str(artifact.case_id),),
        ).fetchall()
        started_probe_ids = tuple(str(row[0]) for row in rows)
    with SQLiteStore(database) as reopened:
        events = CoordinatorEventLogV1.model_validate(
            export_coordinator_event_log(reopened, str(artifact.case_id))
        ).events
        persisted_probe_ids = tuple(event.probe_id for event in events if event.kind == "probe")
        assert started_probe_ids != persisted_probe_ids
        assert artifact.attempted_probe_ids == started_probe_ids
