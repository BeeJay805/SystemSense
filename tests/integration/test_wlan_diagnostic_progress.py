"""Live coordinator admission for one scoped WLAN state question."""

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, cast

import pytest

from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProbeCapability
from systemsense.domain.ids import JsonValue
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import default_probe_definitions
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository
from systemsense.storage.diagnostic_progress import DiagnosticProgressRepository
from systemsense.storage.sqlite_store import SQLiteStore

GUID = "00000000-0000-0000-0000-000000000001"


class CapturingDecision(KeywordBaselineDecisionProvider):
    def __init__(self) -> None:
        self.seen: list[DecisionRequest] = []

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        self.seen.append(request)
        return super().decide(request)


class CapturingReasoning(UnavailableReasoningProvider):
    def __init__(self) -> None:
        self.seen: list[ReasoningRequest] = []

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        self.seen.append(request)
        return super().investigate(request)


def _app(
    store: SQLiteStore,
    states: tuple[str, ...],
    *,
    omitted: int = 0,
    extra_interface: bool = False,
    cancel_on_baseline: Event | None = None,
    decision: CapturingDecision | None = None,
    reasoning: CapturingReasoning | None = None,
) -> Investigator:
    calls = iter(states)
    base = next(
        item
        for item in default_probe_definitions()
        if item.manifest.probe_id == "network.connectivity"
    )

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = datetime.now(UTC)
        state = next(calls)
        if cancel_on_baseline is not None:
            cancel_on_baseline.set()
        wifi_interfaces: list[JsonValue] = [
            {
                "interface_guid": GUID,
                "description": "Wi-Fi",
                "association_state": state,
            }
        ]
        if extra_interface:
            wifi_interfaces.append(
                {
                    "interface_guid": "00000000-0000-0000-0000-000000000002",
                    "description": "Wi-Fi 2",
                    "association_state": state,
                }
            )
        snapshot: dict[str, JsonValue] = {
            "source_id": "src_" + "a" * 64,
            "captured_at": now.isoformat(),
            "wifi_observed_at": now.isoformat(),
            "wifi_status": "available",
            "wifi_interfaces": wifi_interfaces,
            "omitted_wifi_count": omitted,
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
        return ProbeObservation(
            summary="WLAN state",
            facts={"connectivity_detail": snapshot},
            observed_at=now,
            captured_at=now,
        )

    definition = replace(base, handler=collect, isolated=False)
    planner = DeterministicPlanner(
        candidates=(ProbeCandidate(probe_id="network.connectivity", cost_ms=1, value=1),)
    )
    return Investigator(
        store=store,
        runtime=DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(definitions=(definition,)),
        ),
        capabilities=(
            ProbeCapability(
                probe_id="network.connectivity",
                description="Observe WLAN state",
                common=True,
                cost_ms=1,
                resource_class=ResourceClass.CPU,
            ),
        ),
        decision=decision or CapturingDecision(),
        reasoning=reasoning or CapturingReasoning(),
    )


@pytest.mark.parametrize("answer,expected", [("connected", True), ("disconnected", False)])
def test_transitional_baseline_dispatches_one_cited_question(
    tmp_path: Path, answer: str, expected: bool
) -> None:
    with SQLiteStore(tmp_path / "question.db") as store:
        decision = CapturingDecision()
        reasoning = CapturingReasoning()
        app = _app(store, ("authenticating", answer), decision=decision, reasoning=reasoning)
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=3)

        final = app.run(str(initial.case_id))

        assert store.probe_execution_count(case_id=str(initial.case_id)) == 2
        assert final.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
        progress = DiagnosticProgressRepository(store).for_case(initial.case_id)
        assert len(progress) == 1
        assert progress[0].terminal_status == "evaluated"
        assert progress[0].event.evaluation is not None
        assert progress[0].event.evaluation.observed is expected
        assert decision.seen
        assert reasoning.seen
        assert any(
            request.diagnostic_progress
            and request.diagnostic_progress[0].observed is expected
            and request.diagnostic_progress[0].evidence_ids
            for request in decision.seen
        )
        assert any(
            request.diagnostic_progress
            and request.diagnostic_progress[0].observed is expected
            and request.diagnostic_progress[0].evidence_ids
            for request in reasoning.seen
        )


@pytest.mark.parametrize(
    "state,omitted,extra_interface",
    [("connected", 0, False), ("associating", 1, False), ("associating", 0, True)],
)
def test_definitive_or_incomplete_baseline_does_not_repeat(
    tmp_path: Path, state: str, omitted: int, extra_interface: bool
) -> None:
    with SQLiteStore(tmp_path / "decline.db") as store:
        app = _app(store, (state,), omitted=omitted, extra_interface=extra_interface)
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=2)

        app.run(str(initial.case_id))

        assert store.probe_execution_count(case_id=str(initial.case_id)) == 1
        assert DiagnosticProgressRepository(store).for_case(initial.case_id) == ()


def test_exhausted_attempt_cap_declines_second_collection(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "exhausted.db") as store:
        app = _app(store, ("associating",))
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=1)

        app.run(str(initial.case_id))

        assert store.probe_execution_count(case_id=str(initial.case_id)) == 1
        assert DiagnosticProgressRepository(store).for_case(initial.case_id) == ()


def test_cancellation_after_baseline_declines_second_collection(tmp_path: Path) -> None:
    cancellation = Event()
    with SQLiteStore(tmp_path / "cancelled.db") as store:
        app = _app(store, ("associating",), cancel_on_baseline=cancellation)
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=2)

        app.run(str(initial.case_id), cancel_event=cancellation)

        assert store.probe_execution_count(case_id=str(initial.case_id)) == 1
        assert DiagnosticProgressRepository(store).for_case(initial.case_id) == ()


def test_claimed_question_recovers_once_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "claim-crash.db") as store:
        app = _app(store, ("associating",))
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=3)
        original = app.runtime.execute_plan

        def crash_after_claim(*args: Any, **kwargs: Any) -> Any:
            mapping = kwargs.get("diagnostic_admissions_by_instance")
            if mapping is None:
                return original(*args, **kwargs)
            admission_id = next(iter(cast(dict[str, str], mapping).values()))
            with store.transaction():
                DiagnosticIntentRepository(store).claim_dispatch(admission_id)
            raise RuntimeError("simulated owner crash after claim")

        monkeypatch.setattr(app.runtime, "execute_plan", crash_after_claim)
        with pytest.raises(RuntimeError, match="simulated owner crash"):
            app.run(str(initial.case_id))
        assert store.probe_execution_count(case_id=str(initial.case_id)) == 1
        monkeypatch.setattr(app.runtime, "execute_plan", original)
        stranded = app.repository.load(str(initial.case_id))
        queued = app.repository.save(
            stranded.model_copy(update={"status": InvestigationStatus.QUEUED}),
            expected_version=stranded.state_version,
            event="simulated_owner_recovery",
            detail="Recover consumed claim",
        )

        final = app.run(str(initial.case_id))

        assert final.unrecorded_attempt_count == 0
        assert store.probe_execution_count(case_id=str(initial.case_id)) == 1
        assert len(DiagnosticProgressRepository(store).for_case(initial.case_id)) == 1
        assert final.state_version > queued.state_version


def test_transitional_followup_is_cited_unknown_for_both_brains(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "unknown.db") as store:
        decision = CapturingDecision()
        reasoning = CapturingReasoning()
        app = _app(
            store,
            ("authenticating", "associating"),
            decision=decision,
            reasoning=reasoning,
        )
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=3)

        final = app.run(str(initial.case_id))

        projection = DiagnosticProgressRepository(store).for_case(initial.case_id)[0]
        assert projection.terminal_status == "unknown"
        assert projection.event.evidence_ids
        assert not projection.event.diagnostic_progress
        assert final.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
        for requests in (decision.seen, reasoning.seen):
            assert any(
                request.diagnostic_progress
                and request.diagnostic_progress[0].terminal_status == "unknown"
                and request.diagnostic_progress[0].observed is None
                and request.diagnostic_progress[0].evidence_ids == projection.event.evidence_ids
                and request.diagnostic_progress[0].dead_end
                for request in requests
            )


def test_linked_terminal_recovers_projection_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "linked-crash.db") as store:
        app = _app(store, ("authenticating", "connected"))
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=3)
        original = app.runtime.execute_plan

        def crash_after_terminal(*args: Any, **kwargs: Any) -> Any:
            result = original(*args, **kwargs)
            if kwargs.get("diagnostic_admissions_by_instance") is not None:
                raise RuntimeError("simulated crash before projection")
            return result

        monkeypatch.setattr(app.runtime, "execute_plan", crash_after_terminal)
        with pytest.raises(RuntimeError, match="simulated crash before projection"):
            app.run(str(initial.case_id))
        assert store.probe_execution_count(case_id=str(initial.case_id)) == 2
        assert (
            store.connection.execute("SELECT COUNT(*) FROM diagnostic_progress").fetchone()[0] == 0
        )
        monkeypatch.setattr(app.runtime, "execute_plan", original)
        stranded = app.repository.load(str(initial.case_id))
        app.repository.save(
            stranded.model_copy(update={"status": InvestigationStatus.QUEUED}),
            expected_version=stranded.state_version,
            event="simulated_owner_recovery",
            detail="Recover linked terminal",
        )

        app.run(str(initial.case_id))

        assert store.probe_execution_count(case_id=str(initial.case_id)) == 2
        projection = DiagnosticProgressRepository(store).for_case(initial.case_id)
        assert len(projection) == 1
        assert projection[0].terminal_status == "evaluated"


def test_lost_source_custody_before_branch_stop_never_reuses_boolean(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "lost-source.db") as store:

        class LosingSourceReasoning(CapturingReasoning):
            def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
                if request.diagnostic_progress and request.diagnostic_progress[0].observed is True:
                    row = store.connection.execute(
                        "SELECT json_extract(record_json, '$.source_evidence_id') "
                        "FROM diagnostic_intent_admissions WHERE case_id=?",
                        (str(request.case_id),),
                    ).fetchone()
                    assert row is not None
                    with store.transaction():
                        store.connection.execute(
                            "UPDATE evidence SET record_json='{}' WHERE evidence_id=?",
                            (str(row[0]),),
                        )
                return super().investigate(request)

        reasoning = LosingSourceReasoning()
        app = _app(store, ("authenticating", "connected"), reasoning=reasoning)
        initial = app.create(objective="Wi-Fi connection drops", budget_ms=5_000, max_probes=3)

        final = app.run(str(initial.case_id))

        assert store.probe_execution_count(case_id=str(initial.case_id)) == 2
        assert reasoning.seen and reasoning.seen[0].diagnostic_progress[0].observed is True
        with pytest.raises(ValueError):
            DiagnosticProgressRepository(store).for_case(initial.case_id)
        assert final.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
        assert "association question is answered" not in (final.stop_reason or "")
