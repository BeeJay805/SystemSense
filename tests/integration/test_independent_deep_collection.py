"""Bounded deep work overlaps the real coordinator's durable collection path."""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from systemsense.decision.contracts import (
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.decision.frontier_ranker import MixedFrontierRanker
from systemsense.domain.ids import JsonValue
from systemsense.orchestration.probes import ProbeObservation
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition


def _proposal(probe_id: str) -> ProbeProposal:
    return ProbeProposal(
        probe_id=probe_id,
        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
        priority=1,
        estimated_cost_ms=1,
        resource_class=ResourceClass.CPU,
        dedupe_key=probe_id,
    )


def test_oversized_deep_admission_does_not_block_selected_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "deep-admission-limit.db") as store:
        app = investigator(store)
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=5000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )

        def reject_oversized(_task: object) -> bool:
            raise ValueError("deep mailbox request exceeds byte bound")

        monkeypatch.setattr(app._deep_mailbox, "admit", reject_oversized)  # pyright: ignore[reportPrivateUsage]
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state,
            app.context(str(state.case_id), state=state),
            concurrent_proposals=(_proposal("network.snapshot"),),
        )
        assert "network.snapshot" in updated.completed_probe_ids
        assert any("Deep request could not be admitted" in item for item in updated.warnings)
        assert not app._deep_lane.occupied  # pyright: ignore[reportPrivateUsage]


def test_adaptive_deep_clears_an_exact_considered_evidence_request(tmp_path: Path) -> None:
    class ConsideringDeep:
        identity = ProviderIdentity(
            provider_id="considering-deep", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            considered = tuple(item.evidence_id for item in request.evidence_context if item.facts)[
                :1
            ]
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The requested observation was considered; cause remains uncertain.",
                considered_evidence_ids=considered,
            )

    with SQLiteStore(tmp_path / "deep-request-lifecycle.db") as store:
        app = investigator(store, reasoning=ConsideringDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=5000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        context = app.context(str(state.case_id), state=state)
        requested = next(item.evidence_id for item in context if item.facts)
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"requested_evidence_ids": (requested,)}),
            "request_test",
            "An exact current-case observation was requested.",
        )

        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state,
            context,
            concurrent_proposals=(_proposal("network.snapshot"),),
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        updated = app._drain_deep(updated)  # pyright: ignore[reportPrivateUsage]
        assert updated.reasoning_provider == "considering-deep"
        assert requested not in updated.requested_evidence_ids
        assert requested in updated.completed_evidence_requests


def test_adaptive_deep_advances_only_its_frozen_catalog_page(tmp_path: Path) -> None:
    class PagingDeep:
        identity = ProviderIdentity(
            provider_id="paging-deep", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            assert request.catalog_has_more
            assert len(request.evidence_catalog) == 1
            return ReasoningResponse(
                schema_version=3,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Next catalog page is needed.",
                request_next_catalog_page=True,
            )

    with SQLiteStore(tmp_path / "deep-catalog-page.db") as store:
        app = investigator(store, reasoning=PagingDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=5000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"), _proposal("network.snapshot")), None, baseline=True
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"evidence_catalog_limit": 1}),
            "catalog_test",
            "Constrain the frozen catalog page to one entry.",
        )
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        updated = app._drain_deep(updated)  # pyright: ignore[reportPrivateUsage]
        assert updated.evidence_catalog_cursor is not None, updated.warnings
        assert updated.evidence_catalog_followup_pending


@pytest.mark.parametrize("degraded", [False, True])
def test_persisted_collection_unblocks_deep_without_promoting_old_hypothesis(
    tmp_path: Path,
    degraded: bool,
) -> None:
    database = tmp_path / "independent.db"
    started = threading.Event()
    collection_overlapped = threading.Event()
    base = probe_definition("network")

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert started.wait(1), "deep inference must start before selected collection"
        collection_overlapped.set()
        assert base.handler is not None
        return base.handler(parameters)

    class DelayedDeep:
        identity = ProviderIdentity(provider_id="delayed", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            started.set()
            deadline = time.monotonic() + 2
            persisted = False
            with SQLiteStore(database) as reader:
                while time.monotonic() < deadline:
                    row = reader.connection.execute(
                        "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id=?",
                        (str(request.case_id), "network.snapshot"),
                    ).fetchone()
                    if row and int(row[0]) > 0:
                        persisted = True
                        break
                    time.sleep(0.005)
            assert persisted, "deep inference blocked unrelated evidence persistence"
            return ReasoningResponse(
                schema_version=3,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.SUPPORTED,
                summary="An old proposed explanation.",
                degraded=degraded,
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="old",
                        statement="Old snapshot suggests a device issue.",
                        status=HypothesisStatus.SUPPORTED,
                        supporting_evidence_ids=(request.evidence_context[0].evidence_id,),
                    ),
                ),
                distinguishing_probes=(_proposal("devices.snapshot"),),
            )

    with SQLiteStore(database) as store:
        app = investigator(
            store,
            reasoning=DelayedDeep(),
            definitions=(
                probe_definition("core"),
                replace(base, handler=collect),
                probe_definition("devices"),
            ),
        )
        state = app.create(objective="application device issue", budget_ms=4000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        context = app.context(str(state.case_id), state=state)
        updated, proposals = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, context, concurrent_proposals=(_proposal("network.snapshot"),)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        updated = app._drain_deep(updated)  # pyright: ignore[reportPrivateUsage]
        proposals = updated.pending_distinguishing_probes
        assert collection_overlapped.is_set()
        assert "network.snapshot" in updated.completed_probe_ids
        assert all(h.status is HypothesisStatus.UNRESOLVED for h in updated.hypotheses)
        assert updated.assessment is None, "model assertions cannot become verified findings"
        assert tuple(item.probe_id for item in proposals) == (
            () if degraded else ("devices.snapshot",)
        )
        if not degraded:
            assert any("historical" in warning.lower() for warning in updated.warnings)


def test_adaptive_run_starts_deep_before_selected_collection(tmp_path: Path) -> None:
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    started = threading.Event()
    overlapped = threading.Event()
    base = probe_definition("network")

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        if started.wait(0.3):
            overlapped.set()
        assert base.handler is not None
        return base.handler(parameters)

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            started.set()
            overlapped.wait(0.4)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Insufficient evidence.",
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=()
                if "network.snapshot" in request.completed_probe_ids
                else (_proposal("network.snapshot"),),
            )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "run.db") as store:
        app = investigator(
            store,
            definitions=(core, replace(base, handler=collect)),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        case = app.create(objective="network issue", budget_ms=3000)
        result = app.run(str(case.case_id))
        assert overlapped.is_set(), "default adaptive run still waited for collection before deep"
        assert "network.snapshot" in result.completed_probe_ids


def test_fast_followup_completes_while_deep_waits_for_it(tmp_path: Path) -> None:
    from systemsense.application.investigation_state import InvestigationStatus
    from systemsense.decision.laya import LayaDecisionProvider
    from tests.integration.test_investigator_dynamic_followup import (
        ChoosingRanker,
        _investigator,  # pyright: ignore[reportPrivateUsage]
    )

    child_finished = threading.Event()
    deep_saw_child = threading.Event()

    class WaitingDeep:
        identity = ProviderIdentity(provider_id="waiting", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            assert child_finished.wait(2), "fast follow-up was blocked by deep inference"
            deep_saw_child.set()
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="No supported explanation.",
            )

    with SQLiteStore(tmp_path / "followup.db") as store:
        collected: list[str] = []
        app = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker()),
            slow_started=threading.Event(),
            child_finished=child_finished,
            collected=collected,
        )
        app.reasoning = WaitingDeep()
        state = app.create(objective="Game runs at 12 FPS", budget_ms=8000, max_probes=3)
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "started",
            "Started controlled collection overlap.",
        )
        proposals = tuple(
            ProbeProposal(
                probe_id=capability.probe_id,
                purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
                priority=1,
                estimated_cost_ms=capability.cost_ms,
                resource_class=capability.resource_class,
                dedupe_key=capability.probe_id,
            )
            for capability in app.capabilities
            if capability.probe_id != "devices.snapshot"
        )
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, (), concurrent_proposals=proposals
        )
        assert deep_saw_child.is_set()
        assert collected.index("devices.snapshot") < collected.index("gpu.telemetry.sample")
        assert "devices.snapshot" in updated.completed_probe_ids
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM collection_followup_admissions WHERE case_id=?",
                (str(state.case_id),),
            ).fetchone()[0]
            == 1
        )


def test_cancelled_deep_worker_does_not_allow_another_provider_call(tmp_path: Path) -> None:
    from systemsense.inference.control import inference_cancellation

    started = threading.Event()
    release = threading.Event()
    cancel = threading.Event()
    base = probe_definition("network")

    class HangingDeep:
        identity = ProviderIdentity(provider_id="hanging", provider_version="1", role="reasoning")
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            started.set()
            assert release.wait(3)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="No supported explanation.",
            )

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert started.wait(1)
        cancel.set()
        assert base.handler is not None
        return base.handler(parameters)

    provider = HangingDeep()
    with SQLiteStore(tmp_path / "cancel.db") as store:
        app = investigator(store, definitions=(replace(base, handler=collect),), reasoning=provider)
        state = app.create(objective="network issue", budget_ms=3000)
        try:
            with inference_cancellation(cancel):
                state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                    state, (), concurrent_proposals=(_proposal("network.snapshot"),)
                )
            assert provider.calls == 1
            assert app._deep_lane.occupied  # pyright: ignore[reportPrivateUsage]
            app._reason(state, ())  # pyright: ignore[reportPrivateUsage]
            assert provider.calls == 1
        finally:
            release.set()
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]


def test_deep_start_failure_preserves_selected_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_start(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("no worker capacity")

    with SQLiteStore(tmp_path / "start-failure.db") as store:
        app = investigator(store, definitions=(probe_definition("network"),))
        monkeypatch.setattr(app._deep_lane, "start", reject_start)  # pyright: ignore[reportPrivateUsage]
        state = app.create(objective="network issue", budget_ms=3000)
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, (), concurrent_proposals=(_proposal("network.snapshot"),)
        )
        assert "network.snapshot" in updated.completed_probe_ids
        assert any("unavailable" in warning.lower() for warning in updated.warnings)


def test_one_investigator_rejects_concurrent_case_owners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.application.investigation_state import InvestigationState

    started = threading.Event()
    release = threading.Event()
    with SQLiteStore(tmp_path / "ownership.db") as store:
        app = investigator(store)
        first = app.create(objective="first", budget_ms=3000)
        second = app.create(objective="second", budget_ms=3000)

        def run_case(case_id: str, *, cancel_event: threading.Event | None) -> InvestigationState:
            if case_id == str(first.case_id):
                started.set()
                assert release.wait(2)
                return first
            return second

        monkeypatch.setattr(app, "_run", run_case)
        thread = threading.Thread(target=app.run, args=(str(first.case_id),))
        thread.start()
        try:
            assert started.wait(1)
            with pytest.raises(RuntimeError, match="owns this investigator"):
                app.run(str(second.case_id))
        finally:
            release.set()
            thread.join(1)
        assert app.run(str(second.case_id)) == second


def test_slow_deep_does_not_spend_remaining_case_budget_after_collection(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()
    base = probe_definition("network")

    class SlowDeep:
        identity = ProviderIdentity(provider_id="slow", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            started.set()
            assert release.wait(2)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="No supported explanation.",
            )

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert started.wait(1)
        assert base.handler is not None
        return base.handler(parameters)

    with SQLiteStore(tmp_path / "bounded-wait.db") as store:
        app = investigator(
            store, definitions=(replace(base, handler=collect),), reasoning=SlowDeep()
        )
        state = app.create(objective="network issue", budget_ms=3000)
        try:
            before = time.monotonic()
            updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                state, (), concurrent_proposals=(_proposal("network.snapshot"),)
            )
            assert time.monotonic() - before < 0.5, "deep blocked the next fast round"
            assert "network.snapshot" in updated.completed_probe_ids
        finally:
            release.set()
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]


def test_deep_mailbox_survives_two_collections_and_merges_advisory_predictions(
    tmp_path: Path,
) -> None:
    from systemsense.inference.control import current_cancellation
    from systemsense.reasoning.contracts import ExpectedFact

    release = threading.Event()
    started = threading.Event()
    provider_saw_cancel = threading.Event()

    class StrategicDeep:
        identity = ProviderIdentity(provider_id="strategic", provider_version="1", role="reasoning")
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            started.set()
            assert release.wait(2)
            cancel = current_cancellation()
            if cancel is not None and cancel.is_set():
                provider_saw_cancel.set()
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.SUPPORTED,
                summary="Advisory device explanation.",
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="device",
                        statement="A device condition may explain the symptom.",
                        status=HypothesisStatus.SUPPORTED,
                        supporting_evidence_ids=(request.evidence_context[0].evidence_id,),
                        expected_facts=(
                            ExpectedFact(
                                probe_id="devices.snapshot", fact_name="value", expected_value=1
                            ),
                        ),
                    ),
                ),
                distinguishing_probes=(_proposal("devices.snapshot"),),
            )

    provider = StrategicDeep()
    with SQLiteStore(tmp_path / "cross-round.db") as store:
        app = investigator(
            store,
            reasoning=provider,
            definitions=tuple(
                probe_definition(name) for name in ("core", "network", "storage", "devices")
            ),
        )
        state = app.create(objective="application issue", budget_ms=4000)
        state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        try:
            state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                state,
                app.context(str(state.case_id), state=state),
                concurrent_proposals=(_proposal("network.snapshot"),),
            )
            assert started.wait(1)
            state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                state,
                app.context(str(state.case_id), state=state),
                concurrent_proposals=(_proposal("storage.snapshot"),),
            )
            assert provider.calls == 1
        finally:
            release.set()
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        assert not provider_saw_cancel.is_set(), "unrelated observations cancelled strategic work"
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert state.hypotheses[0].status is HypothesisStatus.UNRESOLVED
        assert state.hypotheses[0].expected_facts
        assert state.hypotheses[0].expected_facts_observed_after is not None
        assert state.assessment is None
        assert tuple(p.probe_id for p in state.pending_distinguishing_probes) == (
            "devices.snapshot",
        )
        assert (
            store.connection.execute("SELECT status FROM deep_mailbox").fetchone()[0] == "applied"
        )
