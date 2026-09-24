"""The normal adaptive runner preserves strategic work across fast-policy turns."""

import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProviderIdentity
from systemsense.decision.frontier_ranker import MixedFrontierRanker
from systemsense.domain.ids import JsonValue
from systemsense.inference.control import current_cancellation
from systemsense.orchestration.probes import ProbeObservation
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_independent_deep_collection import (
    _proposal,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator, probe_definition


def test_live_run_keeps_deep_alive_until_second_fast_collection(tmp_path: Path) -> None:
    first_started = threading.Event()
    second_finished = threading.Event()
    deep_cancelled = threading.Event()
    base_network = probe_definition("network")
    base_storage = probe_definition("storage")

    def network(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert first_started.wait(1)
        assert base_network.handler is not None
        return base_network.handler(parameters)

    def storage(parameters: dict[str, JsonValue]) -> ProbeObservation:
        time.sleep(0.06)
        second_finished.set()
        assert base_storage.handler is not None
        return base_storage.handler(parameters)

    class Deep:
        identity = ProviderIdentity(provider_id="late", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            first_started.set()
            assert second_finished.wait(2)
            cancellation = current_cancellation()
            if cancellation is not None and cancellation.is_set():
                deep_cancelled.set()
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.SUPPORTED,
                summary="An advisory network hypothesis.",
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="network",
                        statement="Network warrants review.",
                        status=HypothesisStatus.SUPPORTED,
                        supporting_evidence_ids=(request.evidence_context[0].evidence_id,),
                    ),
                ),
            )

    class Fast:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            remaining = [
                p
                for p in ("network.snapshot", "storage.snapshot")
                if p not in request.completed_probe_ids
            ]
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(_proposal(remaining[0]),) if remaining else (),
            )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "late-run.db") as store:
        app = investigator(
            store,
            reasoning=Deep(),
            decision=Fast(),
            definitions=(
                core,
                replace(base_network, handler=network),
                replace(base_storage, handler=storage),
            ),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Fast.identity, model_weight_sha256="a" * 64
        )
        state = app.create(objective="network issue", budget_ms=4000)
        result = app.run(str(state.case_id))
        assert second_finished.is_set()
        assert not deep_cancelled.is_set()
        assert result.hypotheses and result.hypotheses[0].status is HypothesisStatus.UNRESOLVED
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM deep_mailbox WHERE status='applied'"
            ).fetchone()[0]
            >= 1
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM deep_mailbox WHERE status='running'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("corrupt_dependency", [False, True])
def test_second_owner_cannot_interrupt_live_mailbox_and_corrupt_dependency_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corrupt_dependency: bool,
) -> None:
    from systemsense.application.investigation_state import InvestigationStatus

    release = threading.Event()

    class Slow:
        identity = ProviderIdentity(provider_id="slow", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            assert release.wait(2)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Advisory pending.",
            )

    with SQLiteStore(tmp_path / "owners.db") as store:
        app = investigator(store, reasoning=Slow(), definitions=(probe_definition("network"),))
        state = app.create(objective="network issue", budget_ms=3000)
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING}), "started", "test"
        )
        try:
            state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                state, (), concurrent_proposals=(_proposal("network.snapshot"),)
            )
            other = investigator(store)
            with pytest.raises(RuntimeError, match="already running"):
                other.run(str(state.case_id))
            assert (
                store.connection.execute("SELECT status FROM deep_mailbox").fetchone()[0]
                == "running"
            )
            if corrupt_dependency:

                def corrupt(*_args: object) -> None:
                    raise ValueError("corrupt relationship provenance")

                monkeypatch.setattr(app, "_deep_dependency_error", corrupt)
                state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
                assert (
                    store.connection.execute("SELECT status FROM deep_mailbox").fetchone()[0]
                    == "rejected"
                )
                assert any(
                    "dependency validation unavailable" in warning for warning in state.warnings
                )
        finally:
            release.set()
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
