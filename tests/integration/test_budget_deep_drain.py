"""A full probe budget must not discard deep work already admitted."""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from systemsense.application.investigation_state import InvestigationOutcome
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.decision.frontier_ranker import MixedFrontierRanker
from systemsense.domain.ids import JsonValue
from systemsense.orchestration.probes import ProbeObservation
from systemsense.reasoning.contracts import (
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


@pytest.mark.parametrize("cancel_after_probe", [False, True])
def test_probe_budget_drains_already_admitted_deep_result(
    tmp_path: Path, cancel_after_probe: bool
) -> None:
    collected = threading.Event()
    deep_started = threading.Event()
    deep_completed = threading.Event()
    release_deep = threading.Event()
    cancellation = threading.Event()
    base = probe_definition("network")

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert deep_started.wait(1), "the deep task must overlap the selected measurement"
        assert base.handler is not None
        observation = base.handler(parameters)
        collected.set()
        if cancel_after_probe:
            threading.Timer(0.03, cancellation.set).start()
        return observation

    class DelayedDeep:
        identity = ProviderIdentity(
            provider_id="delayed-budget", provider_version="1", role="reasoning"
        )
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            deep_started.set()
            assert collected.wait(1)
            if cancel_after_probe:
                assert release_deep.wait(2)
            else:
                time.sleep(0.15)
            deep_completed.set()
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The delayed deep assessment was retained.",
            )

    class Decision:
        identity = ProviderIdentity(
            provider_id="fast-budget", provider_version="1", role="fast_decision"
        )

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

    deep = DelayedDeep()
    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "budget-deep.db") as store:
        app = investigator(
            store,
            definitions=(core, replace(base, handler=collect)),
            reasoning=deep,
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        case = app.create(objective="network issue", budget_ms=3000, max_probes=2)
        result = app.run(str(case.case_id), cancel_event=cancellation)
        release_deep.set()

        assert set(result.completed_probe_ids) == {"core.system", "network.snapshot"}
        assert deep.calls == 1, "budget closure must not launch a duplicate deep call"
        if cancel_after_probe:
            assert result.outcome is InvestigationOutcome.CANCELLED
            assert not deep_completed.is_set(), "cancellation must not wait for the deep worker"
            return

        assert deep_completed.is_set(), (
            "case closed before an already admitted deep task finished: "
            f"started={deep_started.is_set()} collected={collected.is_set()} "
            f"calls={deep.calls} probes={result.completed_probe_ids} "
            f"outcome={result.outcome} warnings={result.warnings}"
        )
        assert result.reasoning_provider == "delayed-budget"
        assert result.summary == "Advisory explanation: The delayed deep assessment was retained."
