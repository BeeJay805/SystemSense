"""Measured synthetic journeys through the real bounded investigation coordinator.

These fixtures exercise contracts and failure accounting. They do not measure
diagnostic accuracy and never perform fault injection or local-model inference.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from systemsense.application.case_service import CaseService
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
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.evaluation.models import (
    EpisodeArtifact,
    EpisodeSpec,
    EvaluationMode,
    EvaluationSuite,
    MeasurementSource,
)
from systemsense.evaluation.recorder import EpisodeRecorder
from systemsense.evaluation.tracking import (
    TrackedDecisionProvider,
    TrackedReasoningProvider,
)
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_BUDGET_MS = 2_000
_MAX_ROUNDS = 2
_MAX_PROBES = 2


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class _SyntheticJourney:
    scenario_id: str
    objective: str
    probe_id: str
    facts: dict[str, JsonValue]
    missing_telemetry: bool = False
    invalid_provider: bool = False


_JOURNEYS = (
    _SyntheticJourney(
        scenario_id="synthetic.memory-pressure",
        objective="Investigate synthetic high memory use.",
        probe_id="core.resources",
        facts={"resources": {"memory": {"percent": 96.0}}},
    ),
    _SyntheticJourney(
        scenario_id="synthetic.pending-restart",
        objective="Investigate a synthetic pending restart observation.",
        probe_id="servicing.snapshot",
        facts={"reboot": {"pending": True, "pending_sources": ["servicing"]}},
    ),
    _SyntheticJourney(
        scenario_id="synthetic.device-problem",
        objective="Investigate a synthetic device problem report.",
        probe_id="devices.snapshot",
        facts={"devices": [{"problem_code": 10, "present": True}]},
    ),
    _SyntheticJourney(
        scenario_id="synthetic.missing-telemetry",
        objective="Investigate synthetic missing network telemetry.",
        probe_id="network.snapshot",
        facts={},
        missing_telemetry=True,
    ),
    _SyntheticJourney(
        scenario_id="synthetic.invalid-provider-output",
        objective="Investigate synthetic application telemetry with an invalid adviser.",
        probe_id="application.snapshot",
        facts={"application": {"status": "stopped"}},
        invalid_provider=True,
    ),
)


class _InvalidDecisionProvider:
    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="synthetic-invalid-decision",
            provider_version="1",
            role="fast_decision",
        )

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        response = KeywordBaselineDecisionProvider().decide(request)
        return response.model_copy(update={"state_version": request.state_version + 1})


def run_local_episode_benchmark() -> EvaluationSuite:
    episodes: list[EpisodeArtifact] = []
    with tempfile.TemporaryDirectory(prefix="systemsense-local-episodes-") as temporary:
        database_path = Path(temporary) / "episodes.db"
        with SQLiteStore(database_path) as store:
            for journey in _JOURNEYS:
                investigator, decision, reasoning = _investigator(store, journey)
                episodes.append(
                    EpisodeRecorder().record(
                        investigator=investigator,
                        decision=decision,
                        reasoning=reasoning,
                        spec=EpisodeSpec(
                            scenario_id=journey.scenario_id,
                            objective=journey.objective,
                            measurement_source=MeasurementSource.SIMULATION,
                            synthetic=True,
                            mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
                            budget_ms=_BUDGET_MS,
                            max_rounds=_MAX_ROUNDS,
                            max_probes=_MAX_PROBES,
                        ),
                    )
                )
    return EvaluationSuite(episodes=tuple(episodes))


def _investigator(
    store: SQLiteStore,
    journey: _SyntheticJourney,
) -> tuple[Investigator, TrackedDecisionProvider, TrackedReasoningProvider]:
    definition = _definition(journey)
    planner = DeterministicPlanner(
        candidates=(
            ProbeCandidate(
                probe_id=journey.probe_id,
                cost_ms=10,
                value=1,
                common=True,
            ),
        )
    )
    configured_decision = (
        _InvalidDecisionProvider()
        if journey.invalid_provider
        else KeywordBaselineDecisionProvider()
    )
    decision = TrackedDecisionProvider(configured_decision)
    reasoning = TrackedReasoningProvider(DeterministicReasoningProvider())
    return (
        Investigator(
            store=store,
            runtime=DiagnosticRuntime(
                store=store,
                case_service=CaseService(store, planner),
                probe_runner=ProbeRunner(definitions=(definition,)),
            ),
            capabilities=(
                ProbeCapability(
                    probe_id=journey.probe_id,
                    description="Synthetic read-only observation.",
                    keywords=frozenset(journey.objective.casefold().split()),
                    common=True,
                    cost_ms=10,
                    resource_class=ResourceClass.CPU,
                ),
            ),
            decision=decision,
            reasoning=reasoning,
        ),
        decision,
        reasoning,
    )


def _definition(journey: _SyntheticJourney) -> ProbeDefinition:
    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if journey.missing_telemetry:
            raise RuntimeError("synthetic telemetry unavailable")
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary=f"Synthetic observation from {journey.probe_id}.",
            facts=journey.facts,
            observed_at=observed_at,
            captured_at=observed_at,
        )

    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id=journey.probe_id,
            version=1,
            implementation_id=f"builtin.{journey.probe_id}",
            question="What does the bounded synthetic fixture report?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=1_000, max_output_bytes=32_768, max_records=16),
            category=journey.probe_id,
        ),
        parameter_model=_NoParameters,
        handler=collect,
        isolated=False,
    )


def main() -> int:
    suite = run_local_episode_benchmark()
    print(
        json.dumps(
            {
                "artifact": suite.model_dump(mode="json"),
                "integrity_sha256": suite.integrity_sha256(),
            },
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
