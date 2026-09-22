from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import ProbeCapability, ResourceClass
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.evaluation.models import EpisodeSpec, EvaluationMode, MeasurementSource
from systemsense.evaluation.recorder import EpisodeRecorder
from systemsense.evaluation.tracking import (
    TrackedDecisionProvider,
    TrackedReasoningProvider,
)
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _definition(*, fails: bool = False) -> ProbeDefinition:
    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if fails:
            raise RuntimeError("synthetic telemetry missing")
        now = datetime.now(UTC)
        return ProbeObservation(
            summary="Synthetic memory pressure observation.",
            facts={"resources": {"memory": {"percent": 96.0}}},
            observed_at=now,
            captured_at=now,
        )

    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id="core.resources",
            version=1,
            implementation_id="builtin.core.resources",
            question="What are the synthetic resource facts?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=1000, max_output_bytes=32768, max_records=8),
            category="core.resources",
        ),
        parameter_model=NoParameters,
        handler=collect,
        isolated=False,
    )


def _investigator(
    store: SQLiteStore, *, fails: bool = False
) -> tuple[Investigator, TrackedDecisionProvider, TrackedReasoningProvider]:
    definition = _definition(fails=fails)
    planner = DeterministicPlanner(
        candidates=(ProbeCandidate(probe_id="core.resources", cost_ms=10, value=1, common=True),)
    )
    decision = TrackedDecisionProvider(KeywordBaselineDecisionProvider())
    reasoning = TrackedReasoningProvider(DeterministicReasoningProvider())
    investigator = Investigator(
        store=store,
        runtime=DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(definitions=(definition,)),
        ),
        capabilities=(
            ProbeCapability(
                probe_id="core.resources",
                description="synthetic resource observation",
                keywords=frozenset({"memory"}),
                common=True,
                cost_ms=10,
                resource_class=ResourceClass.CPU,
            ),
        ),
        decision=decision,
        reasoning=reasoning,
    )
    return investigator, decision, reasoning


def test_recorder_runs_real_coordinator_and_records_measured_attempts(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "episode.db") as store:
        investigator, decision, reasoning = _investigator(store)
        artifact = EpisodeRecorder().record(
            investigator=investigator,
            decision=decision,
            reasoning=reasoning,
            spec=EpisodeSpec(
                scenario_id="synthetic.memory-pressure",
                objective="Investigate synthetic memory pressure.",
                measurement_source=MeasurementSource.SIMULATION,
                synthetic=True,
                mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
                budget_ms=2000,
                max_rounds=2,
                max_probes=1,
            ),
        )

    assert artifact.elapsed_ms > 0
    assert artifact.probe_attempts.total == 1
    assert artifact.probe_attempts.failures == 0
    assert artifact.probe_status_counts == {"ok": 1}
    assert artifact.evidence_count == 1
    assert artifact.decision.calls == 1
    assert artifact.review.quality_label.value == "unknown"


def test_recorder_preserves_missing_telemetry_in_failure_denominator(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "missing.db") as store:
        investigator, decision, reasoning = _investigator(store, fails=True)
        artifact = EpisodeRecorder().record(
            investigator=investigator,
            decision=decision,
            reasoning=reasoning,
            spec=EpisodeSpec(
                scenario_id="synthetic.missing-telemetry",
                objective="Investigate synthetic missing telemetry.",
                measurement_source=MeasurementSource.SIMULATION,
                synthetic=True,
                mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
                budget_ms=2000,
                max_rounds=2,
                max_probes=1,
            ),
        )

    assert artifact.probe_attempts.failures == 1
    assert artifact.probe_attempts.total == 1
    assert artifact.probe_status_counts == {"failed": 1}
    assert artifact.coverage_count == 1
