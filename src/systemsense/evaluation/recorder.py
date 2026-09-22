"""Run the real bounded coordinator and record observed episode measurements."""

from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime

from systemsense.application.investigator import Investigator
from systemsense.evaluation.models import (
    EpisodeArtifact,
    EpisodeReview,
    EpisodeSpec,
    FailureCount,
    ProviderMeasurement,
)
from systemsense.evaluation.tracking import TrackedDecisionProvider, TrackedReasoningProvider
from systemsense.orchestration.probes import ProbeRunStatus


class EpisodeRecorder:
    def record(
        self,
        *,
        investigator: Investigator,
        decision: TrackedDecisionProvider,
        reasoning: TrackedReasoningProvider,
        spec: EpisodeSpec,
    ) -> EpisodeArtifact:
        decision_before = decision.measurement()
        reasoning_before = reasoning.measurement()
        started_at = datetime.now(UTC)
        started = time.perf_counter()
        initial = investigator.create(
            objective=spec.objective,
            budget_ms=spec.budget_ms,
            max_rounds=spec.max_rounds,
            max_probes=spec.max_probes,
        )
        result = investigator.run(str(initial.case_id))
        elapsed_ms = (time.perf_counter() - started) * 1000
        finished_at = datetime.now(UTC)

        case_id = str(result.case_id)
        execution_rows = investigator.store.connection.execute(
            "SELECT probe_id, status FROM probe_executions "
            "WHERE case_id = ? ORDER BY started_at, execution_id",
            (case_id,),
        ).fetchall()
        attempted_probe_ids = tuple(str(row[0]) for row in execution_rows)
        attempts = len(execution_rows)
        statuses = tuple(ProbeRunStatus(str(row[1])) for row in execution_rows)
        status_counts = dict(Counter(statuses))
        failures = sum(status is not ProbeRunStatus.OK for status in statuses)
        observed_row = investigator.store.connection.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id = ? "
            "AND json_type(record_json, '$.status') IS NULL",
            (case_id,),
        ).fetchone()
        coverage_row = investigator.store.connection.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id = ? "
            "AND json_type(record_json, '$.status') IS NOT NULL "
            "AND json_type(record_json, '$.category') IS NOT NULL",
            (case_id,),
        ).fetchone()
        assert observed_row is not None and coverage_row is not None
        evidence = int(observed_row[0])
        coverage = int(coverage_row[0])
        attempted_probe_set = frozenset(attempted_probe_ids)
        skipped_probe_ids = tuple(
            capability.probe_id
            for capability in investigator.capabilities
            if capability.probe_id not in attempted_probe_set
        )
        decision_after = decision.measurement()
        reasoning_after = reasoning.measurement()
        return EpisodeArtifact(
            scenario_id=spec.scenario_id,
            measurement_source=spec.measurement_source,
            synthetic=spec.synthetic,
            mode=spec.mode,
            case_id=result.case_id,
            objective=result.objective,
            budget_ms=spec.budget_ms,
            max_rounds=spec.max_rounds,
            max_probes=spec.max_probes,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
            attempted_probe_ids=attempted_probe_ids,
            skipped_probe_ids=skipped_probe_ids,
            probe_attempts=FailureCount(failures=failures, total=attempts),
            probe_status_counts=status_counts,
            evidence_count=evidence,
            coverage_count=coverage,
            decision=_delta(
                decision_before,
                decision_after,
                effective_provider_id=result.decision_provider or None,
            ),
            reasoning=_delta(
                reasoning_before,
                reasoning_after,
                effective_provider_id=result.reasoning_provider or None,
            ),
            terminal_status=result.status,
            terminal_outcome=result.outcome,
            warnings=result.warnings,
            review=EpisodeReview(),
        )


def _delta(
    before: ProviderMeasurement,
    after: ProviderMeasurement,
    *,
    effective_provider_id: str | None,
) -> ProviderMeasurement:
    if before.role != after.role or before.provider_id != after.provider_id:
        raise ValueError("provider telemetry identity changed during the episode")
    calls = after.calls - before.calls
    failures = after.failures - before.failures
    if calls < 0 or failures < 0:
        raise ValueError("provider telemetry counters moved backwards")
    return ProviderMeasurement(
        role=after.role,
        provider_id=after.provider_id,
        effective_provider_id=effective_provider_id,
        model_id=after.model_id,
        calls=calls,
        failures=failures,
    )
