from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationStatus,
)
from systemsense.domain.ids import CaseId
from systemsense.evaluation.models import (
    EpisodeArtifact,
    EpisodeReview,
    EvaluationMode,
    FailureCount,
    MeasurementSource,
    ProviderMeasurement,
    QualityLabel,
)
from systemsense.orchestration.probes import ProbeRunStatus

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def artifact() -> EpisodeArtifact:
    return EpisodeArtifact(
        scenario_id="synthetic.memory-pressure",
        measurement_source=MeasurementSource.SIMULATION,
        synthetic=True,
        mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
        case_id=CaseId(root="case_0123456789abcdef0123456789abcdef"),
        objective="Investigate observed memory pressure.",
        budget_ms=2000,
        max_rounds=2,
        max_probes=3,
        started_at=NOW,
        finished_at=NOW + timedelta(milliseconds=5),
        elapsed_ms=5.25,
        attempted_probe_ids=("core.resources",),
        probe_attempts=FailureCount(failures=0, total=1),
        probe_status_counts={ProbeRunStatus.OK: 1},
        evidence_count=1,
        coverage_count=0,
        decision=ProviderMeasurement(
            role="decision",
            provider_id="keyword-baseline",
            calls=1,
            failures=0,
        ),
        reasoning=ProviderMeasurement(
            role="reasoning",
            provider_id="deterministic-reasoning",
            calls=1,
            failures=0,
        ),
        terminal_status=InvestigationStatus.COMPLETE,
        terminal_outcome=InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
        review=EpisodeReview(),
    )


def test_episode_records_measured_denominators_without_accuracy_claim() -> None:
    episode = artifact()
    assert episode.review.quality_label is QualityLabel.UNKNOWN
    assert episode.probe_attempts.total == 1
    assert episode.integrity_sha256() != episode.outcome_fingerprint()


def test_outcome_fingerprint_excludes_times_and_opaque_case_identity() -> None:
    first = artifact()
    later = first.model_copy(
        update={
            "case_id": CaseId(root="case_fedcba9876543210fedcba9876543210"),
            "started_at": NOW + timedelta(hours=1),
            "finished_at": NOW + timedelta(hours=1, milliseconds=9),
            "elapsed_ms": 9.0,
        }
    )
    assert first.outcome_fingerprint() == later.outcome_fingerprint()
    assert first.integrity_sha256() != later.integrity_sha256()


def test_reviewed_quality_requires_reviewer_and_unknown_cannot_fake_accuracy() -> None:
    with pytest.raises(ValidationError, match="reviewer"):
        EpisodeReview(quality_label=QualityLabel.PASS)
    with pytest.raises(ValidationError, match="unknown"):
        EpisodeReview(quality_label=QualityLabel.UNKNOWN, reviewer="student")


def test_failure_count_cannot_exceed_denominator() -> None:
    with pytest.raises(ValidationError, match="denominator"):
        FailureCount(failures=2, total=1)


def test_evidence_and_coverage_counts_are_not_inferred_from_attempts() -> None:
    payload = artifact().model_dump(mode="json")
    payload.update(
        {
            "probe_attempts": {"failures": 0, "total": 1},
            "evidence_count": 2,
            "coverage_count": 1,
            "skipped_probe_ids": ["network.snapshot"],
        }
    )
    measured = EpisodeArtifact.model_validate(payload)

    assert measured.evidence_count == 2
    assert measured.coverage_count == 1
    assert measured.skipped_probe_ids == ("network.snapshot",)
