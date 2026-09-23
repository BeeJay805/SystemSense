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
from systemsense.evaluation.recorder import (
    _catalog_measurement,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.evaluation.trace import verify_episode_event_projection
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


def test_legacy_episode_omits_optional_catalog_field_on_roundtrip() -> None:
    original = artifact().model_dump(mode="json")
    assert original["schema_version"] == 1
    assert "catalog_attention" not in original
    assert (
        EpisodeArtifact.model_validate(original).integrity_sha256() == artifact().integrity_sha256()
    )


def test_catalog_measurement_requires_version_two_and_valid_role() -> None:
    payload = artifact().model_dump(mode="json")
    payload["catalog_attention"] = {
        "role": "catalog_attention",
        "provider_id": "LayaCatalogAttentionProvider",
        "effective_provider_id": "LayaCatalogAttentionProvider",
        "calls": 2,
        "failures": 1,
    }
    with pytest.raises(ValidationError, match="version"):
        EpisodeArtifact.model_validate(payload)
    payload["schema_version"] = 2
    measured = EpisodeArtifact.model_validate(payload)
    assert measured.catalog_attention is not None
    assert measured.catalog_attention.failures == 1
    assert measured.outcome_fingerprint() != artifact().outcome_fingerprint()


def test_catalog_measurement_counts_journal_calls_and_failures() -> None:
    events: list[dict[str, object]] = [
        {
            "role": "catalog_attention",
            "attempted_provider_id": "LayaCatalogAttentionProvider",
            "effective_provider_id": "LayaCatalogAttentionProvider",
            "failed": False,
        },
        {
            "role": "catalog_attention",
            "attempted_provider_id": "LayaCatalogAttentionProvider",
            "effective_provider_id": "none",
            "failed": True,
        },
    ]
    measured = _catalog_measurement(events)
    assert measured is not None
    assert measured.role == "catalog_attention"
    assert measured.calls == 2
    assert measured.failures == 1
    assert measured.effective_provider_id == "LayaCatalogAttentionProvider"
    assert _catalog_measurement([]) is None
    events[1]["attempted_provider_id"] = "another-provider"
    with pytest.raises(ValueError, match="catalog"):
        _catalog_measurement(events)


def _trace_event(
    sequence: int,
    kind: str,
    **fields: object,
) -> dict[str, object]:
    return {
        "event_id": f"trace_{sequence:06d}",
        "kind": kind,
        "observed_at": (NOW + timedelta(milliseconds=sequence)).isoformat(),
        **fields,
    }


def _catalog_trace() -> tuple[dict[str, object], EpisodeArtifact]:
    base = artifact().model_copy(
        update={
            "attempted_probe_ids": (),
            "probe_attempts": FailureCount(failures=0, total=0),
            "probe_status_counts": {},
            "evidence_count": 0,
            "decision": ProviderMeasurement(
                role="decision", provider_id="keyword-baseline", calls=0, failures=0
            ),
            "reasoning": ProviderMeasurement(
                role="reasoning", provider_id="deterministic-reasoning", calls=0, failures=0
            ),
        }
    )
    events = [
        _trace_event(
            1,
            "provider",
            role="catalog_attention",
            attempted_provider_id="LayaCatalogAttentionProvider",
            effective_provider_id="LayaCatalogAttentionProvider",
            failed=False,
        ),
        _trace_event(
            2,
            "terminal",
            status=base.terminal_status.value,
            outcome=base.terminal_outcome.value,
        ),
    ]
    return {"schema_version": 1, "case_id": str(base.case_id), "events": events}, base


def test_trace_rejects_hidden_catalog_provider_event_in_legacy_episode() -> None:
    trace, legacy = _catalog_trace()
    with pytest.raises(ValueError, match="provider calls"):
        verify_episode_event_projection(trace, legacy)


def test_trace_requires_exact_catalog_call_and_failure_counts() -> None:
    trace, legacy = _catalog_trace()
    measured = legacy.model_copy(
        update={
            "schema_version": 2,
            "catalog_attention": ProviderMeasurement(
                role="catalog_attention",
                provider_id="LayaCatalogAttentionProvider",
                effective_provider_id="LayaCatalogAttentionProvider",
                calls=1,
                failures=0,
            ),
        }
    )
    verify_episode_event_projection(trace, measured)
    undercounted = (
        measured.model_copy(
            update={"catalog_attention": measured.catalog_attention.model_copy(update={"calls": 0})}
        )
        if measured.catalog_attention is not None
        else measured
    )
    with pytest.raises(ValueError, match="provider calls"):
        verify_episode_event_projection(trace, undercounted)
