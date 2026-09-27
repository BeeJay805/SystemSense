"""A source can claim task coverage only from a trusted, exact fixture locator."""

from datetime import UTC, datetime, timedelta

import pytest

from systemsense.application.frontier_policy import (
    _fixture_source_task_relation,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.domain.affected_task import TaskObservationContextV1
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id

CASE = CaseId(root="case_" + "a" * 32)
TASK_EVIDENCE = EvidenceId(root="ev_" + "a" * 32)
SOURCE_EVIDENCE = EvidenceId(root="ev_" + "b" * 32)
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def _task() -> TaskObservationContextV1:
    return TaskObservationContextV1(
        case_id=CASE,
        evidence_id=TASK_EVIDENCE,
        source_id="src_" + "a" * 64,
        collector_id="fixture.task_baseline",
        collector_version=1,
        execution_id=ExecutionId(root="exec_" + "a" * 32),
        record_sha256="a" * 64,
        target_handle="synthetic:browser-profile:one",
        action="open synthetic site item",
        expected="page_loaded",
        observed="timeout",
        window_start=NOW - timedelta(milliseconds=500),
        window_end=NOW,
        sample_window_ms=500,
        observed_at=NOW,
        captured_at=NOW,
        limitation="Synthetic fixture only; no Windows browser was opened.",
    )


def _source(
    *,
    target: str = "synthetic:browser-profile:one",
    coverage_start: datetime | None = None,
    coverage_end: datetime | None = None,
    trusted: bool = True,
) -> EvidenceRecord:
    locator: dict[str, JsonValue] = {
        "case_id": str(CASE),
        "domain": "network_browser",
        "source_index": 49,
        "target_handle": target,
        "coverage_start_utc": (coverage_start or NOW - timedelta(milliseconds=500)).isoformat(),
        "coverage_end_utc": (coverage_end or NOW).isoformat(),
    }
    source_type = "fixture.task_coverage" if trusted else "fixture.scripted.source"
    return EvidenceRecord(
        evidence_id=SOURCE_EVIDENCE,
        case_id=CASE,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW + timedelta(microseconds=1),
        captured_at=NOW + timedelta(microseconds=1),
        source=EvidenceSource(
            type=source_type,
            source_id=stable_source_id(source_type, locator),
            locator=locator,
        ),
        collector=CollectorReference(
            id="fixture.task_coverage" if trusted else "fixture.network_browser",
            version=1,
            execution_id=ExecutionId(root="exec_" + "b" * 32),
        ),
        summary="Browser route sample",
        extraction=Extraction(
            confidence=1.0,
            parser="fixture.task_coverage" if trusted else "fixture.scripted",
            parser_version=1,
        ),
        limitations=("Preexisting synthetic source; no on-case probe execution.",),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )


def test_source_coverage_distinguishes_full_match_from_valid_nonmatch() -> None:
    task = _task()
    matched = _fixture_source_task_relation(_source(), task)
    other_target = _fixture_source_task_relation(_source(target="synthetic:profile:other"), task)
    partial = _fixture_source_task_relation(
        _source(coverage_start=NOW - timedelta(milliseconds=250)), task
    )

    assert matched is not None and matched.status == "same_target_full_window"
    assert other_target is not None and other_target.status == "different_target"
    assert partial is not None and partial.status == "insufficient_window"
    assert matched.task_record_sha256 == task.record_sha256
    assert matched.source_evidence_id == SOURCE_EVIDENCE
    assert _fixture_source_task_relation(_source(trusted=False), task) is None


def test_invalid_trusted_coverage_fails_closed() -> None:
    task = _task()
    source = _source()
    assert source.source.source_id != "src_" + "0" * 64
    broken_source = source.model_copy(
        update={"source": source.source.model_copy(update={"source_id": "src_" + "0" * 64})}
    )
    with pytest.raises(ValueError, match="source identity"):
        _fixture_source_task_relation(broken_source, task)

    late = _source(coverage_end=NOW + timedelta(seconds=1))
    with pytest.raises(ValueError, match="source coverage"):
        _fixture_source_task_relation(late, task)

    malformed = source.model_copy(
        update={"source": source.source.model_copy(update={"locator": {"case_id": str(CASE)}})}
    )
    with pytest.raises(ValueError, match="source coverage"):
        _fixture_source_task_relation(malformed, task)

    unlabeled = source.model_copy(update={"limitations": ()})
    with pytest.raises(ValueError, match="producer"):
        _fixture_source_task_relation(unlabeled, task)

    wrong_locator = {**source.source.locator, "domain": "application_performance"}
    wrong_domain = source.model_copy(
        update={
            "source": source.source.model_copy(
                update={
                    "locator": wrong_locator,
                    "source_id": stable_source_id("fixture.task_coverage", wrong_locator),
                }
            )
        }
    )
    with pytest.raises(ValueError, match="domain"):
        _fixture_source_task_relation(wrong_domain, task)
