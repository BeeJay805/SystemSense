"""The PDF journey joins independent visual witnesses to bounded case exports."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Literal, cast

import pytest

from benchmarks.pdf_journey import (
    PdfJourneyArm,
    PdfJourneyError,
    PdfJourneyManifest,
    PdfJourneyTrial,
    bind_pdf_journey,
)
from benchmarks.pdf_page_oracle import PdfPageResult, VisualSample


def _sample() -> VisualSample:
    return VisualSample(
        "2026-09-23T10:00:00+00:00", "2026-09-23T10:00:00+00:00", 0, 0, "f" * 64, 1, 0
    )


def _visual(
    trial_id: str, phase: Literal["clean", "injected"], lower: float, upper: float
) -> PdfPageResult:
    return PdfPageResult(
        1,
        "pdf_visual_witness_only",
        trial_id,
        phase,
        "measured",
        None,
        100,
        200,
        "2026-09-23T09:00:00+00:00",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        (30, 30, 16, 16),
        (240, 20, 20),
        (20, 240, 20),
        24,
        0.8,
        5000,
        20,
        "2026-09-23T10:00:00+00:00",
        "2026-09-23T10:00:00+00:00",
        lower,
        upper,
        (_sample(), _sample()),
        (_sample(), _sample()),
        "2026-09-23T10:00:01+00:00",
    )


def _case(trial_id: str) -> dict[str, object]:
    return {
        "format": "systemsense-case-report-v1",
        "case": {
            "case_id": trial_id,
            "status": "complete",
            "budget_ms": 30000,
            "read_only": True,
            "evidence": [
                {
                    "evidence_id": f"evidence-{trial_id}",
                    "case_id": trial_id,
                    "historical": False,
                    "probe_id": "process.performance",
                }
            ],
            "coverage": [],
        },
    }


def _bundle() -> tuple[PdfJourneyManifest, tuple[PdfJourneyTrial, ...]]:
    manifest = PdfJourneyManifest(
        journey_id="pdf-journey-01",
        viewer_sha256="a" * 64,
        document_sha256="b" * 64,
        window_title_sha256="c" * 64,
        workload_sha256="d" * 64,
        probe_catalog_sha256="e" * 64,
        common_budget_ms=30000,
        warm_state="warm",
        measured_at=datetime(2026, 9, 23, 10, tzinfo=UTC),
    )
    rows: list[PdfJourneyTrial] = []
    for arm in (PdfJourneyArm.DETERMINISTIC, PdfJourneyArm.ADAPTIVE):
        for index in range(3):
            clean_id = f"{arm.value}-clean-{index}"
            injected_id = f"{arm.value}-injected-{index}"
            rows.append(
                PdfJourneyTrial(arm, index, "clean", _visual(clean_id, "clean", 10, 12), None)
            )
            rows.append(
                PdfJourneyTrial(
                    arm,
                    index,
                    "injected",
                    _visual(injected_id, "injected", 30, 32),
                    _case(injected_id),
                )
            )
    return manifest, tuple(rows)


def test_binds_equal_budget_visual_and_case_evidence_without_cause_claim() -> None:
    manifest, trials = _bundle()
    report = bind_pdf_journey(manifest, trials)
    assert report.schema_version == 1
    assert report.classification == "pdf_journey_host_consistency_only"
    assert report.admitted is True
    assert report.visual_slowdown_supported is True
    assert report.diagnostic_comparison_qualified is False
    assert len(report.arm_results) == 2
    assert all(len(arm.case_evidence_ids) == 3 for arm in report.arm_results)


@pytest.mark.parametrize(
    "change",
    (
        "viewer",
        "settings",
        "missing",
        "budget",
        "case_id",
        "evidence",
        "historical",
        "outcome",
        "duplicate_id",
    ),
)
def test_rejects_unmatched_or_incomplete_journey(change: str) -> None:
    manifest, original = _bundle()
    trials = list(original)
    row = trials[-1]
    if change == "viewer":
        row = replace(row, visual=replace(row.visual, viewer_sha256="0" * 64))
    elif change == "settings":
        row = replace(row, visual=replace(row.visual, client_roi=(31, 30, 16, 16)))
    elif change == "missing":
        trials.pop()
    elif change == "budget":
        assert row.case_export is not None
        case = cast("dict[str, object]", row.case_export["case"])
        row = replace(row, case_export={**row.case_export, "case": {**case, "budget_ms": 20000}})
    elif change == "case_id":
        assert row.case_export is not None
        case = cast("dict[str, object]", row.case_export["case"])
        row = replace(row, case_export={**row.case_export, "case": {**case, "case_id": "other"}})
    elif change == "evidence":
        assert row.case_export is not None
        case = cast("dict[str, object]", row.case_export["case"])
        row = replace(row, case_export={**row.case_export, "case": {**case, "evidence": []}})
    elif change == "historical":
        assert row.case_export is not None
        case = cast("dict[str, object]", row.case_export["case"])
        evidence = cast("list[dict[str, object]]", case["evidence"])
        row = replace(
            row,
            case_export={
                **row.case_export,
                "case": {**case, "evidence": [{**evidence[0], "historical": True}]},
            },
        )
    elif change == "duplicate_id":
        row = replace(row, visual=replace(row.visual, trial_id=trials[0].visual.trial_id))
    else:
        row = replace(
            row, visual=replace(row.visual, outcome="timeout", latency_upper_bound_ms=None)
        )
    if change != "missing":
        trials[-1] = row
    with pytest.raises(PdfJourneyError):
        bind_pdf_journey(manifest, tuple(trials))


def test_interval_overlap_does_not_support_slowdown() -> None:
    manifest, original = _bundle()
    trials = tuple(
        replace(row, visual=replace(row.visual, latency_lower_bound_ms=20))
        if row.phase == "injected"
        else row
        for row in original
    )
    report = bind_pdf_journey(manifest, trials)
    assert report.admitted is True
    assert report.visual_slowdown_supported is False
