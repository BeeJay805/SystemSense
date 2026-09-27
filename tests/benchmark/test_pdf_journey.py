"""The PDF journey joins independent visual witnesses to bounded case exports."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
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

_ACTION = datetime(2026, 9, 23, 10, tzinfo=UTC)


def _time(offset_ms: float) -> str:
    return (_ACTION + timedelta(milliseconds=offset_ms)).isoformat()


def _sample(
    start_ms: float, observed_ms: float, *, before: float, after: float, offset_ms: float = 0
) -> VisualSample:
    return VisualSample(
        _time(offset_ms + start_ms),
        _time(offset_ms + observed_ms),
        round((1000 + offset_ms + start_ms) * 1_000_000),
        round((1000 + offset_ms + observed_ms) * 1_000_000),
        "f" * 64,
        before,
        after,
    )


def _visual(
    trial_id: str,
    phase: Literal["clean", "injected"],
    lower: float,
    upper: float,
    offset_ms: float,
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
        _time(offset_ms),
        _time(offset_ms + 1),
        lower,
        upper,
        (
            _sample(-40, -39, before=1, after=0, offset_ms=offset_ms),
            _sample(-20, -19, before=1, after=0, offset_ms=offset_ms),
        ),
        (
            _sample(lower, lower + 0.5, before=1, after=0, offset_ms=offset_ms),
            _sample(upper - 0.5, upper, before=0, after=1, offset_ms=offset_ms),
            _sample(upper + 1, upper + 2, before=0, after=1, offset_ms=offset_ms),
        ),
        _time(offset_ms + upper + 3),
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
            clean_offset = len(rows) * 10_000
            rows.append(
                PdfJourneyTrial(
                    arm, index, "clean", _visual(clean_id, "clean", 10, 12, clean_offset), None
                )
            )
            injected_offset = len(rows) * 10_000
            rows.append(
                PdfJourneyTrial(
                    arm,
                    index,
                    "injected",
                    _visual(injected_id, "injected", 30, 32, injected_offset),
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
        "replayed_visual_times",
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
    elif change == "replayed_visual_times":
        row = replace(row, visual=replace(trials[-3].visual, trial_id=row.visual.trial_id))
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
        replace(
            row,
            visual=replace(
                row.visual,
                latency_lower_bound_ms=20,
                after=(
                    _sample(
                        20,
                        20.5,
                        before=1,
                        after=0,
                        offset_ms=(
                            datetime.fromisoformat(row.visual.action_started_at or "") - _ACTION
                        ).total_seconds()
                        * 1000,
                    ),
                    *row.visual.after[1:],
                ),
            ),
        )
        if row.phase == "injected"
        else row
        for row in original
    )
    report = bind_pdf_journey(manifest, trials)
    assert report.admitted is True
    assert report.visual_slowdown_supported is False


@pytest.mark.parametrize(
    "change",
    (
        "action_before_baseline",
        "dispatch_after_sample",
        "capture_clock_backwards",
        "sample_order_backwards",
        "finished_before_sample",
        "viewer_created_after_action",
        "latency_exceeds_sample_clock",
        "missing_stable_target",
        "missing_negative_for_lower",
        "non_utc_action",
        "invalid_fraction",
        "invalid_frame_digest",
    ),
)
def test_rejects_impossible_visual_chronology(change: str) -> None:
    manifest, original = _bundle()
    trials = list(original)
    row = trials[-1]
    visual = row.visual
    offset_ms = (
        datetime.fromisoformat(visual.action_started_at or "") - _ACTION
    ).total_seconds() * 1000
    if change == "action_before_baseline":
        visual = replace(visual, action_started_at=_time(offset_ms - 50))
    elif change == "dispatch_after_sample":
        visual = replace(
            visual,
            action_dispatched_at=_time(offset_ms + (visual.latency_upper_bound_ms or 0) + 10),
        )
    elif change == "capture_clock_backwards":
        bad = replace(visual.before[0], observed_at=_time(offset_ms - 41))
        visual = replace(visual, before=(bad, *visual.before[1:]))
    elif change == "sample_order_backwards":
        bad = replace(visual.after[1], capture_started_ns=visual.after[0].capture_started_ns)
        visual = replace(visual, after=(visual.after[0], bad, *visual.after[2:]))
    elif change == "finished_before_sample":
        visual = replace(visual, finished_at=_time(offset_ms + 5))
    elif change == "viewer_created_after_action":
        visual = replace(visual, viewer_created_at=_time(offset_ms + 5))
    elif change == "latency_exceeds_sample_clock":
        visual = replace(visual, latency_upper_bound_ms=50)
    elif change == "missing_stable_target":
        bad = replace(visual.after[-1], before_fraction=1, after_fraction=0)
        visual = replace(visual, after=(*visual.after[:-1], bad))
    elif change == "missing_negative_for_lower":
        visual = replace(visual, after=visual.after[1:])
    elif change == "non_utc_action":
        visual = replace(visual, action_started_at="2026-09-23T10:00:00-07:00")
    elif change == "invalid_fraction":
        bad = replace(visual.after[-1], after_fraction=float("nan"))
        visual = replace(visual, after=(*visual.after[:-1], bad))
    else:
        bad = replace(visual.after[-1], frame_sha256="not-a-digest")
        visual = replace(visual, after=(*visual.after[:-1], bad))
    trials[-1] = replace(row, visual=visual)
    with pytest.raises(PdfJourneyError):
        bind_pdf_journey(manifest, tuple(trials))
