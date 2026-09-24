"""Offline, host-only binding of PDF visual witnesses to read-only case exports.

This checks a submitted journey's shape and byte-equivalent records. It does not
run the viewer, authenticate a rig, or adjudicate the investigator's explanation.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, cast

from benchmarks.pdf_page_oracle import PdfPageResult

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,79}\Z")


class PdfJourneyError(ValueError):
    """A submitted journey cannot be used even as a host consistency report."""


class PdfJourneyArm(StrEnum):
    DETERMINISTIC = "deterministic"
    ADAPTIVE = "adaptive"


@dataclass(frozen=True, slots=True)
class PdfJourneyManifest:
    journey_id: str
    viewer_sha256: str
    document_sha256: str
    window_title_sha256: str
    workload_sha256: str
    probe_catalog_sha256: str
    common_budget_ms: int
    warm_state: Literal["cold", "warm"]
    measured_at: datetime

    def validate(self) -> None:
        if _ID.fullmatch(self.journey_id) is None:
            raise PdfJourneyError("invalid journey ID")
        for digest in (
            self.viewer_sha256,
            self.document_sha256,
            self.window_title_sha256,
            self.workload_sha256,
            self.probe_catalog_sha256,
        ):
            if _DIGEST.fullmatch(digest) is None:
                raise PdfJourneyError("invalid pinned SHA-256")
        if not 100 <= self.common_budget_ms <= 600_000:
            raise PdfJourneyError("invalid common budget")
        if self.warm_state not in ("cold", "warm"):
            raise PdfJourneyError("invalid warm state")
        if self.measured_at.utcoffset() != timedelta(0):
            raise PdfJourneyError("manifest time must be UTC")


@dataclass(frozen=True, slots=True)
class PdfJourneyTrial:
    arm: PdfJourneyArm
    repetition: int
    phase: Literal["clean", "injected"]
    visual: PdfPageResult
    case_export: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class PdfJourneyArmResult:
    arm: PdfJourneyArm
    clean_upper_ms: tuple[float, ...]
    injected_lower_ms: tuple[float, ...]
    case_ids: tuple[str, ...]
    case_evidence_ids: tuple[str, ...]
    visual_record_sha256: tuple[str, ...]
    case_export_sha256: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PdfJourneyReport:
    schema_version: Literal[1]
    classification: Literal["pdf_journey_host_consistency_only"]
    journey_id: str
    admitted: bool
    visual_slowdown_supported: bool
    diagnostic_comparison_qualified: bool
    arm_results: tuple[PdfJourneyArmResult, ...]
    limitations: tuple[str, ...]


def _digest_json(value: object) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise PdfJourneyError("record is not finite JSON") from error
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _check_visual(manifest: PdfJourneyManifest, trial: PdfJourneyTrial) -> tuple[float, float]:
    visual = trial.visual
    if (
        visual.schema_version != 1
        or visual.classification != "pdf_visual_witness_only"
        or visual.phase != trial.phase
        or visual.outcome != "measured"
        or visual.reason is not None
        or _ID.fullmatch(visual.trial_id) is None
    ):
        raise PdfJourneyError("visual witness is missing, failed, or mismatched")
    if (
        visual.viewer_sha256 != manifest.viewer_sha256
        or visual.document_sha256 != manifest.document_sha256
        or visual.window_title_sha256 != manifest.window_title_sha256
    ):
        raise PdfJourneyError("visual target identity changed")
    if (
        visual.viewer_pid <= 0
        or visual.viewer_hwnd <= 0
        or visual.action_started_at is None
        or visual.action_dispatched_at is None
        or len(visual.before) < 2
        or len(visual.after) < 2
    ):
        raise PdfJourneyError("visual action record is incomplete")
    lower, upper = visual.latency_lower_bound_ms, visual.latency_upper_bound_ms
    if (
        lower is None
        or upper is None
        or not math.isfinite(lower)
        or not math.isfinite(upper)
        or lower < 0
        or upper < lower
        or upper > visual.timeout_ms
    ):
        raise PdfJourneyError("invalid interval-censored latency")
    return lower, upper


def _check_case(
    manifest: PdfJourneyManifest, trial: PdfJourneyTrial
) -> tuple[str, tuple[str, ...], str]:
    export = trial.case_export
    if export is None or export.get("format") != "systemsense-case-report-v1":
        raise PdfJourneyError("missing SystemSense case export")
    case = export.get("case")
    if not isinstance(case, dict):
        raise PdfJourneyError("missing case record")
    case = cast("dict[str, object]", case)
    case_id = case.get("case_id")
    if (
        case_id != trial.visual.trial_id
        or case.get("budget_ms") != manifest.common_budget_ms
        or case.get("read_only") is not True
        or case.get("status") != "complete"
    ):
        raise PdfJourneyError("case ID, budget, or completion does not match trial")
    evidence = case.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise PdfJourneyError("current-case evidence is missing")
    evidence = cast("list[object]", evidence)
    evidence_ids: list[str] = []
    for row in evidence:
        if not isinstance(row, dict):
            raise PdfJourneyError("invalid evidence row")
        row = cast("dict[str, object]", row)
        evidence_id = row.get("evidence_id")
        if (
            not isinstance(evidence_id, str)
            or not evidence_id
            or row.get("case_id") != case_id
            or row.get("historical") is not False
        ):
            raise PdfJourneyError("evidence is not bound to the current case")
        evidence_ids.append(evidence_id)
    if len(set(evidence_ids)) != len(evidence_ids):
        raise PdfJourneyError("duplicate case evidence ID")
    assert isinstance(case_id, str)
    return case_id, tuple(evidence_ids), _digest_json(export)


def bind_pdf_journey(
    manifest: PdfJourneyManifest, trials: tuple[PdfJourneyTrial, ...]
) -> PdfJourneyReport:
    """Require three clean and injected page actions for each equal-budget arm.

    The workload and catalog digests are pinned assertions from the caller. An
    independent controller must verify their bytes and the guest's reset state.
    """
    manifest.validate()
    expected = {
        (arm, repetition, phase)
        for arm in PdfJourneyArm
        for repetition in range(3)
        for phase in ("clean", "injected")
    }
    actual = [(trial.arm, trial.repetition, trial.phase) for trial in trials]
    if len(actual) != len(expected) or set(actual) != expected:
        raise PdfJourneyError("exactly three clean and injected trials per arm are required")
    by_key = {(trial.arm, trial.repetition, trial.phase): trial for trial in trials}
    seen_trial_ids: set[str] = set()
    visual_settings: tuple[object, ...] | None = None
    arm_results: list[PdfJourneyArmResult] = []
    slowdown = True
    for arm in PdfJourneyArm:
        clean_upper: list[float] = []
        injected_lower: list[float] = []
        case_ids: list[str] = []
        evidence_ids: list[str] = []
        visual_digests: list[str] = []
        case_digests: list[str] = []
        for repetition in range(3):
            for phase in ("clean", "injected"):
                trial = by_key[(arm, repetition, phase)]
                lower, upper = _check_visual(manifest, trial)
                settings = (
                    trial.visual.client_roi,
                    trial.visual.before_rgb,
                    trial.visual.after_rgb,
                    trial.visual.color_tolerance,
                    trial.visual.min_marker_fraction,
                    trial.visual.timeout_ms,
                    trial.visual.poll_ms,
                )
                if visual_settings is None:
                    visual_settings = settings
                elif settings != visual_settings:
                    raise PdfJourneyError("visual workload settings changed between trials")
                if trial.visual.trial_id in seen_trial_ids:
                    raise PdfJourneyError("visual trial ID was reused")
                seen_trial_ids.add(trial.visual.trial_id)
                visual_digests.append(_digest_json(trial.visual.as_json()))
                if phase == "clean":
                    if trial.case_export is not None:
                        raise PdfJourneyError("clean witness must not carry investigator output")
                    clean_upper.append(upper)
                else:
                    case_id, ids, case_digest = _check_case(manifest, trial)
                    case_ids.append(case_id)
                    evidence_ids.extend(ids)
                    case_digests.append(case_digest)
                    injected_lower.append(lower)
            if injected_lower[-1] < 2 * clean_upper[-1]:
                slowdown = False
        arm_results.append(
            PdfJourneyArmResult(
                arm,
                tuple(clean_upper),
                tuple(injected_lower),
                tuple(case_ids),
                tuple(evidence_ids),
                tuple(visual_digests),
                tuple(case_digests),
            )
        )
    return PdfJourneyReport(
        1,
        "pdf_journey_host_consistency_only",
        manifest.journey_id,
        True,
        slowdown,
        False,
        tuple(arm_results),
        (
            "Visual intervals witness page rendering, not the cause of delay.",
            "Case exports are redacted host reports, not authenticated probe or model traces.",
            "A trusted rig must verify pinned workload, catalog, VM reset, fault, "
            "and reviewer labels.",
        ),
    )
