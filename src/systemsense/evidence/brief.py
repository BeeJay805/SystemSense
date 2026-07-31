"""Revisioned, citation-first evidence briefs with a hard context budget."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime

from pydantic import Field

from systemsense.domain.cases import DiagnosticCase
from systemsense.domain.coverage import CoverageRecord
from systemsense.domain.evidence import FrozenModel, StatementKind
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import UtcDateTime


class BriefEvidence(FrozenModel):
    evidence_id: EvidenceId
    category: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    statement_kind: StatementKind
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    summary: str = Field(min_length=1, max_length=1000)
    score: float = Field(ge=0.0, le=1.0)


class CaseBrief(FrozenModel):
    case_id: CaseId
    revision: int = Field(ge=1)
    generated_at: UtcDateTime
    text: str = Field(min_length=1)
    included_evidence_ids: tuple[EvidenceId, ...]
    delta_evidence_ids: tuple[EvidenceId, ...]
    omitted_evidence_count: int = Field(ge=0)
    omitted_coverage_count: int = Field(ge=0)
    omitted_probe_count: int = Field(ge=0)


class BriefGenerator:
    """Pack the highest-value cited facts into a deterministic text envelope."""

    def __init__(self, *, max_chars: int) -> None:
        if max_chars < 512:
            raise ValueError("max_chars must be at least 512")
        self._max_chars = max_chars

    def generate(
        self,
        *,
        case: DiagnosticCase,
        evidence: Iterable[BriefEvidence],
        pending_probe_ids: Iterable[str],
        generated_at: datetime,
        previous: CaseBrief | None = None,
    ) -> CaseBrief:
        if previous is not None and previous.case_id != case.case_id:
            raise ValueError("previous brief belongs to a different case")

        revision = 1 if previous is None else previous.revision + 1
        candidates = sorted(
            evidence,
            key=lambda item: (-item.score, item.observed_at, str(item.evidence_id)),
        )
        coverage_candidates = sorted(
            case.coverage,
            key=lambda item: (item.category, str(item.evidence_id)),
        )
        probe_candidates = sorted(set(pending_probe_ids))
        previous_ids: set[EvidenceId] = (
            set(previous.included_evidence_ids) if previous is not None else set()
        )

        selected_evidence: list[BriefEvidence] = []
        selected_coverage: list[CoverageRecord] = []
        selected_probes: list[str] = []

        def render() -> tuple[str, tuple[EvidenceId, ...], tuple[EvidenceId, ...]]:
            included = _unique_ids(
                item.evidence_id for item in (*selected_evidence, *selected_coverage)
            )
            delta = tuple(
                evidence_id for evidence_id in included if evidence_id not in previous_ids
            )
            lines = [
                "SYSTEMSENSE EVIDENCE BRIEF",
                "CASE",
                f"case={case.case_id} revision={revision} kind={case.kind.value}",
                (f"window={_iso(case.time_window.start)}..{_iso(case.time_window.end)}"),
                f"symptom={_clip(_neutralize(case.symptom), 160)}",
                "EVIDENCE",
            ]
            lines.extend(
                _evidence_lines(selected_evidence) or [_empty_line("evidence", bool(candidates))]
            )
            lines.append("COVERAGE")
            lines.extend(
                _coverage_lines(selected_coverage)
                or [_empty_line("coverage", bool(coverage_candidates))]
            )
            lines.append("PENDING PROBES")
            lines.extend(
                (f"- {probe_id}" for probe_id in selected_probes),
            )
            if not selected_probes:
                lines.append(_empty_line("probes", bool(probe_candidates)))
            lines.append("DELTA")
            lines.extend(f"- added [{evidence_id}]" for evidence_id in delta)
            if not delta:
                lines.append("- none")
            lines.extend(
                (
                    "LIMITATIONS",
                    (
                        "- Evidence observations only; causal conclusions and action "
                        "instructions are intentionally absent."
                    ),
                    (
                        f"- Budget omitted evidence={len(candidates) - len(selected_evidence)} "
                        f"coverage={len(coverage_candidates) - len(selected_coverage)} "
                        f"probes={len(probe_candidates) - len(selected_probes)}."
                    ),
                )
            )
            return "\n".join(lines), included, delta

        for candidate in candidates:
            selected_evidence.append(candidate)
            if len(render()[0]) > self._max_chars:
                selected_evidence.pop()
        for coverage in coverage_candidates:
            selected_coverage.append(coverage)
            if len(render()[0]) > self._max_chars:
                selected_coverage.pop()
        for probe_id in probe_candidates:
            selected_probes.append(probe_id)
            if len(render()[0]) > self._max_chars:
                selected_probes.pop()

        text, included_ids, delta_ids = render()
        if len(text) > self._max_chars:
            raise ValueError("max_chars is too small for the brief envelope")
        return CaseBrief(
            case_id=case.case_id,
            revision=revision,
            generated_at=generated_at,
            text=text,
            included_evidence_ids=included_ids,
            delta_evidence_ids=delta_ids,
            omitted_evidence_count=len(candidates) - len(selected_evidence),
            omitted_coverage_count=len(coverage_candidates) - len(selected_coverage),
            omitted_probe_count=len(probe_candidates) - len(selected_probes),
        )


def _evidence_lines(evidence: Iterable[BriefEvidence]) -> list[str]:
    return [
        (
            f"- [{item.evidence_id}] {item.statement_kind.value} {item.category} "
            f"observed={_iso(item.observed_at)} captured={_iso(item.captured_at)} | "
            f"{_clip(_neutralize(item.summary), 240)}"
        )
        for item in evidence
    ]


def _coverage_lines(coverage: Iterable[CoverageRecord]) -> list[str]:
    lines: list[str] = []
    for item in coverage:
        line = f"- [{item.evidence_id}] {item.category}={item.status.value}"
        if item.reason:
            line += f" | {_clip(_neutralize(item.reason), 180)}"
        lines.append(line)
    return lines


def _empty_line(section: str, has_candidates: bool) -> str:
    if has_candidates:
        return f"- {section} details omitted by brief budget"
    return "- none"


def _unique_ids(evidence_ids: Iterable[EvidenceId]) -> tuple[EvidenceId, ...]:
    seen: set[str] = set()
    result: list[EvidenceId] = []
    for evidence_id in evidence_ids:
        value = str(evidence_id)
        if value not in seen:
            seen.add(value)
            result.append(evidence_id)
    return tuple(result)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _clip(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


_INTERPRETIVE_LANGUAGE = (
    (re.compile(r"\broot[\s_-]+cause\b", re.IGNORECASE), "causal claim"),
    (re.compile(r"\bdiagnos(?:is|es|ed|ing|tic)\b", re.IGNORECASE), "interpretive claim"),
    (re.compile(r"\brepair(?:s|ed|ing)?\b", re.IGNORECASE), "action claim"),
    (re.compile(r"\bfix(?:es|ed|ing)?\b", re.IGNORECASE), "action claim"),
)


def _neutralize(value: str) -> str:
    normalized = " ".join(value.split())
    for pattern, replacement in _INTERPRETIVE_LANGUAGE:
        normalized = pattern.sub(replacement, normalized)
    return normalized
