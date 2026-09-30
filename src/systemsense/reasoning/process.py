"""Conservative Basic-route findings from focused exact-process evidence."""

from __future__ import annotations

from typing import cast

from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.evidence.targets import exact_executable_name
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import ReasoningRequest


def assess_named_process(request: ReasoningRequest) -> tuple[str, tuple[EvidenceId, ...]] | None:
    """Report a sampled fact only when the focused inventory names one exact executable."""

    name = exact_executable_name(request.objective)
    if name is None:
        return None
    sources = tuple(
        item
        for item in request.evidence_context
        if item.probe_id == "application.snapshot"
        and item.case_scope == "current_case"
        and item.status is EvidenceContextStatus.OBSERVED
        and _search(item, name) is not None
    )
    if not sources:
        return None
    source = max(sources, key=lambda item: (item.captured_at, str(item.evidence_id)))
    search = _search(source, name)
    assert search is not None
    status = search.get("status")
    captured = source.facts.get("collection_completed_at")
    when = captured if isinstance(captured, str) else source.captured_at.isoformat()
    if status == "no_matching_process_in_saved_complete_table":
        omitted = source.facts.get("omitted_counts")
        if (
            search.get("matched_row_count") != 0
            or search.get("omitted_process_count") != 0
            or not isinstance(omitted, dict)
            or omitted.get("processes") != 0
            or source.facts.get("collection_status") != "available"
        ):
            return None
        return (
            f"The exact process {name} was not observed running at the saved snapshot time "
            f"({when}). Its earlier or later state and the cause of the report remain unknown.",
            (source.evidence_id,),
        )
    if status != "matching_process_observed":
        return None
    rows = tuple(
        cast("dict[str, JsonValue]", value)
        for key, value in source.facts.items()
        if key.startswith("processes.")
        and isinstance(value, dict)
        and _matches_name(value.get("name"), name)
        and isinstance(value.get("pid"), int)
        and not isinstance(value.get("pid"), bool)
        and isinstance(value.get("creation_time"), str)
    )
    if search.get("matched_row_count") != len(rows) or not rows:
        return None
    if len(rows) == 1:
        sampled = _matching_pressure(request, name, rows[0])
        if sampled is not None:
            pressure, values, ended, core_values = sampled
            measurements = " and ".join(f"{value:.1f}%" for value in values)
            cores = (
                "; equivalent to "
                + " and ".join(f"{value:.2f}" for value in core_values)
                + " logical cores (1.0 is one core's CPU capacity)"
                if core_values is not None
                else "; logical-core usage was not recorded"
            )
            activity = "No measurable CPU use" if all(value == 0 for value in values) else "CPU use"
            return (
                f"The exact process {name} (PID {rows[0]['pid']}) measured {measurements} "
                f"of total logical-processor CPU capacity{cores}, during identity-bound "
                f"intervals ending {ended}. {activity} was observed "
                "in those intervals; current activity and the cause of the reported slowness "
                "remain unknown.",
                (source.evidence_id, pressure.evidence_id),
            )
    return (
        f"The exact process {name} was present in the saved process inventory at {when}. "
        "That does not establish its health, earlier or current state, or why it may have stopped.",
        (source.evidence_id,),
    )


def _search(item: EvidenceContext, name: str) -> dict[str, JsonValue] | None:
    searches = item.facts.get("target_process_search")
    if not isinstance(searches, list) or len(searches) != 1:
        return None
    raw = searches[0]
    if not isinstance(raw, dict) or not _matches_name(raw.get("name"), name):
        return None
    return cast("dict[str, JsonValue]", raw)


def _matching_pressure(
    request: ReasoningRequest, name: str, row: dict[str, JsonValue]
) -> tuple[EvidenceContext, tuple[float, ...], str, tuple[float, ...] | None] | None:
    for item in sorted(
        request.evidence_context,
        key=lambda context: (context.captured_at, str(context.evidence_id)),
        reverse=True,
    ):
        if (
            item.probe_id != "application.target_pressure"
            or item.case_scope != "current_case"
            or item.status is not EvidenceContextStatus.OBSERVED
        ):
            continue
        pressure = item.facts.get("target_pressure")
        if not isinstance(pressure, dict) or pressure.get("status") != "available":
            continue
        if (
            pressure.get("target_pid") != row["pid"]
            or pressure.get("target_creation_time") != row["creation_time"]
        ):
            continue
        samples = pressure.get("samples")
        ended = pressure.get("window_ended_at")
        if not isinstance(samples, list) or not isinstance(ended, str):
            continue
        measured: list[float] = []
        core_values: list[float] = []
        count = pressure.get("logical_cpu_count")
        valid = True
        for raw in samples:
            if not isinstance(raw, dict) or not _matches_name(raw.get("name"), name):
                valid = False
                break
            if raw.get("delta_status") != "measured":
                continue
            value = raw.get("cpu_percent")
            if (
                raw.get("status") != "available"
                or not isinstance(value, int | float)
                or isinstance(value, bool)
                or not 0 <= value <= 100
            ):
                valid = False
                break
            measured.append(float(value))
            cores = raw.get("cpu_logical_cores")
            if (
                isinstance(count, int)
                and not isinstance(count, bool)
                and count > 0
                and isinstance(cores, int | float)
                and not isinstance(cores, bool)
                and 0 <= cores <= count
                and abs(cores / count * 100 - value) <= 0.001
            ):
                core_values.append(float(cores))
        if valid and measured:
            return (
                item,
                tuple(measured),
                ended,
                tuple(core_values) if len(core_values) == len(measured) else None,
            )
    return None


def _matches_name(value: JsonValue, name: str) -> bool:
    return isinstance(value, str) and value.casefold() == name
