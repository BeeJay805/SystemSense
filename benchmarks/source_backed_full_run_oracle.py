"""Evaluator-only synthetic recipe review after all full-run cells finish."""

from __future__ import annotations

from typing import Any

from benchmarks.source_backed_frontier_oracle import (
    _CAUSES,  # pyright: ignore[reportPrivateUsage]
    _EXPECTED_OBSERVATIONS,  # pyright: ignore[reportPrivateUsage]
)


def review_cells(cells: list[dict[str, Any]]) -> dict[str, Any]:
    reviews: list[dict[str, Any]] = []
    for cell in cells:
        case_key = str(cell["case_key"])
        selected = str(cell["selected_evidence_id"])
        source_index = int(selected.removeprefix("ev_"), 16)
        facts = cell["selected_facts"]
        compatible = tuple(
            cause
            for cause in _CAUSES[case_key]
            if facts == _EXPECTED_OBSERVATIONS[case_key][cause][source_index]
        )
        reviews.append(
            {
                "world_key": cell["world_key"],
                "case_key": case_key,
                "choice": cell["choice"],
                "selected_evidence_id": selected,
                "compatible_toy_causes_before": _CAUSES[case_key],
                "compatible_toy_causes_after": compatible or None,
                "observed_effect": (
                    "reduces_compatible_toy_causes"
                    if len(compatible) == 1
                    else "does_not_reduce_compatible_toy_causes"
                    if len(compatible) == 2
                    else "unknown"
                ),
                "supported_causal_answer": False,
                "observed_effect_scope": "synthetic_recipe_compatibility_only",
            }
        )
    return {"schema_version": 2, "classification": "evaluator_only_synthetic", "reviews": reviews}
