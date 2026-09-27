"""Post-run synthetic cause review; never imported by the scripted ranker."""

from __future__ import annotations

from typing import Any

_CAUSES = {
    "source-network-browser-001": (
        "browser_proxy_configuration",
        "external_site_outage",
    ),
    "source-application-performance-001": (
        "local_viewer_render_delay",
        "external_document_source_delay",
    ),
}

_EXPECTED_OBSERVATIONS = {
    "source-network-browser-001": {
        "browser_proxy_configuration": {
            49: {
                "affected_browser_task": "open synthetic site item in this browser profile",
                "browser_route_result": "timeout",
                "direct_same_origin_result": "reachable",
                "proxy_enabled": True,
                "proxy_endpoint": "127.0.0.1:9",
            },
            50: {"cpu_peak_percent": 92, "duration_ms": 50},
        },
        "external_site_outage": {
            49: {
                "affected_browser_task": "open synthetic site item in this browser profile",
                "browser_route_result": "timeout",
                "direct_same_origin_result": "unreachable",
                "proxy_enabled": False,
                "proxy_endpoint": None,
            },
            50: {"cpu_peak_percent": 92, "duration_ms": 50},
        },
    },
    "source-application-performance-001": {
        "local_viewer_render_delay": {
            49: {
                "affected_viewer_task": "open synthetic document item in the viewer",
                "open_to_interactive_ms": 480,
                "viewer_render_p95_ms": 430,
                "external_fetch_p95_ms": 40,
            },
            50: {"storage_warning_count": 1, "current_queue_length": 0},
        },
        "external_document_source_delay": {
            49: {
                "affected_viewer_task": "open synthetic document item in the viewer",
                "open_to_interactive_ms": 480,
                "viewer_render_p95_ms": 40,
                "external_fetch_p95_ms": 430,
            },
            50: {"storage_warning_count": 1, "current_queue_length": 0},
        },
    },
}


def review_cells(cells: list[dict[str, Any]]) -> dict[str, Any]:
    """Label only a selected and read-back exact synthetic observation."""

    reviews: list[dict[str, Any]] = []
    for cell in cells:
        case_key = str(cell["case_key"])
        selected = str(cell["selected_evidence_id"])
        facts = cell["selected_facts"]
        source_index = int(selected.removeprefix("ev_"), 16)
        if source_index in (49, 50):
            compatible_after = tuple(
                cause
                for cause in _CAUSES[case_key]
                if facts == _EXPECTED_OBSERVATIONS[case_key][cause][source_index]
            )
            effect = (
                "reduces_compatible_toy_causes"
                if 0 < len(compatible_after) < len(_CAUSES[case_key])
                else "does_not_reduce_compatible_toy_causes"
                if len(compatible_after) == len(_CAUSES[case_key])
                else "unknown"
            )
            if not compatible_after:
                compatible_after = None
        else:
            effect, compatible_after = "unknown", None
        reviews.append(
            {
                "case_key": case_key,
                "policy": cell["policy"],
                "selected_evidence_id": selected,
                "observed_effect": effect,
                "compatible_toy_causes_before": _CAUSES[case_key],
                "compatible_toy_causes_after": compatible_after,
                "supported_answer_inferred": False,
                "observed_effect_scope": "synthetic_recipe_compatibility_only",
                "affected_task_outcome": "synthetic_fact_only_real_task_unbound",
            }
        )
    return {"schema_version": 1, "classification": "synthetic_evaluator_only", "reviews": reviews}
