"""Classify a returned local advisory in memory without retaining its content.

The caller records the returned receipt alongside its model-call order. This
checks only the two boundaries that can trigger the provider's validation retry;
``passed_initial_validation`` does not claim final response acceptance.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Literal, cast

from pydantic import ValidationError

from systemsense.domain.ids import JsonValue
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningValidationError
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.reasoning.structured import (
    _ReasoningAdvice,  # pyright: ignore[reportPrivateUsage]
)

Boundary = Literal[
    "pydantic_schema",
    "fitted_visible_prediction",
    "passed_initial_validation",
]

_VISIBLE_FIELDS = frozenset(
    {
        "summary",
        "hypotheses",
        "hypothesis_id",
        "statement",
        "status",
        "supporting_evidence_ids",
        "contradicting_evidence_ids",
        "missing_evidence_ids",
        "distinguishing_probe_ids",
        "expected_facts",
        "probe_id",
        "fact_name",
        "expected_value",
        "requested_evidence_ids",
        "requested_details",
        "evidence_id",
        "match_literals",
        "cancelled_probe_ids",
        "request_next_catalog_page",
    }
)
_ERROR_TYPES = frozenset(
    {
        "missing",
        "extra_forbidden",
        "string_too_short",
        "string_too_long",
        "string_pattern_mismatch",
        "string_type",
        "list_type",
        "tuple_type",
        "bool_type",
        "int_type",
        "literal_error",
        "enum",
        "model_type",
        "dict_type",
        "value_error",
        "greater_than_equal",
        "less_than_equal",
        "too_long",
        "too_short",
    }
)


def _safe_loci(error: ValidationError) -> tuple[tuple[str, str], ...]:
    """Retain only bounded schema coordinates and known error categories."""

    result: list[tuple[str, str]] = []
    for entry in error.errors(include_input=False, include_context=False, include_url=False)[:4]:
        location = entry.get("loc", ())
        parts = [
            "item" if isinstance(part, int) else part if part in _VISIBLE_FIELDS else "field"
            for part in location[:5]
        ]
        error_type = entry.get("type")
        result.append(
            (
                ".".join(parts) if parts else "root",
                error_type if error_type in _ERROR_TYPES else "other",
            )
        )
    return tuple(result)


def classify_returned_advice(
    raw: Mapping[str, JsonValue],
    *,
    request: ReasoningRequest,
    prompt: str,
    schema: Mapping[str, object],
    call_index: int,
) -> dict[str, str | int | tuple[tuple[str, str], ...]]:
    """Return commitments and a bounded label; never serialize ``raw`` or error text."""

    if call_index < 1:
        raise ValueError("model call index must be positive")
    packet = cast(object, json.loads(prompt))
    if not isinstance(packet, dict):
        raise ValueError("fitted prompt must be a JSON object")
    try:
        advice = _ReasoningAdvice.model_validate(raw)
    except ValidationError as error:
        boundary: Boundary = "pydantic_schema"
        validation_loci = _safe_loci(error)
    else:
        validation_loci = ()
        try:
            OllamaReasoningProvider._validate_visible_predictions(  # pyright: ignore[reportPrivateUsage]
                advice, cast(dict[str, object], packet), request
            )
        except ReasoningValidationError:
            boundary = "fitted_visible_prediction"
        else:
            boundary = "passed_initial_validation"
    return {
        "call_index": call_index,
        "request_sha256": hashlib.sha256(request.model_dump_json().encode()).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "schema_sha256": hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest(),
        "validation_boundary": boundary,
        "validation_loci": validation_loci,
    }
