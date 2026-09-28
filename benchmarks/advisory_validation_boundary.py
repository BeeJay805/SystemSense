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
from systemsense.reasoning.ollama import (
    OllamaReasoningProvider,
    _ReasoningAdvice,  # pyright: ignore[reportPrivateUsage]
)

Boundary = Literal[
    "pydantic_schema",
    "fitted_visible_prediction",
    "passed_initial_validation",
]


def classify_returned_advice(
    raw: Mapping[str, JsonValue],
    *,
    request: ReasoningRequest,
    prompt: str,
    schema: Mapping[str, object],
    call_index: int,
) -> dict[str, str | int]:
    """Return commitments and a bounded label; never serialize ``raw`` or error text."""

    if call_index < 1:
        raise ValueError("model call index must be positive")
    packet = cast(object, json.loads(prompt))
    if not isinstance(packet, dict):
        raise ValueError("fitted prompt must be a JSON object")
    try:
        advice = _ReasoningAdvice.model_validate(raw)
    except ValidationError:
        boundary: Boundary = "pydantic_schema"
    else:
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
    }
