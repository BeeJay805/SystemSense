"""Lossless, collision-resistant projection of persisted source paths."""

from __future__ import annotations

import hashlib
import json
import re

from systemsense.domain.ids import JsonValue

_PLAIN_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")


def extend_source_path(path: str, segment: str | int) -> str:
    """Append one unambiguous segment while keeping ordinary paths readable."""

    if isinstance(segment, int):
        rendered = str(segment)
    elif _PLAIN_SEGMENT.fullmatch(segment):
        rendered = segment
    else:
        rendered = f"[{json.dumps(segment, ensure_ascii=False, separators=(',', ':'))}]"
    return f"{path}.{rendered}" if path else rendered


def context_fact(
    source_path: str,
    value: JsonValue,
    *,
    max_bytes: int,
    allow_path_omission: bool,
) -> tuple[str, JsonValue, bool]:
    """Return a schema-safe fact key and value without silently clipping paths.

    The boolean reports whether both the exact source path and value are present.
    """

    if 1 <= len(source_path) <= 120 and all(
        character.isalnum() or character in "_.-" for character in source_path
    ):
        return source_path, value, True
    digest = hashlib.sha256(source_path.encode("utf-8")).hexdigest()
    fact_key = f"source_path.{digest}"
    wrapper: JsonValue = {"source_path": source_path, "value": value}
    if _encoded_size({fact_key: wrapper}) <= max_bytes:
        return fact_key, wrapper, True
    if not allow_path_omission:
        return fact_key, wrapper, False
    bounded: JsonValue = {
        "source_path_sha256": digest,
        "value": value,
        "limitation": "Exact source path omitted from this page; retained in local evidence.",
    }
    if _encoded_size({fact_key: bounded}) <= max_bytes:
        return fact_key, bounded, False
    return (
        fact_key,
        {
            "source_path_sha256": digest,
            "limitation": "Exact source path and oversized value retained in local evidence.",
        },
        False,
    )


def _encoded_size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
