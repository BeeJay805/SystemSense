"""Fair bounded pages of exact persisted facts for the fast attention brain."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterator

from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import JsonValue
from systemsense.evidence.fact_paths import context_fact, extend_source_path
from systemsense.inference.context import EvidenceContext
from systemsense.storage.sqlite_store import SQLiteStore


def attention_pages(
    store: SQLiteStore,
    context: tuple[EvidenceContext, ...],
    *,
    max_pages: int = 256,
) -> tuple[EvidenceContext, ...]:
    """Round-robin exact fact pages across already case/time-scoped observations.

    Repeated IDs identify excerpts of one observation, not independent evidence.
    Arrays are split at item boundaries; the full record remains in SQLite.
    """
    if not 1 <= max_pages <= 256:
        raise ValueError("invalid attention page limit")
    queues: deque[tuple[EvidenceContext, Iterator[dict[str, JsonValue]]]] = deque()
    for item in context:
        row = store.connection.execute(
            "SELECT record_json FROM evidence WHERE evidence_id = ?",
            (str(item.evidence_id),),
        ).fetchone()
        if row is None:
            queues.append((item, iter((item.facts,))))
            continue
        payload = json.loads(str(row[0]))
        values = item.facts
        if isinstance(payload, dict) and "statement_kind" in payload:
            record = EvidenceRecord.model_validate_json(str(row[0]))
            values = {}
            for fact in record.facts:
                value: JsonValue = fact.value
                if fact.unit is not None:
                    value = {"value": fact.value, "unit": fact.unit}
                values[fact.name] = value
        queues.append((item, fact_pages(values)))
    result: list[EvidenceContext] = []
    while queues and len(result) < max_pages:
        item, pages = queues.popleft()
        try:
            facts = next(pages)
        except StopIteration:
            continue
        result.append(item.model_copy(update={"facts": facts}))
        queues.append((item, pages))
    if queues and result:
        result[-1] = result[-1].model_copy(
            update={
                "limitations": (
                    *result[-1].limitations[:15],
                    "Attention page limit reached; some persisted facts were not ranked.",
                ),
            }
        )
    return tuple(result)


def _leaves(path: str, value: JsonValue) -> Iterator[tuple[str, JsonValue]]:
    encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
    # Laya's semantic packet keeps an exact value only through 160 bytes.
    # Keep compact related fields together (notably value/unit pairs), but
    # split a larger object at member boundaries before packet serialization.
    if len(encoded) <= 160:
        key, projected, _exact = context_fact(
            path,
            value,
            max_bytes=8000,
            allow_path_omission=True,
        )
        yield key, projected
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _leaves(extend_source_path(path, key), child)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaves(extend_source_path(path, index), child)
    elif len(encoded) <= 8000:
        # A scalar cannot be split without changing its value. Keep it exact
        # when it still fits the EvidenceContext byte bound, even if it occupies
        # a page by itself.
        key, projected, _exact = context_fact(
            path,
            value,
            max_bytes=8000,
            allow_path_omission=True,
        )
        yield key, projected
    else:
        # The scalar cannot fit a model context. The persisted observation is
        # untouched and the page carries an explicit omission instead.
        key, projected, _exact = context_fact(
            extend_source_path(path, "omitted"),
            "Oversized scalar retained in local evidence.",
            max_bytes=8000,
            allow_path_omission=True,
        )
        yield key, projected


def fact_pages(values: dict[str, JsonValue]) -> Iterator[dict[str, JsonValue]]:
    page: dict[str, JsonValue] = {}
    for name, value in values.items():
        for path, child in _leaves(extend_source_path("", name), value):
            trial = {**page, path: child}
            if page and (len(trial) > 24 or len(json.dumps(trial).encode("utf-8")) > 6000):
                yield page
                page = {}
            page[path] = child
    yield page
