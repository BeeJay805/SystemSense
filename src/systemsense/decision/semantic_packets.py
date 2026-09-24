"""Bounded, provenance-preserving per-fact packets for advisory attention.

The packet serializer never infers a unit, target, or causal relationship. It
uses only already-redacted EvidenceContext facts and relationship IDs whose
provenance explicitly names that evidence. Omissions and scalar truncation are
visible; packet ranking remains advisory, not a measurement or diagnosis.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import cast

from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext

SERIALIZER_ID = "semantic_fact_packets_v1"
_MAX_PACKETS = 256
_MAX_DESCRIPTION_CHARS = 800
_MAX_EXACT_VALUE_BYTES = 160
_ALARM = re.compile(r"critical|fatal|error|fail|denied|warning|offline|timeout|corrupt|disk", re.I)


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _page_order(count: int) -> tuple[int, ...]:
    """Place a spread of late pages in the first Laya microbatch."""

    first_batch = min(20, count)
    sampled = (
        [index * (count - 1) // (first_batch - 1) for index in range(first_batch)]
        if first_batch > 1
        else list(range(first_batch))
    )
    seen = set(sampled)
    return (*sampled, *(index for index in range(count) if index not in seen))


def _fact_paths(context: EvidenceContext, priority_paths: frozenset[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            context.facts,
            key=lambda path: (
                -int(path in priority_paths),
                -int(bool(_ALARM.search(path))),
                path,
            ),
        )
    )


def _source_unit(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    unit = cast(dict[str, object], value).get("unit")
    return unit if isinstance(unit, str) and 0 < len(unit) <= 40 else None


def _entity_hint(context: EvidenceContext) -> str | None:
    value = context.facts.get("entity.id")
    return value if isinstance(value, str) and 0 < len(value) <= 80 else None


def _relation_ids(
    context: EvidenceContext, relationships: Sequence[EvidenceRelation]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                relation.relation_id
                for relation in relationships
                if context.evidence_id in relation.evidence_ids
            }
        )
    )


def _packet_description(
    context: EvidenceContext,
    *,
    page_id: str,
    path: str | None,
    omitted: int,
    relationships: Sequence[EvidenceRelation],
) -> str:
    packet: dict[str, object] = {
        "projection": SERIALIZER_ID,
        "packet_kind": "fact" if path is not None else "status",
        "evidence_id": str(context.evidence_id),
        "page_id": page_id,
        "probe_id": context.probe_id,
        "metric": path,
        "unit": None,
        "status": context.status.value,
        "case_scope": context.case_scope,
        "incident_relevant": context.incident_relevant,
        "observed_at": context.observed_at.isoformat(),
        "captured_at": context.captured_at.isoformat(),
        "redaction_applied": context.redaction_applied,
        "facts_omitted": omitted,
    }
    if context.limitations:
        packet["limitations"] = [item[:80] for item in context.limitations[:1]]
        packet["limitations_omitted"] = max(0, len(context.limitations) - 1)
    relation_ids = _relation_ids(context, relationships)
    if relation_ids:
        packet["relation_ids"] = list(relation_ids[:1])
        packet["relation_ids_omitted"] = max(0, len(relation_ids) - 1)
    entity_hint = _entity_hint(context)
    if entity_hint is not None:
        packet["entity_hint"] = entity_hint
    if path is not None:
        value = context.facts[path]
        encoded = _canonical(value)
        encoded_bytes = encoded.encode("utf-8")
        packet["unit"] = _source_unit(value)
        if len(encoded_bytes) <= _MAX_EXACT_VALUE_BYTES:
            packet["value"] = value
            packet["value_quality"] = "exact"
        else:
            packet["value_quality"] = "truncated"
            packet["value_excerpt"] = encoded[:70]
            packet["value_sha256"] = hashlib.sha256(encoded_bytes).hexdigest()
            packet["value_original_bytes"] = len(encoded_bytes)

    def encode() -> str:
        return _canonical(packet)

    # Optional hints lose precedence to exact metric/value/time and explicit
    # quality. Each dropped field has an omission count in the same packet.
    if len(encode()) > _MAX_DESCRIPTION_CHARS and packet.get("relation_ids"):
        packet["relation_ids"] = []
        packet["relation_ids_omitted"] = len(relation_ids)
    if len(encode()) > _MAX_DESCRIPTION_CHARS and packet.get("limitations"):
        first = context.limitations[0]
        if first.startswith("Source time "):
            packet["limitations"] = [first[:80]]
            packet["limitations_omitted"] = max(0, len(context.limitations) - 1)
        else:
            packet["limitations"] = []
            packet["limitations_omitted"] = len(context.limitations)
    if len(encode()) > _MAX_DESCRIPTION_CHARS:
        packet.pop("entity_hint", None)
    if len(encode()) > _MAX_DESCRIPTION_CHARS and path is not None and "value" in packet:
        value_json = _canonical(packet.pop("value"))
        raw = value_json.encode("utf-8")
        packet["value_quality"] = "truncated"
        packet["value_excerpt"] = value_json[:50]
        packet["value_sha256"] = hashlib.sha256(raw).hexdigest()
        packet["value_original_bytes"] = len(raw)
    if len(encode()) > _MAX_DESCRIPTION_CHARS and "value_excerpt" in packet:
        packet["value_excerpt"] = cast(str, packet["value_excerpt"])[:20]
    if len(encode()) > _MAX_DESCRIPTION_CHARS:
        # The wire page ID starts with the complete evidence ID. Avoid
        # duplicating it inside the description under extreme source paths.
        packet.pop("evidence_id", None)
    if len(encode()) > _MAX_DESCRIPTION_CHARS and context.case_scope == "unspecified":
        packet.pop("case_scope", None)
    if (
        len(encode()) > _MAX_DESCRIPTION_CHARS
        and context.incident_relevant is None
        and not (context.limitations and context.limitations[0].startswith("Source time "))
    ):
        packet.pop("incident_relevant", None)
    if len(encode()) > _MAX_DESCRIPTION_CHARS:
        packet.pop("redaction_applied", None)
    if len(encode()) > _MAX_DESCRIPTION_CHARS and packet.get("unit") is None:
        packet.pop("unit", None)
    result = encode()
    if len(result) > _MAX_DESCRIPTION_CHARS:
        raise ValueError("semantic fact packet cannot fit mandatory provenance")
    return result


def evidence_packets(
    contexts: Sequence[EvidenceContext],
    *,
    relationships: Sequence[EvidenceRelation] = (),
    priority_paths: Sequence[str] = (),
    max_packets: int = _MAX_PACKETS,
) -> tuple[dict[str, str], ...]:
    """Project up to 256 fair, stable per-fact packets for Laya's wire shape.

    A first pass gives every supplied page one packet. Remaining slots cycle
    through pages so a large page cannot eclipse unrelated evidence. Hypothesis
    check paths and explicit alarms lead within their page; other facts use a
    stable path order, independent of dict insertion order.
    """

    if not 1 <= max_packets <= _MAX_PACKETS:
        raise ValueError("semantic packet budget must be between 1 and 256")
    if len(contexts) > max_packets:
        raise ValueError("semantic packet page count exceeds bounded attention context")
    if not contexts:
        return ()
    priorities = frozenset(priority_paths)
    order = _page_order(len(contexts))
    paths = tuple(_fact_paths(context, priorities) for context in contexts)
    page_items = tuple(page_paths if page_paths else (None,) for page_paths in paths)
    selected: list[tuple[int, str | None]] = []
    for depth in range(max(map(len, page_items), default=0)):
        for page_index in order:
            if depth < len(page_items[page_index]):
                selected.append((page_index, page_items[page_index][depth]))
                if len(selected) == max_packets:
                    break
        if len(selected) == max_packets:
            break
    selected_counts: dict[int, int] = {}
    for page_index, path in selected:
        if path is not None:
            selected_counts[page_index] = selected_counts.get(page_index, 0) + 1
    fragments: list[dict[str, str]] = []
    for page_index, path in selected:
        context = contexts[page_index]
        evidence_id = str(context.evidence_id)
        page_id = f"{evidence_id}:{page_index}"
        fragment_id = (
            f"{page_id}:fact:{_sha256(path)}" if path is not None else f"{page_id}:status:0"
        )
        fragments.append(
            {
                "evidence_id": evidence_id,
                "page_id": page_id,
                "fragment_id": fragment_id,
                "description": _packet_description(
                    context,
                    page_id=page_id,
                    path=path,
                    omitted=len(paths[page_index]) - selected_counts.get(page_index, 0),
                    relationships=relationships,
                ),
            }
        )
    return tuple(fragments)
