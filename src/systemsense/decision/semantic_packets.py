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

from systemsense.domain.ids import JsonValue
from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext

SERIALIZER_ID = "semantic_fact_packets_v1"
_MAX_PACKETS = 256
_MAX_DESCRIPTION_CHARS = 800
_MAX_EXACT_VALUE_BYTES = 160
_V2_MAX_EXACT_VALUE_BYTES = 400
_V2_MAX_DEPTH = 12
_V2_MAX_NODES_PER_FACT = 128
_ALARM = re.compile(r"critical|fatal|error|fail|denied|warning|offline|timeout|corrupt|disk", re.I)
_DIAGNOSTIC = re.compile(
    r"gpu|process|pressure|temperature|clock|throttle|utilization|working_set|cpu|memory",
    re.I,
)
_HIGH_VALUE = re.compile(r"throttle|temperature|clock|cpu_percent|working_set", re.I)
_GENERIC_BATCH_SIZE = 4
_MAX_GENERIC_PACKETS = 48
_MAX_GENERIC_BATCHES = 32


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compact_worker_packet(packet: dict[str, str]) -> dict[str, str]:
    """Present one complete fact without repeating authoritative binding fields."""

    source = cast(dict[str, object], json.loads(packet["description"]))
    if source.get("projection") == "semantic_fact_packets_v2":
        # V2 keeps a source-bound nested path and value as one typed unit.
        # Do not reinterpret a truncated value or infer any missing metadata.
        keys = (
            "packet_kind",
            "source_path",
            "source_path_sha256",
            "source_path_original_chars",
            "value",
            "value_excerpt",
            "value_sha256",
            "value_original_bytes",
            "value_quality",
            "value_selection",
            "fields_omitted",
            "unit",
            "status",
            "case_scope",
            "incident_relevant",
            "observed_at",
            "captured_at",
            "probe_id",
            "entity_hint",
            "relation_ids",
            "relation_ids_omitted",
            "limitations",
            "limitations_omitted",
            "limitations_truncated",
            "limitations_sha256",
            "redaction_applied",
            "facts_omitted",
            "nested_paths_omitted",
            "pages_omitted",
        )
        compact = {key: source[key] for key in keys if key in source}
        compact["projection"] = "laya_semantic_v2"
        return {
            "evidence_id": packet["evidence_id"],
            "page_id": packet["page_id"],
            "fragment_id": packet["fragment_id"],
            "description": _canonical(compact),
        }
    projection: dict[str, object] = {
        "projection": "laya_semantic_v1",
        "kind": source["packet_kind"],
        "entity": source.get("entity_hint"),
        "probe": source.get("probe_id"),
        "observable": source.get("metric"),
        "value": source.get("value", source.get("value_excerpt")),
        "unit": source.get("unit"),
        "value_quality": source.get("value_quality"),
        "quality": source.get("status"),
        "case_scope": source.get("case_scope"),
        "incident_relevant": source.get("incident_relevant"),
        "observed_at": source["observed_at"],
        "captured_at": source["captured_at"],
        "limitations": source.get("limitations"),
        "facts_omitted": source.get("facts_omitted"),
        "pages_omitted": source.get("pages_omitted"),
    }
    return {
        "evidence_id": packet["evidence_id"],
        "page_id": packet["page_id"],
        "fragment_id": packet["fragment_id"],
        "description": json.dumps(
            {
                key: value
                for key, value in projection.items()
                if value is not None or (key == "value" and "value" in source)
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
    }


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
                -int(bool(_HIGH_VALUE.search(path))),
                -int(bool(_DIAGNOSTIC.search(path))),
                path,
            ),
        )
    )


def _source_unit(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    unit = cast(dict[str, object], value).get("unit")
    return unit if isinstance(unit, str) and 0 < len(unit) <= 40 else None


def _entity_hint(context: EvidenceContext, path: str | None) -> str | None:
    value = context.facts.get("entity.id")
    if isinstance(value, str) and 0 < len(value) <= 80:
        return value
    if path is not None:
        segments = path.split(".")
        for depth in range(len(segments) - 1, 0, -1):
            prefix = ".".join(segments[:depth])
            for suffix in ("id", "uuid", "pid"):
                value = context.facts.get(f"{prefix}.{suffix}")
                if isinstance(value, (str, int)) and 0 < len(str(value)) <= 80:
                    return str(value)
    return None


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
    pages_omitted: int | None,
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
    if pages_omitted is not None:
        packet["pages_omitted"] = pages_omitted
    if context.limitations:
        packet["limitations"] = [item[:80] for item in context.limitations[:1]]
        packet["limitations_omitted"] = max(0, len(context.limitations) - 1)
    relation_ids = _relation_ids(context, relationships)
    if relation_ids:
        packet["relation_ids"] = list(relation_ids[:1])
        packet["relation_ids_omitted"] = max(0, len(relation_ids) - 1)
    entity_hint = _entity_hint(context, path)
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
    allow_page_omission: bool = False,
) -> tuple[dict[str, str], ...]:
    """Project up to 256 fair, stable per-fact packets for Laya's wire shape.

    A first pass gives every supplied page one packet. Remaining slots cycle
    through pages so a large page cannot eclipse unrelated evidence. Hypothesis
    check paths and explicit alarms lead within their page; other facts use a
    stable path order, independent of dict insertion order.
    """

    if not 1 <= max_packets <= _MAX_PACKETS:
        raise ValueError("semantic packet budget must be between 1 and 256")
    if len(contexts) > max_packets and not allow_page_omission:
        raise ValueError("semantic packet page count exceeds bounded attention context")
    if not contexts:
        return ()
    priorities = frozenset(priority_paths)
    paths = tuple(_fact_paths(context, priorities) for context in contexts)
    order = _page_order(len(contexts))
    if allow_page_omission and len(contexts) > max_packets:
        urgent = tuple(
            index
            for index in order
            if any(path in priorities or _DIAGNOSTIC.search(path) for path in paths[index])
        )
        # Reserve a few slots for related measurements within diagnostic
        # pages; otherwise a single first fact per page hides clocks or
        # throttle state in a large attention context.
        extra_slots = min(
            max_packets // 2, 16, sum(max(0, len(paths[index]) - 1) for index in urgent)
        )
        page_budget = max_packets - extra_slots
        urgent_limit = page_budget * 2 // 3
        first = urgent[:urgent_limit]
        first_set = set(first)
        order = (*first, *(index for index in order if index not in first_set))[:page_budget]
    pages_omitted = len(contexts) - len(order) if allow_page_omission else None
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
                    pages_omitted=pages_omitted,
                    relationships=relationships,
                ),
            }
        )
    return tuple(fragments)


def _pointer_escape(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _nested_nodes(
    value: JsonValue, *, max_nodes: int = _V2_MAX_NODES_PER_FACT
) -> tuple[tuple[tuple[str, JsonValue, int | None], ...], int]:
    """Keep bounded records whole; explicitly label partial sibling-field groups.

    A field group is an exact subset at its parent pointer, never a replacement
    for the entire source object. Array children retain their original indices.
    """
    result: list[tuple[str, JsonValue, int | None]] = []
    stack: list[tuple[str, JsonValue, int]] = [("", value, 0)]
    visited = 0
    while stack and visited < max_nodes:
        path, current, depth = stack.pop()
        visited += 1
        size = len(_canonical(current).encode("utf-8"))
        if size <= _V2_MAX_EXACT_VALUE_BYTES or depth >= _V2_MAX_DEPTH:
            result.append((path, current, None))
            continue
        if isinstance(current, dict) and not set(current) >= {"value", "unit"}:
            scalar_group: dict[str, JsonValue] = {}
            children: list[tuple[str, JsonValue, int]] = []
            for key, child in sorted(current.items()):
                child_path = f"{path}/{_pointer_escape(key)}"
                if (
                    isinstance(child, (dict, list))
                    or len(_canonical({key: child}).encode("utf-8")) > _V2_MAX_EXACT_VALUE_BYTES
                ):
                    children.append((child_path, child, depth + 1))
                    continue
                candidate = {**scalar_group, key: child}
                if len(_canonical(candidate).encode("utf-8")) > _V2_MAX_EXACT_VALUE_BYTES:
                    result.append((path, scalar_group, len(current) - len(scalar_group)))
                    scalar_group = {}
                scalar_group[key] = child
            if scalar_group:
                result.append((path, scalar_group, len(current) - len(scalar_group)))
            stack.extend(reversed(children))
            continue
        if isinstance(current, list):
            stack.extend(
                (f"{path}/{index}", current[index], depth + 1)
                for index in range(len(current) - 1, -1, -1)
            )
            continue
        result.append((path, current, None))
    return tuple(result), len(stack)


def _v2_fragment_token(path: str | None, value: object, fields_omitted: int | None) -> str:
    if fields_omitted is not None:
        return _sha256(_canonical([path, sorted(cast(dict[str, object], value))]))
    return _sha256(path or "status")


def _v2_path_priority(
    path: str, priority_paths: frozenset[str]
) -> tuple[int, int, int, int, int, str]:
    leaf = path.rsplit("/", 1)[-1].casefold()
    return (
        -int(
            any(path == priority or path.startswith(f"{priority}/") for priority in priority_paths)
        ),
        -int("/samples/" in path.casefold()),
        -int(any(token in leaf for token in ("sample", "target", "listener", "status", "outcome"))),
        -int(
            any(
                token in leaf
                for token in ("pid", "birth", "handle", "count", "unit", "window", "time")
            )
        ),
        -int(bool(_ALARM.search(leaf) or _DIAGNOSTIC.search(leaf))),
        path,
    )


def _v2_packet_description(
    context: EvidenceContext,
    *,
    page_id: str,
    source_fact_path: str | None,
    source_path: str | None,
    value: object | None,
    fields_omitted: int | None,
    omitted: int,
    nested_omitted: int,
    pages_omitted: int | None,
    relationships: Sequence[EvidenceRelation],
) -> str:
    packet: dict[str, object] = {
        "projection": "semantic_fact_packets_v2",
        "packet_kind": "fact" if source_path is not None else "status",
        "source_path": source_path,
        "status": context.status.value,
        "case_scope": context.case_scope,
        "incident_relevant": context.incident_relevant,
        "observed_at": context.observed_at.isoformat().replace("+00:00", "Z"),
        "captured_at": context.captured_at.isoformat().replace("+00:00", "Z"),
        "redaction_applied": context.redaction_applied,
        "facts_omitted": omitted,
        "nested_paths_omitted": nested_omitted,
    }
    if pages_omitted:
        packet["pages_omitted"] = pages_omitted
    if context.probe_id:
        packet["probe_id"] = context.probe_id
    if context.limitations:
        packet["limitations"] = [item[:80] for item in context.limitations[:1]]
        packet["limitations_omitted"] = max(0, len(context.limitations) - 1)
        packet["limitations_truncated"] = int(len(context.limitations[0]) > 80)
        if len(context.limitations) > 1 or packet["limitations_truncated"]:
            packet["limitations_sha256"] = _sha256(_canonical(list(context.limitations)))
    relation_ids = _relation_ids(context, relationships)
    if relation_ids:
        packet["relation_ids"] = list(relation_ids[:1])
        packet["relation_ids_omitted"] = max(0, len(relation_ids) - 1)
    if fields_omitted is not None:
        packet["value_selection"] = "fields"
        packet["fields_omitted"] = fields_omitted
    if source_path is not None:
        encoded = _canonical(value)
        raw = encoded.encode("utf-8")
        unit = _source_unit(value)
        if unit is not None:
            packet["unit"] = unit
        if len(raw) <= _V2_MAX_EXACT_VALUE_BYTES:
            packet["value"] = value
            packet["value_quality"] = "exact"
        else:
            packet["value_quality"] = "truncated"
            packet["value_excerpt"] = encoded[:48]
            packet["value_sha256"] = hashlib.sha256(raw).hexdigest()
            packet["value_original_bytes"] = len(raw)
    text = _canonical(packet)
    if len(text) > _MAX_DESCRIPTION_CHARS and packet.get("relation_ids"):
        packet["relation_ids_omitted"] = len(relation_ids)
        packet.pop("relation_ids")
        text = _canonical(packet)
    if len(text) > _MAX_DESCRIPTION_CHARS and packet.get("limitations"):
        packet.pop("limitations")
        packet.pop("limitations_truncated", None)
        packet["limitations_omitted"] = len(context.limitations)
        packet["limitations_sha256"] = _sha256(_canonical(list(context.limitations)))
        text = _canonical(packet)
    if len(text) > _MAX_DESCRIPTION_CHARS:
        # These optional annotations duplicate the source-bound outer reference;
        # absent omission counts explicitly default to zero in the V2 contract.
        packet.pop("probe_id", None)
        for key in ("facts_omitted", "nested_paths_omitted"):
            if packet.get(key) == 0:
                packet.pop(key)
        text = _canonical(packet)
    if len(text) > _MAX_DESCRIPTION_CHARS and "value" in packet:
        encoded = _canonical(packet.pop("value"))
        raw = encoded.encode("utf-8")
        packet.update(
            value_quality="truncated",
            value_excerpt=encoded[:32],
            value_sha256=hashlib.sha256(raw).hexdigest(),
            value_original_bytes=len(raw),
        )
        text = _canonical(packet)
    if len(text) > _MAX_DESCRIPTION_CHARS and packet.get("relation_ids"):
        packet["relation_ids_omitted"] = len(relation_ids)
        packet.pop("relation_ids", None)
        text = _canonical(packet)
    if len(text) > _MAX_DESCRIPTION_CHARS and packet.get("limitations"):
        limitation = cast(list[str], packet["limitations"])[0]
        packet["limitations"] = [limitation[:24]]
        packet["limitations_omitted"] = len(context.limitations)
        packet["limitations_sha256"] = _sha256(_canonical(list(context.limitations)))
        text = _canonical(packet)
    if len(text) > _MAX_DESCRIPTION_CHARS or (fields_omitted is not None and "value" not in packet):
        # A pathological nested path/value cannot abort a whole investigation.
        # Preserve status, time, and a digest of the omitted path explicitly.
        packet = {
            "projection": "semantic_fact_packets_v2",
            "packet_kind": "status",
            "page_id": page_id,
            "status": context.status.value,
            "observed_at": context.observed_at.isoformat().replace("+00:00", "Z"),
            "captured_at": context.captured_at.isoformat().replace("+00:00", "Z"),
            "redaction_applied": context.redaction_applied,
            "case_scope": context.case_scope,
            "incident_relevant": context.incident_relevant,
            "value_quality": "omitted",
            "source_path_sha256": _v2_fragment_token(source_path, value, fields_omitted),
            "source_path_original_chars": len(source_path or ""),
            "facts_omitted": max(omitted, 1),
            "nested_paths_omitted": max(nested_omitted, 1),
        }
        if context.limitations:
            packet["limitations_omitted"] = len(context.limitations)
            packet["limitations_sha256"] = _sha256(_canonical(list(context.limitations)))
        text = _canonical(packet)
        if len(text) > _MAX_DESCRIPTION_CHARS:
            raise ValueError("nested status packet cannot fit fixed provenance")
    return text


def nested_evidence_packets(
    contexts: Sequence[EvidenceContext],
    *,
    relationships: Sequence[EvidenceRelation] = (),
    priority_paths: Sequence[str] = (),
    max_packets: int = 16,
    allow_page_omission: bool = True,
) -> tuple[dict[str, str], ...]:
    """V2 nested projection. Input contexts must already be row-validated/redacted.

    Unlike V1, this explicitly projects nested JSON paths. It neither parses
    free-form prose nor manufactures a value, unit, target, or diagnosis.
    """
    if not 1 <= max_packets <= 16:
        raise ValueError("V2 packet budget must be between 1 and 16")
    if len(contexts) > max_packets and not allow_page_omission:
        raise ValueError("V2 packet page count exceeds bounded attention context")
    priorities = frozenset(priority_paths)
    per_page: list[list[tuple[str | None, str | None, object | None, int | None]]] = []
    skipped_paths: list[int] = []
    for context in contexts:
        nodes: list[tuple[str, str, object, int | None]] = []
        skipped = 0
        for fact_path, root_value in sorted(context.facts.items()):
            projected, not_visited = _nested_nodes(root_value)
            skipped += not_visited
            for relative, value, fields_omitted in projected:
                full = f"/{_pointer_escape(fact_path)}{relative}"
                nodes.append((full, fact_path, value, fields_omitted))
        nodes.sort(key=lambda row: _v2_path_priority(row[0], priorities))
        candidates: list[tuple[str | None, str | None, object | None, int | None]] = []
        if not nodes or context.status.value != "observed":
            candidates.append((None, None, None, None))
        candidates.extend(nodes)
        per_page.append(candidates)
        skipped_paths.append(skipped)
    if not contexts:
        return ()
    order = _page_order(len(contexts))
    page_rank = {
        index: min(
            (_v2_path_priority(row[0], priorities) for row in per_page[index] if row[0]),
            default=(0, 0, 0, 0, 0, ""),
        )
        for index in range(len(contexts))
    }
    order = tuple(sorted(order, key=lambda index: (page_rank[index], order.index(index))))
    if len(contexts) > max_packets:
        if not allow_page_omission:
            raise ValueError("V2 packet page count exceeds bounded attention context")
        order = order[:max_packets]
    selected: list[tuple[int, str | None, str | None, object | None, int | None]] = []
    positions = {index: 0 for index in order}

    def take_next(indices: Sequence[int], limit: int) -> int:
        added = 0
        while added < limit and len(selected) < max_packets:
            progressed = False
            for index in indices:
                position = positions[index]
                if position >= len(per_page[index]):
                    continue
                path, fact, value, fields_omitted = per_page[index][position]
                selected.append((index, path, fact, value, fields_omitted))
                positions[index] = position + 1
                added += 1
                progressed = True
                if added >= limit or len(selected) >= max_packets:
                    break
            if not progressed:
                break
        return added

    take_next(order, len(order))  # First packet for each selected page.
    # Prefer completing bounded source records over scattering status leaves
    # across very large inventories. Every selected page already has one slot.
    for index in sorted(
        order, key=lambda item: (len(per_page[item]) - positions[item], page_rank[item])
    ):
        remaining = len(per_page[index]) - positions[index]
        if remaining <= max_packets - len(selected):
            take_next((index,), remaining)
    take_next(order, max_packets - len(selected))
    counts: dict[int, int] = {}
    for index, *_ in selected:
        counts[index] = counts.get(index, 0) + 1
    fragments: list[dict[str, str]] = []
    pages_omitted = max(0, len(contexts) - len(order)) if allow_page_omission else None
    for index, source_path, fact_path, value, fields_omitted in selected:
        context = contexts[index]
        evidence_id = str(context.evidence_id)
        page_id = f"{evidence_id}:{index}"
        token = _v2_fragment_token(source_path, value, fields_omitted)
        description = _v2_packet_description(
            context,
            page_id=page_id,
            source_fact_path=fact_path,
            source_path=source_path,
            value=value,
            fields_omitted=fields_omitted,
            omitted=max(
                0,
                len(context.facts)
                - len({fact for _, fact, _, _ in per_page[index][: counts[index]]}),
            ),
            nested_omitted=max(0, len(per_page[index]) - counts[index]) + skipped_paths[index],
            pages_omitted=pages_omitted,
            relationships=relationships,
        )
        packed: object = json.loads(description)
        packed_map = cast(dict[str, object], packed)
        kind = cast(str, packed_map["packet_kind"])
        token = cast(str, packed_map.get("source_path_sha256", token))
        if kind == "fact":
            token = _v2_fragment_token(source_path, value, fields_omitted)
        fragments.append(
            {
                "evidence_id": evidence_id,
                "page_id": page_id,
                "fragment_id": f"{page_id}:{kind}:{token}",
                "description": description,
            }
        )
    return tuple(fragments)


def generic_decision_evidence_packets(
    contexts: Sequence[EvidenceContext],
    *,
    candidate_count: int,
    relationships: Sequence[EvidenceRelation] = (),
    priority_paths: Sequence[str] = (),
) -> tuple[dict[str, str], ...]:
    """Freeze a GPU-size-safe fast-decision projection with explicit omissions.

    The actual 4090 profile uses four candidates per worker microbatch. Keep
    every eligible probe; reserve its batches before granting up to 48 source
    packets. Extraordinary 128-probe menus leave no evidence batch capacity.
    """

    if not 0 <= candidate_count <= 128:
        raise ValueError("generic decision candidate count is invalid")
    probe_batches = (candidate_count + _GENERIC_BATCH_SIZE - 1) // _GENERIC_BATCH_SIZE
    remaining = _GENERIC_BATCH_SIZE * (_MAX_GENERIC_BATCHES - probe_batches)
    budget = min(_MAX_GENERIC_PACKETS, remaining)
    if budget <= 0:
        return ()
    return evidence_packets(
        contexts,
        relationships=relationships,
        priority_paths=priority_paths,
        max_packets=budget,
        allow_page_omission=True,
    )
