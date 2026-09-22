"""Bounded exact-target and literal-detail retrieval inside admitted evidence."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator

from pydantic import Field, ValidationError

from systemsense.domain.evidence import EvidenceRecord, FrozenModel
from systemsense.domain.ids import JsonValue
from systemsense.evidence.fact_paths import context_fact, extend_source_path
from systemsense.inference.context import EvidenceContext
from systemsense.reasoning.contracts import EvidenceDetailRequest
from systemsense.storage.sqlite_store import SQLiteStore

_IPV4_PORT = re.compile(r"(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5})(?![0-9])")
_PID = re.compile(r"\bpid\s*[:#]?\s*([0-9]{1,10})\b", re.IGNORECASE)
_MAX_SCANNED_OBJECTS = 2048
_MAX_MATCHES = 16
_MAX_SELECTED_FACT_BYTES = 8000
_SOURCE_METADATA_FIELDS = (
    "omitted_listener_count",
    "omitted_counts",
    "collection_status",
)


class TargetEvidenceSelection(FrozenModel):
    """Exact persisted excerpts selected without creating new observations."""

    context: tuple[EvidenceContext, ...] = Field(default=(), max_length=16)
    matched_row_paths: tuple[str, ...] = Field(default=(), max_length=16)
    matched_request_keys: tuple[str, ...] = Field(default=(), max_length=4)
    notes: tuple[str, ...] = Field(default=(), max_length=8)
    scanned_object_count: int = Field(default=0, ge=0, le=_MAX_SCANNED_OBJECTS)
    truncated: bool = False


def select_target_evidence(
    store: SQLiteStore,
    scoped_context: tuple[EvidenceContext, ...],
    objective: str,
) -> TargetEvidenceSelection:
    """Select complete rows matching literal IPv4:port or ``PID n`` targets."""

    endpoints, pids = _strict_targets(objective)
    if not endpoints and not pids:
        return TargetEvidenceSelection(
            notes=(
                "No supported exact IPv4:port or PID literal was present; "
                "no target evidence was selected.",
            )
        )
    matches: dict[str, dict[str, JsonValue]] = {}
    values_by_id: dict[str, dict[str, JsonValue]] = {}
    matched_paths: list[str] = []
    scanned = 0
    truncated = False
    stop = False
    for item in scoped_context:
        evidence_key = str(item.evidence_id)
        values = _persisted_facts(store, item)
        values_by_id[evidence_key] = values
        for path, value in _atomic_objects(values):
            if scanned >= _MAX_SCANNED_OBJECTS:
                truncated = True
                stop = True
                break
            scanned += 1
            if not isinstance(value, dict) or not _strict_row_match(value, endpoints, pids):
                continue
            selected = matches.setdefault(evidence_key, {})
            if not _append_exact_fact(selected, path, value):
                truncated = True
                continue
            matched_paths.append(f"{evidence_key}:{path}")
            if len(matched_paths) >= _MAX_MATCHES:
                truncated = True
                stop = True
                break
        if stop:
            break
    contexts = _matched_contexts(scoped_context, matches, values_by_id, strict_identity=True)
    notes = [
        f"Scanned {scanned} bounded atomic objects from already scoped evidence.",
    ]
    if contexts:
        notes.append(
            "Exact target matches are positive observations only; they do not prove sole "
            "ownership, complete table coverage, or causality."
        )
    elif truncated:
        notes.append(
            "No exact match was returned before the scan limit; later objects were not inspected."
        )
    else:
        notes.append("No exact persisted row matched the literal target; no entity was guessed.")
    if truncated:
        notes.append(
            "Target detail scan or output limit was reached; additional matches may exist."
        )
    return TargetEvidenceSelection(
        context=contexts,
        matched_row_paths=tuple(matched_paths),
        notes=tuple(notes),
        scanned_object_count=scanned,
        truncated=truncated,
    )


def retrieve_details(
    store: SQLiteStore,
    scoped_context: tuple[EvidenceContext, ...],
    requests: tuple[EvidenceDetailRequest, ...],
) -> TargetEvidenceSelection:
    """Find complete atomic objects containing every requested plain literal.

    Matching is case-insensitive substring retrieval, not identity or causal proof.
    Only evidence IDs already present in ``scoped_context`` may be searched.
    """

    if len(requests) > 4:
        raise ValueError("detail retrieval accepts at most four requests")
    scoped_by_id = {str(item.evidence_id): item for item in scoped_context}
    if any(str(request.evidence_id) not in scoped_by_id for request in requests):
        raise ValueError("detail request references evidence outside scoped context")
    request_by_evidence: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
    for request in requests:
        request_by_evidence.setdefault(str(request.evidence_id), []).append(
            (
                request.key(),
                tuple(value.casefold() for value in request.match_literals),
            )
        )

    matches: dict[str, dict[str, JsonValue]] = {}
    values_by_id: dict[str, dict[str, JsonValue]] = {}
    matched_paths: list[str] = []
    matched_request_keys: set[str] = set()
    scanned = 0
    truncated = False
    stop = False
    for item in scoped_context:
        evidence_key = str(item.evidence_id)
        literal_sets = request_by_evidence.get(evidence_key)
        if literal_sets is None:
            continue
        values = _persisted_facts(store, item)
        values_by_id[evidence_key] = values
        for path, value in _atomic_objects(values):
            if scanned >= _MAX_SCANNED_OBJECTS:
                truncated = True
                stop = True
                break
            scanned += 1
            serialized = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).casefold()
            matching_keys = tuple(
                request_key
                for request_key, literals in literal_sets
                if all(literal in serialized for literal in literals)
            )
            if not matching_keys:
                continue
            selected = matches.setdefault(evidence_key, {})
            if not _append_exact_fact(selected, path, value):
                truncated = True
                continue
            matched_request_keys.update(matching_keys)
            matched_paths.append(f"{evidence_key}:{path}")
            if len(matched_paths) >= _MAX_MATCHES:
                truncated = True
                stop = True
                break
        if stop:
            break
    contexts = _matched_contexts(scoped_context, matches, values_by_id, strict_identity=False)
    notes = [
        f"Scanned {scanned} bounded atomic objects from {len(request_by_evidence)} "
        "requested scoped observations.",
        "Detail matching uses case-insensitive plain substrings and is not identity or "
        "causal proof.",
    ]
    if not contexts and not truncated:
        notes.append(
            "No complete atomic object contained all requested literals; no entity was guessed."
        )
    if truncated:
        notes.append("Detail scan limit was reached; later objects or matches were not inspected.")
    return TargetEvidenceSelection(
        context=contexts,
        matched_row_paths=tuple(matched_paths),
        matched_request_keys=tuple(
            request.key() for request in requests if request.key() in matched_request_keys
        ),
        notes=tuple(notes),
        scanned_object_count=scanned,
        truncated=truncated,
    )


def _strict_targets(objective: str) -> tuple[frozenset[tuple[str, int]], frozenset[int]]:
    endpoints: set[tuple[str, int]] = set()
    for match in _IPV4_PORT.finditer(objective):
        try:
            address = str(ipaddress.IPv4Address(match.group(1)))
            port = int(match.group(2))
        except (ipaddress.AddressValueError, ValueError):
            continue
        if 1 <= port <= 65_535:
            endpoints.add((address, port))
    pids = frozenset(pid for match in _PID.finditer(objective) if (pid := int(match.group(1))) > 0)
    return frozenset(endpoints), pids


def _strict_row_match(
    value: dict[str, JsonValue],
    endpoints: frozenset[tuple[str, int]],
    pids: frozenset[int],
) -> bool:
    raw_address = value.get("local_address")
    raw_port = value.get("local_port")
    endpoint_match = False
    if (
        isinstance(raw_address, str)
        and isinstance(raw_port, int)
        and not isinstance(raw_port, bool)
    ):
        try:
            endpoint_match = (str(ipaddress.IPv4Address(raw_address)), raw_port) in endpoints
        except ipaddress.AddressValueError:
            endpoint_match = False
    raw_pid = value.get("pid")
    pid_match = isinstance(raw_pid, int) and not isinstance(raw_pid, bool) and raw_pid in pids
    return endpoint_match or pid_match


def _persisted_facts(
    store: SQLiteStore,
    context: EvidenceContext,
) -> dict[str, JsonValue]:
    row = store.connection.execute(
        "SELECT record_json FROM evidence WHERE evidence_id = ?",
        (str(context.evidence_id),),
    ).fetchone()
    if row is None:
        return context.facts
    try:
        record = EvidenceRecord.model_validate_json(str(row[0]))
    except (ValidationError, ValueError):
        return context.facts
    return {fact.name: fact.value for fact in record.facts}


def _atomic_objects(values: dict[str, JsonValue]) -> Iterator[tuple[str, JsonValue]]:
    for name, value in values.items():
        if name in _SOURCE_METADATA_FIELDS:
            continue
        yield from _walk_atomic(extend_source_path("", name), value)


def _walk_atomic(path: str, value: JsonValue) -> Iterator[tuple[str, JsonValue]]:
    if isinstance(value, list):
        for index, child in enumerate(value):
            child_path = extend_source_path(path, index)
            if isinstance(child, list):
                yield from _walk_atomic(child_path, child)
            elif isinstance(child, dict) and len(json.dumps(child).encode("utf-8")) > 8000:
                yield from _walk_atomic(child_path, child)
            else:
                yield child_path, child
        return
    if isinstance(value, dict) and len(json.dumps(value).encode("utf-8")) > 8000:
        for name, child in value.items():
            yield from _walk_atomic(extend_source_path(path, name), child)
        return
    yield path, value


def _append_exact_fact(
    selected: dict[str, JsonValue],
    path: str,
    value: JsonValue,
) -> bool:
    fact_key, projected, exact = context_fact(
        path,
        value,
        max_bytes=_MAX_SELECTED_FACT_BYTES,
        allow_path_omission=False,
    )
    if not exact or fact_key in selected:
        return False
    candidate = {**selected, fact_key: projected}
    if len(candidate) > 30:
        return False
    if len(json.dumps(candidate, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > (
        _MAX_SELECTED_FACT_BYTES
    ):
        return False
    selected[fact_key] = projected
    return True


def _matched_contexts(
    scoped_context: tuple[EvidenceContext, ...],
    matches: dict[str, dict[str, JsonValue]],
    values_by_id: dict[str, dict[str, JsonValue]],
    *,
    strict_identity: bool,
) -> tuple[EvidenceContext, ...]:
    result: list[EvidenceContext] = []
    for item in scoped_context:
        evidence_key = str(item.evidence_id)
        selected = matches.get(evidence_key)
        if not selected:
            continue
        values = values_by_id[evidence_key]
        listener_match = any(path.startswith("listeners.") for path in selected)
        if listener_match:
            for metadata_name in _SOURCE_METADATA_FIELDS:
                metadata = values.get(metadata_name)
                if metadata is not None:
                    _append_exact_fact(selected, metadata_name, metadata)
        packet_limitations = {
            "Evidence facts were truncated for this compact packet.",
            "Evidence facts exceeded the inference context byte budget.",
            "fact content compacted by retrieval budget",
        }
        limitations = [
            limitation for limitation in item.limitations if limitation not in packet_limitations
        ][:13]
        limitations.append(
            "Complete matched rows were rehydrated from persisted evidence; unrelated facts "
            "remain omitted from this excerpt."
        )
        if strict_identity:
            omitted = values.get("omitted_listener_count") if listener_match else None
            if isinstance(omitted, int) and not isinstance(omitted, bool):
                limitations.append(
                    f"Listener source reported {omitted} omitted rows; the match does not prove "
                    "sole ownership."
                )
            elif listener_match:
                limitations.append(
                    "Listener omission count was unavailable; the match does not prove "
                    "sole ownership."
                )
            else:
                limitations.append(
                    "Exact PID matching does not establish process role or causality."
                )
        else:
            limitations.append(
                "Plain substring matching is retrieval only, not identity or causal proof."
            )
        result.append(
            item.model_copy(
                update={
                    "facts": selected,
                    "limitations": tuple(dict.fromkeys(limitations))[:16],
                }
            )
        )
    return tuple(result)
