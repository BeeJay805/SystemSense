"""Narrow deterministic completion claims built from exact observed facts.

This module never interprets model prose as proof.  It recognizes only reviewed,
typed observations that directly answer an equally narrow objective, and always
keeps broader root-cause attribution unresolved.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import AddressValueError, IPv4Address
from typing import TYPE_CHECKING, Literal, cast

from pydantic import Field, StrictBool, StrictInt, ValidationError, field_validator

from systemsense.domain.evidence import EvidenceRecord, FrozenModel
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus

if TYPE_CHECKING:
    from systemsense.application.investigation_state import InvestigationState


class AssessmentDisposition(StrEnum):
    SUPPORTED_OBSERVED_EXPLANATION = "supported_observed_explanation"
    SUPPORTED_OBSERVED_FINDING = "supported_observed_finding"
    UNRESOLVED = "unresolved"


class ObservedClaimKind(StrEnum):
    LISTENER_OWNER = "listener_owner"
    DEVICE_PROBLEM_CODE = "device_problem_code"
    OWNED_TCP_BIND_CONFLICT = "owned_tcp_bind_conflict"


class TargetBindFailureV1(FrozenModel):
    """Exact target-side socket result; only a trusted persisted source may supply it."""

    contract_version: StrictInt = Field(ge=1, le=1)
    failure_kind: Literal["winsock_bind"]
    winsock_error: StrictInt = Field(ge=10048, le=10048)
    protocol: Literal["tcp4"]
    local_address: str
    local_port: StrictInt = Field(ge=1, le=65_535)
    target_pid: StrictInt = Field(gt=0)
    target_process_creation_time: datetime
    socket_exclusive_address_use: StrictBool
    socket_reuse_address: StrictBool

    @field_validator("local_address")
    @classmethod
    def exact_ipv4(cls, value: str) -> str:
        if str(IPv4Address(value)) != value:
            raise ValueError("bind address must be canonical IPv4")
        return value

    @field_validator("target_process_creation_time")
    @classmethod
    def aware_creation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("target process creation time must be timezone aware")
        return value


class AssessmentDecision(FrozenModel):
    disposition: AssessmentDisposition
    claim_kind: ObservedClaimKind | None = None
    advisory_hypothesis_id: str | None = Field(default=None, max_length=100)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    explanation: str = Field(min_length=1, max_length=1200)
    root_cause_proven: Literal[False] = False
    limitations: tuple[str, ...] = Field(default=(), max_length=8)


def assess_investigation(
    *,
    state: InvestigationState,
    context: tuple[EvidenceContext, ...],
    relationships: tuple[EvidenceRelation, ...],
    trusted_bind_evidence_ids: frozenset[str] = frozenset(),
    trusted_listener_records: tuple[EvidenceRecord, ...] = (),
) -> AssessmentDecision:
    """Return a bounded observed claim only when a reviewed validator admits it."""

    del relationships  # Machine edges remain evidence, never generic completion rules.
    detailed_ids = {str(item.evidence_id) for item in context if item.facts}
    if any(str(item) not in detailed_ids for item in state.requested_evidence_ids):
        return _unresolved("Requested observation detail is still unavailable.")
    if state.requested_details:
        return _unresolved("Requested literal detail retrieval is still pending.")

    causal_bind = _owned_tcp_bind_conflict_claim(
        state,
        context,
        trusted_bind_evidence_ids,
        trusted_listener_records,
    )
    if causal_bind is not None:
        return causal_bind
    listener = _listener_owner_claim(state, context)
    if listener is not None:
        return listener
    bind_finding = _bind_conflict_listener_finding(state, context)
    if bind_finding is not None:
        return bind_finding
    device = _device_problem_claim(state, context)
    if device is not None:
        return device
    return _unresolved(
        "No reviewed narrow observation directly answers the objective without causal inference."
    )


def _owned_tcp_bind_conflict_claim(
    state: InvestigationState,
    context: tuple[EvidenceContext, ...],
    trusted_bind_ids: frozenset[str],
    trusted_listener_records: tuple[EvidenceRecord, ...],
) -> AssessmentDecision | None:
    target = explicit_bind_conflict_target(state.objective)
    if target is None:
        return None
    failures = [
        item
        for item in context
        if item.probe_id == "target.bind_failure" and str(item.evidence_id) in trusted_bind_ids
    ]
    if len(failures) != 1:
        return None
    failure = failures[0]
    if not _is_exact_current_observation(failure, state):
        return None
    if len(trusted_listener_records) != 2 or failure.observed_at > failure.captured_at:
        return None
    intervals = [
        (record, interval)
        for record in trusted_listener_records
        if (interval := _listener_query_interval(record, state)) is not None
    ]
    if len(intervals) != 2:
        return None
    (before, before_interval), (after, after_interval) = sorted(
        intervals, key=lambda item: item[1][0]
    )
    if before.evidence_id == after.evidence_id:
        return None
    context_ids = {
        str(item.evidence_id) for item in context if item.probe_id == "network.listeners"
    }
    if any(
        record.case_id != state.case_id
        or str(record.evidence_id) not in context_ids
        or not state.incident_start <= record.observed_at <= state.incident_end
        or record.observed_at > record.captured_at
        for record in (before, after)
    ):
        return None
    if not (
        timedelta(0) < failure.observed_at - before_interval[1] <= timedelta(seconds=2)
        and timedelta(0) < after_interval[0] - failure.observed_at <= timedelta(seconds=2)
    ):
        return None
    try:
        bind = TargetBindFailureV1.model_validate(failure.facts)
    except (ValidationError, AddressValueError):
        return None
    if (bind.local_address, bind.local_port) != target:
        return None
    if bind.socket_exclusive_address_use is not True or bind.socket_reuse_address is not False:
        return None
    if bind.target_process_creation_time > failure.observed_at:
        return None
    before_owner = _exact_listener_owner(before, bind, before_interval[0])
    after_owner = _exact_listener_owner(after, bind, after_interval[0])
    if before_owner is None or after_owner is None or before_owner != after_owner:
        return None
    name, pid, created = before_owner
    if pid == bind.target_pid:
        return None  # A self-conflict or PID reuse cannot name an external owner.
    return AssessmentDecision(
        disposition=AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION,
        claim_kind=ObservedClaimKind.OWNED_TCP_BIND_CONFLICT,
        evidence_ids=(before.evidence_id, failure.evidence_id, after.evidence_id),
        explanation=(
            f"The target process (PID {bind.target_pid}) reported Winsock bind error 10048 "
            f"for tcp4 {bind.local_address}:{bind.local_port}. Complete listener-table reads "
            f"before and after that failure reported the same endpoint owned by {name} "
            f"(PID {pid}, created {created.isoformat()}). This temporal association "
            "supports, but does not prove, that this owner caused the bind conflict."
        ),
        limitations=(
            "This claim covers one observed bind attempt and exact IPv4 endpoint only.",
            "Socket ownership could change between reads; ownership at the failure "
            "instant is unverified.",
            "No repair or effect of a repair is established or authorized.",
        ),
    )


def _listener_query_interval(
    record: EvidenceRecord, state: InvestigationState
) -> tuple[datetime, datetime] | None:
    facts = {fact.name: fact.value for fact in record.facts}
    return _bounded_listener_table_interval(facts, record.observed_at, record.captured_at, state)


def _bounded_listener_table_interval(
    facts: dict[str, JsonValue],
    observed_at: datetime,
    captured_at: datetime,
    state: InvestigationState,
) -> tuple[datetime, datetime] | None:
    raw = (
        facts.get("collection_started_at"),
        facts.get("listener_table_started_at"),
        facts.get("listener_table_completed_at"),
        facts.get("collection_completed_at"),
    )
    if any(not isinstance(value, str) for value in raw):
        return None
    try:
        collection_start, table_start, table_end, collection_end = (
            datetime.fromisoformat(cast(str, value)) for value in raw
        )
    except ValueError:
        return None
    if any(
        value.tzinfo is None or value.utcoffset() is None
        for value in (collection_start, table_start, table_end, collection_end)
    ):
        return None
    if not (
        state.incident_start
        <= collection_start
        <= table_start
        <= table_end
        <= collection_end
        <= observed_at
        <= captured_at
        <= state.incident_end
    ):
        return None
    return table_start, table_end


def _exact_listener_owner(
    record: EvidenceRecord, bind: TargetBindFailureV1, table_started_at: datetime
) -> tuple[str, int, datetime] | None:
    facts = {fact.name: fact.value for fact in record.facts}
    status = facts.get("collection_status")
    unrelated_owner_gap = "one or more listener process identities were unavailable"
    interval_limitations = {
        "Listener table and owner identities were read over the collection interval",
        "listener table and process owners were read sequentially; "
        "owners may have changed after the table query",
    }
    limitations = set(record.limitations) - interval_limitations
    if (
        status not in ("available", "partial")
        or facts.get("omitted_listener_count") != 0
        or (status == "available" and bool(limitations))
        or (status == "partial" and limitations != {unrelated_owner_gap})
    ):
        return None
    # A selected/reconstructed row cannot establish complete endpoint coverage.
    rows = facts.get("listeners")
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        return None
    typed_rows = cast(list[dict[str, JsonValue]], rows)
    same_port = [row for row in typed_rows if row.get("local_port") == bind.local_port]
    if len(same_port) != 1:
        return None
    row = same_port[0]
    pid = row.get("pid")
    name = row.get("process_name")
    created_raw = row.get("process_creation_time")
    if (
        row.get("protocol") != "tcp4"
        or row.get("local_address") != bind.local_address
        or row.get("owner_status") != "available"
        or not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or not isinstance(name, str)
        or not name
        or not isinstance(created_raw, str)
    ):
        return None
    try:
        created = datetime.fromisoformat(created_raw)
    except ValueError:
        return None
    if created.tzinfo is None or created.utcoffset() is None or created > table_started_at:
        return None
    return name, pid, created


def _listener_owner_claim(
    state: InvestigationState, context: tuple[EvidenceContext, ...]
) -> AssessmentDecision | None:
    target = _listener_target(state.objective)
    if target is None or not _asks_for_listener_owner(state.objective, target):
        return None
    target_address, port = target
    for item in context:
        if item.probe_id != "network.listeners" or not _is_exact_current_observation(item, state):
            continue
        interval = _bounded_listener_table_interval(
            item.facts, item.observed_at, item.captured_at, state
        )
        if interval is None:
            continue
        raw_listeners = _listener_rows(item.facts)
        if not raw_listeners:
            continue
        matches: list[tuple[str, str, int, str, str]] = []
        for listener in raw_listeners:
            if listener.get("local_port") != port or listener.get("owner_status") != "available":
                continue
            pid = listener.get("pid")
            name = listener.get("process_name")
            created = listener.get("process_creation_time")
            address = listener.get("local_address")
            protocol = listener.get("protocol")
            if (
                not isinstance(pid, int)
                or isinstance(pid, bool)
                or pid <= 0
                or not isinstance(name, str)
                or not name
                or not isinstance(created, str)
                or not _creation_predates_table(created, interval[0])
                or not isinstance(address, str)
                or not isinstance(protocol, str)
            ):
                continue
            if target_address is not None and address != target_address:
                continue
            matches.append((name, created, pid, protocol, address))
        identities = {(name.casefold(), created, pid): name for name, created, pid, _, _ in matches}
        if len(identities) != 1:
            continue
        hypothesis = _admitted_hypothesis(state, context, item.evidence_id, "network.listeners")
        if hypothesis is None:
            continue
        identity = next(iter(identities))
        _normalized_name, created, pid = identity
        name = identities[identity]
        endpoints = sorted(
            {f"{protocol} {address}:{port}" for _, _, _, protocol, address in matches}
        )
        limitations = [
            "This supports only the owner reported for the listener-table read interval.",
            "Owner lookup finished after the table read; ownership may have changed.",
            "The associated advisory hypothesis text was not endorsed as fact.",
            "This does not prove the root cause of a broader symptom.",
        ]
        omitted = item.facts.get("omitted_listener_count")
        if not isinstance(omitted, int) or isinstance(omitted, bool) or omitted != 0:
            limitations.append(
                "The observation does not establish that this was the endpoint's sole owner."
            )
        return AssessmentDecision(
            disposition=AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION,
            claim_kind=ObservedClaimKind.LISTENER_OWNER,
            advisory_hypothesis_id=hypothesis.hypothesis_id,
            evidence_ids=(item.evidence_id,),
            explanation=(
                f"The listener table observed {', '.join(endpoints)} owned by process "
                f"{name} (PID {pid}, created {created})."
            ),
            limitations=tuple(limitations),
        )
    return None


def _bind_conflict_listener_finding(
    state: InvestigationState, context: tuple[EvidenceContext, ...]
) -> AssessmentDecision | None:
    """Report an exact observed owner without calling it the bind failure's cause."""

    target = explicit_bind_conflict_target(state.objective)
    if target is None or "network.listeners" not in state.completed_probe_ids:
        return None
    address, port = target
    owner_identities: set[tuple[str, int, str]] = set()
    endpoints: set[str] = set()
    citations: list[EvidenceId] = []
    for item in context:
        if item.probe_id != "network.listeners":
            continue
        if not _is_exact_current_observation(item, state):
            return None
        interval = _bounded_listener_table_interval(
            item.facts, item.observed_at, item.captured_at, state
        )
        if interval is None:
            return None
        facts = item.facts
        omitted = facts.get("omitted_listener_count")
        if (
            not isinstance(omitted, int)
            or isinstance(omitted, bool)
            or omitted != 0
            or facts.get("collection_status") not in ("available", "partial")
        ):
            return None
        rows = _listener_rows(facts)
        if not rows:
            return None
        matched = False
        for row in rows:
            if row.get("local_address") != address or row.get("local_port") != port:
                continue
            matched = True
            pid = row.get("pid")
            name = row.get("process_name")
            created = row.get("process_creation_time")
            protocol = row.get("protocol")
            if (
                row.get("owner_status") != "available"
                or not isinstance(pid, int)
                or isinstance(pid, bool)
                or pid <= 0
                or not isinstance(name, str)
                or not name
                or not isinstance(created, str)
                or not _creation_predates_table(created, interval[0])
                or protocol != "tcp4"
            ):
                return None
            owner_identities.add((name, pid, created))
            endpoints.add(f"{protocol} {address}:{port}")
        if matched:
            citations.append(item.evidence_id)
    if len(owner_identities) != 1 or not citations or len(citations) > 8:
        return None
    name, pid, created = next(iter(owner_identities))
    return AssessmentDecision(
        disposition=AssessmentDisposition.SUPPORTED_OBSERVED_FINDING,
        claim_kind=ObservedClaimKind.LISTENER_OWNER,
        evidence_ids=tuple(citations),
        explanation=(
            f"The listener table observed {', '.join(sorted(endpoints))} owned by process "
            f"{name} (PID {pid}, created {created})."
        ),
        limitations=(
            "This supports only the owner reported for the listener-table read interval.",
            "Owner lookup finished after the table read; ownership may have changed.",
            "The bind failure cause remains unproven by listener ownership alone.",
            "A repair and its effect remain unproven; no action is authorized by this finding.",
        ),
    )


def explicit_bind_conflict_target(objective: str) -> tuple[str, int] | None:
    """Admit only a primary bind-conflict goal with one literal IPv4 endpoint."""

    endpoints: set[tuple[str, int]] = set()
    for raw_address, raw_port in re.findall(
        r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):([0-9]{1,5})\b", objective
    ):
        port = int(raw_port)
        if not 0 < port <= 65_535:
            return None
        try:
            endpoints.add((str(IPv4Address(raw_address)), port))
        except AddressValueError:
            return None
    if len(endpoints) != 1:
        return None
    target = next(iter(endpoints))
    mentioned_ports = {
        int(raw_port) for raw_port in re.findall(r"\bport\s+([0-9]{1,5})\b", objective, flags=re.I)
    }
    if mentioned_ports - {target[1]}:
        return None
    normalized = " ".join(objective.casefold().split())
    sentences = re.split(r"(?<=[.!?])\s+", normalized)
    bind_failure = re.compile(
        r"\b(?:cannot|can't|could not|couldn't|fails? to|failed to|unable to)\s+bind\b"
    )
    conflict = re.compile(
        r"\b(?:address|port)\b.{0,60}\b(?:already\s+)?in\s+use\b"
        r"|\bwinerror\s*10048\b|\b(?:bind|port|address)\s+conflict\b"
    )
    relevant = sentences[0]
    if not bind_failure.search(relevant):
        if not _asks_for_listener_owner(relevant, target) or len(sentences) < 2:
            return None
        relevant = sentences[1]
    primary_bind_subject = re.compile(
        r"^(?:(?:the|my|this|a)\s+)?(?:(?:target|local)\s+)?"
        r"(?:application|app|service|program|server|process)\b"
        r"|^(?:cannot|can't|failed to|fails to|unable to)\s+bind\b"
    )
    if not primary_bind_subject.search(relevant):
        return None
    if not bind_failure.search(relevant) or not conflict.search(relevant):
        return None
    return target


def _listener_rows(facts: dict[str, JsonValue]) -> tuple[dict[str, JsonValue], ...]:
    rows: list[dict[str, JsonValue]] = []
    raw_listeners = facts.get("listeners")
    if isinstance(raw_listeners, list):
        rows.extend(
            cast(dict[str, JsonValue], row) for row in raw_listeners if isinstance(row, dict)
        )
    for name, value in facts.items():
        if name.startswith("listeners.") and isinstance(value, dict):
            rows.append(cast(dict[str, JsonValue], value))
            continue
        if not isinstance(value, dict):
            continue
        source_path = value.get("source_path")
        wrapped = value.get("value")
        if isinstance(source_path, str) and isinstance(wrapped, dict):
            rows.append(cast(dict[str, JsonValue], wrapped))
    return tuple(rows)


def _device_problem_claim(
    state: InvestigationState, context: tuple[EvidenceContext, ...]
) -> AssessmentDecision | None:
    objective = state.objective.casefold()
    for item in context:
        if item.probe_id != "devices.snapshot" or not _is_exact_current_observation(item, state):
            continue
        for device in _device_rows(item.facts):
            device_id = device.get("instance_id")
            name = device.get("name")
            code = device.get("problem_code")
            if (
                not isinstance(device_id, str)
                or not device_id
                or device_id.casefold() not in objective
                or not isinstance(code, int)
                or isinstance(code, bool)
                or code <= 0
            ):
                continue
            if not _asks_for_device_problem_code(state.objective, device_id):
                continue
            hypothesis = _admitted_hypothesis(state, context, item.evidence_id, "devices.snapshot")
            if hypothesis is None:
                continue
            label = name if isinstance(name, str) and name else device_id
            return AssessmentDecision(
                disposition=AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION,
                claim_kind=ObservedClaimKind.DEVICE_PROBLEM_CODE,
                advisory_hypothesis_id=hypothesis.hypothesis_id,
                evidence_ids=(item.evidence_id,),
                explanation=(
                    f"Windows reported device {label} ({device_id}) with problem code {code}."
                ),
                limitations=(
                    "This supports only the reported device status at the observation time.",
                    "A problem code does not by itself prove why the broader symptom occurred.",
                ),
            )
    return None


def _device_rows(facts: dict[str, JsonValue]) -> tuple[dict[str, JsonValue], ...]:
    """Read only exact device rows, whether raw or losslessly paged."""

    rows: list[dict[str, JsonValue]] = []
    raw_devices = facts.get("devices")
    if isinstance(raw_devices, list):
        rows.extend(cast(dict[str, JsonValue], row) for row in raw_devices if isinstance(row, dict))
    for name, value in facts.items():
        if re.fullmatch(r"devices\.[0-9]+", name) and isinstance(value, dict):
            rows.append(cast(dict[str, JsonValue], value))
        if not name.startswith("source_path.") or not isinstance(value, dict):
            continue
        source_path = value.get("source_path")
        wrapped = value.get("value")
        if (
            isinstance(source_path, str)
            and re.fullmatch(r"devices\.[0-9]+", source_path)
            and name == "source_path." + hashlib.sha256(source_path.encode("utf-8")).hexdigest()
            and isinstance(wrapped, dict)
        ):
            rows.append(cast(dict[str, JsonValue], wrapped))
    return tuple(rows)


def _admitted_hypothesis(
    state: InvestigationState,
    context: tuple[EvidenceContext, ...],
    evidence_id: EvidenceId,
    required_probe: str,
) -> Hypothesis | None:
    completed = set(state.completed_probe_ids)
    if required_probe not in completed or state.pending_probe_ids:
        return None
    trusted_ids = {
        str(item.evidence_id) for item in context if _is_exact_current_observation(item, state)
    }
    for hypothesis in state.hypotheses:
        if (
            hypothesis.status is not HypothesisStatus.CONTESTED
            and evidence_id in hypothesis.supporting_evidence_ids
            and {str(item) for item in hypothesis.supporting_evidence_ids} <= trusted_ids
            and not hypothesis.contradicting_evidence_ids
            and not hypothesis.missing_evidence_ids
            and set(hypothesis.distinguishing_probe_ids) <= completed
        ):
            return hypothesis
    return None


def _asks_for_listener_owner(objective: str, target: tuple[str | None, int]) -> bool:
    normalized = " ".join(objective.casefold().split()).rstrip(" ?.!\t")
    if _asks_for_causal_explanation(normalized):
        return False
    address, port = target
    target_pattern = re.escape(f"{address}:{port}") if address is not None else rf"port\s+{port}"
    target_pattern = (
        r"(?:(?:the\s+)?(?:tcp\s+)?(?:listening\s+endpoint|listener)(?:\s+at)?\s+)?"
        + target_pattern
    )
    subject = r"(?:process|program|application|app|executable)"
    details = (
        r"(?:\s+(?:and\s+)?(?:include|show|report)(?:\s+the)?\s+"
        r"(?:pid|process\s+id)(?:\s*(?:,|and)\s*(?:the\s+)?"
        r"(?:process\s+)?creation\s+time)?|[?.]\s+identify\s+its\s+observed\s+pid\s+"
        r"and\s+creation\s+time)?"
    )
    patterns = (
        rf"(?:which|what)\s+{subject}\s+(?:owns|is\s+listening\s+on)\s+"
        rf"{target_pattern}{details}",
        rf"who\s+(?:owns|is\s+listening\s+on)\s+{target_pattern}{details}",
        rf"(?:the\s+)?owner\s+of\s+{target_pattern}{details}",
        rf"(?:the\s+)?{subject}\s+(?:owns|listening\s+on)\s+{target_pattern}{details}",
    )
    return any(re.fullmatch(pattern, normalized) for pattern in patterns)


def _asks_for_device_problem_code(objective: str, device_id: str) -> bool:
    normalized = " ".join(objective.casefold().split()).rstrip(" ?.!\t")
    if _asks_for_causal_explanation(normalized):
        return False
    target = re.escape(device_id.casefold())
    patterns = (
        rf"(?:what|which)\s+(?:device\s+)?problem(?:\s+code)?\s+is\s+reported\s+for\s+{target}",
        rf"what\s+problem\s+code\s+does\s+{target}\s+report",
        rf"(?:what|which)\s+(?:device\s+)?status\s+does\s+windows\s+report\s+for\s+{target}",
        rf"what\s+does\s+windows\s+report\s+for\s+{target}",
        rf"what\s+is\s+(?:the\s+)?(?:problem\s+code|device\s+status)\s+for\s+{target}",
        rf"(?:report|show)\s+(?:the\s+)?(?:problem\s+code|device\s+status)\s+for\s+{target}",
    )
    return any(re.fullmatch(pattern, normalized) for pattern in patterns)


def _asks_for_causal_explanation(normalized: str) -> bool:
    return (
        re.search(
            r"\b(?:why|cause|caused|causes|causing|causal|crash|crashed|crashes|crashing|"
            r"freeze|froze|frozen|freezing|hang|hung|hanging)\b",
            normalized,
        )
        is not None
    )


def _listener_target(objective: str) -> tuple[str | None, int] | None:
    exact_targets: set[tuple[str, int]] = set()
    for address, raw_port in re.findall(
        r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):([0-9]{1,5})\b", objective
    ):
        port = int(raw_port)
        if not 0 < port <= 65_535:
            continue
        try:
            exact_targets.add((str(IPv4Address(address)), port))
        except AddressValueError:
            continue
    if len(exact_targets) == 1:
        return next(iter(exact_targets))
    if exact_targets:
        return None
    ports = {
        int(match)
        for match in re.findall(r"\bport\s+([0-9]{1,5})\b", objective, re.I)
        if 0 < int(match) <= 65_535
    }
    if len(ports) != 1:
        return None
    return None, next(iter(ports))


def _is_exact_current_observation(item: EvidenceContext, state: InvestigationState) -> bool:
    if item.status is not EvidenceContextStatus.OBSERVED or not item.facts:
        return False
    if not state.incident_start <= item.observed_at <= state.incident_end:
        return False
    unsafe_markers = ("historical observation", "stale", "facts omitted", "facts were truncated")
    return not any(
        marker in limitation.casefold()
        for limitation in item.limitations
        for marker in unsafe_markers
    )


def _aware_datetime(value: str) -> bool:
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def _creation_predates_table(value: str, table_started_at: datetime) -> bool:
    if not _aware_datetime(value):
        return False
    return datetime.fromisoformat(value) <= table_started_at


def _unresolved(reason: str) -> AssessmentDecision:
    return AssessmentDecision(
        disposition=AssessmentDisposition.UNRESOLVED,
        explanation="The bounded assessment remains unresolved.",
        limitations=(reason, "No root-cause claim was made."),
    )
