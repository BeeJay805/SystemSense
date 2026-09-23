from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from systemsense.application.assessment import (
    AssessmentDisposition,
    ObservedClaimKind,
    assess_investigation,
    explicit_bind_conflict_target,
)
from systemsense.application.investigation_state import InvestigationState
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
LISTENER_EVIDENCE = EvidenceId(root="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
BIND_EVIDENCE = EvidenceId(root="ev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
AFTER_LISTENER_EVIDENCE = EvidenceId(root="ev_cccccccccccccccccccccccccccccccc")


def _state(
    *,
    objective: str,
    hypothesis: Hypothesis | None = None,
    completed: tuple[str, ...],
) -> InvestigationState:
    return InvestigationState(
        case_id=CaseId(root="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        objective=objective,
        created_at=NOW,
        updated_at=NOW,
        deadline_at=NOW + timedelta(minutes=3),
        incident_start=NOW - timedelta(minutes=15),
        incident_end=NOW + timedelta(minutes=5),
        budget_ms=180_000,
        completed_probe_ids=completed,
        hypotheses=(hypothesis,) if hypothesis is not None else (),
    )


def _context(
    evidence_id: EvidenceId,
    probe_id: str,
    facts: dict[str, object],
    *,
    limitations: tuple[str, ...] = (),
) -> EvidenceContext:
    source_facts = dict(facts)
    if probe_id == "network.listeners":
        for field in (
            "collection_started_at",
            "listener_table_started_at",
            "listener_table_completed_at",
            "collection_completed_at",
        ):
            source_facts.setdefault(field, NOW.isoformat())
    return EvidenceContext.model_validate(
        {
            "evidence_id": str(evidence_id),
            "observed_at": NOW.isoformat(),
            "captured_at": NOW.isoformat(),
            "probe_id": probe_id,
            "summary": "exact observed fixture",
            "facts": source_facts,
            "status": EvidenceContextStatus.OBSERVED.value,
            "limitations": limitations,
        }
    )


def _hypothesis(
    evidence_id: EvidenceId,
    *,
    statement: str = "A model-authored statement must not define the verified claim.",
    contradicting: tuple[EvidenceId, ...] = (),
    missing: tuple[EvidenceId, ...] = (),
    probes: tuple[str, ...] = (),
) -> Hypothesis:
    return Hypothesis(
        hypothesis_id="candidate",
        statement=statement,
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(evidence_id,),
        contradicting_evidence_ids=contradicting,
        missing_evidence_ids=missing,
        distinguishing_probe_ids=probes,
    )


def _complete_listener_facts(*, rows: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "listeners": rows
        if rows is not None
        else [
            {
                "protocol": "tcp4",
                "local_address": "127.0.0.1",
                "local_port": 18765,
                "pid": 4242,
                "process_name": "owner.exe",
                "process_creation_time": NOW.isoformat(),
                "owner_status": "available",
            }
        ],
        "omitted_listener_count": 0,
        "collection_status": "available",
    }


def _bind_failure_facts() -> dict[str, object]:
    return {
        "contract_version": 1,
        "failure_kind": "winsock_bind",
        "winsock_error": 10048,
        "protocol": "tcp4",
        "local_address": "127.0.0.1",
        "local_port": 18765,
        "target_pid": 9000,
        "target_process_creation_time": (NOW - timedelta(minutes=2)).isoformat(),
        "socket_exclusive_address_use": True,
        "socket_reuse_address": False,
    }


def _listener_record(
    evidence_id: EvidenceId,
    observed_at: datetime,
    *,
    facts: dict[str, object] | None = None,
    limitations: tuple[str, ...] = (),
) -> EvidenceRecord:
    source_facts = dict(_complete_listener_facts() if facts is None else facts)
    source_facts.setdefault(
        "collection_started_at", (observed_at - timedelta(milliseconds=30)).isoformat()
    )
    source_facts.setdefault(
        "listener_table_started_at", (observed_at - timedelta(milliseconds=20)).isoformat()
    )
    source_facts.setdefault(
        "listener_table_completed_at", (observed_at - timedelta(milliseconds=10)).isoformat()
    )
    source_facts.setdefault("collection_completed_at", observed_at.isoformat())
    return EvidenceRecord(
        evidence_id=evidence_id,
        case_id=_state(objective="fixture", completed=()).case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=f"src_{'a' * 64}",
            locator={"probe_id": "network.listeners"},
        ),
        collector=CollectorReference(
            id="network.listeners",
            version=1,
            execution_id=ExecutionId(root="exec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ),
        summary="Complete listener source record",
        facts=tuple(
            EvidenceFact(name=name, value=cast(JsonValue, value))
            for name, value in source_facts.items()
        ),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        limitations=limitations,
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )


def test_bracketing_listener_records_support_same_owner_across_bind_failure() -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=(),
    )
    facts = _complete_listener_facts()
    cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
        NOW - timedelta(minutes=2)
    ).isoformat()
    before = _listener_record(LISTENER_EVIDENCE, NOW - timedelta(milliseconds=200), facts=facts)
    after = _listener_record(
        AFTER_LISTENER_EVIDENCE, NOW + timedelta(milliseconds=200), facts=facts
    )
    failure = _context(BIND_EVIDENCE, "target.bind_failure", _bind_failure_facts())
    context = (
        _context(LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
            update={"observed_at": before.observed_at, "captured_at": before.captured_at}
        ),
        failure,
        _context(AFTER_LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
            update={"observed_at": after.observed_at, "captured_at": after.captured_at}
        ),
    )

    result = assess_investigation(
        state=state,
        context=context,
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=(before, after),
    )

    assert result.claim_kind is ObservedClaimKind.OWNED_TCP_BIND_CONFLICT
    assert result.evidence_ids == (LISTENER_EVIDENCE, BIND_EVIDENCE, AFTER_LISTENER_EVIDENCE)


@pytest.mark.parametrize(
    "before_observed_at",
    (NOW - timedelta(milliseconds=200), NOW + timedelta(milliseconds=100)),
)
def test_listener_query_overlapping_failure_cannot_prove_prior_owner(
    before_observed_at: datetime,
) -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=(),
    )
    before_facts = _complete_listener_facts()
    after_facts = deepcopy(before_facts)
    for facts in (before_facts, after_facts):
        cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
            NOW - timedelta(minutes=2)
        ).isoformat()
    before_facts.update(
        collection_started_at=(NOW - timedelta(milliseconds=300)).isoformat(),
        listener_table_started_at=(NOW - timedelta(milliseconds=250)).isoformat(),
        listener_table_completed_at=(NOW + timedelta(milliseconds=50)).isoformat(),
        collection_completed_at=(NOW + timedelta(milliseconds=100)).isoformat(),
    )
    after_facts.update(
        collection_started_at=(NOW + timedelta(milliseconds=200)).isoformat(),
        listener_table_started_at=(NOW + timedelta(milliseconds=210)).isoformat(),
        listener_table_completed_at=(NOW + timedelta(milliseconds=220)).isoformat(),
        collection_completed_at=(NOW + timedelta(milliseconds=300)).isoformat(),
    )
    before = _listener_record(LISTENER_EVIDENCE, before_observed_at, facts=before_facts)
    after = _listener_record(
        AFTER_LISTENER_EVIDENCE, NOW + timedelta(milliseconds=300), facts=after_facts
    )
    failure = _context(BIND_EVIDENCE, "target.bind_failure", _bind_failure_facts())

    result = assess_investigation(
        state=state,
        context=(
            _context(LISTENER_EVIDENCE, "network.listeners", before_facts).model_copy(
                update={"observed_at": before.observed_at}
            ),
            failure,
            _context(AFTER_LISTENER_EVIDENCE, "network.listeners", after_facts).model_copy(
                update={"observed_at": after.observed_at}
            ),
        ),
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=(before, after),
    )

    assert result.claim_kind is not ObservedClaimKind.OWNED_TCP_BIND_CONFLICT


def test_prior_listener_table_can_support_claim_when_owner_lookup_finishes_later() -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=(),
    )
    before_facts = _complete_listener_facts()
    after_facts = deepcopy(before_facts)
    for facts in (before_facts, after_facts):
        cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
            NOW - timedelta(minutes=2)
        ).isoformat()
    before_facts.update(
        collection_started_at=(NOW - timedelta(milliseconds=200)).isoformat(),
        listener_table_started_at=(NOW - timedelta(milliseconds=190)).isoformat(),
        listener_table_completed_at=(NOW - timedelta(milliseconds=150)).isoformat(),
        collection_completed_at=(NOW + timedelta(milliseconds=50)).isoformat(),
    )
    after_facts.update(
        collection_started_at=(NOW + timedelta(milliseconds=100)).isoformat(),
        listener_table_started_at=(NOW + timedelta(milliseconds=110)).isoformat(),
        listener_table_completed_at=(NOW + timedelta(milliseconds=140)).isoformat(),
        collection_completed_at=(NOW + timedelta(milliseconds=200)).isoformat(),
    )
    interval_limitations = (
        "listener table and process owners were read sequentially; "
        "owners may have changed after the table query",
        "Listener table and owner identities were read over the collection interval",
    )
    before = _listener_record(
        LISTENER_EVIDENCE,
        NOW + timedelta(milliseconds=50),
        facts=before_facts,
        limitations=interval_limitations,
    )
    after = _listener_record(
        AFTER_LISTENER_EVIDENCE,
        NOW + timedelta(milliseconds=200),
        facts=after_facts,
        limitations=interval_limitations,
    )
    failure = _context(BIND_EVIDENCE, "target.bind_failure", _bind_failure_facts())

    result = assess_investigation(
        state=state,
        context=(
            _context(LISTENER_EVIDENCE, "network.listeners", before_facts).model_copy(
                update={"observed_at": before.observed_at, "captured_at": before.captured_at}
            ),
            failure,
            _context(AFTER_LISTENER_EVIDENCE, "network.listeners", after_facts).model_copy(
                update={"observed_at": after.observed_at, "captured_at": after.captured_at}
            ),
        ),
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=(before, after),
    )

    assert result.claim_kind is ObservedClaimKind.OWNED_TCP_BIND_CONFLICT


def test_persisted_target_bind_failure_and_complete_unique_listener_support_narrow_cause() -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=("target.bind_failure", "network.listeners"),
    )
    failure = _context(BIND_EVIDENCE, "target.bind_failure", _bind_failure_facts())
    facts = _complete_listener_facts()
    cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
        NOW - timedelta(minutes=2)
    ).isoformat()
    before = _listener_record(LISTENER_EVIDENCE, NOW - timedelta(milliseconds=200), facts=facts)
    after = _listener_record(
        AFTER_LISTENER_EVIDENCE, NOW + timedelta(milliseconds=200), facts=facts
    )
    before_context = _context(LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
        update={"observed_at": before.observed_at, "captured_at": before.captured_at}
    )
    after_context = _context(AFTER_LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
        update={"observed_at": after.observed_at, "captured_at": after.captured_at}
    )

    result = assess_investigation(
        state=state,
        context=(before_context, failure, after_context),
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=(before, after),
    )

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert result.claim_kind is ObservedClaimKind.OWNED_TCP_BIND_CONFLICT
    assert result.evidence_ids == (LISTENER_EVIDENCE, BIND_EVIDENCE, AFTER_LISTENER_EVIDENCE)
    assert "owner.exe" in result.explanation
    assert result.root_cause_proven is False


def test_causal_bind_claim_accepts_pre_run_persisted_listener_without_completed_state() -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=(),
    )
    failure = _context(BIND_EVIDENCE, "target.bind_failure", _bind_failure_facts())
    facts = _complete_listener_facts()
    cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
        NOW - timedelta(minutes=2)
    ).isoformat()
    before = _listener_record(LISTENER_EVIDENCE, NOW - timedelta(milliseconds=200), facts=facts)
    after = _listener_record(
        AFTER_LISTENER_EVIDENCE, NOW + timedelta(milliseconds=200), facts=facts
    )
    before_context = _context(LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
        update={"observed_at": before.observed_at, "captured_at": before.captured_at}
    )
    after_context = _context(AFTER_LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
        update={"observed_at": after.observed_at, "captured_at": after.captured_at}
    )

    result = assess_investigation(
        state=state,
        context=(before_context, failure, after_context),
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=(before, after),
    )

    assert result.claim_kind is ObservedClaimKind.OWNED_TCP_BIND_CONFLICT


def test_causal_bind_claim_allows_unrelated_listener_owner_gaps() -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=(),
    )
    facts = _complete_listener_facts()
    rows = cast("list[dict[str, object]]", facts["listeners"])
    rows.append(
        {
            "protocol": "tcp4",
            "local_address": "127.0.0.1",
            "local_port": 25000,
            "pid": None,
            "process_name": None,
            "process_creation_time": None,
            "owner_status": "unsupported",
        }
    )
    facts["collection_status"] = "partial"
    cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
        NOW - timedelta(minutes=2)
    ).isoformat()
    limitations = ("one or more listener process identities were unavailable",)
    before = _listener_record(
        LISTENER_EVIDENCE,
        NOW - timedelta(milliseconds=200),
        facts=facts,
        limitations=limitations,
    )
    after = _listener_record(
        AFTER_LISTENER_EVIDENCE,
        NOW + timedelta(milliseconds=200),
        facts=facts,
        limitations=limitations,
    )
    failure = _context(BIND_EVIDENCE, "target.bind_failure", _bind_failure_facts())
    before_context = _context(LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
        update={"observed_at": before.observed_at, "captured_at": before.captured_at}
    )
    after_context = _context(AFTER_LISTENER_EVIDENCE, "network.listeners", facts).model_copy(
        update={"observed_at": after.observed_at, "captured_at": after.captured_at}
    )

    result = assess_investigation(
        state=state,
        context=(before_context, failure, after_context),
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=(before, after),
    )

    assert result.claim_kind is ObservedClaimKind.OWNED_TCP_BIND_CONFLICT


def test_causal_bind_claim_reads_full_verified_record_when_context_is_compact() -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=(),
    )
    facts = _complete_listener_facts()
    rows = cast("list[dict[str, object]]", facts["listeners"])
    rows.extend(
        {
            "protocol": "tcp4",
            "local_address": "127.0.0.1",
            "local_port": 25000 + n,
            "pid": None,
            "process_name": None,
            "process_creation_time": None,
            "owner_status": "unsupported",
        }
        for n in range(42)
    )
    facts["collection_status"] = "partial"
    cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
        NOW - timedelta(minutes=2)
    ).isoformat()
    source_limitations = ("one or more listener process identities were unavailable",)
    before = _listener_record(
        LISTENER_EVIDENCE,
        NOW - timedelta(milliseconds=200),
        facts=facts,
        limitations=source_limitations,
    )
    after = _listener_record(
        AFTER_LISTENER_EVIDENCE,
        NOW + timedelta(milliseconds=200),
        facts=facts,
        limitations=source_limitations,
    )
    compact_before = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {"collection_status": "partial"},
        limitations=(*source_limitations, "Evidence facts were truncated for this compact packet."),
    ).model_copy(update={"observed_at": before.observed_at, "captured_at": before.captured_at})
    compact_after = _context(
        AFTER_LISTENER_EVIDENCE,
        "network.listeners",
        {"collection_status": "partial"},
        limitations=(*source_limitations, "Evidence facts were truncated for this compact packet."),
    ).model_copy(update={"observed_at": after.observed_at, "captured_at": after.captured_at})
    failure = _context(BIND_EVIDENCE, "target.bind_failure", _bind_failure_facts())

    result = assess_investigation(
        state=state,
        context=(compact_before, failure, compact_after),
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=(before, after),
    )

    assert result.claim_kind is ObservedClaimKind.OWNED_TCP_BIND_CONFLICT


@pytest.mark.parametrize(
    "gap",
    [
        "missing_failure",
        "untrusted_failure_probe",
        "wrong_error",
        "wrong_endpoint",
        "unknown_socket_options",
        "coerced_socket_options",
        "coerced_contract_version",
        "target_is_owner",
        "ambiguous_owner",
        "wrong_family",
        "wildcard_listener",
        "omitted_rows",
        "partial_collection",
        "old_snapshot",
        "future_snapshot",
        "owner_started_after_failure",
        "future_process",
        "unsupported_version",
        "stale_failure",
        "missing_after",
        "missing_before",
        "same_time",
        "after_same_time",
        "post_only",
        "swapped_owner",
        "pid_reused",
        "stale_listener",
    ],
)
def test_causal_bind_claim_fails_closed_when_required_evidence_has_gap(gap: str) -> None:
    state = _state(
        objective="The app cannot bind to 127.0.0.1:18765 because the address is in use.",
        completed=("target.bind_failure", "network.listeners"),
    )
    failure_facts = _bind_failure_facts()
    listener_facts = _complete_listener_facts()
    failure_probe = "target.bind_failure"
    failure_limitations: tuple[str, ...] = ()
    before_time = NOW - timedelta(milliseconds=200)
    after_time = NOW + timedelta(milliseconds=200)
    listener_limitations: tuple[str, ...] = ()
    if gap == "untrusted_failure_probe":
        failure_probe = "user.report"
    elif gap == "wrong_error":
        failure_facts["winsock_error"] = 10013
    elif gap == "wrong_endpoint":
        failure_facts["local_port"] = 18766
    elif gap == "unknown_socket_options":
        failure_facts.pop("socket_exclusive_address_use")
    elif gap == "coerced_socket_options":
        failure_facts["socket_exclusive_address_use"] = 1
        failure_facts["socket_reuse_address"] = 0
    elif gap == "coerced_contract_version":
        failure_facts["contract_version"] = True
    elif gap == "target_is_owner":
        failure_facts["target_pid"] = 4242
        failure_facts["target_process_creation_time"] = NOW.isoformat()
    elif gap == "ambiguous_owner":
        row = cast("list[dict[str, object]]", listener_facts["listeners"])[0]
        listener_facts["listeners"] = [row, {**row, "pid": 5000, "process_name": "other.exe"}]
    elif gap == "wrong_family":
        cast("list[dict[str, object]]", listener_facts["listeners"])[0]["protocol"] = "tcp6"
    elif gap == "wildcard_listener":
        cast("list[dict[str, object]]", listener_facts["listeners"])[0]["local_address"] = "0.0.0.0"
    elif gap == "omitted_rows":
        listener_facts["omitted_listener_count"] = 1
    elif gap == "partial_collection":
        listener_facts["collection_status"] = "partial"
    elif gap == "old_snapshot":
        before_time = NOW - timedelta(seconds=5)
    elif gap == "future_snapshot":
        before_time = NOW + timedelta(seconds=1)
    elif gap == "owner_started_after_failure":
        cast("list[dict[str, object]]", listener_facts["listeners"])[0]["process_creation_time"] = (
            NOW + timedelta(milliseconds=100)
        ).isoformat()
    elif gap == "future_process":
        cast("list[dict[str, object]]", listener_facts["listeners"])[0]["process_creation_time"] = (
            NOW + timedelta(seconds=1)
        ).isoformat()
    elif gap == "unsupported_version":
        failure_facts["contract_version"] = 2
    elif gap == "stale_failure":
        failure_limitations = ("Historical observation; freshness requires review.",)
    elif gap == "same_time":
        before_time = NOW
        listener_facts["listener_table_completed_at"] = NOW.isoformat()
    elif gap == "after_same_time":
        after_time = NOW
    elif gap == "post_only":
        before_time = NOW + timedelta(milliseconds=100)
    elif gap == "stale_listener":
        listener_limitations = ("stale source snapshot",)
    if gap not in ("owner_started_after_failure", "future_process", "target_is_owner"):
        cast("list[dict[str, object]]", listener_facts["listeners"])[0]["process_creation_time"] = (
            NOW - timedelta(minutes=2)
        ).isoformat()
    after_facts = deepcopy(listener_facts)
    if gap == "swapped_owner":
        row = cast("list[dict[str, object]]", after_facts["listeners"])[0]
        row["pid"] = 5000
        row["process_name"] = "replacement.exe"
    elif gap == "pid_reused":
        cast("list[dict[str, object]]", after_facts["listeners"])[0]["process_creation_time"] = (
            NOW - timedelta(minutes=1)
        ).isoformat()
    failure = _context(BIND_EVIDENCE, failure_probe, failure_facts, limitations=failure_limitations)
    before = _listener_record(
        LISTENER_EVIDENCE,
        before_time,
        facts=listener_facts,
        limitations=listener_limitations,
    )
    after = _listener_record(AFTER_LISTENER_EVIDENCE, after_time, facts=after_facts)
    before_context = _context(LISTENER_EVIDENCE, "network.listeners", listener_facts).model_copy(
        update={"observed_at": before_time, "captured_at": before_time}
    )
    after_context = _context(AFTER_LISTENER_EVIDENCE, "network.listeners", after_facts).model_copy(
        update={"observed_at": after_time, "captured_at": after_time}
    )
    context = (
        (before_context, after_context)
        if gap == "missing_failure"
        else (before_context, failure, after_context)
    )
    records = (
        (before,)
        if gap == "missing_after"
        else (after,)
        if gap == "missing_before"
        else (before, after)
    )

    result = assess_investigation(
        state=state,
        context=context,
        relationships=(),
        trusted_bind_evidence_ids=frozenset({str(BIND_EVIDENCE)}),
        trusted_listener_records=records,
    )

    assert result.disposition is not AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION


def test_public_bind_conflict_target_requires_primary_explicit_ipv4_endpoint() -> None:
    assert explicit_bind_conflict_target(
        "The app cannot bind to 127.0.0.1:18765 because the address is in use."
    ) == ("127.0.0.1", 18765)
    assert explicit_bind_conflict_target("My game is slow; a log mentions 127.0.0.1:18765.") is None


@pytest.mark.parametrize(
    "objective",
    [
        "Which process owns TCP listener 127.0.0.1:18765? "
        "The target application cannot bind because its address is in use.",
        "The application cannot bind to 127.0.0.1:18765 because the address is already in use. "
        "Investigate the failure.",
    ],
)
def test_broad_bind_conflict_reports_cited_observation_without_hypothesis(objective: str) -> None:
    state = _state(objective=objective, completed=("network.listeners",))
    context = _context(LISTENER_EVIDENCE, "network.listeners", _complete_listener_facts())

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition.value == "supported_observed_finding"
    assert result.claim_kind is ObservedClaimKind.LISTENER_OWNER
    assert result.advisory_hypothesis_id is None
    assert result.evidence_ids == (LISTENER_EVIDENCE,)
    assert "owner.exe" in result.explanation
    assert "4242" in result.explanation
    assert result.root_cause_proven is False
    assert any("bind failure" in note and "unproven" in note for note in result.limitations)
    assert any("repair" in note and "unproven" in note for note in result.limitations)


@pytest.mark.parametrize(
    "objective",
    [
        "The game has low FPS; 127.0.0.1:18765 appeared in a log.",
        "The game has low FPS; yesterday I saw a bind conflict on 127.0.0.1:18765.",
        "My game runs at 12 FPS, and a log says an app cannot bind to "
        "127.0.0.1:18765 because the address is in use.",
        "The application cannot bind to 127.0.0.1:18765 because the address is in use. "
        "The application also cannot bind to 127.0.0.1:18766.",
        "The application cannot bind to port 18765 because the address is in use.",
    ],
)
def test_observed_finding_rejects_incidental_or_nonunique_endpoint(objective: str) -> None:
    state = _state(objective=objective, completed=("network.listeners",))
    context = _context(LISTENER_EVIDENCE, "network.listeners", _complete_listener_facts())

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


@pytest.mark.parametrize(
    "gap",
    ["probe", "missing_owner", "ambiguous", "stale", "truncated", "omitted", "denied"],
)
def test_broad_bind_finding_requires_complete_current_unique_target(gap: str) -> None:
    objective = "The app cannot bind to 127.0.0.1:18765 because the address is in use."
    state = _state(
        objective=objective,
        completed=() if gap == "probe" else ("network.listeners",),
    )
    facts = _complete_listener_facts()
    row = dict(cast("list[dict[str, object]]", facts["listeners"])[0])
    if gap == "missing_owner":
        row.update({"owner_status": "unavailable", "pid": None})
        facts["listeners"] = [row]
    elif gap == "ambiguous":
        other = {**row, "pid": 9090, "process_name": "other.exe"}
        facts["listeners"] = [row, other]
    elif gap == "omitted":
        facts["omitted_listener_count"] = 1
    elif gap == "denied":
        facts["collection_status"] = "denied"
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        facts,
        limitations=("Historical observation; freshness requires review.",)
        if gap == "stale"
        else ("Evidence facts were truncated for this compact packet.",)
        if gap == "truncated"
        else (),
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_exact_listener_owner_can_complete_without_endorsing_model_causality() -> None:
    state = _state(
        objective="Which process owns port 18765?",
        hypothesis=_hypothesis(
            LISTENER_EVIDENCE,
            statement="The GPU caused the problem and also owns the port.",
            probes=("network.listeners",),
        ),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "systemsense-preview.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ],
            "omitted_listener_count": 0,
            "collection_status": "available",
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert result.claim_kind is ObservedClaimKind.LISTENER_OWNER
    assert result.evidence_ids == (LISTENER_EVIDENCE,)
    assert "18765" in result.explanation
    assert "4242" in result.explanation
    assert "systemsense-preview.exe" in result.explanation
    assert "GPU" not in result.explanation
    assert result.root_cause_proven is False


def test_listener_owner_claim_rejects_process_created_after_table_query() -> None:
    state = _state(
        objective="Which process owns port 18765?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    facts = _complete_listener_facts()
    cast("list[dict[str, object]]", facts["listeners"])[0]["process_creation_time"] = (
        NOW + timedelta(milliseconds=1)
    ).isoformat()
    context = _context(LISTENER_EVIDENCE, "network.listeners", facts)

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


@pytest.mark.parametrize(
    "objective",
    [
        "Which process owns 127.0.0.1:18765 and include PID and creation time?",
        "Which process owns the listening endpoint 127.0.0.1:18765? "
        "Identify its observed PID and creation time.",
        "Which process owns the listener at 127.0.0.1:18765?",
    ],
)
def test_exact_listener_owner_can_request_precise_identity_fields(objective: str) -> None:
    state = _state(
        objective=objective,
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION


def test_listener_owner_does_not_complete_a_mixed_action_goal() -> None:
    state = _state(
        objective="Which process owns port 18765 and fix the performance issue?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_listener_owner_requires_an_explicit_owner_question() -> None:
    state = _state(
        objective="Which process used the most memory while port 18765 was active?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_listener_owner_does_not_answer_a_causal_process_question() -> None:
    state = _state(
        objective="Which process owns port 18765, and why did it crash?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ],
            "omitted_listener_count": 0,
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_address_qualified_listener_question_matches_the_exact_endpoint_only() -> None:
    state = _state(
        objective="Which process owns 127.0.0.1:18765?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "0.0.0.0",
                    "local_port": 18765,
                    "pid": 1111,
                    "process_name": "wrong-address.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                },
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "exact-owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                },
            ],
            "omitted_listener_count": 9,
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert "exact-owner.exe" in result.explanation
    assert "wrong-address.exe" not in result.explanation
    assert any("not establish" in limitation for limitation in result.limitations)


def test_listener_claim_allows_additional_valid_current_citations() -> None:
    second_evidence = EvidenceId(root="ev_ffffffffffffffffffffffffffffffff")
    hypothesis = Hypothesis(
        hypothesis_id="candidate",
        statement="Advisory text.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(LISTENER_EVIDENCE, second_evidence),
        distinguishing_probe_ids=("network.listeners",),
    )
    state = _state(
        objective="Which process owns port 18765?",
        hypothesis=hypothesis,
        completed=("network.listeners",),
    )
    listener_context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )
    second_context = _context(second_evidence, "system.snapshot", {"hostname": "fixture"})

    result = assess_investigation(
        state=state, context=(listener_context, second_context), relationships=()
    )

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION


@pytest.mark.parametrize(
    "facts",
    [
        {
            "listeners.180": {
                "protocol": "tcp4",
                "local_address": "127.0.0.1",
                "local_port": 18765,
                "pid": 4242,
                "process_name": "rehydrated.exe",
                "process_creation_time": NOW.isoformat(),
                "owner_status": "available",
            },
            "omitted_listener_count": 0,
        },
        {
            "fact_abc123": {
                "source_path": "nested.unsafe listener path.0",
                "value": {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "rehydrated.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                },
            },
            "omitted_listener_count": 0,
        },
    ],
)
def test_listener_claim_accepts_complete_rehydrated_target_rows(
    facts: dict[str, object],
) -> None:
    state = _state(
        objective="Which process owns 127.0.0.1:18765?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(LISTENER_EVIDENCE, "network.listeners", facts)

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert "rehydrated.exe" in result.explanation


@pytest.mark.parametrize("gap", ["probe", "contradiction", "missing", "historical"])
def test_listener_completion_rejects_unresolved_gaps(gap: str) -> None:
    contradiction = (
        (EvidenceId(root="ev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),) if gap == "contradiction" else ()
    )
    missing = (EvidenceId(root="ev_cccccccccccccccccccccccccccccccc"),) if gap == "missing" else ()
    state = _state(
        objective="process listening on port 18765",
        hypothesis=_hypothesis(
            LISTENER_EVIDENCE,
            contradicting=contradiction,
            missing=missing,
            probes=("network.listeners",),
        ),
        completed=() if gap == "probe" else ("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "0.0.0.0",
                    "local_port": 18765,
                    "pid": 7,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ],
            "omitted_listener_count": 0,
        },
        limitations=("Historical observation; freshness requires review.",)
        if gap == "historical"
        else (),
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED
    assert result.root_cause_proven is False


def test_exact_device_problem_code_is_a_finding_not_root_cause_proof() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=r"What problem is reported for PCI\VEN_1234&DEV_ABCD?",
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert result.claim_kind is ObservedClaimKind.DEVICE_PROBLEM_CODE
    assert "problem code 28" in result.explanation
    assert result.root_cause_proven is False


def test_device_problem_code_does_not_answer_a_causal_crash_question() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=r"What problem code does PCI\VEN_1234&DEV_ABCD report, and why did it crash?",
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_device_problem_code_requires_an_explicit_status_question() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=r"What driver version is installed for PCI\VEN_1234&DEV_ABCD?",
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_device_problem_code_does_not_complete_a_mixed_diagnostic_goal() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=(
            r"What problem code is reported for PCI\VEN_1234&DEV_ABCD and identify the reason "
            "for low FPS?"
        ),
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_generic_correlated_gpu_theory_cannot_complete() -> None:
    evidence_id = EvidenceId(root="ev_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    state = _state(
        objective="Why did the application freeze?",
        hypothesis=_hypothesis(evidence_id, statement="GPU use caused the freeze."),
        completed=("gpu.telemetry.sample",),
    )
    context = _context(
        evidence_id,
        "gpu.telemetry.sample",
        {"gpu_utilization_percent": 99},
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED
    assert result.claim_kind is None
    assert result.root_cause_proven is False
