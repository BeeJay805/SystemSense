"""Per-fact Laya packets retain provenance without claiming causal meaning."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import cast

from systemsense.decision.semantic_packets import evidence_packets
from systemsense.domain.ids import EntityId, EvidenceId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus

NOW = datetime.now(UTC) - timedelta(minutes=1)


def _context(
    *,
    evidence_id: EvidenceId | None = None,
    facts: dict[str, object] | None = None,
    status: EvidenceContextStatus = EvidenceContextStatus.OBSERVED,
) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=evidence_id or EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW + timedelta(seconds=1),
        probe_id="application.snapshot",
        summary="A bounded observation",
        facts=cast(dict[str, JsonValue], facts or {}),
        status=status,
        case_scope="current_case",
        incident_relevant=True,
        limitations=("Some records denied",)
        if status is not EvidenceContextStatus.OBSERVED
        else (),
    )


def _description(fragment: dict[str, str]) -> dict[str, object]:
    value: object = json.loads(fragment["description"])
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_packet_order_is_stable_across_shuffled_facts_and_late_priority() -> None:
    evidence_id = EvidenceId.new()
    facts: dict[str, object] = {f"routine.{index:02}": index for index in range(25)}
    facts["device.problem_code"] = 10
    first = _context(evidence_id=evidence_id, facts=facts)
    shuffled = _context(evidence_id=evidence_id, facts=dict(reversed(tuple(facts.items()))))

    a = evidence_packets((first,), priority_paths=("device.problem_code",))
    b = evidence_packets((shuffled,), priority_paths=("device.problem_code",))

    assert a == b
    assert len(a) == 26
    assert _description(a[0])["metric"] == "device.problem_code"
    assert _description(a[0])["value"] == 10
    assert _description(a[0])["value_quality"] == "exact"
    assert _description(a[0])["unit"] is None
    assert _description(a[0])["observed_at"] == NOW.isoformat()


def test_first_batch_fairly_reaches_late_page_and_its_decisive_fact() -> None:
    evidence_id = EvidenceId.new()
    pages = tuple(
        _context(
            evidence_id=evidence_id,
            facts={
                **{f"routine.{fact:02}": "context" for fact in range(12)},
                "critical.failure": "DISK_FAILURE" if index == 38 else "none",
            },
        )
        for index in range(39)
    )
    fragments = evidence_packets(pages)

    assert len({item["page_id"] for item in fragments[:20]}) == 20
    late = next(item for item in fragments[:20] if item["page_id"].endswith(":38"))
    assert _description(late)["metric"] == "critical.failure"
    assert _description(late)["value"] == "DISK_FAILURE"


def test_explicit_source_unit_and_grounded_relation_hint_survive() -> None:
    context = _context(facts={"gpu.clock": {"value": 450, "unit": "MHz"}, "entity.id": "gpu-1"})
    unrelated = EvidenceId.new()
    relevant_relation = EvidenceRelation(
        relation_id="rel_" + "1" * 32,
        source_entity_id=EntityId.new(),
        target_entity_id=EntityId.new(),
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(context.evidence_id,),
    )
    unrelated_relation = relevant_relation.model_copy(
        update={"relation_id": "rel_" + "2" * 32, "evidence_ids": (unrelated,)}
    )

    packets = evidence_packets((context,), relationships=(unrelated_relation, relevant_relation))
    clock = next(
        _description(item) for item in packets if _description(item).get("metric") == "gpu.clock"
    )

    assert clock["value"] == {"value": 450, "unit": "MHz"}
    assert clock["unit"] == "MHz"
    assert clock["entity_hint"] == "gpu-1"
    assert clock["relation_ids"] == [relevant_relation.relation_id]


def test_long_value_is_explicitly_truncated_and_missing_status_is_a_packet() -> None:
    long_value = "sensitive-redacted-" * 30
    observed = _context(facts={"document.state": long_value})
    missing = _context(status=EvidenceContextStatus.MISSING)

    packets = evidence_packets((observed, missing))
    value_packet = _description(
        next(item for item in packets if item["evidence_id"] == str(observed.evidence_id))
    )
    status_packet = _description(
        next(item for item in packets if item["evidence_id"] == str(missing.evidence_id))
    )

    assert value_packet["value_quality"] == "truncated"
    assert "value" not in value_packet
    assert (
        value_packet["value_sha256"]
        == hashlib.sha256(
            json.dumps(long_value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )
    original_bytes = value_packet["value_original_bytes"]
    excerpt = value_packet["value_excerpt"]
    assert isinstance(original_bytes, int) and isinstance(excerpt, str)
    assert original_bytes > len(excerpt)
    assert status_packet["packet_kind"] == "status"
    assert status_packet["status"] == "missing"
    limitations = status_packet["limitations"]
    assert isinstance(limitations, list)
    assert "Some records denied" in cast(list[object], limitations)


def test_global_bound_keeps_one_per_page_and_reports_fact_omissions() -> None:
    pages = tuple(
        _context(facts={f"metric.{index:02}": index for index in range(32)}) for _ in range(256)
    )
    packets = evidence_packets(pages)

    assert len(packets) == 256
    assert len({item["page_id"] for item in packets}) == 256
    assert all(_description(item)["facts_omitted"] == 31 for item in packets)
