"""Per-fact Laya packets retain provenance without claiming causal meaning."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from pydantic import ValidationError

from systemsense.decision.frontier_ranker import SemanticPacketRefV1, SemanticPacketRefV2
from systemsense.decision.semantic_packets import (
    compact_worker_packet,
    evidence_packets,
    generic_decision_evidence_packets,
    nested_evidence_packets,
)
from systemsense.domain.ids import EntityId, EvidenceId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.pages import fact_pages
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    _focused_preview,  # pyright: ignore[reportPrivateUsage]
)

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


def test_v2_nested_cpu_and_process_identity_survive_final_16_worker_path() -> None:
    pressure = _context(
        facts={
            "target_pressure": {
                "samples": [
                    {"value": 0.07, "unit": "normalized_pct", "window_s": 5},
                    {"value": 0.08, "unit": "normalized_pct", "window_s": 5},
                ],
                "sample_count": 2,
            },
            "process_identity": {"pid": 4321, "birth_time": "2026-09-30T18:00:00+00:00"},
        }
    )
    context = _context(facts={f"adapter.field{index}": f"value{index}" for index in range(5)})
    other_pages = tuple(
        _context(facts={f"host.fact{index}": index for index in range(4)}) for _ in range(5)
    )
    packets = nested_evidence_packets(
        (pressure, context, *other_pages),
        max_packets=16,
        priority_paths=("/target_pressure/samples",),
    )
    assert len(packets) == 16
    typed = tuple(SemanticPacketRefV2.model_validate(packet) for packet in packets)
    compact = tuple(compact_worker_packet(packet.wire()) for packet in typed)
    focused = [json.loads(_focused_preview(item["description"])) for item in compact]
    pressure_value = next(
        item["value"] for item in focused if item.get("source_path") == "/target_pressure"
    )
    identity = next(
        item["value"] for item in focused if item.get("source_path") == "/process_identity"
    )
    assert pressure_value == pressure.facts["target_pressure"]
    assert identity == pressure.facts["process_identity"]
    assert pressure_value["samples"][0] == {"value": 0.07, "unit": "normalized_pct", "window_s": 5}
    assert all(len(item["description"]) <= 800 for item in compact)
    with pytest.raises(ValidationError):
        SemanticPacketRefV1.model_validate(packets[0])


def test_v2_http_json_shapes_are_bounded_and_do_not_expose_file_content() -> None:
    http = _context(
        facts={
            "loopback_replay": {
                "status": 503,
                "request_started_at": "2026-09-30T18:00:00+00:00",
                "request_finished_at": "2026-09-30T18:00:01+00:00",
                "outcome": "http_error",
            },
            "listener_ownership": {
                "pid": 4321,
                "birth_time": "2026-09-30T18:00:00+00:00",
                "handle_count": 1,
            },
        }
    )
    safe_json = _context(
        facts={
            "selected_file": {"sha256": "a" * 64, "captured_at": "2026-09-30T18:00:00+00:00"},
            "file_json_check": {
                "stage": "parse",
                "outcome": "rejected",
                "error_code": "invalid_json",
                "location": {"line": 2},
            },
        }
    )
    packets = nested_evidence_packets((http, safe_json), max_packets=16)
    descriptions = [
        json.loads(
            _focused_preview(
                compact_worker_packet(SemanticPacketRefV2.model_validate(p).wire())["description"]
            )
        )
        for p in packets
    ]
    values = {
        p["source_path"]: p["value"] for p in descriptions if p.get("value_quality") == "exact"
    }
    assert values["/loopback_replay"] == http.facts["loopback_replay"]
    assert values["/loopback_replay"]["status"] == 503
    assert values["/listener_ownership"] == http.facts["listener_ownership"]
    assert values["/listener_ownership"]["pid"] == 4321
    assert values["/file_json_check"] == safe_json.facts["file_json_check"]
    assert values["/file_json_check"]["error_code"] == "invalid_json"
    assert all(
        "file_content" not in json.dumps(p) and "selected_file/path" not in json.dumps(p)
        for p in descriptions
    )


def test_v2_status_and_omissions_are_explicit_and_timestamp_validated() -> None:
    denied = _context(facts={}, status=EvidenceContextStatus.DENIED)
    packets = nested_evidence_packets((denied,))
    assert len(packets) == 1
    typed = SemanticPacketRefV2.model_validate(packets[0])
    assert json.loads(typed.description)["packet_kind"] == "status"
    bad = json.loads(typed.description)
    bad["captured_at"] = "not-a-time"
    with pytest.raises(ValidationError):
        SemanticPacketRefV2.model_validate({**packets[0], "description": json.dumps(bad)})

    huge = _context(facts={"large": {"payload": "x" * 5000}})
    packets = nested_evidence_packets((huge,))
    large = next(json.loads(p["description"]) for p in packets if "large" in p["description"])
    assert large["value_quality"] == "truncated"
    assert large["value_original_bytes"] > 0
    assert len(large["value_sha256"]) == 64


@pytest.mark.parametrize(
    "changes",
    [
        {"value_quality": "truncated", "value_sha256": "a" * 64, "value_original_bytes": 2},
        {"value_excerpt": "conflicting value"},
        {"redaction_applied": False},
        {"evidence_id": "another-source"},
        {"status": "verified_cause"},
        {"case_scope": "another_case"},
    ],
)
def test_v2_rejects_ambiguous_value_and_provenance(changes: dict[str, object]) -> None:
    packet = nested_evidence_packets((_context(facts={"temperature": 42}),))[0]
    body = {**json.loads(packet["description"]), **changes}
    with pytest.raises(ValueError):
        SemanticPacketRefV2.model_validate({**packet, "description": json.dumps(body)})


def test_v2_worker_preserves_all_omission_disclosures() -> None:
    context = _context(facts={"record": {"x" * 700: 1}}).model_copy(
        update={"limitations": ("First source limitation", "Another source limitation")}
    )
    packet = nested_evidence_packets((context,))[0]
    source = json.loads(packet["description"])
    assert source["value_quality"] == "omitted"
    typed = SemanticPacketRefV2.model_validate(packet)
    focused = json.loads(_focused_preview(compact_worker_packet(typed.wire())["description"]))
    for key in (
        "source_path_sha256",
        "source_path_original_chars",
        "limitations_omitted",
        "limitations_sha256",
        "facts_omitted",
        "nested_paths_omitted",
        "case_scope",
        "incident_relevant",
        "observed_at",
        "captured_at",
        "redaction_applied",
    ):
        assert focused[key] == source[key]


def test_v2_retains_observed_empty_object() -> None:
    packet = nested_evidence_packets((_context(facts={"result": {}}),))[0]
    source = json.loads(packet["description"])
    assert source["packet_kind"] == "fact"
    assert source["value"] == {}
    assert source["value_quality"] == "exact"


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


def test_custom_packet_budget_reports_omissions_for_delivered_fragments() -> None:
    context = _context(facts={f"metric.{index:02}": index for index in range(32)})

    packets = evidence_packets((context,), max_packets=24)

    assert len(packets) == 24
    assert all(_description(item)["facts_omitted"] == 8 for item in packets)


def test_generic_projection_bounds_batches_and_keeps_late_gpu_process_values() -> None:
    routine = tuple(_context(facts={f"routine.{index:03}": index}) for index in range(138))
    gpu = _context(
        facts={
            "gpu.metrics.temperature": {"value": 98, "unit": "C"},
            "gpu.metrics.clock": {"value": 210, "unit": "MHz"},
            "gpu.metrics.throttle_reasons_active": "thermal",
        }
    )
    process = _context(
        facts={
            "process.pressure.cpu_percent": {"value": 93.5, "unit": "%"},
            "process.pressure.working_set": {"value": 1_073_741_824, "unit": "bytes"},
        }
    )
    pages = (*routine, gpu, process)

    packets = generic_decision_evidence_packets(pages, candidate_count=8)
    previews = tuple(_description(item) for item in packets)

    assert len(packets) == 48
    assert (len(packets) + 3) // 4 + (8 + 3) // 4 <= 32
    assert all(packet["pages_omitted"] == 95 for packet in previews)
    assert any(
        packet.get("metric") == "gpu.metrics.temperature"
        and packet.get("value") == {"value": 98, "unit": "C"}
        for packet in previews
    )
    assert any(
        packet.get("metric") == "process.pressure.cpu_percent"
        and packet.get("value") == {"value": 93.5, "unit": "%"}
        for packet in previews
    )
    assert any(
        packet.get("metric") == "gpu.metrics.clock"
        and packet.get("value") == {"value": 210, "unit": "MHz"}
        for packet in previews
    )
    assert any(
        packet.get("metric") == "gpu.metrics.throttle_reasons_active"
        and packet.get("value") == "thermal"
        for packet in previews
    )


def test_small_frontier_budget_keeps_multiple_pages_when_every_page_is_diagnostic() -> None:
    pages = tuple(
        _context(
            facts={
                "gpu.temperature": index,
                "gpu.clock": index,
                "gpu.throttle": "thermal",
            }
        )
        for index in range(20)
    )

    packets = evidence_packets(pages, max_packets=16, allow_page_omission=True)

    assert len(packets) == 16
    seen_pages = {item["page_id"] for item in packets}
    assert len(seen_pages) >= 8
    assert all(_description(item)["pages_omitted"] == 20 - len(seen_pages) for item in packets)


def test_time_caveat_survives_description_overflow() -> None:
    caveat = "Source time unknown/legacy_capture is unverified; incident relevance unverified."
    context = _context(facts={"metric." + "x" * 110: "long-value" * 80}).model_copy(
        update={
            "incident_relevant": None,
            "limitations": (caveat, *("optional context " * 20 for _ in range(15))),
        }
    )

    packet = _description(evidence_packets((context,), max_packets=24)[0])

    assert packet["incident_relevant"] is None
    assert "unknown/legacy_capture" in cast(list[str], packet["limitations"])[0]


def test_nested_gpu_diagnostic_values_survive_page_to_laya_preview() -> None:
    gpu: dict[str, JsonValue] = {
        "id": "gpu-0",
        "driver": "a" * 72,
        "observed_at": NOW.isoformat(),
        "metrics": {
            "utilization": {"value": 99, "unit": "%"},
            "clock": {"value": 210, "unit": "MHz"},
            "temperature": {"value": 98, "unit": "C"},
            "throttle_reasons_active": "thermal",
        },
    }
    pages = tuple(
        _context(facts=cast(dict[str, object], page)) for page in fact_pages({"gpu": gpu})
    )

    previews = [
        json.loads(_focused_preview(item["description"])) for item in evidence_packets(pages)
    ]
    temperature = next(item for item in previews if item.get("metric") == "gpu.metrics.temperature")
    throttle = next(
        item for item in previews if item.get("metric") == "gpu.metrics.throttle_reasons_active"
    )

    assert temperature["value"] == {"value": 98, "unit": "C"}
    assert temperature["unit"] == "C"
    assert temperature["entity_hint"] == "gpu-0"
    assert temperature["observed_at"] == NOW.isoformat()
    assert temperature["value_quality"] == "exact"
    assert throttle["value"] == "thermal"


def test_nested_process_pressure_keeps_pid_and_unit_in_laya_preview() -> None:
    process: dict[str, JsonValue] = {
        "pid": 4242,
        "image": "viewer.exe",
        "metadata": "redacted" * 25,
        "pressure": {
            "working_set": {"value": 1_073_741_824, "unit": "bytes"},
            "cpu_percent": {"value": 93.5, "unit": "%"},
        },
    }
    pages = tuple(
        _context(facts=cast(dict[str, object], page)) for page in fact_pages({"process": process})
    )

    previews = [
        json.loads(_focused_preview(item["description"])) for item in evidence_packets(pages)
    ]
    pressure = next(item for item in previews if item.get("metric") == "process.pressure")

    assert pressure["value"] == {
        "cpu_percent": {"value": 93.5, "unit": "%"},
        "working_set": {"value": 1_073_741_824, "unit": "bytes"},
    }
    assert pressure["entity_hint"] == "4242"
    assert pressure["value_quality"] == "exact"


def test_v2_realistic_sample_bundle_reaches_worker_without_losing_context() -> None:
    stamp = "2026-09-30T11:30:16.669286Z"
    samples = [
        {
            "cpu_logical_cores": value,
            "cpu_percent": None if value is None else value / 24 * 100,
            "delta_status": "baseline" if value is None else "measured",
            "name": "target-123456789abcdef.exe",
            "observed_at": stamp,
            "query_started_at": stamp,
            "read_bytes_delta": None if value is None else 0,
            "rss_bytes": 13242368,
            "status": "available",
            "write_bytes_delta": None if value is None else 0,
        }
        for value in (None, 0.905113, 0.983647)
    ]
    notes = [
        "first sample is a counter baseline; CPU and I/O deltas begin with sample 2",
        "cpu_percent is the share of total logical-processor capacity; "
        "cpu_logical_cores is CPU seconds per elapsed second, so 1.0 means one logical core",
        "samples are separate instants and do not measure application interaction latency",
    ]
    value = {
        "captured_at": stamp,
        "inter_sample_delay_seconds": 1.0,
        "limitations": notes,
        "logical_cpu_count": 24,
        "samples": samples,
        "schema_version": 2,
        "status": "available",
        "target_creation_time": stamp,
        "target_pid": 4242,
        "window_ended_at": stamp,
        "window_started_at": stamp,
    }
    target = _context(facts={"target_pressure": value}).model_copy(
        update={
            "probe_id": "application.target_pressure",
            "limitations": (
                "Source time bounded_interval/collector_upper_bound is an upper bound; "
                "incident relevance unverified.",
                "First sample is a baseline",
                "Limited observation",
                "No interaction timing",
            ),
            "incident_relevant": None,
        }
    )
    others = tuple(
        _context(
            facts={
                "pressure": {
                    "samples": [
                        {
                            "pid": n,
                            "cpu_percent": n / 3,
                            "observed_at": stamp,
                            "status": "available",
                        }
                        for n in range(60)
                    ]
                }
            }
        )
        for _ in range(3)
    )
    packets = nested_evidence_packets((target, *others, _context(facts={"cpu_count": 24})))
    assert len(packets) <= 16
    delivered: dict[str, object] = {}

    def walk(path: str, node: object) -> None:
        delivered[path] = node
        if isinstance(node, dict):
            for key, child in cast(dict[str, object], node).items():
                walk(path + "/" + key.replace("~", "~0").replace("/", "~1"), child)
        elif isinstance(node, list):
            for i, child in enumerate(cast(list[object], node)):
                walk(path + "/" + str(i), child)

    for item in packets:
        SemanticPacketRefV2.model_validate(item)
        preview = json.loads(_focused_preview(compact_worker_packet(item)["description"]))
        assert len(item["description"]) <= 800
        if (
            item["evidence_id"] == str(target.evidence_id)
            and preview.get("value_quality") == "exact"
        ):
            walk(preview["source_path"], preview["value"])
    for i, sample in enumerate(samples):
        assert delivered[f"/target_pressure/samples/{i}"] == sample
    for name in (
        "target_pid",
        "target_creation_time",
        "logical_cpu_count",
        "window_started_at",
        "window_ended_at",
    ):
        assert delivered[f"/target_pressure/{name}"] == value[name]
    assert delivered["/target_pressure/limitations"] == notes


def test_v2_single_long_limitation_discloses_truncation() -> None:
    context = _context(facts={"metric": 42}).model_copy(update={"limitations": ("caveat " * 30,)})
    packet = nested_evidence_packets((context,))[0]
    preview = json.loads(compact_worker_packet(packet)["description"])
    assert preview["limitations_truncated"] == 1
    assert (
        preview["limitations_sha256"]
        == hashlib.sha256(
            json.dumps(
                list(context.limitations), sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        ).hexdigest()
    )


def test_v2_partial_sibling_groups_have_distinct_bound_identities() -> None:
    fields = {f"field_{i:02}": "x" * 80 for i in range(10)}
    packet_rows = nested_evidence_packets((_context(facts={"record": fields}),))
    assert len(packet_rows) > 1
    assert len({p["fragment_id"] for p in packet_rows}) == len(packet_rows)
    recovered: dict[str, object] = {}
    for packet in packet_rows:
        SemanticPacketRefV2.model_validate(packet)
        body = json.loads(packet["description"])
        assert body["value_selection"] == "fields"
        assert body["fields_omitted"] == len(fields) - len(body["value"])
        assert not set(recovered).intersection(body["value"])
        recovered.update(body["value"])
        bad = {**body, "value": {"substituted_key": 42}}
        with pytest.raises(ValueError):
            SemanticPacketRefV2.model_validate({**packet, "description": json.dumps(bad)})
    assert recovered == fields


def test_v2_multiple_source_relations_disclose_omitted_ids() -> None:
    context = _context(facts={"temperature": 42})
    relation = EvidenceRelation(
        relation_id="rel_" + "1" * 32,
        source_entity_id=EntityId.new(),
        target_entity_id=EntityId.new(),
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(context.evidence_id,),
    )
    relations = (relation, relation.model_copy(update={"relation_id": "rel_" + "2" * 32}))
    packet = nested_evidence_packets((context,), relationships=relations)[0]
    preview = json.loads(compact_worker_packet(packet)["description"])
    assert len(preview.get("relation_ids", [])) + preview["relation_ids_omitted"] == 2


@pytest.mark.parametrize("value", [{f"field_{i}": "x" * 8 for i in range(250)}, list(range(1000))])
def test_v2_wide_validated_context_remains_bounded_and_discloses_gaps(value: JsonValue) -> None:
    context = _context(facts={"record": value})
    packets = nested_evidence_packets((context,))
    assert len(packets) <= 16
    for packet in packets:
        SemanticPacketRefV2.model_validate(packet)
        assert len(packet["description"]) <= 800
    if isinstance(value, list):
        assert all(
            json.loads(packet["description"])["nested_paths_omitted"] > 0 for packet in packets
        )


def test_oversized_context_is_rejected_before_nested_projection() -> None:
    with pytest.raises(ValidationError, match="facts content exceeds 8192 bytes"):
        _context(facts={"oversized": "x" * 100_000})
