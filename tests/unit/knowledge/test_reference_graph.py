import json
from pathlib import Path
from typing import Any

import pytest

import systemsense.knowledge as knowledge
from systemsense.knowledge import (
    DEFAULT_REGISTERED_PROBE_IDS,
    KnowledgeDirection,
    KnowledgeQuery,
    ReferenceKnowledgeGraph,
    ReferencePackError,
)


def test_default_pack_is_substantive_sourced_and_domain_balanced() -> None:
    graph = ReferenceKnowledgeGraph.load_default()

    assert graph.pack.pack_id == "windows-it-reference"
    assert graph.pack.version == 5
    assert "network.connectivity" in DEFAULT_REGISTERED_PROBE_IDS
    assert {"kr_wifi_001", "kr_wifi_002", "kr_wifi_003"} <= {
        relation.relation_id for relation in graph.pack.relations
    }
    assert len(graph.pack.relations) >= 100
    assert {
        "applications",
        "services",
        "processes",
        "devices",
        "drivers",
        "storage",
        "filesystems",
        "network",
        "dns",
        "proxy",
        "tls",
        "power",
        "hardware",
        "security",
        "update",
        "runtime",
        "cuda",
    } <= {node.category for node in graph.pack.nodes}
    assert all(relation.source_ids for relation in graph.pack.relations)
    assert all(relation.mechanism for relation in graph.pack.relations)
    assert all(relation.conditions for relation in graph.pack.relations)
    assert all(relation.distinguishing_probe_ids for relation in graph.pack.relations)
    assert all(relation.counterevidence for relation in graph.pack.relations)
    assert all(relation.limitations for relation in graph.pack.relations)
    assert graph.pack.schema_version == 1
    assert all(relation.reviewed_at is None for relation in graph.pack.relations)
    assert "reviewed_at" not in graph.pack.relations[0].model_dump(mode="json")
    assert "citations" not in graph.pack.relations[0].model_dump(mode="json")


def _v2_single_relation_payload() -> dict[str, Any]:
    payload = json.loads(ReferenceKnowledgeGraph.default_pack_path().read_text(encoding="utf-8"))
    relation = payload["relations"][0]
    payload["schema_version"] = 2
    payload["sources"] = [
        source for source in payload["sources"] if source["source_id"] in relation["sources"]
    ]
    payload["nodes"] = [
        node for node in payload["nodes"] if node["id"] in {relation["from"], relation["to"]}
    ]
    payload["relations"] = [
        dict(
            relation,
            reviewed_at="2026-09-23",
            citations=[
                {
                    "source_id": relation["sources"][0],
                    "revision": "0123456789abcdef0123456789abcdef01234567",
                    "section": "Windows Error Reporting overview",
                    "license_id": "CC-BY-4.0",
                    "license_url": "https://github.com/MicrosoftDocs/win32/blob/docs/LICENSE",
                    "pinned_url": (
                        "https://raw.githubusercontent.com/MicrosoftDocs/win32/"
                        "0123456789abcdef0123456789abcdef01234567/desktop-src/wer/overview.md"
                    ),
                    "content_sha256": "a" * 64,
                }
            ],
        )
    ]
    return payload


def test_v2_relation_provenance_survives_bounded_query(tmp_path: Path) -> None:
    path = tmp_path / "reference-v2.json"
    path.write_text(json.dumps(_v2_single_relation_payload()), encoding="utf-8")

    packet = ReferenceKnowledgeGraph.load_json(
        path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS
    ).query(KnowledgeQuery(max_relations=1))

    assert packet.relations[0].reviewed_at == "2026-09-23"
    citation = packet.relations[0].citations[0]
    assert citation.source_id == packet.relations[0].source_ids[0]
    assert citation.revision == "0123456789abcdef0123456789abcdef01234567"
    assert citation.license_id == "CC-BY-4.0"
    assert citation.pinned_url.startswith("https://raw.githubusercontent.com/")
    assert citation.content_sha256 == "a" * 64


def test_legacy_probe_hints_are_screening_not_discriminating() -> None:
    packet = ReferenceKnowledgeGraph.load_default().query(KnowledgeQuery(max_relations=1))

    roles = knowledge.probe_roles_for_relation(packet, packet.relations[0])

    assert roles.screening_probe_ids == packet.relations[0].distinguishing_probe_ids
    assert roles.discriminating_probe_ids == ()
    assert roles.unavailable_measurements == ()


def _v3_single_relation_payload() -> dict[str, Any]:
    payload = _v2_single_relation_payload()
    payload["schema_version"] = 3
    relation = payload["relations"][0]
    relation.pop("probes")
    relation["probe_roles"] = {
        "screening_probe_ids": ["application.snapshot"],
        "discriminating_probe_ids": ["incident.events"],
        "unavailable_measurements": ["Affected action latency against a pinned workload"],
    }
    return payload


def test_v3_probe_roles_survive_query_and_keep_unavailable_measurements_out_of_probe_ids(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reference-v3.json"
    path.write_text(json.dumps(_v3_single_relation_payload()), encoding="utf-8")

    graph = ReferenceKnowledgeGraph.load_json(
        path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS
    )
    packet = graph.query(KnowledgeQuery(probe_ids=("incident.events",)))
    roles = knowledge.probe_roles_for_relation(packet, packet.relations[0])

    assert packet.schema_version == 3
    assert roles.screening_probe_ids == ("application.snapshot",)
    assert roles.discriminating_probe_ids == ("incident.events",)
    assert roles.unavailable_measurements == ("Affected action latency against a pinned workload",)
    assert not graph.query(KnowledgeQuery(probe_ids=("affected action latency",))).relations


def test_v3_unavailable_only_relation_cannot_mint_a_probe(tmp_path: Path) -> None:
    payload = _v3_single_relation_payload()
    payload["relations"][0]["probe_roles"] = {
        "screening_probe_ids": [],
        "discriminating_probe_ids": [],
        "unavailable_measurements": ["Independent affected-task latency"],
    }
    path = tmp_path / "reference-gap-v3.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    graph = ReferenceKnowledgeGraph.load_json(
        path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS
    )
    packet = graph.query(KnowledgeQuery())
    roles = knowledge.probe_roles_for_relation(packet, packet.relations[0])

    assert roles.screening_probe_ids == ()
    assert roles.discriminating_probe_ids == ()
    assert roles.unavailable_measurements == ("Independent affected-task latency",)
    assert not graph.query(KnowledgeQuery(probe_ids=("application.snapshot",))).relations


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_roles",
        "missing_role_field",
        "legacy_probes",
        "overlapping",
        "unregistered",
        "empty_roles",
    ],
)
def test_v3_rejects_ambiguous_or_unregistered_probe_roles(tmp_path: Path, mutation: str) -> None:
    payload = _v3_single_relation_payload()
    relation = payload["relations"][0]
    roles = relation["probe_roles"]
    if mutation == "missing_roles":
        relation.pop("probe_roles")
    elif mutation == "missing_role_field":
        roles.pop("unavailable_measurements")
    elif mutation == "legacy_probes":
        relation["probes"] = ["application.snapshot"]
    elif mutation == "overlapping":
        roles["discriminating_probe_ids"] = ["application.snapshot"]
    elif mutation == "unregistered":
        roles["discriminating_probe_ids"] = ["arbitrary.command"]
    else:
        roles["screening_probe_ids"] = []
        roles["discriminating_probe_ids"] = []
        roles["unavailable_measurements"] = []
    path = tmp_path / "invalid-v3.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferencePackError):
        ReferenceKnowledgeGraph.load_json(path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS)


def test_v2_rejects_v3_probe_roles(tmp_path: Path) -> None:
    payload = _v2_single_relation_payload()
    payload["relations"][0]["probe_roles"] = {"screening_probe_ids": ["application.snapshot"]}
    path = tmp_path / "invalid-v2-roles.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferencePackError):
        ReferenceKnowledgeGraph.load_json(path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS)


def test_v1_rejects_explicit_null_v3_probe_roles(tmp_path: Path) -> None:
    payload = json.loads(ReferenceKnowledgeGraph.default_pack_path().read_text(encoding="utf-8"))
    payload["relations"][0]["probe_roles"] = None
    path = tmp_path / "invalid-v1-roles.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferencePackError):
        ReferenceKnowledgeGraph.load_json(path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS)


def test_v2_authoring_schema_requires_review_and_pinned_citations() -> None:
    path = ReferenceKnowledgeGraph.default_pack_path().with_name("reference_pack.v2.schema.json")
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == 2
    relation = schema["$defs"]["relation"]
    assert {"reviewed_at", "citations"} <= set(relation["required"])
    assert {
        "revision",
        "section",
        "license_id",
        "license_url",
        "pinned_url",
        "content_sha256",
    } <= set(schema["$defs"]["citation"]["required"])


def test_v3_authoring_schema_requires_explicit_probe_roles_and_pinned_citations() -> None:
    path = ReferenceKnowledgeGraph.default_pack_path().with_name("reference_pack.v3.schema.json")
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == 3
    relation = schema["$defs"]["relation"]
    assert {"probe_roles", "reviewed_at", "citations"} <= set(relation["required"])
    assert "probes" not in relation["properties"]
    roles = schema["$defs"]["probe_roles"]
    assert {
        "screening_probe_ids",
        "discriminating_probe_ids",
        "unavailable_measurements",
    } <= set(roles["properties"])


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "unmatched",
        "moving",
        "invalid_date",
        "missing_pinned_url",
        "missing_digest",
        "revision_not_in_url",
        "revision_only_in_fragment",
        "malformed_digest",
    ],
)
def test_v2_rejects_unreviewable_provenance(tmp_path: Path, mutation: str) -> None:
    payload = _v2_single_relation_payload()
    relation = payload["relations"][0]
    if mutation == "missing":
        relation.pop("citations")
    elif mutation == "unmatched":
        relation["citations"][0]["source_id"] = "ks_unreferenced"
    elif mutation == "moving":
        relation["citations"][0]["revision"] = "main"
    elif mutation == "invalid_date":
        relation["reviewed_at"] = "2026-02-30"
    elif mutation == "missing_pinned_url":
        relation["citations"][0].pop("pinned_url")
    elif mutation == "missing_digest":
        relation["citations"][0].pop("content_sha256")
    elif mutation == "revision_not_in_url":
        relation["citations"][0]["pinned_url"] = "https://example.com/other-release/artifact.md"
    elif mutation == "revision_only_in_fragment":
        relation["citations"][0]["pinned_url"] = (
            "https://example.com/artifact.md#0123456789abcdef0123456789abcdef01234567"
        )
    else:
        relation["citations"][0]["content_sha256"] = "not-a-sha256"
    path = tmp_path / "invalid-v2.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferencePackError):
        ReferenceKnowledgeGraph.load_json(path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS)


def test_v1_rejects_explicit_v2_fields_even_when_empty(tmp_path: Path) -> None:
    payload = json.loads(ReferenceKnowledgeGraph.default_pack_path().read_text(encoding="utf-8"))
    payload["relations"][0]["citations"] = []
    path = tmp_path / "invalid-v1.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferencePackError, match="schema v1"):
        ReferenceKnowledgeGraph.load_json(path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS)


def test_v2_rejects_invalid_pack_review_date(tmp_path: Path) -> None:
    payload = _v2_single_relation_payload()
    payload["reviewed_at"] = "2026-02-30"
    path = tmp_path / "invalid-review-date.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferencePackError):
        ReferenceKnowledgeGraph.load_json(path, registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS)


def test_query_returns_bounded_offline_references_not_evidence() -> None:
    graph = ReferenceKnowledgeGraph.load_default()

    packet = graph.query(
        KnowledgeQuery(
            keywords=("dns", "timeout"),
            categories=("dns", "network"),
            max_relations=3,
            max_chars=9_000,
        )
    )

    assert 0 < len(packet.relations) <= 3
    assert len(packet.model_dump_json()) <= 9_000
    assert all(relation.relation_id.startswith("kr_") for relation in packet.relations)
    assert all(not relation.relation_id.startswith("ev_") for relation in packet.relations)
    assert all(source.url.startswith("https://") for source in packet.sources)
    assert packet.disclaimer.startswith("Reference relationships are hypotheses")


def test_many_anchored_network_edges_do_not_exclude_a_separate_game_symptom() -> None:
    graph = ReferenceKnowledgeGraph.load_default()

    packet = graph.focused_packet(
        objective="WiFi disconnected and my game runs at 12 FPS",
        seed_node_ids=(
            "kn_network_failure",
            "kn_wifi_association_failure",
            "kn_wifi_auth_failure",
            "kn_ip_config_failure",
        ),
        max_relations=6,
        max_chars=6_000,
    )

    relation_ids = {relation.relation_id for relation in packet.relations}
    assert any(item.startswith("kr_wifi_") for item in relation_ids)
    assert any(item.startswith("kr_game_") for item in relation_ids)
    assert packet.pack_id == graph.pack.pack_id
    assert packet.pack_version == graph.pack.version
    assert all(relation.source_ids for relation in packet.relations)
    assert len(packet.relations) <= 6


@pytest.mark.parametrize("max_relations,max_chars", ((0, 6_000), (6, 512)))
def test_focused_reference_packet_rejects_unbounded_or_empty_limits(
    max_relations: int, max_chars: int
) -> None:
    graph = ReferenceKnowledgeGraph.load_default()

    with pytest.raises(ValueError):
        graph.focused_packet(
            objective="WiFi disconnected", max_relations=max_relations, max_chars=max_chars
        )


def test_low_fps_reference_links_are_sourced_conditional_and_honest_about_coverage() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    nodes = {node.node_id for node in graph.pack.nodes}
    relations = {relation.relation_id: relation for relation in graph.pack.relations}
    sources = {source.source_id: source for source in graph.pack.sources}

    assert {
        "kn_game_low_fps",
        "kn_game_frame_cap",
        "kn_display_refresh_limit",
        "kn_game_render_gpu_mismatch",
        "kn_gpu_clock_limiting",
        "kn_gpu_power_cap",
        "kn_gpu_thermal_slowdown",
        "kn_background_gpu_contention",
        "kn_game_vram_pressure",
    } <= nodes
    game_links = {key: value for key, value in relations.items() if key.startswith("kr_game_")}
    assert len(game_links) >= 10
    assert all(
        set(relation.distinguishing_probe_ids) <= DEFAULT_REGISTERED_PROBE_IDS
        for relation in game_links.values()
    )
    assert all(
        relation.source_ids and set(relation.source_ids) <= sources.keys()
        for relation in game_links.values()
    )
    assert all(
        relation.conditions and relation.counterevidence and relation.limitations
        for relation in game_links.values()
    )
    assert all(
        sources[source_id].publisher in {"Microsoft", "NVIDIA", "Intel"}
        for relation in game_links.values()
        for source_id in relation.source_ids
    )
    assert any(
        "12 fps" in note.lower() for note in game_links["kr_game_refresh_001"].counterevidence
    )
    assert "display.mode" in DEFAULT_REGISTERED_PROBE_IDS
    assert "display.mode" in game_links["kr_game_refresh_001"].distinguishing_probe_ids
    assert all(
        "do not measure active monitor refresh" not in note.lower()
        for note in game_links["kr_game_refresh_001"].limitations
    )
    assert any("not collect" in note.lower() for note in game_links["kr_game_cap_001"].limitations)
    assert {"gpu.telemetry.sample", "pressure.sample", "devices.snapshot"} <= {
        probe for relation in game_links.values() for probe in relation.distinguishing_probe_ids
    }

    packet = graph.query(
        KnowledgeQuery(keywords=("low fps",), categories=("gaming",), max_relations=24)
    )
    assert len(packet.relations) >= 8
    assert all(relation.relation_id.startswith("kr_game_") for relation in packet.relations)


def test_pdf_screening_references_are_conditional_and_do_not_name_bound_target() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    relations = {item.relation_id: item for item in graph.pack.relations}
    sources = {item.source_id for item in graph.pack.sources}
    pdf = {key: value for key, value in relations.items() if key.startswith("kr_pdf_")}

    assert set(pdf) == {
        "kr_pdf_001",
        "kr_pdf_002",
        "kr_pdf_003",
        "kr_pdf_004",
        "kr_pdf_005",
        "kr_pdf_006",
    }
    assert pdf["kr_pdf_001"].relationship == "depends_on"
    assert pdf["kr_pdf_001"].source_node_id == "kn_pdf_page_action"
    assert all(item.source_ids and set(item.source_ids) <= sources for item in pdf.values())
    assert all(
        item.conditions and item.counterevidence and item.limitations for item in pdf.values()
    )
    assert all(
        set(item.distinguishing_probe_ids) <= DEFAULT_REGISTERED_PROBE_IDS for item in pdf.values()
    )
    assert all(
        "application.target_pressure" not in item.distinguishing_probe_ids for item in pdf.values()
    )
    assert all(any("screen" in note.lower() for note in item.limitations) for item in pdf.values())
    assert all(
        any("cannot" in note.lower() and "latency" in note.lower() for note in item.limitations)
        for item in pdf.values()
    )
    packet = graph.query(
        KnowledgeQuery(keywords=("slow PDF",), categories=("pdf",), max_relations=8)
    )
    assert {item.relation_id for item in packet.relations} == set(pdf)
    assert packet.disclaimer.startswith("Reference relationships are hypotheses")


def test_new_wifi_pdf_dns_and_game_routes_are_conditional_screening_only() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    relations = {relation.relation_id: relation for relation in graph.pack.relations}
    source_ids = {source.source_id for source in graph.pack.sources}
    new_ids = {
        "kr_pdf_003",
        "kr_pdf_004",
        "kr_pdf_005",
        "kr_pdf_006",
        "kr_wifi_004",
        "kr_wifi_005",
        "kr_wifi_006",
        "kr_dns_007",
        "kr_game_load_001",
    }

    for relation_id in new_ids:
        relation = relations[relation_id]
        assert relation.conditions and relation.counterevidence and relation.limitations
        assert relation.source_ids and set(relation.source_ids) <= source_ids
        assert set(relation.distinguishing_probe_ids) <= DEFAULT_REGISTERED_PROBE_IDS
        assert relation.probe_roles is None

    assert relations["kr_pdf_006"].source_node_id == "kn_pdf_accessibility_processing"
    assert relations["kr_wifi_004"].target_node_id == "kn_wifi_association_failure"
    assert relations["kr_wifi_006"].target_node_id == "kn_ip_config_failure"
    assert relations["kr_game_load_001"].target_node_id == "kn_game_low_fps"
    assert any(
        "frame" in limitation.lower() for limitation in relations["kr_game_load_001"].limitations
    )


@pytest.mark.parametrize(
    ("keyword", "category", "relation_id"),
    (
        ("page cache", "pdf", "kr_pdf_004"),
        ("accessibility", "pdf", "kr_pdf_006"),
        ("WlanSvc", "network", "kr_wifi_004"),
        ("DHCP", "network", "kr_wifi_006"),
        ("DNS server", "dns", "kr_dns_007"),
        ("render scale", "gaming", "kr_game_load_001"),
    ),
)
def test_new_routes_are_retrievable_by_specific_technical_clues(
    keyword: str, category: str, relation_id: str
) -> None:
    packet = ReferenceKnowledgeGraph.load_default().query(
        KnowledgeQuery(keywords=(keyword,), categories=(category,), max_relations=64)
    )

    assert relation_id in {relation.relation_id for relation in packet.relations}


def test_query_reports_honest_truncation() -> None:
    graph = ReferenceKnowledgeGraph.load_default()

    packet = graph.query(KnowledgeQuery(keywords=("windows",), max_relations=2))

    assert len(packet.relations) == 2
    assert packet.truncated is True
    assert packet.omitted_relation_count > 0
    assert "query limits omitted matching reference relationships" in packet.limitations


def test_expand_is_deterministic_and_enforces_graph_bounds() -> None:
    graph = ReferenceKnowledgeGraph.load_default()

    first = graph.expand(
        start_node_ids=("kn_dns_resolution",),
        direction=KnowledgeDirection.BOTH,
        max_depth=2,
        max_nodes=5,
        max_edges=3,
        max_chars=12_000,
    )
    second = graph.expand(
        start_node_ids=("kn_dns_resolution",),
        direction=KnowledgeDirection.BOTH,
        max_depth=2,
        max_nodes=5,
        max_edges=3,
        max_chars=12_000,
    )

    assert first == second
    assert len(first.nodes) <= 5
    assert len(first.relations) <= 3
    assert first.truncated is True


def test_loader_rejects_dangling_sources_unknown_probes_and_oversized_pack(
    tmp_path: Path,
) -> None:
    valid_path = ReferenceKnowledgeGraph.default_pack_path()
    payload = json.loads(valid_path.read_text(encoding="utf-8"))

    dangling = dict(payload)
    dangling["relations"] = [dict(payload["relations"][0], source_ids=["ks_missing"])]
    dangling_path = tmp_path / "dangling.json"
    dangling_path.write_text(json.dumps(dangling), encoding="utf-8")
    with pytest.raises(ReferencePackError, match="unknown source"):
        ReferenceKnowledgeGraph.load_json(
            dangling_path,
            registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS,
        )

    unknown_probe = dict(payload)
    unknown_probe["relations"] = [
        dict(payload["relations"][0], distinguishing_probe_ids=["arbitrary.command"])
    ]
    unknown_probe_path = tmp_path / "unknown-probe.json"
    unknown_probe_path.write_text(json.dumps(unknown_probe), encoding="utf-8")
    with pytest.raises(ReferencePackError, match="unregistered probe"):
        ReferenceKnowledgeGraph.load_json(
            unknown_probe_path,
            registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS,
        )

    oversized = dict(payload)
    oversized["relations"] = [payload["relations"][0]] * 2_049
    oversized_path = tmp_path / "oversized.json"
    oversized_path.write_text(json.dumps(oversized), encoding="utf-8")
    with pytest.raises(ReferencePackError, match="at most 2048"):
        ReferenceKnowledgeGraph.load_json(
            oversized_path,
            registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS,
        )


def test_loader_is_atomic_and_rejects_conflicting_duplicate_ids(tmp_path: Path) -> None:
    payload = json.loads(ReferenceKnowledgeGraph.default_pack_path().read_text(encoding="utf-8"))
    first = payload["relations"][0]
    payload["relations"] = [first, dict(first, target_node_id="kn_cpu_pressure")]
    invalid_path = tmp_path / "duplicate.json"
    invalid_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferencePackError, match="duplicate relation ID"):
        ReferenceKnowledgeGraph.load_json(
            invalid_path,
            registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_depth", 5, "max_depth"),
        ("max_nodes", 65, "max_nodes"),
        ("max_edges", 129, "max_edges"),
    ],
)
def test_expand_rejects_unbounded_requests(field: str, value: int, message: str) -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    arguments = {
        "start_node_ids": ("kn_dns_resolution",),
        "max_depth": 1,
        "max_nodes": 8,
        "max_edges": 8,
    }
    arguments[field] = value

    with pytest.raises(ValueError, match=message):
        graph.expand(**arguments)  # type: ignore[arg-type]
