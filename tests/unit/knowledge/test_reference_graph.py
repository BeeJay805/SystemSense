import json
from pathlib import Path

import pytest

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
    assert graph.pack.version == 3
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
