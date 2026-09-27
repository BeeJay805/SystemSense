"""The reviewed layer must fail closed without changing legacy pack loading."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from systemsense.knowledge import DEFAULT_REGISTERED_PROBE_IDS, ReferenceKnowledgeGraph
from systemsense.knowledge.catalog import ReferencePackError
from systemsense.knowledge.models import KnowledgeQuery, KnowledgeRelation, KnowledgeReviewManifest


def _inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    data = ReferenceKnowledgeGraph.default_pack_path().parent
    pack = json.loads((data / "windows_it_v1.json").read_text(encoding="utf-8"))
    reviews = json.loads((data / "reference_reviews.v1.json").read_text(encoding="utf-8"))
    return pack, reviews


def _load(tmp_path: Path, pack: dict[str, Any], reviews: dict[str, Any]) -> ReferenceKnowledgeGraph:
    pack_path = tmp_path / "pack.json"
    review_path = tmp_path / "reviews.json"
    pack_path.write_text(json.dumps(pack), encoding="utf-8")
    review_path.write_text(json.dumps(reviews), encoding="utf-8")
    return ReferenceKnowledgeGraph.load_json(
        pack_path,
        registered_probe_ids=DEFAULT_REGISTERED_PROBE_IDS,
        review_manifest_path=review_path,
    )


def _digest(relation: dict[str, Any]) -> str:
    normalized = KnowledgeRelation.model_validate(relation).model_dump(mode="json")
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_review_schema_artifact_matches_versioned_model() -> None:
    data = ReferenceKnowledgeGraph.default_pack_path().parent
    stored = json.loads((data / "reference_reviews.v1.schema.json").read_text(encoding="utf-8"))
    expected = KnowledgeReviewManifest.model_json_schema()
    assert stored["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert stored["$id"].endswith("reference-reviews.v1.schema.json")
    assert {
        key: value for key, value in stored.items() if key not in {"$schema", "$id"}
    } == expected


def test_reviewed_relations_keep_provenance_and_missing_observability() -> None:
    graph = ReferenceKnowledgeGraph.load_default()

    assert len(graph.reviewed_relation_ids) >= 12
    assert graph.reviewed_relation_ids < {item.relation_id for item in graph.pack.relations}
    for relation_id in graph.reviewed_relation_ids:
        review = graph.review_for(relation_id)
        assert review is not None
        assert review.status == "active"
        assert review.source_sections
        assert review.supporting_observations
    assert graph.review_for("kr_wifi_001") is None  # legacy, source URL only


def test_review_manifest_rejects_stale_pack_and_missing_source(tmp_path: Path) -> None:
    pack, reviews = _inputs()
    reviews["pack_version"] += 1
    with pytest.raises(ReferencePackError, match="pack version"):
        _load(tmp_path, pack, reviews)

    pack, reviews = _inputs()
    reviews["reviews"][0]["source_sections"][0]["source_id"] = "ks_missing"
    with pytest.raises(ReferencePackError, match="source"):
        _load(tmp_path, pack, reviews)

    pack, reviews = _inputs()
    next(item for item in pack["relations"] if item["id"] == reviews["reviews"][0]["relation_id"])[
        "mechanism"
    ] = "Changed after the relation was reviewed."
    with pytest.raises(ReferencePackError, match="digest mismatch"):
        _load(tmp_path, pack, reviews)

    pack, reviews = _inputs()
    next(item for item in pack["nodes"] if item["id"] == "kn_firefox_request")["label"] = (
        "Changed node semantics without review"
    )
    with pytest.raises(ReferencePackError, match="pack digest mismatch"):
        _load(tmp_path, pack, reviews)


def test_reviewed_primary_source_host_and_date_are_checked(tmp_path: Path) -> None:
    pack, reviews = _inputs()
    source_id = reviews["reviews"][0]["source_sections"][0]["source_id"]
    next(item for item in pack["sources"] if item["source_id"] == source_id)["url"] = (
        "https://example.com/borrowed-microsoft-title"
    )
    with pytest.raises(ReferencePackError, match="primary source"):
        _load(tmp_path, pack, reviews)

    pack, reviews = _inputs()
    reviews["reviews"][0]["source_sections"][0]["source_updated_at"] = "2027-01-01"
    with pytest.raises(ReferencePackError, match="source date after review"):
        _load(tmp_path, pack, reviews)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("min_windows_build", 30000, "build range"),
        ("supporting_observations", ["  "], "observation"),
        ("status", "trusted_by_model", "status"),
    ],
)
def test_review_manifest_rejects_invalid_claims(
    tmp_path: Path, field: str, value: Any, message: str
) -> None:
    pack, reviews = _inputs()
    reviews["reviews"][0][field] = value
    if field == "min_windows_build":
        reviews["reviews"][0]["max_windows_build"] = 20000
    with pytest.raises(ReferencePackError, match=message):
        _load(tmp_path, pack, reviews)


def test_review_manifest_rejects_duplicate_semantics_and_dependency_cycle(tmp_path: Path) -> None:
    pack, reviews = _inputs()
    reviews["reviews"].append(dict(reviews["reviews"][0]))
    with pytest.raises(ReferencePackError, match="duplicate review"):
        _load(tmp_path, pack, reviews)

    pack, reviews = _inputs()
    relation = next(
        item for item in pack["relations"] if item["id"] == "kr_ref_dns_client_depends_001"
    )
    duplicate = dict(relation, id="kr_ref_dns_client_depends_002")
    pack["relations"].append(duplicate)
    reviews["reviews"].append(
        dict(reviews["reviews"][0], relation_id=duplicate["id"], relation_sha256=_digest(duplicate))
    )
    with pytest.raises(ReferencePackError, match="duplicate semantics"):
        _load(tmp_path, pack, reviews)

    pack, reviews = _inputs()
    reverse = dict(
        relation,
        id="kr_ref_dns_client_depends_002",
        **{"from": relation["to"], "to": relation["from"]},
    )
    pack["relations"].append(reverse)
    reviews["reviews"].append(
        dict(reviews["reviews"][0], relation_id=reverse["id"], relation_sha256=_digest(reverse))
    )
    with pytest.raises(ReferencePackError, match="dependency cycle"):
        _load(tmp_path, pack, reviews)


def test_bounded_reviewed_retrieval_preserves_counterevidence() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    packet = graph.query_reviewed(KnowledgeQuery(keywords=("proxy",), max_relations=2))

    assert len(packet.relations) <= 2
    assert packet.truncated
    assert any(item.counterevidence for item in packet.relations)
    assert all(item.source_ids for item in packet.relations)
    assert any(item.relation_id in graph.reviewed_relation_ids for item in packet.relations)


def test_named_browser_branch_beats_earlier_generic_proxy_edge() -> None:
    packet = ReferenceKnowledgeGraph.load_default().focused_packet(
        objective="Firefox website fails through proxy while another app works",
        max_relations=6,
        max_chars=6_000,
    )

    relation_ids = {item.relation_id for item in packet.relations}
    assert "kr_ref_firefox_proxy_001" in relation_ids
    assert "kr_ref_proxy_request_001" not in relation_ids


def _reviewed_graph() -> ReferenceKnowledgeGraph:
    graph = ReferenceKnowledgeGraph.load_default()
    return ReferenceKnowledgeGraph(
        graph.pack.model_copy(
            update={
                "relations": tuple(
                    relation
                    for relation in graph.pack.relations
                    if relation.relation_id in graph.reviewed_relation_ids
                )
            }
        )
    )


def test_generic_browser_proxy_clue_keeps_conditional_alternatives_without_game() -> None:
    packet = _reviewed_graph().focused_packet(
        objective=(
            "Browser cannot open the requested site. "
            "Observe the affected browser request route: proxy denied"
        ),
        max_relations=6,
        max_chars=6_000,
    )

    relation_ids = {item.relation_id for item in packet.relations}
    assert "kr_ref_game_frametime_001" not in relation_ids
    assert any(
        item.startswith("kr_ref_dns_") or item.startswith("kr_ref_proxy_") for item in relation_ids
    )
    assert all(
        item.conditions and item.counterevidence and item.limitations for item in packet.relations
    )
    conditional = next(
        item for item in packet.relations if item.relation_id == "kr_ref_proxy_request_001"
    )
    assert "When the affected request uses WinHTTP" in conditional.conditions[0]
    assert "not machine observations" in packet.disclaimer


def test_generic_document_clues_do_not_rank_a_game_specific_reference() -> None:
    graph = _reviewed_graph()
    base = "Document opens slowly. Observe the affected document opening task: slow. "
    for objective in (base, base + "Measure document storage latency: high"):
        packet = graph.focused_packet(
            objective=objective,
            max_relations=6,
            max_chars=6_000,
        )
        assert "kr_ref_game_frametime_001" not in {item.relation_id for item in packet.relations}
        assert any(item.relation_id.startswith("kr_pdf_") for item in packet.relations)
        assert all(
            item.conditions and item.counterevidence and item.limitations
            for item in packet.relations
        )
        assert len(packet.model_dump_json()) <= 6_000


def test_named_and_seeded_game_context_retains_game_branch() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    named = graph.focused_packet(
        objective="Game stutter with inconsistent frame time", max_relations=6, max_chars=6_000
    )
    seeded = graph.focused_packet(
        objective="Browser cannot open site",
        seed_node_ids=("kn_game_poor_smoothness",),
        max_relations=6,
        max_chars=6_000,
    )
    gpu = graph.focused_packet(
        objective="GPU power cap and thermal slowdown", max_relations=6, max_chars=6_000
    )

    assert any(item.relation_id.startswith("kr_game_") for item in named.relations)
    assert "kr_ref_game_frametime_001" in {item.relation_id for item in seeded.relations}
    assert "kr_game_power_001" in {item.relation_id for item in gpu.relations}
    assert (
        graph.focused_packet(
            objective="Game stutter with inconsistent frame time", max_relations=6, max_chars=6_000
        )
        == named
    )


def test_generic_proxy_and_dns_observations_preserve_distinct_reference_sets() -> None:
    graph = _reviewed_graph()
    prefix = "Browser cannot reliably open the requested site. Observe browser request route: "
    proxy = graph.focused_packet(
        objective=prefix + "proxy denied", max_relations=6, max_chars=6_000
    )
    dns = graph.focused_packet(objective=prefix + "dns failure", max_relations=6, max_chars=6_000)
    assert {item.relation_id for item in proxy.relations} != {
        item.relation_id for item in dns.relations
    }


def test_explicit_pdf_and_winhttp_scope_retains_conditional_source_paths() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    pdf = graph.focused_packet(
        objective="PDF document opens slowly with high storage latency",
        max_relations=6,
        max_chars=6_000,
    )
    winhttp = graph.focused_packet(
        objective="WinHTTP request fails through a configured proxy",
        max_relations=6,
        max_chars=6_000,
    )
    assert any(item.relation_id.startswith("kr_pdf_") for item in pdf.relations)
    assert any(item.source_node_id.startswith("kn_winhttp_") for item in winhttp.relations)


def test_equal_score_keeps_existing_route_branch_in_bounded_packet() -> None:
    packet = ReferenceKnowledgeGraph.load_default().focused_packet(
        objective="Internet route mismatch",
        max_relations=6,
        max_chars=6_000,
    )

    assert "kr_net_001" in {item.relation_id for item in packet.relations}


def test_deprecated_review_is_not_retrieved(tmp_path: Path) -> None:
    pack, reviews = _inputs()
    relation_id = reviews["reviews"][0]["relation_id"]
    reviews["reviews"][0]["status"] = "deprecated"
    graph = _load(tmp_path, pack, reviews)

    assert relation_id not in graph.reviewed_relation_ids
    assert relation_id not in {
        item.relation_id
        for item in graph.query(
            KnowledgeQuery(node_ids=("kn_application_hostname_request",))
        ).relations
    }


def test_graph_expansion_uses_adjacency_without_scanning_all_relations() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    packet = graph.expand(start_node_ids=("kn_dns_resolution",), max_depth=2, max_edges=8)
    assert len(packet.relations) <= 8
    assert any(item.source_node_id == "kn_dns_resolution" for item in packet.relations)


def test_reviewed_stage_paths_require_different_evidence() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    stage_ids = {
        "kr_wifi_002",  # association
        "kr_wifi_003",  # IP and route
        "kr_wifi_005",  # radio state
        "kr_wifi_006",  # DHCP
        "kr_pdf_002",  # CPU scheduling
        "kr_pdf_003",  # Acrobat content rendering
        "kr_pdf_007",  # document file I/O
        "kr_game_power_001",  # power cap
        "kr_game_thermal_001",  # thermal slowdown
    }
    assert stage_ids <= graph.reviewed_relation_ids
    for relation_id in stage_ids:
        review = graph.review_for(relation_id)
        assert review is not None
        assert review.source_sections
        assert review.supporting_observations
        assert review.unavailable_measurements


def test_reviewed_query_keeps_competing_stages_without_claiming_a_cause() -> None:
    graph = ReferenceKnowledgeGraph.load_default()
    wifi = graph.query_reviewed(
        KnowledgeQuery(node_ids=("kn_wifi_association_failure",), max_relations=16)
    )
    pdf = graph.query_reviewed(KnowledgeQuery(node_ids=("kn_pdf_page_delay",), max_relations=16))
    game = graph.query_reviewed(
        KnowledgeQuery(node_ids=("kn_gpu_clock_limiting",), max_relations=16)
    )

    assert "kr_wifi_002" in {item.relation_id for item in wifi.relations}
    assert {"kr_pdf_002", "kr_pdf_003", "kr_pdf_007"} <= {
        item.relation_id for item in pdf.relations
    }
    assert {"kr_game_power_001", "kr_game_thermal_001"} <= {
        item.relation_id for item in game.relations
    }
    for packet in (wifi, pdf, game):
        assert all(
            item.conditions and item.counterevidence and item.limitations
            for item in packet.relations
        )
        assert "not machine observations" in packet.disclaimer
