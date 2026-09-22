from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from systemsense.domain.ids import EntityId, EvidenceId
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceGraph,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)

_PROCESS = EntityId(root="entity_0123456789abcdef0123456789abcdef")
_MODULE = EntityId(root="entity_fedcba9876543210fedcba9876543210")
_DEVICE = EntityId(root="entity_11111111111111111111111111111111")
_EVIDENCE = EvidenceId(root="ev_0123456789abcdef0123456789abcdef")
_OBSERVED = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _relation(
    relation_id: str,
    source: EntityId = _PROCESS,
    target: EntityId = _MODULE,
    *,
    kind: RelationKind = RelationKind.DEPENDS_ON,
    layer: MemoryLayer = MemoryLayer.MACHINE,
    status: AssertionStatus = AssertionStatus.OBSERVED,
    version: int = 1,
    valid_from: datetime | None = _OBSERVED,
    valid_until: datetime | None = None,
    evidence_ids: tuple[EvidenceId, ...] = (_EVIDENCE,),
    source_ids: tuple[str, ...] = (),
) -> EvidenceRelation:
    return EvidenceRelation(
        relation_id=relation_id,
        source_entity_id=source,
        target_entity_id=target,
        relationship=kind,
        memory_layer=layer,
        assertion_status=status,
        relation_version=version,
        valid_from=valid_from,
        valid_until=valid_until,
        evidence_ids=evidence_ids,
        source_ids=source_ids,
        conditions=("same host",),
        applicability=("windows",),
        version_metadata={"os_build": "26100"},
    )


def test_relation_has_typed_temporal_provenance_and_metadata() -> None:
    relation = _relation("rel_0123456789abcdef0123456789abcdef")

    assert relation.relationship is RelationKind.DEPENDS_ON
    assert relation.memory_layer is MemoryLayer.MACHINE
    assert relation.assertion_status is AssertionStatus.OBSERVED
    assert relation.valid_from == _OBSERVED
    assert relation.evidence_ids == (_EVIDENCE,)
    assert relation.conditions == ("same host",)
    assert relation.version_metadata["os_build"] == "26100"


def test_observed_relation_requires_provenance() -> None:
    with pytest.raises(ValidationError, match="provenance"):
        _relation(
            "rel_0123456789abcdef0123456789abcdef",
            evidence_ids=(),
            source_ids=(),
        )


def test_relation_rejects_reversed_validity_interval() -> None:
    with pytest.raises(ValidationError, match="validity"):
        _relation(
            "rel_0123456789abcdef0123456789abcdef",
            valid_from=_OBSERVED,
            valid_until=datetime(2026, 7, 30, 11, 0, tzinfo=UTC),
        )


def test_graph_allows_cycles_without_reverse_or_causal_inference() -> None:
    graph = EvidenceGraph()
    graph.add_relation(_relation("rel_0123456789abcdef0123456789abcdef"))
    graph.add_relation(
        _relation(
            "rel_11111111111111111111111111111111",
            source=_MODULE,
            target=_PROCESS,
            kind=RelationKind.CORRELATED_WITH,
            status=AssertionStatus.INFERRED,
            evidence_ids=(),
            source_ids=("src_" + "a" * 64,),
        )
    )

    traversed = graph.traverse(start_entity_id=_PROCESS)

    assert tuple(edge.target_entity_id for edge in traversed) == (_MODULE, _PROCESS)
    assert traversed[0].relationship is RelationKind.DEPENDS_ON
    assert traversed[1].relationship is RelationKind.CORRELATED_WITH

    directed_only = EvidenceGraph()
    directed_only.add_relation(_relation("rel_22222222222222222222222222222222"))
    assert directed_only.traverse(start_entity_id=_MODULE) == ()


def test_traversal_filters_by_time_kind_and_layer() -> None:
    graph = EvidenceGraph()
    graph.add_relation(_relation("rel_0123456789abcdef0123456789abcdef"))
    graph.add_relation(
        _relation(
            "rel_11111111111111111111111111111111",
            source=_PROCESS,
            target=_DEVICE,
            kind=RelationKind.USES_DEVICE,
            layer=MemoryLayer.REFERENCE,
            valid_from=datetime(2026, 8, 1, tzinfo=UTC),
            evidence_ids=(),
            source_ids=("src_" + "b" * 64,),
        )
    )

    traversed = graph.traverse(
        start_entity_id=_PROCESS,
        relation_kinds={RelationKind.DEPENDS_ON},
        memory_layers={MemoryLayer.MACHINE},
        as_of=datetime(2026, 7, 31, tzinfo=UTC),
    )

    assert tuple(edge.relation_id for edge in traversed) == (
        "rel_0123456789abcdef0123456789abcdef",
    )


def test_traversal_is_deterministic_and_enforces_node_and_edge_limits() -> None:
    graph = EvidenceGraph()
    graph.add_relation(_relation("rel_22222222222222222222222222222222", target=_DEVICE))
    graph.add_relation(_relation("rel_11111111111111111111111111111111"))
    graph.add_relation(
        _relation(
            "rel_33333333333333333333333333333333",
            source=_MODULE,
            target=_DEVICE,
            status=AssertionStatus.INFERRED,
            evidence_ids=(),
            source_ids=("src_" + "c" * 64,),
        )
    )

    first = graph.traverse(start_entity_id=_PROCESS, max_nodes=2, max_edges=1)
    second = graph.traverse(start_entity_id=_PROCESS, max_nodes=2, max_edges=1)

    assert first == second
    assert len(first) == 1
    assert first[0].relation_id == "rel_22222222222222222222222222222222"


def test_exact_duplicate_is_idempotent_but_conflicting_versions_remain_explicit() -> None:
    graph = EvidenceGraph()
    first = _relation("rel_0123456789abcdef0123456789abcdef")
    graph.add_relation(first)
    graph.add_relation(first)
    graph.add_relation(
        _relation(
            first.relation_id,
            version=2,
            valid_from=datetime(2026, 8, 1, tzinfo=UTC),
        )
    )

    assert len(graph.relations) == 2
    assert tuple(edge.relation_version for edge in graph.relations) == (1, 2)

    with pytest.raises(ValueError, match="conflicting"):
        graph.add_relation(first.model_copy(update={"target_entity_id": _DEVICE}))
