import pytest
from pydantic import ValidationError

from systemsense.domain.ids import EntityId, EvidenceId
from systemsense.evidence.graph import EvidenceGraph, EvidenceRelation

_PROCESS = EntityId(root="entity_0123456789abcdef0123456789abcdef")
_MODULE = EntityId(root="entity_fedcba9876543210fedcba9876543210")
_EVIDENCE = EvidenceId(root="ev_0123456789abcdef0123456789abcdef")


def test_entity_relation_always_cites_evidence() -> None:
    graph = EvidenceGraph()
    relation = EvidenceRelation(
        source_entity_id=_PROCESS,
        target_entity_id=_MODULE,
        relationship="loaded_module",
        evidence_ids=(_EVIDENCE,),
    )

    graph.add_relation(relation)

    assert graph.relations == (relation,)


def test_relation_without_evidence_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EvidenceRelation(
            source_entity_id=_PROCESS,
            target_entity_id=_MODULE,
            relationship="loaded_module",
            evidence_ids=(),
        )
