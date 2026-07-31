"""Evidence-cited relationships between normalized system entities."""

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EntityId, EvidenceId


class EvidenceRelation(FrozenModel):
    """One directional relationship supported by at least one evidence record."""

    source_entity_id: EntityId
    target_entity_id: EntityId
    relationship: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1)


class EvidenceGraph:
    """Small in-memory graph used while assembling a diagnostic case."""

    def __init__(self) -> None:
        self._relations: list[EvidenceRelation] = []

    @property
    def relations(self) -> tuple[EvidenceRelation, ...]:
        return tuple(self._relations)

    def add_relation(self, relation: EvidenceRelation) -> None:
        self._relations.append(relation)
