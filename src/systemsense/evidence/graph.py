"""Provenance-aware temporal relationships between system entities.

This graph stores evidence relationships only.  It is not an executable task
dependency graph, and an edge never implies a causal explanation by itself.
"""

import re
from collections import deque
from collections.abc import Iterable
from enum import StrEnum
from typing import Literal

from pydantic import AliasChoices, Field, field_validator, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EntityId, EvidenceId, JsonValue
from systemsense.domain.time import UtcDateTime


class RelationKind(StrEnum):
    """Closed vocabulary for directed evidence relationships."""

    DEPENDS_ON = "depends_on"
    USES_DEVICE = "uses_device"
    STORED_ON = "stored_on"
    CONFIGURED_BY = "configured_by"
    INSTALLED_VERSION = "installed_version"
    CORRELATED_WITH = "correlated_with"
    OBSERVED_AFTER = "observed_after"
    CAN_CONTRIBUTE_TO = "can_contribute_to"
    RUNS_IN_PROCESS = "runs_in_process"
    USES_DRIVER = "uses_driver"


class MemoryLayer(StrEnum):
    REFERENCE = "reference"
    MACHINE = "machine"
    EXPERIENCE = "experience"


class AssertionStatus(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"


class EvidenceRelation(FrozenModel):
    """One directed, versioned relationship supported by provenance.

    ``relationship`` describes what was recorded; it is not an instruction to
    execute work and does not establish causality.  Versions allow a revised
    relationship to coexist with an earlier or conflicting assertion.
    """

    schema_version: Literal[1] = 1
    relation_id: str = Field(pattern=r"^rel_[0-9a-f]{32}$")
    source_entity_id: EntityId
    target_entity_id: EntityId
    relationship: RelationKind = Field(
        validation_alias=AliasChoices("relationship", "relation_kind")
    )
    memory_layer: MemoryLayer
    assertion_status: AssertionStatus
    relation_version: int = Field(ge=1)
    valid_from: UtcDateTime | None = None
    valid_until: UtcDateTime | None = None
    evidence_ids: tuple[EvidenceId, ...] = ()
    source_ids: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()
    applicability: tuple[str, ...] = ()
    version_metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @property
    def relation_kind(self) -> RelationKind:
        """Convenient semantic alias for callers using ``relation_kind``."""

        return self.relationship

    @field_validator("source_ids")
    @classmethod
    def source_ids_must_be_stable_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"src_[0-9a-f]{64}", value) is None for value in values):
            raise ValueError("source_ids must contain stable source IDs")
        return values

    @model_validator(mode="after")
    def validate_temporal_provenance(self) -> "EvidenceRelation":
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and self.valid_until < self.valid_from
        ):
            raise ValueError("validity interval must be ordered")
        if not self.evidence_ids and not self.source_ids:
            raise ValueError("relation provenance requires evidence or source references")
        if self.assertion_status is AssertionStatus.OBSERVED and not (
            self.evidence_ids or self.source_ids
        ):
            raise ValueError("observed relation requires provenance")
        return self

    def is_valid_at(self, at: UtcDateTime) -> bool:
        """Return whether this edge is valid at an inclusive point in time."""

        return (self.valid_from is None or self.valid_from <= at) and (
            self.valid_until is None or at <= self.valid_until
        )


class EvidenceGraph:
    """Bounded in-memory graph for directed evidence relationships.

    Cycles are valid because this structure represents evidence, not an
    executable dependency DAG.  Traversal follows stored direction only and
    never creates reverse edges or causal conclusions.
    """

    def __init__(self) -> None:
        self._relations: dict[tuple[str, int], EvidenceRelation] = {}

    @property
    def relations(self) -> tuple[EvidenceRelation, ...]:
        """Return relations in a stable identity/version order."""

        return tuple(
            self._relations[key]
            for key in sorted(self._relations, key=lambda item: (item[0], item[1]))
        )

    def add_relation(self, relation: EvidenceRelation) -> None:
        """Add an edge, ignoring exact duplicates and rejecting same-key conflicts."""

        key = (relation.relation_id, relation.relation_version)
        existing = self._relations.get(key)
        if existing is None:
            self._relations[key] = relation
            return
        if existing != relation:
            raise ValueError("conflicting relation for the same identity and version")

    def traverse(
        self,
        *,
        start_entity_id: EntityId,
        relation_kinds: Iterable[RelationKind | str] | None = None,
        memory_layers: Iterable[MemoryLayer | str] | None = None,
        as_of: UtcDateTime | None = None,
        max_depth: int = 8,
        max_nodes: int = 256,
        max_edges: int = 512,
    ) -> tuple[EvidenceRelation, ...]:
        """Traverse directed, filtered edges with hard node and edge limits."""

        if max_depth < 0:
            raise ValueError("max_depth must not be negative")
        if max_nodes < 1:
            raise ValueError("max_nodes must be positive")
        if max_edges < 0:
            raise ValueError("max_edges must not be negative")

        allowed_kinds = (
            None
            if relation_kinds is None
            else frozenset(RelationKind(kind) for kind in relation_kinds)
        )
        allowed_layers = (
            None
            if memory_layers is None
            else frozenset(MemoryLayer(layer) for layer in memory_layers)
        )
        visited: set[str] = {str(start_entity_id)}
        pending: deque[tuple[EntityId, int]] = deque([(start_entity_id, 0)])
        result: list[EvidenceRelation] = []

        while pending and len(result) < max_edges:
            entity_id, depth = pending.popleft()
            if depth >= max_depth:
                continue
            candidates = sorted(
                (
                    relation
                    for relation in self._relations.values()
                    if relation.source_entity_id == entity_id
                    and (allowed_kinds is None or relation.relationship in allowed_kinds)
                    and (allowed_layers is None or relation.memory_layer in allowed_layers)
                    and (as_of is None or relation.is_valid_at(as_of))
                ),
                key=self._traversal_key,
            )
            for relation in candidates:
                target_key = str(relation.target_entity_id)
                target_is_new = target_key not in visited
                if target_is_new and len(visited) >= max_nodes:
                    continue
                result.append(relation)
                if target_is_new:
                    visited.add(target_key)
                    pending.append((relation.target_entity_id, depth + 1))
                if len(result) >= max_edges:
                    break

        return tuple(result)

    @staticmethod
    def _traversal_key(relation: EvidenceRelation) -> tuple[str, str, str, int, str]:
        return (
            str(relation.target_entity_id),
            relation.relationship.value,
            relation.memory_layer.value,
            relation.relation_version,
            relation.relation_id,
        )
