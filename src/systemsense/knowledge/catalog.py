"""Atomic bounded loader and local retrieval for reference knowledge."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from systemsense.knowledge.models import (
    KnowledgeDirection,
    KnowledgePacket,
    KnowledgeQuery,
    KnowledgeRelation,
    ReferencePack,
)

DEFAULT_REGISTERED_PROBE_IDS = frozenset(
    {
        "application.snapshot",
        "core.resources",
        "core.system",
        "devices.snapshot",
        "gpu.telemetry.sample",
        "incident.events",
        "local_ai.snapshot",
        "network.configuration",
        "network.connectivity",
        "network.listeners",
        "network.snapshot",
        "power.snapshot",
        "pressure.sample",
        "security.snapshot",
        "servicing.snapshot",
        "storage.snapshot",
    }
)

_MAX_PACK_BYTES = 4_000_000
_DISCLAIMER = (
    "Reference relationships are hypotheses for investigation, not machine observations, "
    "proof of cause, permissions, or instructions to change the system."
)


class ReferencePackError(ValueError):
    """The complete reference pack failed validation and was not loaded."""


class ReferenceKnowledgeGraph:
    """Immutable curated graph, deliberately separate from the evidence graph."""

    def __init__(self, pack: ReferencePack) -> None:
        self.pack = pack
        self._nodes = {item.node_id: item for item in pack.nodes}
        self._sources = {item.source_id: item for item in pack.sources}

    @staticmethod
    def default_pack_path() -> Path:
        return Path(__file__).with_name("data") / "windows_it_v1.json"

    @classmethod
    def load_default(
        cls,
        *,
        registered_probe_ids: frozenset[str] = DEFAULT_REGISTERED_PROBE_IDS,
    ) -> ReferenceKnowledgeGraph:
        return cls.load_json(cls.default_pack_path(), registered_probe_ids=registered_probe_ids)

    @classmethod
    def load_json(
        cls,
        path: Path,
        *,
        registered_probe_ids: frozenset[str],
    ) -> ReferenceKnowledgeGraph:
        """Validate a whole bounded pack before making any of it observable."""

        try:
            size = path.stat().st_size
            if size > _MAX_PACK_BYTES:
                raise ReferencePackError("reference pack exceeds 4000000 bytes")
            pack = ReferencePack.model_validate_json(path.read_text(encoding="utf-8"))
            cls._validate_references(pack, registered_probe_ids=registered_probe_ids)
        except ReferencePackError:
            raise
        except (OSError, UnicodeError, ValidationError, ValueError) as error:
            raise ReferencePackError(str(error)) from error
        return cls(pack)

    @staticmethod
    def _validate_references(
        pack: ReferencePack,
        *,
        registered_probe_ids: frozenset[str],
    ) -> None:
        node_ids = {item.node_id for item in pack.nodes}
        source_ids = {item.source_id for item in pack.sources}
        for relation in pack.relations:
            for node_id in (relation.source_node_id, relation.target_node_id):
                if node_id not in node_ids:
                    raise ReferencePackError(
                        f"relation {relation.relation_id} references unknown node {node_id}"
                    )
            for source_id in relation.source_ids:
                if source_id not in source_ids:
                    raise ReferencePackError(
                        f"relation {relation.relation_id} references unknown source {source_id}"
                    )
            for probe_id in relation.distinguishing_probe_ids:
                if probe_id not in registered_probe_ids:
                    raise ReferencePackError(
                        f"relation {relation.relation_id} references unregistered probe {probe_id}"
                    )

    def query(self, query: KnowledgeQuery) -> KnowledgePacket:
        matches = tuple(
            relation for relation in self.pack.relations if self._matches(relation, query)
        )
        return self._bounded_packet(
            matches, max_relations=query.max_relations, max_chars=query.max_chars
        )

    def expand(
        self,
        *,
        start_node_ids: tuple[str, ...],
        direction: KnowledgeDirection = KnowledgeDirection.BOTH,
        max_depth: int = 2,
        max_nodes: int = 32,
        max_edges: int = 64,
        max_chars: int = 32_000,
    ) -> KnowledgePacket:
        if not 0 <= max_depth <= 4:
            raise ValueError("max_depth must be between 0 and 4")
        if not 1 <= max_nodes <= 64:
            raise ValueError("max_nodes must be between 1 and 64")
        if not 0 <= max_edges <= 128:
            raise ValueError("max_edges must be between 0 and 128")
        if not 1024 <= max_chars <= 100_000:
            raise ValueError("max_chars must be between 1024 and 100000")
        if not start_node_ids or len(start_node_ids) > 16:
            raise ValueError("start_node_ids must contain between 1 and 16 IDs")
        missing = tuple(item for item in start_node_ids if item not in self._nodes)
        if missing:
            raise ValueError(f"unknown start node: {missing[0]}")

        visited = set(start_node_ids)
        pending = deque((node_id, 0) for node_id in start_node_ids)
        selected: list[KnowledgeRelation] = []
        exhausted_by_bounds = False
        while pending:
            node_id, depth = pending.popleft()
            if depth >= max_depth:
                continue
            candidates = tuple(
                relation
                for relation in self.pack.relations
                if self._touches(relation, node_id=node_id, direction=direction)
            )
            for relation in candidates:
                if relation in selected:
                    continue
                if len(selected) >= max_edges:
                    exhausted_by_bounds = True
                    break
                adjacent = self._adjacent(relation, node_id=node_id, direction=direction)
                new_nodes = tuple(item for item in adjacent if item not in visited)
                if len(visited) + len(new_nodes) > max_nodes:
                    exhausted_by_bounds = True
                    continue
                selected.append(relation)
                for next_node in new_nodes:
                    visited.add(next_node)
                    pending.append((next_node, depth + 1))
            if len(selected) >= max_edges:
                exhausted_by_bounds = exhausted_by_bounds or bool(pending)
                break

        packet = self._bounded_packet(
            tuple(selected), max_relations=max(1, max_edges), max_chars=max_chars
        )
        if exhausted_by_bounds and not packet.truncated:
            return packet.model_copy(
                update={
                    "truncated": True,
                    "omitted_relation_count": 1,
                    "limitations": (
                        *packet.limitations,
                        "graph expansion limits omitted additional relationships",
                    ),
                }
            )
        return packet

    def _matches(self, relation: KnowledgeRelation, query: KnowledgeQuery) -> bool:
        source_node = self._nodes[relation.source_node_id]
        target_node = self._nodes[relation.target_node_id]
        if query.categories and not (
            source_node.category in query.categories or target_node.category in query.categories
        ):
            return False
        if query.node_ids and not (
            relation.source_node_id in query.node_ids or relation.target_node_id in query.node_ids
        ):
            return False
        if query.relationship_kinds and relation.relationship not in query.relationship_kinds:
            return False
        if query.probe_ids and not set(query.probe_ids).intersection(
            relation.distinguishing_probe_ids
        ):
            return False
        if query.keywords:
            haystack = " ".join(
                (
                    source_node.label,
                    *source_node.aliases,
                    target_node.label,
                    *target_node.aliases,
                    relation.mechanism,
                    *relation.conditions,
                    *relation.symptoms,
                    *relation.counterevidence,
                    *relation.applicability,
                )
            ).casefold()
            if not all(keyword in haystack for keyword in query.keywords):
                return False
        return True

    def _bounded_packet(
        self,
        matches: tuple[KnowledgeRelation, ...],
        *,
        max_relations: int,
        max_chars: int,
    ) -> KnowledgePacket:
        selected: list[KnowledgeRelation] = []
        for relation in matches[:max_relations]:
            candidate = self._packet((*selected, relation), total=len(matches))
            if len(candidate.model_dump_json()) > max_chars:
                break
            selected.append(relation)
        return self._packet(tuple(selected), total=len(matches))

    def _packet(
        self,
        relations: tuple[KnowledgeRelation, ...],
        *,
        total: int,
    ) -> KnowledgePacket:
        node_ids = {
            node_id
            for relation in relations
            for node_id in (relation.source_node_id, relation.target_node_id)
        }
        source_ids = {source_id for relation in relations for source_id in relation.source_ids}
        omitted = max(0, total - len(relations))
        limitations = ("query limits omitted matching reference relationships",) if omitted else ()
        return KnowledgePacket(
            pack_id=self.pack.pack_id,
            pack_version=self.pack.version,
            nodes=tuple(item for item in self.pack.nodes if item.node_id in node_ids),
            relations=relations,
            sources=tuple(item for item in self.pack.sources if item.source_id in source_ids),
            truncated=bool(omitted),
            omitted_relation_count=omitted,
            limitations=limitations,
            disclaimer=_DISCLAIMER,
        )

    @staticmethod
    def _touches(
        relation: KnowledgeRelation,
        *,
        node_id: str,
        direction: KnowledgeDirection,
    ) -> bool:
        return (
            direction in {KnowledgeDirection.OUTGOING, KnowledgeDirection.BOTH}
            and relation.source_node_id == node_id
        ) or (
            direction in {KnowledgeDirection.INCOMING, KnowledgeDirection.BOTH}
            and relation.target_node_id == node_id
        )

    @staticmethod
    def _adjacent(
        relation: KnowledgeRelation,
        *,
        node_id: str,
        direction: KnowledgeDirection,
    ) -> Iterable[str]:
        if relation.source_node_id == node_id and direction in {
            KnowledgeDirection.OUTGOING,
            KnowledgeDirection.BOTH,
        }:
            yield relation.target_node_id
        if relation.target_node_id == node_id and direction in {
            KnowledgeDirection.INCOMING,
            KnowledgeDirection.BOTH,
        }:
            yield relation.source_node_id
