"""Atomic bounded loader and local retrieval for reference knowledge."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from systemsense.knowledge.models import (
    KnowledgeDirection,
    KnowledgePacket,
    KnowledgeQuery,
    KnowledgeRelation,
    KnowledgeRelationKind,
    KnowledgeRelationReview,
    KnowledgeReviewManifest,
    ReferencePack,
)

DEFAULT_REGISTERED_PROBE_IDS = frozenset(
    {
        "application.snapshot",
        "core.resources",
        "core.system",
        "devices.snapshot",
        "display.mode",
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
_PRIMARY_HOSTS = {
    "Microsoft": frozenset(
        {"learn.microsoft.com", "support.microsoft.com", "devblogs.microsoft.com"}
    ),
    "NVIDIA": frozenset({"docs.nvidia.com", "www.nvidia.com"}),
    "AMD": frozenset({"www.amd.com", "docs.amd.com"}),
    "Intel": frozenset({"www.intel.com"}),
    "Mozilla": frozenset({"support.mozilla.org", "developer.mozilla.org"}),
    "Chromium": frozenset({"www.chromium.org", "chromium.googlesource.com"}),
    "Adobe": frozenset({"helpx.adobe.com"}),
}
_FOCUS_SCOPES = (
    ("pdf", frozenset({"pdf", "acrobat"})),
    ("firefox", frozenset({"firefox"})),
    ("winhttp", frozenset({"winhttp"})),
    ("game", frozenset({"game", "gaming", "fps"})),
    ("wifi", frozenset({"wifi", "wireless", "wlan"})),
)


class ReferencePackError(ValueError):
    """The complete reference pack failed validation and was not loaded."""


class ReferenceKnowledgeGraph:
    """Immutable curated graph, deliberately separate from the evidence graph."""

    def __init__(self, pack: ReferencePack, reviews: KnowledgeReviewManifest | None = None) -> None:
        self.pack = pack
        self._nodes = {item.node_id: item for item in pack.nodes}
        self._sources = {item.source_id: item for item in pack.sources}
        self._reviews = (
            {review.relation_id: review for review in reviews.reviews}
            if reviews is not None
            else {}
        )
        self._relation_order = {
            relation.relation_id: index for index, relation in enumerate(pack.relations)
        }
        self.reviewed_relation_ids = frozenset(
            relation_id
            for relation_id, review in self._reviews.items()
            if review.status == "active"
        )
        self._available_relations = tuple(
            relation
            for relation in pack.relations
            if relation.relation_id not in self._reviews
            or self._reviews[relation.relation_id].status == "active"
        )
        outgoing: dict[str, list[KnowledgeRelation]] = {node_id: [] for node_id in self._nodes}
        incoming: dict[str, list[KnowledgeRelation]] = {node_id: [] for node_id in self._nodes}
        for relation in self._available_relations:
            outgoing[relation.source_node_id].append(relation)
            incoming[relation.target_node_id].append(relation)
        self._outgoing = {node_id: tuple(items) for node_id, items in outgoing.items()}
        self._incoming = {node_id: tuple(items) for node_id, items in incoming.items()}
        self._focus_terms: dict[str, tuple[frozenset[str], frozenset[str], frozenset[str]]] = {}
        self._focus_scope_terms: dict[str, tuple[frozenset[str], ...]] = {}
        for relation in self._available_relations:
            source = self._nodes[relation.source_node_id]
            target = self._nodes[relation.target_node_id]
            nodes = _reference_terms(
                " ".join((source.label, *source.aliases, target.label, *target.aliases))
            )
            symptoms = _reference_terms(" ".join(relation.symptoms))
            details = _reference_terms(
                " ".join((relation.mechanism, *relation.conditions, *relation.applicability))
            )
            self._focus_terms[relation.relation_id] = (nodes, symptoms, details)
            endpoints = (relation.source_node_id, relation.target_node_id)
            self._focus_scope_terms[relation.relation_id] = tuple(
                (
                    cues | frozenset({"gpu"})
                    if scope == "game"
                    and all(node_id.startswith("kn_gpu_") for node_id in endpoints)
                    else cues
                )
                for scope, cues in _FOCUS_SCOPES
                if relation.relation_id.startswith((f"kr_{scope}_", f"kr_ref_{scope}_"))
                or any(node_id.startswith(f"kn_{scope}_") for node_id in endpoints)
            )

    def review_for(self, relation_id: str) -> KnowledgeRelationReview | None:
        return self._reviews.get(relation_id)

    @staticmethod
    def default_pack_path() -> Path:
        return Path(__file__).with_name("data") / "windows_it_v1.json"

    @classmethod
    def load_default(
        cls,
        *,
        registered_probe_ids: frozenset[str] = DEFAULT_REGISTERED_PROBE_IDS,
    ) -> ReferenceKnowledgeGraph:
        path = cls.default_pack_path()
        return cls.load_json(
            path,
            registered_probe_ids=registered_probe_ids,
            review_manifest_path=path.with_name("reference_reviews.v1.json"),
        )

    @classmethod
    def load_json(
        cls,
        path: Path,
        *,
        registered_probe_ids: frozenset[str],
        review_manifest_path: Path | None = None,
    ) -> ReferenceKnowledgeGraph:
        """Validate a whole bounded pack before making any of it observable."""

        try:
            size = path.stat().st_size
            if size > _MAX_PACK_BYTES:
                raise ReferencePackError("reference pack exceeds 4000000 bytes")
            pack = ReferencePack.model_validate_json(path.read_text(encoding="utf-8"))
            cls._validate_references(pack, registered_probe_ids=registered_probe_ids)
            reviews = (
                KnowledgeReviewManifest.model_validate_json(
                    review_manifest_path.read_text(encoding="utf-8")
                )
                if review_manifest_path is not None
                else None
            )
            if reviews is not None:
                cls._validate_reviews(pack, reviews)
        except ReferencePackError:
            raise
        except (OSError, UnicodeError, ValidationError, ValueError) as error:
            raise ReferencePackError(str(error)) from error
        return cls(pack, reviews)

    @staticmethod
    def _validate_reviews(pack: ReferencePack, manifest: KnowledgeReviewManifest) -> None:
        if manifest.pack_id != pack.pack_id or manifest.pack_version != pack.version:
            raise ReferencePackError("review manifest pack ID or pack version mismatch")
        relations = {item.relation_id: item for item in pack.relations}
        sources = {item.source_id: item for item in pack.sources}
        nodes = {item.node_id: item for item in pack.nodes}
        reviews = {item.relation_id: item for item in manifest.reviews}
        semantic_keys: set[tuple[str, str, KnowledgeRelationKind, tuple[str, ...]]] = set()
        dependency_out: dict[str, set[str]] = {}
        normalized_ids: set[str] = set()
        for review in manifest.reviews:
            relation = relations.get(review.relation_id)
            if relation is None:
                raise ReferencePackError(f"review references unknown relation {review.relation_id}")
            digest = hashlib.sha256(
                json.dumps(
                    relation.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            if digest != review.relation_sha256:
                raise ReferencePackError(f"review {review.relation_id} relation digest mismatch")
            normalized_id = re.sub(r"0+(\d+)$", r"\1", review.relation_id.replace("-", "_"))
            if normalized_id in normalized_ids:
                raise ReferencePackError(f"near-duplicate review ID {review.relation_id}")
            normalized_ids.add(normalized_id)
            if set(section.source_id for section in review.source_sections) != set(
                relation.source_ids
            ) or len(review.source_sections) != len(relation.source_ids):
                raise ReferencePackError(f"review {review.relation_id} source sections mismatch")
            for section in review.source_sections:
                source = sources.get(section.source_id)
                if source is None:
                    raise ReferencePackError(f"review {review.relation_id} unknown source")
                parsed = urlsplit(source.url)
                if (
                    source.publisher not in _PRIMARY_HOSTS
                    or parsed.hostname not in _PRIMARY_HOSTS[source.publisher]
                    or parsed.username is not None
                    or parsed.fragment
                ):
                    raise ReferencePackError(f"review {review.relation_id} lacks a primary source")
                if (
                    section.source_updated_at is not None
                    and section.source_updated_at > review.reviewed_at
                ):
                    raise ReferencePackError(
                        f"review {review.relation_id} source date after review"
                    )
            for text in (*relation.conditions, *relation.applicability, *relation.limitations):
                if not text.strip() or text != text.strip() or len(text) > 240:
                    raise ReferencePackError(f"review {review.relation_id} malformed conditions")
            semantic_key = (
                relation.source_node_id,
                relation.target_node_id,
                relation.relationship,
                tuple(item.casefold() for item in relation.conditions),
            )
            if semantic_key in semantic_keys:
                raise ReferencePackError(f"review {review.relation_id} duplicate semantics")
            semantic_keys.add(semantic_key)
            if (
                relation.relationship
                in {
                    KnowledgeRelationKind.SUPPORTS,
                    KnowledgeRelationKind.COUNTEREVIDENCE_FOR,
                }
                and nodes[relation.source_node_id].kind != "observation"
            ):
                raise ReferencePackError(
                    f"review {review.relation_id} evidence edge lacks observation"
                )
            if relation.relationship in {
                KnowledgeRelationKind.SUPPORTS,
                KnowledgeRelationKind.COUNTEREVIDENCE_FOR,
            } and nodes[relation.target_node_id].kind not in {"condition", "mechanism"}:
                raise ReferencePackError(
                    f"review {review.relation_id} evidence edge lacks a mechanism target"
                )
            if relation.relationship == KnowledgeRelationKind.CAN_CAUSE_WHEN and not any(
                "if " in item.casefold() or "when " in item.casefold()
                for item in relation.conditions
            ):
                raise ReferencePackError(
                    f"review {review.relation_id} causal edge lacks precondition"
                )
            if relation.relationship in {
                KnowledgeRelationKind.DEPENDS_ON,
                KnowledgeRelationKind.USES,
            }:
                dependency_out.setdefault(relation.source_node_id, set()).add(
                    relation.target_node_id
                )
            if review.status == "superseded":
                replacement = reviews.get(review.superseded_by or "")
                if replacement is None or replacement.status != "active":
                    raise ReferencePackError(f"review {review.relation_id} invalid supersession")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ReferencePackError("reviewed dependency cycle")
            if node_id in visited:
                return
            visiting.add(node_id)
            for target_id in dependency_out.get(node_id, ()):
                visit(target_id)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in dependency_out:
            visit(node_id)
        pack_digest = hashlib.sha256(
            json.dumps(pack.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        if pack_digest != manifest.pack_sha256:
            raise ReferencePackError("review manifest pack digest mismatch")

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
            if relation.probe_roles is not None:
                for probe_id in (
                    *relation.probe_roles.screening_probe_ids,
                    *relation.probe_roles.discriminating_probe_ids,
                ):
                    if probe_id not in registered_probe_ids:
                        raise ReferencePackError(
                            f"relation {relation.relation_id} references unregistered probe "
                            f"{probe_id}"
                        )

    def query(self, query: KnowledgeQuery) -> KnowledgePacket:
        matches = tuple(
            relation for relation in self._available_relations if self._matches(relation, query)
        )
        return self._bounded_packet(
            matches, max_relations=query.max_relations, max_chars=query.max_chars
        )

    def query_reviewed(self, query: KnowledgeQuery) -> KnowledgePacket:
        """Retrieve only active source-section-reviewed relations, within normal bounds."""

        matches = tuple(
            relation
            for relation in self._available_relations
            if relation.relation_id in self.reviewed_relation_ids and self._matches(relation, query)
        )
        return self._bounded_packet(
            matches, max_relations=query.max_relations, max_chars=query.max_chars
        )

    def focused_packet(
        self,
        *,
        objective: str,
        hypothesis_briefs: tuple[str, ...] = (),
        seed_node_ids: tuple[str, ...] = (),
        exclude_terms: frozenset[str] = frozenset(),
        max_relations: int = 6,
        max_chars: int = 6_000,
    ) -> KnowledgePacket:
        """Select relevant mechanisms across branches, without promoting them to facts."""

        if not 1 <= max_relations <= 64:
            raise ValueError("max_relations must be between 1 and 64")
        if not 1_024 <= max_chars <= 100_000:
            raise ValueError("max_chars must be between 1024 and 100000")
        if len(hypothesis_briefs) > 16 or any(len(brief) > 1200 for brief in hypothesis_briefs):
            raise ValueError("hypothesis input exceeds the bounded reasoning contract")
        objective_terms = _reference_terms(objective) - exclude_terms
        hypothesis_terms = _reference_terms(" ".join(hypothesis_briefs)) - exclude_terms
        stated_terms = objective_terms | hypothesis_terms
        seeds = set(seed_node_ids) & self._nodes.keys()
        focus_terms: dict[str, frozenset[str]] = {}
        seeded: list[tuple[int, KnowledgeRelation]] = []
        scored: dict[str, list[tuple[int, KnowledgeRelation]]] = {}
        for relation in self._available_relations:
            source = self._nodes[relation.source_node_id]
            nodes, symptoms, details = self._focus_terms[relation.relation_id]
            seed_match = int(relation.source_node_id in seeds or relation.target_node_id in seeds)
            # A generic observed value (for example "normal" or "slow") is
            # not evidence that this is Firefox, WinHTTP, Acrobat/PDF, a game,
            # or Wi-Fi. Such branches need an explicit scope cue or graph seed.
            if not seed_match and any(
                not (stated_terms & required)
                for required in self._focus_scope_terms[relation.relation_id]
            ):
                continue
            direct_match = bool(objective_terms & (nodes | symptoms) or hypothesis_terms & nodes)
            if not seed_match and not direct_match:
                continue
            focus_terms[relation.relation_id] = nodes | symptoms
            score = (
                20 * seed_match
                # A seeded node is a symptom/stage anchor. Show its direct
                # route toward the observed outcome before deeper incoming
                # subcauses that merely touch the same seed; otherwise adding
                # one new subcause can crowd the whole stage map out of a
                # bounded packet.
                + 20 * int(relation.source_node_id in seeds)
                + 8 * len(objective_terms & nodes)
                + 4 * len(objective_terms & symptoms)
                + 2 * len(objective_terms & details)
                + 2 * len(hypothesis_terms & nodes)
                + len(hypothesis_terms & (symptoms | details))
            )
            if seed_match:
                seeded.append((score, relation))
            else:
                scored.setdefault(source.category, []).append((score, relation))
        seeded.sort(key=lambda item: (-item[0], item[1].relation_id))
        # Select the strongest relation inside each competing category. Source
        # file order only breaks equal-score ties, preserving established paths.
        for branch in scored.values():
            branch.sort(key=lambda item: (-item[0], self._relation_order[item[1].relation_id]))
        # Exact error or interface anchors deserve first attention, but a broad
        # seed must not consume the entire packet when the user named another
        # symptom. The remaining anchored edges compete by mechanism branch.
        seeded_categories = {
            self._nodes[relation.source_node_id].category for _, relation in seeded
        }
        covered_terms = frozenset[str]().union(
            *(focus_terms[relation.relation_id] for _, relation in seeded)
        )
        uncovered_terms = objective_terms - covered_terms
        competing = sorted(
            (
                category
                for category, branch in scored.items()
                if category not in seeded_categories
                and any(
                    focus_terms[relation.relation_id] & uncovered_terms for _, relation in branch
                )
            ),
            key=lambda category: (-max(score for score, _ in scored[category]), category),
        )
        anchor_limit = min(2 if competing and max_relations > 1 else 3, max_relations)
        ordered: list[KnowledgeRelation] = [relation for _, relation in seeded[:anchor_limit]]
        for category in competing:
            branch = scored[category]
            for index, (_, relation) in enumerate(branch):
                if focus_terms[relation.relation_id] & uncovered_terms:
                    ordered.append(relation)
                    del branch[index]
                    break
        for score, relation in seeded[anchor_limit:]:
            scored.setdefault(self._nodes[relation.source_node_id].category, []).append(
                (score, relation)
            )
        scored = {category: branch for category, branch in scored.items() if branch}
        for branch in scored.values():
            branch.sort(key=lambda item: (-item[0], self._relation_order[item[1].relation_id]))
        branches = sorted(scored, key=lambda category: (-scored[category][0][0], category))
        for index in range(max((len(branch) for branch in scored.values()), default=0)):
            for category in branches:
                if index < len(scored[category]):
                    ordered.append(scored[category][index][1])
        return self._bounded_packet(
            tuple(ordered), max_relations=max_relations, max_chars=max_chars
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
            candidates = self._adjacent_relations(node_id, direction)
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

    def _adjacent_relations(
        self, node_id: str, direction: KnowledgeDirection
    ) -> tuple[KnowledgeRelation, ...]:
        if direction == KnowledgeDirection.OUTGOING:
            return self._outgoing[node_id]
        if direction == KnowledgeDirection.INCOMING:
            return self._incoming[node_id]
        adjacent = set(self._outgoing[node_id]) | set(self._incoming[node_id])
        return tuple(sorted(adjacent, key=lambda item: self._relation_order[item.relation_id]))

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
        probe_ids = (
            (
                *relation.probe_roles.screening_probe_ids,
                *relation.probe_roles.discriminating_probe_ids,
            )
            if relation.probe_roles is not None
            else relation.distinguishing_probe_ids
        )
        if query.probe_ids and not set(query.probe_ids).intersection(probe_ids):
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
            schema_version=self.pack.schema_version,
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


_REFERENCE_STOP_WORDS = frozenset(
    {
        "a",
        "after",
        "an",
        "and",
        "are",
        "at",
        "by",
        "can",
        "cannot",
        "cant",
        "for",
        "from",
        "has",
        "in",
        "is",
        "it",
        "my",
        "no",
        "not",
        "of",
        "on",
        "or",
        "the",
        "this",
        "to",
        "with",
        "windows",
    }
)


def _reference_terms(text: str) -> frozenset[str]:
    normalized = re.sub(r"\bwi[\s-]?fi\b", "wifi", text.casefold())
    return frozenset(
        term
        for term in re.findall(r"[a-z][a-z0-9]*", normalized)
        if len(term) >= 2 and term not in _REFERENCE_STOP_WORDS
    )
