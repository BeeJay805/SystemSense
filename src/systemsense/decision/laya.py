"""Advisory Laya provider that ranks only registered read-only probes."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import cast

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
    ResponseValidationError,
)
from systemsense.domain.ids import JsonValue
from systemsense.inference.laya_runtime import LayaRanker, LayaRuntimeError
from systemsense.inference.settings import ProviderStatus


class LayaDecisionProvider:
    """Use Laya as an ordinal ranker; never treat its scores as diagnostic confidence."""

    def __init__(
        self,
        *,
        ranker: LayaRanker,
        fallback: KeywordBaselineDecisionProvider | None = None,
        timeout_seconds: float = 5,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._ranker = ranker
        self._fallback = fallback or KeywordBaselineDecisionProvider()
        self._timeout_seconds = timeout_seconds
        self._status = ProviderStatus(
            provider_id="laya-local-decision",
            enabled=True,
            available=False,
            detail="not_checked",
        )

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="laya-local-decision",
            provider_version="1",
            role="fast_decision",
        )

    @property
    def status(self) -> ProviderStatus:
        return self._status

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        remaining = (request.deadline_at - datetime.now(UTC)).total_seconds()
        timeout = min(self._timeout_seconds, remaining)
        if timeout <= 0:
            return self._degraded(request, "laya_deadline_unavailable")
        candidates = () if request.attention_only else self._eligible_candidates(request)
        evidence_fragments = self._evidence_fragments(request)
        if not candidates and not evidence_fragments:
            return self._degraded(request, "laya_nothing_to_rank")
        wire_candidates = tuple(
            {"probe_id": candidate.probe_id, "description": candidate.description}
            for candidate in candidates
        )
        try:
            attention = self._ranker.attend(
                state=self._state(request),
                evidence=evidence_fragments,
                candidates=wire_candidates,
                timeout_seconds=timeout,
            )
            ranked_ids = attention.ranked_probe_ids
            expected = {candidate.probe_id for candidate in candidates}
            if (
                len(ranked_ids) != len(expected)
                or set(ranked_ids) != expected
                or set(attention.considered_probe_ids) != expected
            ):
                raise LayaRuntimeError("Laya did not return an exact candidate permutation")
            evidence_by_text = {
                str(evidence_id): evidence_id for evidence_id in request.evidence_ids
            }
            if not set(attention.ranked_evidence_ids).issubset(evidence_by_text):
                raise LayaRuntimeError("Laya returned an unknown evidence ID")
            if not set(attention.considered_evidence_ids).issubset(evidence_by_text):
                raise LayaRuntimeError("Laya considered an unknown evidence ID")
            pages = request.attention_context or request.evidence_context
            known_page_ids = {f"{item.evidence_id}:{index}" for index, item in enumerate(pages)}
            if not set(attention.ranked_attention_page_ids).issubset(known_page_ids):
                raise LayaRuntimeError("Laya returned an unknown attention page ID")
            if not set(attention.considered_attention_page_ids).issubset(known_page_ids):
                raise LayaRuntimeError("Laya considered an unknown attention page ID")
            attention_notes = list(attention.attention_notes[:15])
            if len(attention.ranked_evidence_ids) > 64:
                attention_notes.append(
                    f"ranked_evidence_returned=64_of_{len(attention.ranked_evidence_ids)}"
                )
            if len(attention.ranked_attention_page_ids) > 64:
                page_note = (
                    f"ranked_pages_returned=64_of_{len(attention.ranked_attention_page_ids)}"
                )
                if len(attention_notes) < 16:
                    attention_notes.append(page_note)
            by_id = {candidate.probe_id: candidate for candidate in candidates}
            proposals: list[ProbeProposal] = []
            total_cost = 0
            count = len(ranked_ids)
            for rank, probe_id in enumerate(ranked_ids):
                capability = by_id[probe_id]
                if len(proposals) == request.max_probes:
                    break
                if total_cost + capability.cost_ms > request.budget_ms:
                    continue
                proposals.append(
                    ProbeProposal(
                        probe_id=probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=(count - rank) / count,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key=f"{probe_id}:laya-rank-v1",
                        permission_class=capability.permission_class,
                        safety_class=capability.safety_class,
                    )
                )
                total_cost += capability.cost_ms
            response = DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=tuple(proposals),
                ranked_evidence_ids=tuple(
                    evidence_by_text[evidence_id]
                    for evidence_id in attention.ranked_evidence_ids[:64]
                ),
                ranked_attention_page_ids=attention.ranked_attention_page_ids[:64],
                attention_notes=tuple(attention_notes),
                considered_evidence_count=min(64, len(set(attention.considered_evidence_ids))),
            ).validate_against(request)
        except (KeyError, LayaRuntimeError, ResponseValidationError, ValueError) as error:
            return self._degraded(request, _failure_detail(error))
        self._status = self._status.model_copy(update={"available": True, "detail": "ready"})
        return response

    def _eligible_candidates(self, request: DecisionRequest) -> tuple[ProbeCapability, ...]:
        terms = set(re.findall(r"[a-z0-9]+", request.symptom.casefold()))
        eligible = (
            capability
            for capability in request.available_probes
            if capability.probe_id not in request.completed_probe_ids
            and capability.probe_id not in request.fresh_probe_ids
        )
        preferred = set(request.preferred_probe_ids)
        return tuple(
            sorted(
                eligible,
                key=lambda capability: (
                    -int(capability.probe_id in preferred),
                    -int(bool(capability.keywords & terms)),
                    -int(bool(capability.target_traits & request.target_traits)),
                    -int(capability.common),
                    -capability.baseline_priority,
                    capability.probe_id,
                ),
            )
        )

    @staticmethod
    def _state(request: DecisionRequest) -> dict[str, object]:
        hypotheses = [brief[:400] for brief in request.hypothesis_briefs[:4]]
        references = _compact_reference_relations(request.reference_context, limit=3)
        relationships = [
            {
                "relation_id": item.relation_id,
                "relationship": item.relationship.value,
                "observed_identity": _compact_mapping(item.version_metadata, limit=4),
                "conditions": list(item.conditions[:2]),
                "applicability": list(item.applicability[:2]),
                "evidence_ids": [str(evidence_id) for evidence_id in item.evidence_ids[:2]],
                "assertion_status": item.assertion_status.value,
            }
            for item in request.relationships[:4]
        ]
        reference_relation_count = sum(
            len(relations)
            for item in request.reference_context
            if isinstance((relations := item.get("relations")), (list, tuple))
        )
        coverage_notes: list[str] = []
        if len(request.symptom) > 1000:
            coverage_notes.append("symptom_compacted")
        if len(request.hypothesis_briefs) > len(hypotheses):
            coverage_notes.append("hypothesis_context_compacted")
        if reference_relation_count > len(references):
            coverage_notes.append("reference_context_compacted")
        if len(request.relationships) > len(relationships):
            coverage_notes.append("relationship_context_compacted")
        return {
            # Laya truncates state on the right. Put compact graph semantics and
            # the requested probe frontier first so they remain model-visible.
            "reference_knowledge": references,
            "machine_relationships": relationships,
            "preferred_probe_ids": list(request.preferred_probe_ids),
            "symptom": request.symptom[:1000],
            "hypothesis_briefs": hypotheses,
            "target_traits": sorted(request.target_traits),
            "coverage_notes": coverage_notes,
            "context_counts": {
                "hypotheses_supplied": len(request.hypothesis_briefs),
                "references_supplied": len(request.reference_context),
                "reference_relations_supplied": reference_relation_count,
                "relationships_supplied": len(request.relationships),
            },
        }

    @staticmethod
    def _evidence_fragments(request: DecisionRequest) -> tuple[dict[str, str], ...]:
        fragments: list[dict[str, str]] = []
        contexts = request.attention_context or request.evidence_context
        for page_index, context in enumerate(contexts):
            evidence_id = str(context.evidence_id)
            page_id = f"{evidence_id}:{page_index}"
            serialized = json.dumps(
                context.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            pieces = tuple(
                serialized[index : index + 500] for index in range(0, len(serialized), 500)
            ) or ("{}",)
            for piece_index, piece in enumerate(pieces):
                fragments.append(
                    {
                        "evidence_id": evidence_id,
                        "page_id": page_id,
                        "fragment_id": f"{page_id}:piece:{piece_index}",
                        "description": piece,
                    }
                )
        return tuple(fragments)

    def _degraded(self, request: DecisionRequest, detail: str) -> DecisionResponse:
        self._status = self._status.model_copy(update={"available": False, "detail": detail})
        baseline = self._fallback.decide(request)
        return baseline.model_copy(
            update={"degraded": True, "stop_reason": detail}
        ).validate_against(request)


def _compact_reference_relations(
    packets: tuple[dict[str, JsonValue], ...], *, limit: int
) -> list[dict[str, object]]:
    compact: list[dict[str, object]] = []
    for packet in packets:
        node_labels: dict[str, str] = {}
        nodes_raw = packet.get("nodes")
        if isinstance(nodes_raw, (list, tuple)):
            nodes = cast(list[object] | tuple[object, ...], nodes_raw)
            for node_raw in nodes:
                if not isinstance(node_raw, dict):
                    continue
                node = cast(dict[str, object], node_raw)
                node_id, label = node.get("node_id"), node.get("label")
                if isinstance(node_id, str) and isinstance(label, str):
                    node_labels[node_id] = label[:80]
        relations_raw = packet.get("relations")
        if not isinstance(relations_raw, (list, tuple)):
            continue
        relation_items = cast(list[object] | tuple[object, ...], relations_raw)
        for relation_raw in relation_items:
            if len(compact) == limit:
                return compact
            if not isinstance(relation_raw, dict):
                continue
            relation = cast(dict[str, object], relation_raw)
            mechanism = relation.get("mechanism")
            if not isinstance(mechanism, str) or not mechanism.strip():
                continue
            source_id = relation.get("source_node_id", relation.get("from", ""))
            target_id = relation.get("target_node_id", relation.get("to", ""))
            compact.append(
                {
                    "relation_id": _bounded_string(relation.get("relation_id"), 120),
                    "relationship": _bounded_string(relation.get("relationship"), 60),
                    "source": node_labels.get(str(source_id), str(source_id)[:80]),
                    "target": node_labels.get(str(target_id), str(target_id)[:80]),
                    "mechanism": mechanism[:220],
                    "conditions": _bounded_strings(relation.get("conditions"), 2, 100),
                    "distinguishing_probe_ids": _bounded_strings(
                        relation.get("distinguishing_probe_ids", relation.get("probes")),
                        4,
                        120,
                    ),
                    "limitations": _bounded_strings(relation.get("limitations"), 1, 100),
                }
            )
    return compact


def _compact_mapping(value: object, *, limit: int) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    items = cast(dict[object, object], value)
    compact: dict[str, object] = {}
    for key, item in sorted(items.items(), key=lambda pair: str(pair[0]))[:limit]:
        if isinstance(item, (str, int, float, bool)) or item is None:
            compact[str(key)[:80]] = item[:100] if isinstance(item, str) else item
    return compact


def _bounded_string(value: object, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _bounded_strings(value: object, count: int, limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    items = cast(list[object] | tuple[object, ...], value)
    return [item[:limit] for item in items[:count] if isinstance(item, str)]


def _failure_detail(error: Exception) -> str:
    """Keep controlled failure mechanics without echoing model or evidence payloads."""

    raw = f"{type(error).__name__}:{error}"
    bounded = re.sub(r"[^a-zA-Z0-9_.: =-]", "?", raw)[:90]
    return f"laya_invalid_or_unavailable:{bounded}"[:120]
