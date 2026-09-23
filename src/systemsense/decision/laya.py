"""Advisory Laya provider that ranks only registered read-only probes."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import cast

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionPresentationTrace,
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    FastSignal,
    FastSignalKind,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
    ResponseValidationError,
    presentation_payload_sha256,
)
from systemsense.decision.measurement import catalog_bound_measurement_need
from systemsense.domain.ids import JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    LayaRanker,
    LayaRuntimeError,
    LayaSubprocessRuntime,
)
from systemsense.inference.settings import ProviderStatus

_PREVIEW_CHARS = 650
_ALARM_TERMS = re.compile(
    r"critical|fatal|error|fail|denied|warning|offline|timeout|corrupt|disk", re.I
)


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
        evidence_fragments = self.evidence_fragments_for_laya(request)
        if not candidates and not evidence_fragments:
            return self._degraded(request, "laya_nothing_to_rank")
        wire_candidates = tuple(
            {"probe_id": candidate.probe_id, "description": candidate.description}
            for candidate in candidates
        )
        try:
            attention = self._ranker.attend(
                state=self.state_for_laya(request),
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
            # The runtime reports this note only when its evidence deadline cut
            # off work. A missing *page*, not a low score or unrelated anomaly,
            # is the deterministic reason to ask the deep brain to reassess.
            missed_pages = known_page_ids - set(attention.considered_attention_page_ids)
            coverage_gap = "coverage_limited=true" in attention.attention_notes and bool(
                missed_pages
            )
            contradiction_signals = _typed_contradiction_signals(
                request,
                considered_evidence_ids=frozenset(attention.considered_evidence_ids),
                considered_page_ids=frozenset(attention.considered_attention_page_ids),
                presented_fragments=evidence_fragments,
                fully_presented_fragment_ids=_fully_presented_fragment_ids(attention),
            )
            no_progress_signal = (
                (FastSignal(kind=FastSignalKind.NO_PROGRESS_SUSPECTED),)
                if request.stagnant_rounds >= 2
                else ()
            )
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
                need = catalog_bound_measurement_need(capability)
                if len(proposals) == request.max_probes:
                    break
                if total_cost + capability.cost_ms > request.budget_ms:
                    continue
                proposals.append(
                    ProbeProposal(
                        schema_version=2 if need is not None else 1,
                        probe_id=probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=(count - rank) / count,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key=f"{probe_id}:laya-rank-v1",
                        permission_class=capability.permission_class,
                        safety_class=capability.safety_class,
                        measurement_need=need,
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
                considered_evidence_ids=tuple(
                    evidence_by_text[evidence_id]
                    for evidence_id in dict.fromkeys(attention.considered_evidence_ids)
                ),
                requires_reasoning=coverage_gap
                or bool(contradiction_signals or no_progress_signal),
                signals=(
                    *contradiction_signals,
                    *no_progress_signal,
                    *((FastSignal(kind=FastSignalKind.COVERAGE_GAP),) if coverage_gap else ()),
                )[:8],
                presentation_trace=self._presentation_trace(
                    attention, evidence_fragments, wire_candidates
                ),
            ).validate_against(request)
        except (KeyError, LayaRuntimeError, ResponseValidationError, ValueError) as error:
            return self._degraded(request, _failure_detail(error))
        self._status = self._status.model_copy(update={"available": True, "detail": "ready"})
        return response

    def _eligible_candidates(self, request: DecisionRequest) -> tuple[ProbeCapability, ...]:
        return eligible_laya_candidates(request)

    def _presentation_trace(
        self,
        attention: LayaAttentionResult,
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
    ) -> DecisionPresentationTrace | None:
        # Test doubles and injected worker transports are useful for contracts,
        # but they cannot attest that a local worker saw these exact bytes.
        if (
            type(self._ranker) is not LayaSubprocessRuntime
            or not self._ranker._using_real_subprocess
            or not attention.microbatches
        ):
            return None
        seen: dict[str, list[str]] = {"evidence": [], "probe": []}
        for batch in attention.microbatches:
            if batch.inference_ids and batch.worker_presentation is None:
                return None
            if any(origin.presentation_sha256 is None for origin in batch.cached_origins):
                return None
            seen[batch.phase].extend(batch.candidate_ids)
        expected_evidence = [item["fragment_id"] for item in evidence]
        expected_probes = [item["probe_id"] for item in candidates]
        if seen["evidence"] != expected_evidence[: len(seen["evidence"])]:
            return None
        if seen["probe"] != expected_probes[: len(seen["probe"])]:
            return None
        if len(seen["probe"]) != len(expected_probes):
            return None
        payload: dict[str, JsonValue] = {
            "microbatches": [batch.model_dump(mode="json") for batch in attention.microbatches]
        }
        return DecisionPresentationTrace(
            provider=self.identity,
            format_id="laya-worker-attention-v1",
            payload=payload,
            payload_sha256=presentation_payload_sha256(payload),
        )

    @staticmethod
    def state_for_laya(request: DecisionRequest) -> dict[str, object]:
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
        if request.attention_context or request.evidence_context:
            coverage_notes.append("evidence_pages_are_bounded_previews")
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
            "hypothesis_checks": [
                {
                    "hypothesis_index": item.hypothesis_index,
                    "probe_id": item.probe_id,
                    "fact_name": item.fact_name,
                    "expected_value": item.expected_value,
                }
                for item in request.hypothesis_checks
            ],
            "stagnant_rounds": request.stagnant_rounds,
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
    def evidence_fragments_for_laya(request: DecisionRequest) -> tuple[dict[str, str], ...]:
        fragments: list[dict[str, str]] = []
        contexts = request.attention_context or request.evidence_context
        # Spread the first (normally 20-item) batch over the complete timeline.
        # A deadline may stop subsequent batches, including on an oversized case.
        first_batch = min(20, len(contexts))
        sampled = (
            [index * (len(contexts) - 1) // (first_batch - 1) for index in range(first_batch)]
            if first_batch > 1
            else list(range(first_batch))
        )
        sampled_set = set(sampled)
        order = (*sampled, *(index for index in range(len(contexts)) if index not in sampled_set))
        for page_index in order:
            context = contexts[page_index]
            evidence_id = str(context.evidence_id)
            page_id = f"{evidence_id}:{page_index}"
            fragments.append(
                {
                    "evidence_id": evidence_id,
                    "page_id": page_id,
                    "fragment_id": f"{page_id}:preview:0",
                    "description": _page_preview(context),
                }
            )
        return tuple(fragments)

    def _degraded(self, request: DecisionRequest, detail: str) -> DecisionResponse:
        self._status = self._status.model_copy(update={"available": False, "detail": detail})
        baseline = self._fallback.decide(request)
        return baseline.model_copy(
            update={"degraded": True, "stop_reason": detail}
        ).validate_against(request)


def eligible_laya_candidates(request: DecisionRequest) -> tuple[ProbeCapability, ...]:
    """Return the exact eligible wire order used by Laya and teacher drafts."""

    terms = set(re.findall(r"[a-z0-9]+", request.symptom.casefold()))
    eligible = (
        capability
        for capability in request.available_probes
        if capability.probe_id not in request.completed_probe_ids
        and capability.probe_id not in request.fresh_probe_ids
        and (
            not capability.target_handles or catalog_bound_measurement_need(capability) is not None
        )
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


def _fully_presented_fragment_ids(attention: LayaAttentionResult) -> frozenset[str]:
    """Trust only worker-attested, untruncated inference, never preview or cache alone."""

    presented: set[str] = set()
    for batch in attention.microbatches:
        worker = batch.worker_presentation
        if batch.phase != "evidence" or worker is None:
            continue
        if (
            worker.fitted_state_tokens != worker.state_tokens_original
            or worker.state_fields_omitted
            or worker.state_list_items_omitted
        ):
            continue
        for fragment_id in batch.inference_ids:
            questions = tuple(item for item in worker.questions if item.item_id == fragment_id)
            # The worker splits long descriptions across questions; their
            # aggregate token coverage does not prove the fact and value
            # occurred together in any one model-visible instruction.
            if len(questions) == 1 and all(
                item.instruction_presented_tokens == item.instruction_tokens
                and item.criteria_presented_tokens == item.criteria_tokens
                and item.state_presented_tokens == worker.fitted_state_tokens
                for item in questions
            ):
                presented.add(fragment_id)
    return frozenset(presented)


def _typed_contradiction_signals(
    request: DecisionRequest,
    *,
    considered_evidence_ids: frozenset[str],
    considered_page_ids: frozenset[str],
    presented_fragments: tuple[dict[str, str], ...],
    fully_presented_fragment_ids: frozenset[str],
) -> tuple[FastSignal, ...]:
    """Escalate a categorical mismatch, not an inferred Windows root cause.

    The deep brain supplies the explicit expectation. Only a newer exact,
    current-case fact whose exact value is present in a considered preview
    attested as fully presented to the worker can trigger review. Matching
    only the evidence ID or preview is insufficient: the worker may have seen
    another page, a truncated scalar excerpt, or a truncated instruction.
    Missing, partial, historical, or clock-inconsistent values are unknown.
    """

    visible_facts: dict[str, list[dict[str, object]]] = {}
    for fragment in presented_fragments:
        if (
            fragment["page_id"] not in considered_page_ids
            or fragment["fragment_id"] not in fully_presented_fragment_ids
        ):
            continue
        try:
            preview_raw: object = json.loads(fragment["description"])
        except ValueError:
            continue
        if not isinstance(preview_raw, dict):
            continue
        preview = cast(dict[str, object], preview_raw)
        facts_raw = preview.get("facts")
        if preview.get("projection") != "bounded_preview_not_full_page" or not isinstance(
            facts_raw, dict
        ):
            continue
        visible_facts.setdefault(fragment["evidence_id"], []).append(
            cast(dict[str, object], facts_raw)
        )
    result: list[FastSignal] = []
    now = datetime.now(UTC)
    for check in request.hypothesis_checks:
        matching = sorted(
            (
                item
                for item in request.evidence_context
                if str(item.evidence_id) in considered_evidence_ids
                and item.probe_id == check.probe_id
                and item.case_scope == "current_case"
                and item.incident_relevant is True
                and item.status is EvidenceContextStatus.OBSERVED
                and check.observed_after < item.observed_at <= item.captured_at
                and item.captured_at <= now
                and check.fact_name in item.facts
            ),
            key=lambda item: (item.observed_at, str(item.evidence_id)),
            reverse=True,
        )
        if not matching:
            continue
        latest = matching[0]
        observed = latest.facts[check.fact_name]
        expected = check.expected_value
        if type(observed) is not type(expected) or observed == expected:
            continue
        if not any(
            check.fact_name in facts
            and type(facts[check.fact_name]) is type(observed)
            and facts[check.fact_name] == observed
            for facts in visible_facts.get(str(latest.evidence_id), ())
        ):
            continue
        result.append(
            FastSignal(
                kind=FastSignalKind.CONTRADICTION_SUSPECTED,
                evidence_ids=(latest.evidence_id,),
                hypothesis_index=check.hypothesis_index,
            )
        )
        if len(result) == 8:
            break
    return tuple(result)


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


def _page_preview(context: EvidenceContext) -> str:
    """Bounded search aid; the stored redacted page remains the source of detail."""
    preview: dict[str, object] = {
        "projection": "bounded_preview_not_full_page",
        "status": context.status.value,
        # Focused probe ranking consumes the first 240 characters of a preview.
        "facts": {},
        "facts_omitted": len(context.facts),
        "fact_values_truncated": 0,
        "probe_id": context.probe_id,
        "observed_at": context.observed_at.isoformat(),
        "captured_at": context.captured_at.isoformat(),
        "redaction_applied": context.redaction_applied,
        "summary": context.summary[:80],
        "summary_truncated": len(context.summary) > 80,
        "limitations": list(context.limitations[:3]),
        "limitations_omitted": max(0, len(context.limitations) - 3),
    }

    def encode() -> str:
        return json.dumps(preview, ensure_ascii=False, separators=(",", ":"))

    # Metadata and collection limitations take precedence over fact excerpts.
    while len(encode()) > _PREVIEW_CHARS and preview["limitations"]:
        limitations = cast(list[str], preview["limitations"])
        limitations.pop()
        preview["limitations_omitted"] = len(context.limitations) - len(limitations)
    if len(encode()) > _PREVIEW_CHARS:
        preview["summary"] = context.summary[:40]
        preview["summary_truncated"] = len(context.summary) > 40

    facts = cast(dict[str, object], preview["facts"])
    ordered = sorted(
        enumerate(context.facts.items()),
        key=lambda indexed: (
            -int(bool(_ALARM_TERMS.search(indexed[1][0] + " " + str(indexed[1][1])))),
            -int(indexed[0] == len(context.facts) - 1),
            indexed[0],
        ),
    )
    for _, (name, value) in ordered:
        serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        excerpt: object = (
            value
            if len(serialized) <= 72
            else (value[:70] if isinstance(value, str) else serialized[:70])
        )
        facts[name] = excerpt
        preview["facts_omitted"] = len(context.facts) - len(facts)
        preview["fact_values_truncated"] = sum(
            len(json.dumps(context.facts[key], ensure_ascii=False, separators=(",", ":"))) > 72
            for key in facts
        )
        if len(encode()) > _PREVIEW_CHARS and len(facts) == 1:
            # The first salient fact outranks optional prose. Keep its exact
            # name and excerpt when the mandatory provenance still fits.
            limitations = cast(list[str], preview["limitations"])
            while limitations and len(encode()) > _PREVIEW_CHARS:
                limitations.pop()
                preview["limitations_omitted"] = len(context.limitations) - len(limitations)
            if len(encode()) > _PREVIEW_CHARS:
                preview["summary"] = ""
                preview["summary_truncated"] = True
        if len(encode()) > _PREVIEW_CHARS:
            del facts[name]
            preview["facts_omitted"] = len(context.facts) - len(facts)
            preview["fact_values_truncated"] = sum(
                len(json.dumps(context.facts[key], ensure_ascii=False, separators=(",", ":"))) > 72
                for key in facts
            )
            if not facts:
                preview["fact_excerpt_unavailable"] = "budget"
    return encode()


def _failure_detail(error: Exception) -> str:
    """Keep controlled failure mechanics without echoing model or evidence payloads."""

    raw = f"{type(error).__name__}:{error}"
    bounded = re.sub(r"[^a-zA-Z0-9_.: =-]", "?", raw)[:90]
    return f"laya_invalid_or_unavailable:{bounded}"[:120]
