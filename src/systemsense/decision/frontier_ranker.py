"""Versioned advisory ranking of typed, already-admitted search references.

This adapter receives no runner, store, filesystem, or operating-system handle.
Its output is an ordering of caller-supplied opaque IDs, not task admission.
The application must re-read and claim each frontier item under current policy.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from pydantic import Field, model_validator

from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.semantic_packets import SERIALIZER_ID, compact_worker_packet
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import MeasurementWindow
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.graph import AssertionStatus, RelationKind
from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    LayaRanker,
    LayaRuntimeError,
    LayaWorkerPresentation,
)
from systemsense.storage.search_frontier import FrontierItemV1, FrontierStatus

_DIGEST = r"^[0-9a-f]{64}$"


def _worker_failure_category(
    error: Exception,
) -> Literal[
    "deadline",
    "protocol",
    "admission",
    "request_bounds",
    "transport",
    "runtime",
    "unexpected",
    "worker_rejected",
    "capture_response_limit",
    "capture_tensor_limit",
    "state_fit_limit",
    "instruction_fit_limit",
    "question_expansion_limit",
    "model_output_invalid",
    "invalid_envelope",
    "invalid_ranking",
    "invalid_scores",
    "invalid_token_provenance",
    "invalid_presentation",
    "invalid_exact_capture",
]:
    """Collapse worker failures to fixed codes; never persist exception text."""

    if not isinstance(error, LayaRuntimeError):
        return "unexpected"
    if error.failure_code is not None:
        return error.failure_code
    message = str(error).casefold()
    if "deadline" in message:
        return "deadline"
    if "invalid response" in message or "invalid ranking" in message:
        return "protocol"
    if "admission" in message:
        return "admission"
    if "exceeds the configured byte limit" in message or "bounded size" in message:
        return "request_bounds"
    if "request write failed" in message or "stdin is unavailable" in message:
        return "transport"
    return "runtime"


class SemanticPacketRefV1(FrozenModel):
    """A bounded, self-contained, already-redacted worker packet."""

    evidence_id: str = Field(min_length=1, max_length=80)
    page_id: str = Field(min_length=1, max_length=128)
    fragment_id: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=800)

    @model_validator(mode="after")
    def validate_projection(self) -> SemanticPacketRefV1:
        try:
            parsed: object = json.loads(self.description)
        except json.JSONDecodeError as error:
            raise ValueError("semantic packet is not JSON") from error
        if not isinstance(parsed, dict):
            raise ValueError("semantic packet must be an object")
        packet = cast(dict[str, object], parsed)
        kind = packet.get("packet_kind")
        if (
            not self.page_id.startswith(f"{self.evidence_id}:")
            or not self.fragment_id.startswith(f"{self.page_id}:")
            or packet.get("projection") != SERIALIZER_ID
            or packet.get("page_id") != self.page_id
            or packet.get("evidence_id", self.evidence_id) != self.evidence_id
            or kind not in {"fact", "status"}
            or not isinstance(packet.get("observed_at"), str)
            or not isinstance(packet.get("captured_at"), str)
        ):
            raise ValueError("semantic packet provenance or serializer mismatch")
        try:
            observed = datetime.fromisoformat(cast(str, packet["observed_at"]))
            captured = datetime.fromisoformat(cast(str, packet["captured_at"]))
        except ValueError as error:
            raise ValueError("semantic packet timestamps are invalid") from error
        if (
            observed.utcoffset() != UTC.utcoffset(None)
            or captured.utcoffset() != UTC.utcoffset(None)
            or observed > captured
        ):
            raise ValueError("semantic packet timestamps are inconsistent")
        if kind == "fact" and (
            not isinstance(packet.get("metric"), str)
            or packet.get("value_quality") not in {"exact", "truncated"}
            or (packet.get("value_quality") == "exact") != ("value" in packet)
        ):
            raise ValueError("semantic fact packet has ambiguous value quality")
        if kind == "status" and "value" in packet:
            raise ValueError("semantic status packet must not claim a value")
        return self

    def wire(self) -> dict[str, str]:
        return self.model_dump(mode="python")


class MeasurementParameterSemanticV1(FrozenModel):
    """Allowlisted, bounded hint; never an executable parameter or selector."""

    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-z][a-z0-9_]*$")
    value_type: Literal["integer", "utc_timestamp", "masked"]
    value_hint: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 _:.+\-<>]+$")


class MeasurementSemanticsV1(FrozenModel):
    """Source-bound description of a registered measurement, without authority."""

    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    observable: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    invocation_sha256: str = Field(pattern=_DIGEST)
    target_bound: bool
    parameters: tuple[MeasurementParameterSemanticV1, ...] = Field(default=(), max_length=8)


class FrontierItemSemanticV1(FrozenModel):
    """Caller-supplied, source-bound meaning for one opaque frontier reference.

    The adapter verifies shape/binding, not source authenticity. The application
    must derive this from readback-validated catalog, evidence, graph, or a
    frozen reasoning question and pass the authoritative record digest.
    """

    schema_version: Literal[1] = 1
    item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")
    case_id: CaseId
    reference_id: str = Field(min_length=1, max_length=80)
    source_kind: Literal[
        "evidence_repository", "capability_registry", "knowledge_graph", "reasoning_question"
    ]
    source_record_sha256: str = Field(pattern=_DIGEST)
    source_recorded_at: UtcDateTime | None = None
    source_time_quality: Literal["source_recorded", "not_available"]
    quality: Literal["observed", "documented", "inferred", "limited", "proposed"]
    information_goal: str = Field(min_length=8, max_length=240)
    target_scope: Literal[
        "host", "device", "application", "network_adapter", "service", "component", "unknown"
    ]
    target_label: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 _.-]+$")
    measurement_window: MeasurementWindow | None = None
    measurement: MeasurementSemanticsV1 | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    relation_id: str | None = Field(default=None, pattern=r"^rel_[0-9a-f]{32}$")
    relation_kind: RelationKind | None = None
    relation_assertion_status: AssertionStatus | None = None
    relation_source_label: str | None = Field(
        default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 _.-]+$"
    )
    relation_target_label: str | None = Field(
        default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 _.-]+$"
    )
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=80)], ...] = Field(
        default=(), max_length=2
    )

    @model_validator(mode="after")
    def bounded_meaning(self) -> FrontierItemSemanticV1:
        if not self.information_goal.endswith("?"):
            raise ValueError("frontier information goal must be a question, not a causal claim")
        allowed_quality = {
            "evidence_repository": {"observed", "limited"},
            "capability_registry": {"documented", "limited"},
            "knowledge_graph": {"observed", "inferred", "limited"},
            "reasoning_question": {"proposed"},
        }
        if self.quality not in allowed_quality[self.source_kind]:
            raise ValueError("frontier semantic quality does not match source kind")
        if self.quality == "limited" and not self.limitations:
            raise ValueError("limited frontier semantics require a limitation")
        if (self.source_recorded_at is None) != (self.source_time_quality == "not_available"):
            raise ValueError("frontier source time quality contradicts source timestamp")
        relation_fields = (
            self.relation_id,
            self.relation_kind,
            self.relation_assertion_status,
            self.relation_source_label,
            self.relation_target_label,
        )
        if self.source_kind == "knowledge_graph":
            if any(value is None for value in relation_fields):
                raise ValueError("graph branch needs an explicit sourced relationship")
            if (
                self.quality == "inferred"
                and self.relation_assertion_status is not AssertionStatus.INFERRED
            ):
                raise ValueError("inferred graph quality needs inferred assertion status")
            if (
                self.quality == "observed"
                and self.relation_assertion_status is not AssertionStatus.OBSERVED
            ):
                raise ValueError("observed graph quality needs observed assertion status")
        elif any(value is not None for value in relation_fields):
            raise ValueError("non-graph frontier item cannot claim a graph relationship")
        if self.source_kind != "capability_registry" and (
            self.measurement_window is not None or self.measurement is not None
        ):
            raise ValueError("only a measurement candidate may carry measurement semantics")
        return self


class FrontierRankRequestV1(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    provider: ProviderIdentity
    model_weight_sha256: str = Field(pattern=_DIGEST)
    evidence_serializer: Literal["semantic_fact_packets_v1"] = SERIALIZER_ID
    deadline_at: UtcDateTime
    symptom: str = Field(min_length=1, max_length=1000)
    hypothesis_briefs: tuple[Annotated[str, Field(min_length=1, max_length=240)], ...] = Field(
        default=(), max_length=8
    )
    items: tuple[FrontierItemV1, ...] = Field(min_length=1, max_length=32)
    item_semantics: tuple[FrontierItemSemanticV1, ...] = Field(min_length=1, max_length=32)
    evidence_packets: tuple[SemanticPacketRefV1, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_scope(self) -> FrontierRankRequestV1:
        if self.provider.role != "fast_decision":
            raise ValueError("frontier ranking needs a fast-decision provider")
        if any(
            item.case_id != self.case_id or item.status is not FrontierStatus.REQUESTED
            for item in self.items
        ):
            raise ValueError("frontier rank input contains another case or non-requested item")
        if len({item.item_id for item in self.items}) != len(self.items):
            raise ValueError("frontier rank input repeats an item ID")
        source_kinds = {
            "retrieve_evidence": "evidence_repository",
            "measure": "capability_registry",
            "review_branch": "knowledge_graph",
            "consult_deep": "reasoning_question",
        }
        if len(self.item_semantics) != len(self.items):
            raise ValueError("frontier item semantic descriptions are missing")
        for item, semantic in zip(self.items, self.item_semantics, strict=True):
            ref = item.reference
            reference_id = (
                str(ref.evidence_id)
                if ref.evidence_id is not None
                else ref.candidate_id or ref.branch_id or ref.question_id
            )
            if (
                semantic.item_id != item.item_id
                or semantic.case_id != self.case_id
                or semantic.reference_id != reference_id
                or semantic.source_kind != source_kinds[ref.kind]
                or semantic.measurement_window != ref.window
            ):
                raise ValueError("frontier item semantic description does not bind item/source")
        if len({item.fragment_id for item in self.evidence_packets}) != len(self.evidence_packets):
            raise ValueError("frontier rank input repeats a semantic packet")
        return self


class FrontierRankResponseV1(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    provider: ProviderIdentity
    context_sha256: str = Field(pattern=_DIGEST)
    ranked_item_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    considered_item_ids: tuple[str, ...] = Field(default=(), max_length=32)
    ranking_source: Literal["laya", "deterministic_fallback"]
    model_abstained: bool
    coverage_complete: bool
    degraded_reason: (
        Literal[
            "deadline_expired",
            "worker_unavailable",
            "worker_error",
            "incomplete_model_coverage",
            "presentation_incomplete",
        ]
        | None
    ) = None
    cache_hit: bool = False
    attention_notes: tuple[str, ...] = Field(default=(), max_length=16)
    presentation_trace: LayaAttentionResult | None = None

    def validate_against(self, request: FrontierRankRequestV1) -> FrontierRankResponseV1:
        offered = tuple(item.item_id for item in request.items)
        if (
            self.case_id != request.case_id
            or self.provider != request.provider
            or self.context_sha256 != _context_sha256(request)
            or len(self.ranked_item_ids) != len(offered)
            or set(self.ranked_item_ids) != set(offered)
            or len(set(self.ranked_item_ids)) != len(offered)
            or not set(self.considered_item_ids).issubset(offered)
        ):
            raise ValueError("frontier rank response escapes offered IDs or case")
        if self.ranking_source == "laya" and (
            self.model_abstained
            or not self.coverage_complete
            or self.degraded_reason is not None
            or self.considered_item_ids != offered
        ):
            raise ValueError("Laya ranking claims incomplete coverage")
        if self.ranking_source == "deterministic_fallback" and (
            not self.model_abstained
            or self.coverage_complete
            or self.degraded_reason is None
            or self.ranked_item_ids != offered
        ):
            raise ValueError("fallback must disclose model abstention")
        if self.presentation_trace is not None and (
            self.ranking_source != "laya"
            or not _attention_valid(self.presentation_trace, request)[0]
            or self.presentation_trace.ranked_probe_ids != self.ranked_item_ids
            or self.presentation_trace.attention_notes[:16] != self.attention_notes
        ):
            raise ValueError("frontier worker trace differs from validated Laya ranking")
        return self


def _context_sha256(request: FrontierRankRequestV1) -> str:
    # Exclude only the execution deadline, which is checked before every hit
    # and is not supplied to the model. Everything model-visible, relevant
    # versions, provider/model pin, ordered IDs and packet bytes is included.
    payload = request.model_dump(mode="json", exclude={"deadline_at"})
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate_description(item: FrontierItemV1, semantic: FrontierItemSemanticV1) -> str:
    ref = item.reference
    window = semantic.measurement_window
    window_values = {"window_start": window.start, "window_end": window.end} if window else {}

    def duplicate_window_parameter(parameter: MeasurementParameterSemanticV1) -> bool:
        expected = window_values.get(parameter.name)
        if expected is None or parameter.value_type != "utc_timestamp":
            return False
        try:
            return datetime.fromisoformat(parameter.value_hint) == expected
        except ValueError:
            return False

    description: dict[str, object] = {
        "kind": ref.kind,
        "information_goal": semantic.information_goal,
        "target_scope": semantic.target_scope,
        "target_label": semantic.target_label,
        "measurement_window": (
            semantic.measurement_window.model_dump(mode="json")
            if semantic.measurement_window is not None
            else None
        ),
        "measurement": (
            {
                "probe_id": semantic.measurement.probe_id,
                "observable": semantic.measurement.observable,
                "target_bound": semantic.measurement.target_bound,
                "parameters": [
                    parameter.model_dump(mode="json")
                    for parameter in semantic.measurement.parameters
                    if not duplicate_window_parameter(parameter)
                ],
            }
            if semantic.measurement is not None
            else None
        ),
        "relation_kind": semantic.relation_kind,
        "relation_assertion_status": semantic.relation_assertion_status,
        "relation_source_label": semantic.relation_source_label,
        "relation_target_label": semantic.relation_target_label,
        "relation_is_causal_proof": False,
        "source_recorded_at": (
            semantic.source_recorded_at.isoformat()
            if semantic.source_recorded_at is not None
            else None
        ),
        "source_time_quality": semantic.source_time_quality,
        "quality": semantic.quality,
        "limitations": semantic.limitations,
    }
    return json.dumps(
        {key: value for key, value in description.items() if value is not None and value != ()},
        sort_keys=True,
        separators=(",", ":"),
    )


def _attention_valid(
    result: LayaAttentionResult,
    request: FrontierRankRequestV1,
) -> tuple[bool, Literal["incomplete_model_coverage", "presentation_incomplete"]]:
    item_ids = tuple(item.item_id for item in request.items)
    fragment_ids = tuple(item.fragment_id for item in request.evidence_packets)
    page_ids = {item.page_id for item in request.evidence_packets}
    if (
        len(result.ranked_probe_ids) != len(item_ids)
        or set(result.ranked_probe_ids) != set(item_ids)
        or len(set(result.ranked_probe_ids)) != len(item_ids)
        or len(result.considered_probe_ids) != len(item_ids)
        or set(result.considered_probe_ids) != set(item_ids)
        or set(result.considered_attention_page_ids) != page_ids
        or len(set(result.considered_attention_page_ids)) != len(page_ids)
        or not set(result.ranked_attention_page_ids).issubset(page_ids)
        or not set(result.considered_evidence_ids).issubset(
            {item.evidence_id for item in request.evidence_packets}
        )
        or not set(result.ranked_evidence_ids).issubset(
            {item.evidence_id for item in request.evidence_packets}
        )
    ):
        return False, "incomplete_model_coverage"
    evidence_batches = tuple(batch for batch in result.microbatches if batch.phase == "evidence")
    item_batches = tuple(batch for batch in result.microbatches if batch.phase == "probe")
    comparison_batches = tuple(batch for batch in result.microbatches if batch.phase == "compare")
    if (
        tuple(item for batch in evidence_batches for item in batch.candidate_ids) != fragment_ids
        or tuple(item for batch in item_batches for item in batch.candidate_ids) != item_ids
        or tuple(batch.batch_index for batch in evidence_batches)
        != tuple(range(len(evidence_batches)))
        or tuple(batch.batch_index for batch in item_batches) != tuple(range(len(item_batches)))
        or tuple(batch.batch_index for batch in comparison_batches)
        != tuple(range(len(comparison_batches)))
        or tuple(batch.phase for batch in result.microbatches)
        != (
            *("evidence" for _ in evidence_batches),
            *("probe" for _ in item_batches),
            *("compare" for _ in comparison_batches),
        )
        or (len(item_batches) > 1 and not comparison_batches)
        or (len(item_batches) <= 1 and bool(comparison_batches))
        or any(
            len(batch.candidate_ids) < 2
            or len(set(batch.candidate_ids)) != len(batch.candidate_ids)
            or not set(batch.candidate_ids).issubset(item_ids)
            or set(batch.inference_ids) | set(batch.cache_hit_ids) != set(batch.candidate_ids)
            or set(batch.inference_ids) & set(batch.cache_hit_ids)
            for batch in comparison_batches
        )
        or (
            comparison_batches
            and result.ranked_probe_ids[0] not in comparison_batches[-1].candidate_ids
        )
    ):
        return False, "incomplete_model_coverage"
    if any(
        (batch.inference_ids and batch.worker_presentation is None)
        or any(origin.presentation_sha256 is None for origin in batch.cached_origins)
        for batch in result.microbatches
    ):
        return False, "presentation_incomplete"
    for required in (
        "coverage_limited=false",
        "state_truncated_batches=0",
        "instruction_truncated_items=0",
    ):
        if required not in result.attention_notes:
            return False, "presentation_incomplete"
    return True, "incomplete_model_coverage"


class MixedFrontierRanker:
    """Advisory Laya attention with exact-context cache and complete safe fallback."""

    def __init__(
        self,
        *,
        ranker: LayaRanker | None,
        provider: ProviderIdentity,
        model_weight_sha256: str,
        timeout_seconds: float = 2.0,
        cache_size: int = 64,
    ) -> None:
        if provider.role != "fast_decision" or re.fullmatch(_DIGEST, model_weight_sha256) is None:
            raise ValueError("frontier ranker requires a pinned fast provider/model")
        if not 0 < timeout_seconds <= 30 or not 0 <= cache_size <= 256:
            raise ValueError("frontier ranker limits are invalid")
        self._ranker = ranker
        self._provider = provider
        self._model_weight_sha256 = model_weight_sha256
        self._timeout_seconds = timeout_seconds
        self._cache_size = cache_size
        self._cache: OrderedDict[str, FrontierRankResponseV1] = OrderedDict()
        self._cache_lock = threading.Lock()

    @property
    def provider(self) -> ProviderIdentity:
        """The pinned provider identity used to bind every ranking request."""

        return self._provider

    @property
    def model_weight_sha256(self) -> str:
        """The pinned model weight digest used in the exact-context cache."""

        return self._model_weight_sha256

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        # model_copy bypasses Pydantic validation; restore the boundary here.
        request = FrontierRankRequestV1.model_validate(request.model_dump(mode="json"))
        if (
            request.provider != self._provider
            or request.model_weight_sha256 != self._model_weight_sha256
        ):
            raise ValueError("frontier request provider/model pin differs from adapter")
        context_sha = _context_sha256(request)
        offered = tuple(item.item_id for item in request.items)

        def fallback(
            reason: Literal[
                "deadline_expired",
                "worker_unavailable",
                "worker_error",
                "incomplete_model_coverage",
                "presentation_incomplete",
            ],
            considered: tuple[str, ...] = (),
            notes: tuple[str, ...] = (),
        ) -> FrontierRankResponseV1:
            return FrontierRankResponseV1(
                case_id=request.case_id,
                provider=request.provider,
                context_sha256=context_sha,
                ranked_item_ids=offered,
                considered_item_ids=considered,
                ranking_source="deterministic_fallback",
                model_abstained=True,
                coverage_complete=False,
                degraded_reason=reason,
                attention_notes=notes[:16],
            ).validate_against(request)

        remaining = (request.deadline_at - utc_now()).total_seconds()
        if remaining <= 0:
            return fallback("deadline_expired")
        cached = None
        if capture_worker_batch is None:
            with self._cache_lock:
                cached = self._cache.get(context_sha)
                if cached is not None:
                    self._cache.move_to_end(context_sha)
        if cached is not None:
            return cached.model_copy(update={"cache_hit": True}).validate_against(request)
        if self._ranker is None:
            return fallback("worker_unavailable")
        try:
            capture_options = (
                {
                    "capture_exact_worker_call": capture_worker_batch,
                    "capture_model_input": True,
                }
                if capture_worker_batch is not None
                else {}
            )
            result = self._ranker.attend(
                state={
                    "attention_kind": "mixed_frontier_relevance",
                    "symptom": request.symptom,
                    "hypothesis_briefs": request.hypothesis_briefs,
                },
                evidence=tuple(
                    compact_worker_packet(item.wire()) for item in request.evidence_packets
                ),
                candidates=tuple(
                    {
                        "probe_id": item.item_id,
                        "description": _candidate_description(item, semantic),
                    }
                    for item, semantic in zip(request.items, request.item_semantics, strict=True)
                ),
                timeout_seconds=min(self._timeout_seconds, remaining),
                **capture_options,
            )
            result = LayaAttentionResult.model_validate(result.model_dump(mode="json"))
        except Exception as error:
            category = _worker_failure_category(error)
            bytes_seen = error.failure_bytes if isinstance(error, LayaRuntimeError) else None
            size_note = (
                (f"laya_failure_bytes={bytes_seen}",)
                if bytes_seen is not None and bytes_seen < 262_144
                else ("laya_failure_bytes_at_least=262144",)
                if bytes_seen == 262_144
                else ()
            )
            return fallback(
                "deadline_expired" if category == "deadline" else "worker_error",
                notes=(f"laya_failure={category}", *size_note),
            )
        if utc_now() >= request.deadline_at:
            return fallback("deadline_expired")
        considered = tuple(item for item in offered if item in result.considered_probe_ids)
        valid, reason = _attention_valid(result, request)
        if not valid:
            return fallback(reason, considered, result.attention_notes)
        response = FrontierRankResponseV1(
            case_id=request.case_id,
            provider=request.provider,
            context_sha256=context_sha,
            ranked_item_ids=result.ranked_probe_ids,
            considered_item_ids=offered,
            ranking_source="laya",
            model_abstained=False,
            coverage_complete=True,
            attention_notes=result.attention_notes[:16],
            presentation_trace=result,
        ).validate_against(request)
        if self._cache_size and capture_worker_batch is None:
            with self._cache_lock:
                self._cache[context_sha] = response
                self._cache.move_to_end(context_sha)
                while len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)
        return response
