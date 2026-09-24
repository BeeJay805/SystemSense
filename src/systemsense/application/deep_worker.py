"""Frozen, store-free deep-brain work and conservative result applicability.

The coordinator owns evidence reads, persistence, scheduling, and probe admission.
This module only calls a replaceable reasoning provider on a detached request.
The coordinator must use a bounded executor and revalidate all suggested probes
against its *current* case state before any dispatch. No result applies itself.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from typing import Literal, cast

from pydantic import Field, model_validator

from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.inference.control import inference_cancellation
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.provider import ReasoningProvider
from systemsense.storage.presented_read_set import PresentedReadSetCheckV1, PresentedReadSetV1


def canonical_reasoning_request_json(payload: dict[str, object]) -> str:
    """Preserve ordered evidence while normalizing schema-defined unordered sets."""

    normalized = deepcopy(payload)

    def sort_string_set(container: dict[str, object], key: str) -> None:
        value = container.get(key)
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in cast(list[object], value)
        ):
            raise ValueError(f"reasoning_request_{key}_is_not_a_string_set")
        container[key] = sorted(cast(list[str], value))

    for key in ("completed_probe_ids", "satisfied_probe_ids"):
        sort_string_set(normalized, key)
    probes = normalized.get("available_probes")
    if not isinstance(probes, list):
        raise ValueError("reasoning_request_available_probes_invalid")
    for probe in cast(list[object], probes):
        if not isinstance(probe, dict):
            raise ValueError("reasoning_request_probe_invalid")
        typed_probe = cast(dict[str, object], probe)
        for key in ("keywords", "target_traits"):
            sort_string_set(typed_probe, key)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _request_digest(request: ReasoningRequest) -> str:
    payload = canonical_reasoning_request_json(request.model_dump(mode="json"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class FrozenDeepTaskV1(FrozenModel):
    """One bounded request plus immutable case/evidence/hypothesis basis."""

    schema_version: Literal[1] = 1
    request: ReasoningRequest
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_identity: ProviderIdentity
    presented_read_set: PresentedReadSetV1
    hypothesis_revision: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_basis(self) -> FrozenDeepTaskV1:
        if self.request_sha256 != _request_digest(self.request):
            raise ValueError("frozen_reasoning_request_digest_mismatch")
        if self.request.case_id != self.presented_read_set.case_id:
            raise ValueError("read_set_case_mismatch")
        if any(item.case_scope == "unspecified" for item in self.request.evidence_context):
            raise ValueError("unscoped_focused_evidence")
        visible_case_ids = tuple(
            item.evidence_id
            for item in self.request.evidence_context
            if item.case_scope == "current_case"
        )
        entries = self.presented_read_set.entries
        if tuple(item.evidence_id for item in entries) != visible_case_ids or any(
            item.kind not in {"evidence", "coverage"} for item in entries
        ):
            raise ValueError("presented_read_set_does_not_match_focused_case_evidence")
        return self


def freeze_deep_task(
    request: ReasoningRequest,
    presented_read_set: PresentedReadSetV1,
    *,
    provider_identity: ProviderIdentity,
    hypothesis_revision: int,
) -> FrozenDeepTaskV1:
    """Freeze a coordinator-built request; never discover evidence here."""

    detached = ReasoningRequest.model_validate_json(request.model_dump_json())
    return FrozenDeepTaskV1(
        request=detached,
        request_sha256=_request_digest(detached),
        provider_identity=provider_identity,
        presented_read_set=presented_read_set,
        hypothesis_revision=hypothesis_revision,
    )


class DeepWorkerResultV1(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_identity: ProviderIdentity
    status: Literal["completed", "rejected", "cancelled", "deadline"]
    started_at: UtcDateTime
    finished_at: UtcDateTime
    elapsed_ms: float = Field(ge=0)
    response: ReasoningResponse | None = None
    failure_kind: str | None = Field(default=None, max_length=80)

    @model_validator(mode="after")
    def validate_result(self) -> DeepWorkerResultV1:
        if (self.response is not None) != (self.status == "completed"):
            raise ValueError("worker_response_presence_mismatch")
        if self.response is not None and self.response.case_id != self.case_id:
            raise ValueError("worker_response_case_mismatch")
        if self.response is not None and self.response.provider != self.provider_identity:
            raise ValueError("worker_response_provider_mismatch")
        if self.finished_at < self.started_at:
            raise ValueError("worker_finished_before_start")
        return self


def run_deep_worker(
    provider: ReasoningProvider,
    task: FrozenDeepTaskV1,
    *,
    cancel_event: threading.Event | None,
    clock: Callable[[], datetime] = utc_now,
) -> DeepWorkerResultV1:
    """Run one provider call, normally on a caller-owned bounded worker thread.

    No store, probe runtime, or case mutation is passed to this function. The
    provider must honor its deadline; Python cannot forcibly interrupt a hung
    provider, so the owner must retain and account for its occupied worker slot.
    """

    task = FrozenDeepTaskV1.model_validate(task.model_dump(mode="json"))
    started_at = clock()
    started = time.monotonic()
    status: Literal["completed", "rejected", "cancelled", "deadline"]
    response: ReasoningResponse | None = None
    failure_kind: str | None = None
    if provider.identity != task.provider_identity:
        status = "rejected"
        failure_kind = "ProviderIdentityMismatch"
    elif cancel_event is not None and cancel_event.is_set():
        status = "cancelled"
    elif started_at >= task.request.deadline_at:
        status = "deadline"
    else:
        try:
            with inference_cancellation(cancel_event):
                proposed = provider.investigate(task.request.model_copy(deep=True))
            proposed.validate_against(task.request)
            if proposed.provider != provider.identity:
                raise ValueError("reasoning_provider_identity_mismatch")
            if cancel_event is not None and cancel_event.is_set():
                status = "cancelled"
            elif clock() >= task.request.deadline_at:
                status = "deadline"
            else:
                status = "completed"
                response = ReasoningResponse.model_validate_json(proposed.model_dump_json())
        except Exception as error:
            status = (
                "cancelled" if cancel_event is not None and cancel_event.is_set() else "rejected"
            )
            failure_kind = type(error).__name__
    finished_at = clock()
    if status == "completed" and finished_at >= task.request.deadline_at:
        status = "deadline"
        response = None
    return DeepWorkerResultV1(
        case_id=task.request.case_id,
        request_sha256=task.request_sha256,
        provider_identity=task.provider_identity,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=max(0.0, (time.monotonic() - started) * 1000),
        response=response,
        failure_kind=failure_kind,
    )


class DeepResultApplicabilityV1(FrozenModel):
    schema_version: Literal[1] = 1
    applicability: Literal["reject", "historical_only", "coordinator_revalidation_required"]
    assessed_through_generation: int = Field(ge=1)
    reasons: tuple[str, ...] = ()


def assess_deep_result(
    task: FrozenDeepTaskV1,
    result: DeepWorkerResultV1,
    read_set_check: PresentedReadSetCheckV1,
    *,
    current_hypothesis_revision: int,
    case_terminal: bool,
    cancelled: bool,
    now: datetime,
) -> DeepResultApplicabilityV1:
    """Pure preliminary gate; only the coordinator may rebase/save a result.

    A generation advance does not imply the frozen rows changed. It does mean
    newly appended observations were not considered, so hypotheses remain
    historical and cannot be promoted as a current supported explanation.
    """

    reasons: list[str] = []
    if (
        result.case_id != task.request.case_id
        or result.request_sha256 != task.request_sha256
        or result.provider_identity != task.provider_identity
    ):
        reasons.append("worker_task_identity_mismatch")
    if result.status != "completed" or result.response is None:
        reasons.append("worker_not_completed")
    else:
        try:
            result.response.validate_against(task.request)
        except ValueError:
            reasons.append("worker_response_invalid")
    if read_set_check.case_id != task.request.case_id or (
        read_set_check.frozen_generation != task.presented_read_set.case_generation
    ):
        reasons.append("read_set_basis_mismatch")
    if not read_set_check.consistent or read_set_check.generation_regressed:
        reasons.append("presented_evidence_changed")
    if current_hypothesis_revision != task.hypothesis_revision:
        reasons.append("hypothesis_lineage_advanced")
    if case_terminal:
        reasons.append("case_terminal")
    if cancelled:
        reasons.append("cancelled")
    if now >= task.request.deadline_at or result.finished_at >= task.request.deadline_at:
        reasons.append("deadline_expired")
    if reasons:
        applicability: Literal["reject", "historical_only", "coordinator_revalidation_required"] = (
            "reject"
        )
    elif read_set_check.current_generation > task.presented_read_set.case_generation:
        applicability = "historical_only"
    else:
        applicability = "coordinator_revalidation_required"
    return DeepResultApplicabilityV1(
        applicability=applicability,
        assessed_through_generation=task.presented_read_set.case_generation,
        reasons=tuple(reasons),
    )
