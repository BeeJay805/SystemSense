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
from typing import Annotated, Literal, cast

from pydantic import Field, model_validator

from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.retrieval import EvidenceCatalogCursor
from systemsense.inference.control import inference_cancellation
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider
from systemsense.storage.presented_read_set import PresentedReadSetCheckV1, PresentedReadSetV1
from systemsense.storage.sqlite_store import SQLiteStore


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


class DeepDeliveryBasisV1(FrozenModel):
    """Coordinator delivery bookkeeping, never provider-issued authority."""

    matched_detail_request_keys: tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...] = (
        Field(default=(), max_length=4)
    )
    catalog_current_cursor: EvidenceCatalogCursor | None = None
    catalog_next_cursor: EvidenceCatalogCursor | None = None
    catalog_generation: int | None = Field(default=None, ge=0)
    catalog_limit: int | None = Field(default=None, ge=1, le=64)

    @model_validator(mode="after")
    def validate_delivery(self) -> DeepDeliveryBasisV1:
        if len(set(self.matched_detail_request_keys)) != len(self.matched_detail_request_keys):
            raise ValueError("duplicate matched detail request keys")
        if (self.catalog_generation is None) != (self.catalog_limit is None):
            raise ValueError("catalog generation and limit must be supplied together")
        if self.catalog_generation is None and (
            self.catalog_current_cursor is not None or self.catalog_next_cursor is not None
        ):
            raise ValueError("catalog cursors require generation and limit")
        return self

    def delivery_payload(self) -> dict[str, object]:
        payload = {name: getattr(self, name) for name in DeepDeliveryBasisV1.model_fields}
        normalized = DeepDeliveryBasisV1.model_validate(payload).model_dump(
            mode="json", exclude_defaults=True
        )
        if self.matched_detail_request_keys:
            normalized["matched_detail_request_keys"] = sorted(self.matched_detail_request_keys)
        return normalized


def _request_digest(
    request: ReasoningRequest,
    question_id: str | None = None,
    delivery_basis: dict[str, object] | None = None,
) -> str:
    data = request.model_dump(mode="json")
    if question_id is not None:
        data["frontier_question_id"] = question_id
    if delivery_basis:
        data["delivery_basis"] = delivery_basis
    payload = canonical_reasoning_request_json(data)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class FrozenDeepTaskV1(DeepDeliveryBasisV1):
    """One bounded request plus immutable case/evidence/hypothesis basis."""

    schema_version: Literal[1] = 1
    request: ReasoningRequest
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_identity: ProviderIdentity
    presented_read_set: PresentedReadSetV1
    historical_read_sets: tuple[PresentedReadSetV1, ...] = Field(default=(), max_length=64)
    hypothesis_revision: int = Field(ge=0)
    question_id: str | None = Field(default=None, pattern=r"^question_v1_[0-9a-f]{32}$")

    @model_validator(mode="after")
    def validate_basis(self) -> FrozenDeepTaskV1:
        if self.request_sha256 != _request_digest(
            self.request, self.question_id, self.delivery_payload()
        ):
            raise ValueError("frozen_reasoning_request_digest_mismatch")
        if self.catalog_generation is not None:
            if self.catalog_generation != self.presented_read_set.case_generation:
                raise ValueError("catalog generation differs from frozen source basis")
            if len(self.request.evidence_catalog) > cast(int, self.catalog_limit):
                raise ValueError("catalog page exceeds frozen limit")
            if self.request.catalog_has_more != (self.catalog_next_cursor is not None):
                raise ValueError("catalog continuation differs from presented request")
            if self.catalog_next_cursor is not None:
                if not self.request.evidence_catalog:
                    raise ValueError("catalog continuation without presented page")
                tail = self.request.evidence_catalog[-1]
                cursor = EvidenceCatalogCursor.model_validate(
                    {"evidence_id": tail.get("evidence_id"), "observed_at": tail.get("observed_at")}
                )
                if cursor != self.catalog_next_cursor:
                    raise ValueError("catalog continuation does not match presented page")
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
        historical_ids = {
            str(item.evidence_id)
            for item in self.request.evidence_context
            if item.case_scope == "historical"
        }
        historical_entries = tuple(
            entry for source in self.historical_read_sets for entry in source.entries
        )
        if (
            len(historical_entries) != len(historical_ids)
            or {str(entry.evidence_id) for entry in historical_entries} != historical_ids
            or any(source.case_id == self.request.case_id for source in self.historical_read_sets)
            or any(entry.kind not in {"evidence", "coverage"} for entry in historical_entries)
        ):
            raise ValueError("historical_read_sets_do_not_match_focused_evidence")
        return self


def freeze_deep_task(
    request: ReasoningRequest,
    presented_read_set: PresentedReadSetV1,
    *,
    provider_identity: ProviderIdentity,
    hypothesis_revision: int,
    historical_read_sets: tuple[PresentedReadSetV1, ...] = (),
    question_id: str | None = None,
    matched_detail_request_keys: tuple[str, ...] = (),
    catalog_current_cursor: EvidenceCatalogCursor | None = None,
    catalog_next_cursor: EvidenceCatalogCursor | None = None,
    catalog_generation: int | None = None,
    catalog_limit: int | None = None,
) -> FrozenDeepTaskV1:
    """Freeze a coordinator-built request; never discover evidence here."""

    detached = ReasoningRequest.model_validate_json(request.model_dump_json())
    delivery = DeepDeliveryBasisV1(
        matched_detail_request_keys=matched_detail_request_keys,
        catalog_current_cursor=catalog_current_cursor,
        catalog_next_cursor=catalog_next_cursor,
        catalog_generation=catalog_generation,
        catalog_limit=catalog_limit,
    )
    return FrozenDeepTaskV1(
        request=detached,
        request_sha256=_request_digest(detached, question_id, delivery.delivery_payload()),
        provider_identity=provider_identity,
        presented_read_set=presented_read_set,
        hypothesis_revision=hypothesis_revision,
        historical_read_sets=historical_read_sets,
        question_id=question_id,
        matched_detail_request_keys=delivery.matched_detail_request_keys,
        catalog_current_cursor=delivery.catalog_current_cursor,
        catalog_next_cursor=delivery.catalog_next_cursor,
        catalog_generation=delivery.catalog_generation,
        catalog_limit=delivery.catalog_limit,
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
        if self.response is not None and not _matches_worker_provider(
            self.response, self.provider_identity
        ):
            raise ValueError("worker_response_provider_mismatch")
        if self.finished_at < self.started_at:
            raise ValueError("worker_finished_before_start")
        return self


def _matches_worker_provider(response: ReasoningResponse, pinned: ProviderIdentity) -> bool:
    return response.provider == pinned or (
        response.degraded and response.provider == DeterministicReasoningProvider().identity
    )


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
            if not _matches_worker_provider(proposed, provider.identity):
                raise ValueError("reasoning_provider_identity_mismatch")
            if proposed.degraded and proposed.provider != provider.identity:
                provider_status = getattr(provider, "status", None)
                detail = getattr(provider_status, "detail", None)
                failure_kind = (
                    detail[:80]
                    if isinstance(detail, str) and detail
                    else "DegradedDeterministicFallback"
                )
            if cancel_event is not None and cancel_event.is_set():
                status = "cancelled"
            elif clock() >= task.request.deadline_at:
                status = "deadline"
            else:
                serialized = proposed.model_dump_json()
                # Leave room for the result envelope within the durable 64 KiB
                # bound. Oversized advice is a provider failure, not a case failure.
                if len(serialized.encode("utf-8")) > 60_000:
                    status = "rejected"
                    failure_kind = "ResponseByteLimitExceeded"
                else:
                    status = "completed"
                    response = ReasoningResponse.model_validate_json(serialized)
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


class DeepWorkerLane:
    """One coordinator-owned slot, retained until the provider really returns.

    Only the owner calls start/poll/cancel. The daemon worker holds detached
    input, never a store or coordinator callback. Cancellation does not free
    capacity and shutdown never joins an uncooperative provider indefinitely.
    """

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._done = threading.Event()
        self._result: DeepWorkerResultV1 | None = None

    def start(self, provider: ReasoningProvider, task: FrozenDeepTaskV1) -> bool:
        if self._thread is not None:
            return False
        detached = FrozenDeepTaskV1.model_validate_json(task.model_dump_json())
        self._cancel = threading.Event()
        self._done.clear()
        self._result = None

        def run() -> None:
            try:
                self._result = run_deep_worker(
                    provider, detached, cancel_event=self._cancel, clock=self._clock
                )
            finally:
                self._done.set()

        self._thread = threading.Thread(target=run, name="systemsense-deep", daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self._thread = None
            raise
        return True

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def occupied(self) -> bool:
        return self._thread is not None

    def wait(self, timeout: float) -> bool:
        if not 0 <= timeout <= 1:
            raise ValueError("deep worker wait must be between zero and one second")
        return self._done.wait(timeout)

    def poll(self) -> DeepWorkerResultV1 | None:
        if self._thread is None or self._thread.is_alive():
            return None
        self._thread.join(timeout=0)
        result = self._result
        self._thread = None
        self._result = None
        return result


def deep_basis_sha256(task: FrozenDeepTaskV1) -> str:
    """Deduplicate unchanged meaning across coordinator bookkeeping revisions."""
    payload = task.request.model_dump(mode="json")
    for name in ("state_version", "correlation_id", "deadline_at", "budget_ms"):
        payload.pop(name, None)
    payload["provider"] = task.provider_identity.model_dump(mode="json")
    if delivery := task.delivery_payload():
        payload["delivery_basis"] = delivery
    return hashlib.sha256(canonical_reasoning_request_json(payload).encode("utf-8")).hexdigest()


class DeepMailboxRepository:
    """Coordinator-only durable custody; worker threads never receive this object."""

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def admit(self, task: FrozenDeepTaskV1) -> bool:
        task = FrozenDeepTaskV1.model_validate_json(task.model_dump_json())
        encoded = task.model_dump_json()
        if len(encoded.encode("utf-8")) > 262_144:
            raise ValueError("deep mailbox request exceeds byte bound")
        with self.store.transaction():
            rows = self.store.connection.execute(
                "SELECT status, basis_sha256 FROM deep_mailbox WHERE case_id=?",
                (str(task.request.case_id),),
            ).fetchall()
            basis = deep_basis_sha256(task)
            if len(rows) >= 128 or any(row[0] == "running" or row[1] == basis for row in rows):
                return False
            stamp = utc_now().isoformat()
            self.store.connection.execute(
                "INSERT INTO deep_mailbox (case_id,request_sha256,basis_sha256,schema_version,"
                "task_json,status,created_at,updated_at) VALUES (?,?,?,1,?,'running',?,?)",
                (str(task.request.case_id), task.request_sha256, basis, encoded, stamp, stamp),
            )
        return True

    def finish(
        self,
        task: FrozenDeepTaskV1,
        status: Literal["applied", "rejected", "cancelled", "interrupted", "failed"],
        *,
        result: DeepWorkerResultV1 | None = None,
        reason: str = "",
    ) -> bool:
        with self.store.transaction():
            return self.finish_in_transaction(task, status, result=result, reason=reason)

    def finish_in_transaction(
        self,
        task: FrozenDeepTaskV1,
        status: Literal["applied", "rejected", "cancelled", "interrupted", "failed"],
        *,
        result: DeepWorkerResultV1 | None = None,
        reason: str = "",
    ) -> bool:
        """Only deterministic SQL; called with checkpoint save's existing transaction."""
        if not self.store.connection.in_transaction:
            raise RuntimeError("deep completion requires an owned transaction")
        task = FrozenDeepTaskV1.model_validate_json(task.model_dump_json())
        stored = self.store.connection.execute(
            "SELECT task_json,basis_sha256 FROM deep_mailbox WHERE case_id=? AND request_sha256=?",
            (str(task.request.case_id), task.request_sha256),
        ).fetchone()
        if (
            stored is None
            or FrozenDeepTaskV1.model_validate_json(str(stored[0])) != task
            or (str(stored[1]) != deep_basis_sha256(task))
        ):
            raise ValueError("deep mailbox completion basis mismatch")
        if result is not None:
            result = DeepWorkerResultV1.model_validate_json(result.model_dump_json())
        if result is not None and (
            result.case_id != task.request.case_id
            or result.request_sha256 != task.request_sha256
            or result.provider_identity != task.provider_identity
        ):
            raise ValueError("deep mailbox result identity mismatch")
        if status == "applied" and (result is None or result.status != "completed"):
            raise ValueError("deep mailbox cannot apply an incomplete result")
        encoded = result.model_dump_json() if result else None
        if encoded is not None and len(encoded.encode("utf-8")) > 65_536:
            raise ValueError("deep mailbox result exceeds byte bound")
        changed = self.store.connection.execute(
            "UPDATE deep_mailbox SET status=?,result_json=?,reason=?,updated_at=? "
            "WHERE case_id=? AND request_sha256=? AND status='running'",
            (
                status,
                encoded,
                reason[:240],
                utc_now().isoformat(),
                str(task.request.case_id),
                task.request_sha256,
            ),
        )
        return changed.rowcount == 1

    def recover(self, case_id: CaseId, *, live_request_sha256: str | None = None) -> int:
        """Orphaned requests become explicit interrupted attempts, never replayed."""
        with self.store.transaction():
            changed = self.store.connection.execute(
                "UPDATE deep_mailbox SET status='interrupted',reason='worker custody lost',"
                "updated_at=? WHERE case_id=? AND status='running' AND request_sha256<>?",
                (utc_now().isoformat(), str(case_id), live_request_sha256 or ""),
            )
        return changed.rowcount


class DeepMailboxCompletionV1(FrozenModel):
    """Typed database transition, never an executable callback or model permission."""

    schema_version: Literal[1] = 1
    task: FrozenDeepTaskV1
    result: DeepWorkerResultV1
    status: Literal["applied", "rejected"]
    reason: str = Field(default="", max_length=240)


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
