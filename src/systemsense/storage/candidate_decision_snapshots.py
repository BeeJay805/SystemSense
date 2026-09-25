"""Private, immutable custody of vNext candidate-ID advisory decisions.

This is not an execution permit or a training label. It verifies frozen
registry-row bytes, not source/dependency/target eligibility; live registry
resolution and dispatch policy remain separate. An execution link is a
coordinator association, not independent proof of runner target/window use
or that an execution was inserted in the same transaction as the link.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    candidate_decision_request_json,
)
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
)
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import ProbeInvocation, SafetyClass
from systemsense.domain.time import utc_now
from systemsense.evidence.retrieval import (
    EvidenceCatalogEntry,
    EvidenceCatalogQuery,
    EvidenceRetriever,
)
from systemsense.inference.laya_runtime import (
    _verify_exact_worker_capture,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.case_candidates import CandidateRecord, CaseCandidateRegistry
from systemsense.storage.search_frontier import SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore

_SERIALIZER = "candidate-decision-json-v1"
_MAX_WORKER_DRAFT_BYTES = 2 * 1024 * 1024
_REGISTRY_COLUMNS = (
    "candidate_id",
    "schema_version",
    "case_id",
    "epoch_state_version",
    "probe_id",
    "manifest_version",
    "manifest_sha256",
    "invocation_json",
    "invocation_sha256",
    "observable",
    "target_handle",
    "source_evidence_id",
    "source_evidence_sha256",
    "dependency_bindings_json",
    "dependency_sha256",
    "binding_sha256",
    "cost_ms",
    "resource_class",
    "safety_class",
    "description",
    "issued_at",
    "expires_at",
)
_SNAPSHOT_COLUMNS = (
    "snapshot_id",
    "schema_version",
    "serializer_version",
    "case_id",
    "epoch_state_version",
    "correlation_id",
    "request_frozen_at",
    "captured_at",
    "request_json",
    "request_sha256",
    "response_json",
    "response_sha256",
    "candidate_ids_json",
    "candidate_manifest_sha256",
    "registry_refs_json",
    "registry_manifest_sha256",
)


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _worker_ordered_json_bytes(value: object) -> bytes:
    # Laya attests the original JSON key order, so sorting nested worker-call
    # keys would invalidate its ordinary presentation hashes at readback.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )


def _worker_model_input_sha256(value: object) -> str:
    return hashlib.sha256(
        b"systemsense.laya.model_input.v1\0" + _worker_ordered_json_bytes(value)
    ).hexdigest()


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("candidate snapshot chronology is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(None):
        raise ValueError("candidate snapshot timestamp must be UTC")
    return parsed


def _invocation_json(invocation: ProbeInvocation) -> str:
    return _canonical(invocation.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class CandidateDecisionSnapshot:
    snapshot_id: str
    case_id: CaseId
    epoch_state_version: int
    request_frozen_at: datetime
    captured_at: datetime
    request: CandidateDecisionRequestV1
    response: CandidateDecisionResponseV1 | CandidateDecisionGapV1
    request_sha256: str
    response_sha256: str
    candidate_ids: tuple[str, ...]
    registry_manifest_sha256: str
    # Worker trace digests do not prove token parity or cache-origin authenticity.
    training_admissible: bool = False
    registry_source_eligibility_proven: bool = False


@dataclass(frozen=True, slots=True)
class FrontierCandidateSnapshot:
    snapshot_id: str
    case_id: CaseId
    epoch_state_version: int
    request_frozen_at: datetime
    captured_at: datetime
    request: FrontierRankRequestV1
    response: FrontierRankResponseV1
    selected_item_id: str
    candidate_id: str | None
    candidate_refs: tuple[AdmittedCandidateRefV1, ...]
    selected_kind: str


@dataclass(frozen=True, slots=True)
class FrontierWorkerCaptureDraft:
    """Unreviewed exact worker input; never a training or privacy approval."""

    snapshot_id: str
    case_id: CaseId
    capture_bytes: bytes
    capture_sha256: str
    captured_at: datetime
    privacy_review_status: str = "unreviewed"
    training_admissible: bool = False

    @property
    def captured_calls(self) -> dict[tuple[str, int], dict[str, object]]:
        payload = cast(dict[str, object], json.loads(self.capture_bytes))
        batches = cast(list[dict[str, object]], payload["batches"])
        return {
            (cast(str, batch["phase"]), cast(int, batch["batch_index"])): cast(
                dict[str, object], batch["call"]
            )
            for batch in batches
        }


def _validated_worker_draft_bytes(
    snapshot: FrontierCandidateSnapshot,
    captured_calls: dict[tuple[str, int], dict[str, object]],
) -> bytes:
    response = snapshot.response
    attention = response.presentation_trace
    offered = tuple(item.item_id for item in snapshot.request.items)
    fragments = tuple(packet.fragment_id for packet in snapshot.request.evidence_packets)
    if (
        response.ranking_source != "laya"
        or response.cache_hit
        or not response.coverage_complete
        or attention is None
        or attention.ranked_probe_ids != response.ranked_item_ids
        or len(attention.considered_probe_ids) != len(offered)
        or set(attention.considered_probe_ids) != set(offered)
        or response.considered_item_ids != offered
        or not 1 <= len(attention.microbatches) <= 32
        or len(captured_calls) != len(attention.microbatches)
    ):
        raise ValueError("frontier worker draft requires full uncached Laya coverage")
    batches: list[dict[str, object]] = []
    actual_ids: dict[str, list[str]] = {"evidence": [], "probe": []}
    expected_index = {"evidence": 0, "probe": 0}
    probe_started = False
    for batch in attention.microbatches:
        phase, index = batch.phase, batch.batch_index
        if index != expected_index[phase] or (phase == "evidence" and probe_started):
            raise ValueError("frontier worker draft batch order is invalid")
        expected_index[phase] += 1
        probe_started |= phase == "probe"
        call = captured_calls.get((phase, index))
        if (
            batch.cache_hit_ids
            or batch.cached_origins
            or batch.inference_ids != batch.candidate_ids
            or batch.worker_presentation is None
            or not isinstance(call, dict)
            or type(call.get("schema_version")) is not int
            or call.get("schema_version") != 2
        ):
            raise ValueError("frontier worker draft needs exact uncached schema-2 model input")
        _verify_exact_worker_capture(call, batch.worker_presentation)
        model_input_sha256 = getattr(batch.worker_presentation, "model_input_sha256", None)
        if model_input_sha256 is None or model_input_sha256 != _worker_model_input_sha256(
            call["model_input"]
        ):
            raise ValueError("frontier worker model input digest differs from presentation")
        questions = cast(list[dict[str, object]], call["questions"])
        presented_ids = tuple(
            dict.fromkeys(cast(str, question["item_id"]) for question in questions)
        )
        if presented_ids != batch.candidate_ids:
            raise ValueError("frontier worker draft questions differ from batch identity")
        actual_ids[phase].extend(batch.candidate_ids)
        batches.append({"phase": phase, "batch_index": index, "call": call})
    if (
        tuple(actual_ids["evidence"]) != fragments
        or tuple(actual_ids["probe"]) != offered
        or set(captured_calls)
        != {(batch.phase, batch.batch_index) for batch in attention.microbatches}
    ):
        raise ValueError("frontier worker draft coverage is incomplete")
    try:
        raw = _worker_ordered_json_bytes(
            {"schema_version": 1, "snapshot_id": snapshot.snapshot_id, "batches": batches}
        )
    except (TypeError, ValueError) as error:
        raise ValueError("frontier worker draft is not canonical JSON") from error
    if len(raw) > _MAX_WORKER_DRAFT_BYTES:
        raise ValueError("frontier worker draft exceeds local byte bound")
    return raw


@dataclass(frozen=True, slots=True)
class CandidateSnapshotSelection:
    snapshot_id: str
    candidate_id: str
    case_id: CaseId
    epoch_state_version: int
    invocation_sha256: str
    dispatch_authorized: bool = False


@dataclass(frozen=True, slots=True)
class CandidateExecutionLink:
    snapshot_id: str
    candidate_id: str
    execution_id: str
    case_id: CaseId
    epoch_state_version: int
    executed_invocation: ProbeInvocation
    # The current runner may consume validated parameters rather than the full
    # invocation metadata; this is coordinator custody, not host-use proof.
    runner_consumption_proven: bool = False
    same_transaction_insert_proven: bool = False


class CandidateDecisionSnapshotRepository:
    def __init__(self, store: SQLiteStore, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock

    def capture_frontier(
        self,
        request: FrontierRankRequestV1,
        response: FrontierRankResponseV1,
        *,
        registry: CaseCandidateRegistry | None,
        retriever: EvidenceRetriever,
        frontier: SearchFrontierRepository,
        catalog_entries: tuple[EvidenceCatalogEntry, ...],
        candidate_refs: tuple[AdmittedCandidateRefV1, ...],
        selected_item_id: str,
        epoch_state_version: int,
        request_frozen_at: datetime,
        packet_receipt_id: str | None = None,
    ) -> FrontierCandidateSnapshot:
        """Freeze the selected ranked kind and every registered measurement row."""

        response.validate_against(request)
        # Semantic packet shape alone does not prove the packet is the exact
        # projection of a current case-evidence row. Until that readset is
        # source-bound, measurement custody must not offer such packets.
        if request.evidence_packets and packet_receipt_id is None:
            raise ValueError("frontier measurement evidence packets are not source-bound")
        from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository

        receipt_repo = FrontierPacketReceiptRepository(self._store)
        if packet_receipt_id is not None:
            receipt = receipt_repo.readback(packet_receipt_id)
            if (
                receipt.case_id != request.case_id
                or receipt.epoch_state_version != epoch_state_version
                or receipt.case_generation != request.items[0].versions.evidence
                or receipt.packets != request.evidence_packets
                or receipt.frozen_at > request_frozen_at
                or receipt.frozen_at >= request.deadline_at
            ):
                raise ValueError("frontier packet receipt does not match frozen request")
        # Reassemble every source, including retrieval items, from local custody.
        # This also checks the case evidence generation after inference.
        from systemsense.application.frontier_policy import assemble_frontier_request

        authoritative = assemble_frontier_request(
            case_id=request.case_id,
            items=request.items,
            versions=request.items[0].versions,
            symptom=request.symptom,
            hypothesis_briefs=request.hypothesis_briefs,
            deadline_at=request.deadline_at,
            provider=request.provider,
            model_weight_sha256=request.model_weight_sha256,
            catalog_entries=catalog_entries,
            candidate_refs=candidate_refs,
            candidate_registry=registry,
            candidate_epoch=epoch_state_version,
            store=self._store,
            retriever=retriever,
            frontier=frontier,
            evidence_packets=request.evidence_packets,
            allow_evidence_generation_advance=packet_receipt_id is not None
            and all(item.reference.kind == "measure" for item in request.items),
        )
        if authoritative != request:
            raise ValueError("frontier source changed or request is unauthenticated")
        frozen_at = _utc(request_frozen_at.isoformat())
        captured_at = _utc(self._clock().isoformat())
        selected = next((item for item in request.items if item.item_id == selected_item_id), None)
        candidate_ids = tuple(
            item.reference.candidate_id
            for item in request.items
            if item.reference.kind == "measure"
        )
        if (
            selected is None
            or response.ranked_item_ids[0] != selected_item_id
            or len(candidate_ids) != len(candidate_refs)
            or candidate_ids != tuple(item.candidate_id for item in candidate_refs)
            or not frozen_at <= captured_at < request.deadline_at
        ):
            raise ValueError("frontier snapshot selection or chronology is invalid")
        snapshot_id = f"frontier_decision_snapshot_{uuid4().hex}"
        request_json = _canonical(request.model_dump(mode="json"))
        response_json = _canonical(response.model_dump(mode="json"))
        candidates_json = _canonical([item.model_dump(mode="json") for item in candidate_refs])
        with self._store.transaction():
            case = self._store.case(str(request.case_id))
            if (
                case is None
                or case.status != "collecting"
                or case.state_version != epoch_state_version
            ):
                raise ValueError("frontier snapshot case epoch is stale")
            refs = self._registry_refs_for(
                candidate_refs, request.case_id, epoch_state_version, frozen_at
            )
            self._store.connection.execute(
                "INSERT INTO candidate_decision_snapshots ("
                + ",".join(_SNAPSHOT_COLUMNS)
                + ") VALUES ("
                + ",".join("?" for _ in _SNAPSHOT_COLUMNS)
                + ")",
                (
                    snapshot_id,
                    2,
                    "frontier-rank-json-v1",
                    str(request.case_id),
                    epoch_state_version,
                    selected_item_id,
                    frozen_at.isoformat(),
                    captured_at.isoformat(),
                    request_json,
                    _digest(request_json),
                    response_json,
                    _digest(response_json),
                    _canonical(candidate_ids),
                    _digest(candidates_json),
                    _canonical(refs),
                    _digest(_canonical(refs)),
                ),
            )
            if packet_receipt_id is not None:
                receipt_repo.bind_snapshot(packet_receipt_id, snapshot_id)
            return self.readback_frontier(snapshot_id)

    def readback_frontier(self, snapshot_id: str) -> FrontierCandidateSnapshot:
        row = self._store.connection.execute(
            "SELECT "
            + ",".join(_SNAPSHOT_COLUMNS)
            + " FROM candidate_decision_snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            raise ValueError("frontier decision snapshot is unavailable")
        data = dict(zip(_SNAPSHOT_COLUMNS, row, strict=True))
        if (
            int(data["schema_version"]) != 2
            or data["serializer_version"] != "frontier-rank-json-v1"
            or re.fullmatch(r"frontier_decision_snapshot_[0-9a-f]{32}", snapshot_id) is None
        ):
            raise ValueError("frontier decision snapshot version is unsupported")
        request_json, response_json = str(data["request_json"]), str(data["response_json"])
        if (
            _digest(request_json) != data["request_sha256"]
            or _digest(response_json) != data["response_sha256"]
        ):
            raise ValueError("frontier decision snapshot digest mismatch")
        try:
            request = FrontierRankRequestV1.model_validate_json(request_json)
            response = FrontierRankResponseV1.model_validate_json(response_json)
            response.validate_against(request)
            candidate_ids = json.loads(str(data["candidate_ids_json"]))
            refs = json.loads(str(data["registry_refs_json"]))
            frozen_at = _utc(str(data["request_frozen_at"]))
            captured_at = _utc(str(data["captured_at"]))
            epoch = int(data["epoch_state_version"])
        except (TypeError, ValueError) as error:
            raise ValueError("frontier decision snapshot payload is invalid") from error
        selected_id = str(data["correlation_id"])
        from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository

        bound_receipt = FrontierPacketReceiptRepository(self._store).bound_receipt(snapshot_id)
        if request.evidence_packets and (
            bound_receipt is None
            or bound_receipt.case_id != request.case_id
            or bound_receipt.epoch_state_version != epoch
            or bound_receipt.case_generation != request.items[0].versions.evidence
            or bound_receipt.packets != request.evidence_packets
            or bound_receipt.frozen_at > frozen_at
        ):
            raise ValueError("frontier measurement evidence packets are not source-bound")
        if bound_receipt is not None and bound_receipt.packets != request.evidence_packets:
            raise ValueError("frontier packet binding differs from request")
        if bound_receipt is not None and any(
            item.reference.kind
            not in {"retrieve_evidence", "measure", "review_branch", "consult_deep"}
            for item in request.items
        ):
            raise ValueError("receipt-backed frontier snapshot contains unsupported item")
        selected = next((item for item in request.items if item.item_id == selected_id), None)
        measurement_ids = tuple(
            item.reference.candidate_id
            for item in request.items
            if item.reference.kind == "measure"
        )
        if (
            request_json != _canonical(request.model_dump(mode="json"))
            or response_json != _canonical(response.model_dump(mode="json"))
            or request.case_id != CaseId(root=str(data["case_id"]))
            or selected is None
            or response.ranked_item_ids[0] != selected_id
            or candidate_ids != list(measurement_ids)
            or str(data["candidate_ids_json"]) != _canonical(candidate_ids)
            or not frozen_at <= captured_at < request.deadline_at
        ):
            raise ValueError("frontier decision snapshot binding mismatch")
        candidates = tuple(
            self._candidate_ref_from_row(
                self._registry_row(str(candidate_id), request.case_id, epoch)
            )
            for candidate_id in measurement_ids
        )
        candidates_json = _canonical([item.model_dump(mode="json") for item in candidates])
        if (
            _digest(candidates_json) != data["candidate_manifest_sha256"]
            or refs != self._registry_refs_for(candidates, request.case_id, epoch, frozen_at)
            or str(data["registry_refs_json"]) != _canonical(refs)
            or _digest(_canonical(refs)) != data["registry_manifest_sha256"]
        ):
            raise ValueError("frontier decision registry custody mismatch")
        for item, semantic in zip(request.items, request.item_semantics, strict=True):
            if item.reference.kind == "retrieve_evidence":
                evidence_id = item.reference.evidence_id
                assert evidence_id is not None
                source_row = self._store.evidence(
                    case_id=str(request.case_id), evidence_id=str(evidence_id)
                )
                if source_row is None:
                    raise ValueError("frontier retrieval source is no longer verifiable")
                record = EvidenceRecord.model_validate_json(source_row.record_json)
                entry = EvidenceCatalogEntry(
                    evidence_id=evidence_id,
                    case_id=request.case_id,
                    observed_at=record.observed_at,
                    captured_at=record.captured_at,
                    collector_id=record.collector.id,
                    source_id=record.source.source_id,
                    summary=record.summary[:240],
                )
                from systemsense.application.frontier_policy import (
                    _evidence_semantic,  # pyright: ignore[reportPrivateUsage]
                )

                if semantic != _evidence_semantic(item=item, entry=entry, store=self._store):
                    raise ValueError("frontier retrieval semantic source differs from evidence")
                continue
            if item.reference.kind == "review_branch":
                from systemsense.application.frontier_policy import (
                    _branch_semantic,  # pyright: ignore[reportPrivateUsage]
                )

                if semantic != _branch_semantic(item=item, store=self._store):
                    raise ValueError("frontier branch semantic source differs from graph")
                continue
            if item.reference.kind == "consult_deep":
                from systemsense.application.frontier_policy import (
                    _deep_question_semantic,  # pyright: ignore[reportPrivateUsage]
                )

                if semantic != _deep_question_semantic(
                    item=item, store=self._store, requested_symptom=request.symptom
                ):
                    raise ValueError("frontier deep semantic source differs from case")
                continue
            if item.reference.kind != "measure":
                raise ValueError("frontier snapshot contains unsupported source kind")
            candidate_id = item.reference.candidate_id
            assert candidate_id is not None
            candidate = next(ref for ref in candidates if ref.candidate_id == candidate_id)
            row_data = self._registry_row(candidate_id, request.case_id, epoch)
            invocation = ProbeInvocation.model_validate_json(str(row_data["invocation_json"]))
            record = CandidateRecord.model_validate(
                {"schema_version": 1, **candidate.model_dump(mode="json")}
            )
            from systemsense.application.frontier_policy import (
                _candidate_semantic_from_resolution,  # pyright: ignore[reportPrivateUsage]
            )

            expected_semantic = _candidate_semantic_from_resolution(
                item=item, candidate=record, invocation=invocation
            )
            if (
                item.cost_ms != candidate.cost_ms
                or item.reference.window != invocation.window
                or semantic != expected_semantic
            ):
                raise ValueError("frontier semantic source differs from registry")
        candidate_id = selected.reference.candidate_id
        if selected.reference.kind == "measure" and candidate_id is None:
            raise ValueError("frontier measurement lacks registered candidate")
        return FrontierCandidateSnapshot(
            snapshot_id,
            request.case_id,
            epoch,
            frozen_at,
            captured_at,
            request,
            response,
            selected_id,
            candidate_id,
            candidates,
            selected.reference.kind,
        )

    def capture_frontier_worker_draft(
        self,
        snapshot_id: str,
        captured_calls: dict[tuple[str, int], dict[str, object]],
    ) -> FrontierWorkerCaptureDraft:
        """Bind opt-in worker tensors to a frozen Laya snapshot, without review claims."""

        snapshot = self.readback_frontier(snapshot_id)
        capture_bytes = _validated_worker_draft_bytes(snapshot, captured_calls)
        captured_at = _utc(self._clock().isoformat())
        if captured_at < snapshot.captured_at:
            raise ValueError("worker draft capture precedes its frontier snapshot")
        with self._store.transaction():
            self._store.connection.execute(
                "INSERT INTO frontier_worker_capture_drafts "
                "(snapshot_id,schema_version,case_id,capture_bytes,capture_sha256,captured_at,"
                "privacy_review_status,training_admissible) VALUES (?,1,?,?,?,?, 'unreviewed',0)",
                (
                    snapshot_id,
                    str(snapshot.case_id),
                    capture_bytes,
                    hashlib.sha256(capture_bytes).hexdigest(),
                    captured_at.isoformat(),
                ),
            )
            return self.readback_frontier_worker_draft(snapshot_id)

    def readback_frontier_worker_draft(self, snapshot_id: str) -> FrontierWorkerCaptureDraft:
        """Recheck the immutable bytes and full worker presentation against custody."""

        row = self._store.connection.execute(
            "SELECT schema_version,case_id,capture_bytes,capture_sha256,captured_at,"
            "privacy_review_status,training_admissible "
            "FROM frontier_worker_capture_drafts WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            raise ValueError("frontier worker draft is unavailable")
        version, case_id, raw, digest, time_text, review, admitted = row
        if (
            version != 1
            or not isinstance(raw, bytes)
            or not 1 <= len(raw) <= _MAX_WORKER_DRAFT_BYTES
            or digest != hashlib.sha256(raw).hexdigest()
            or review != "unreviewed"
            or admitted != 0
        ):
            raise ValueError("frontier worker draft digest or status is invalid")
        snapshot = self.readback_frontier(snapshot_id)
        if case_id != str(snapshot.case_id):
            raise ValueError("frontier worker draft case binding differs from snapshot")
        try:
            payload: object = json.loads(raw)
            if not isinstance(payload, dict) or set(cast(dict[str, object], payload)) != {
                "schema_version",
                "snapshot_id",
                "batches",
            }:
                raise ValueError("frontier worker draft payload is invalid")
            typed = cast(dict[str, object], payload)
            batches = typed["batches"]
            if (
                typed["schema_version"] != 1
                or typed["snapshot_id"] != snapshot_id
                or not isinstance(batches, list)
            ):
                raise ValueError("frontier worker draft binding is invalid")
            calls: dict[tuple[str, int], dict[str, object]] = {}
            for item in cast(list[object], batches):
                if not isinstance(item, dict) or set(cast(dict[str, object], item)) != {
                    "phase",
                    "batch_index",
                    "call",
                }:
                    raise ValueError("frontier worker draft batch is invalid")
                batch = cast(dict[str, object], item)
                phase, index, call = batch["phase"], batch["batch_index"], batch["call"]
                if (
                    phase not in {"evidence", "probe"}
                    or type(index) is not int
                    or not isinstance(call, dict)
                    or (phase, index) in calls
                ):
                    raise ValueError("frontier worker draft batch identity is invalid")
                calls[(cast(str, phase), index)] = cast(dict[str, object], call)
            if raw != _validated_worker_draft_bytes(snapshot, calls):
                raise ValueError("frontier worker draft bytes differ from canonical presentation")
            captured_at = _utc(str(time_text))
        except (UnicodeDecodeError, TypeError, ValueError) as error:
            raise ValueError("frontier worker draft payload or presentation is invalid") from error
        if captured_at < snapshot.captured_at:
            raise ValueError("frontier worker draft chronology is invalid")
        return FrontierWorkerCaptureDraft(
            snapshot_id=snapshot_id,
            case_id=snapshot.case_id,
            capture_bytes=raw,
            capture_sha256=str(digest),
            captured_at=captured_at,
        )

    def capture(
        self,
        request: CandidateDecisionRequestV1,
        response: CandidateDecisionResponseV1 | CandidateDecisionGapV1,
        *,
        request_frozen_at: datetime,
    ) -> CandidateDecisionSnapshot:
        """Freeze exact ordered request, validated response, and private registry rows."""

        response.validate_against(request)
        captured_at = _utc(self._clock().isoformat())
        if _utc(request_frozen_at.isoformat()) > captured_at:
            raise ValueError("candidate request freeze time follows capture")
        if isinstance(response, CandidateDecisionResponseV1) and captured_at >= request.deadline_at:
            raise ValueError("candidate decision response arrived after its deadline")
        request_json = candidate_decision_request_json(request)
        response_json = _canonical(response.model_dump(mode="json"))
        candidate_ids = tuple(item.candidate_id for item in request.available_candidates)
        snapshot_id = f"candidate_decision_snapshot_{uuid4().hex}"
        with self._store.transaction():
            case = self._store.case(str(request.case_id))
            if (
                case is None
                or case.state_version != request.state_version
                or (
                    isinstance(response, CandidateDecisionResponseV1)
                    and case.status != "collecting"
                )
            ):
                raise ValueError("candidate snapshot case epoch is stale")
            refs = self._registry_refs(request, request_frozen_at)
            self._store.connection.execute(
                "INSERT INTO candidate_decision_snapshots ("
                + ",".join(_SNAPSHOT_COLUMNS)
                + ") VALUES ("
                + ",".join("?" for _ in _SNAPSHOT_COLUMNS)
                + ")",
                (
                    snapshot_id,
                    1,
                    _SERIALIZER,
                    str(request.case_id),
                    request.state_version,
                    request.correlation_id,
                    request_frozen_at.isoformat(),
                    captured_at.isoformat(),
                    request_json,
                    _digest(request_json),
                    response_json,
                    _digest(response_json),
                    _canonical(candidate_ids),
                    request.candidate_manifest_sha256,
                    _canonical(refs),
                    _digest(_canonical(refs)),
                ),
            )
            return self.readback(snapshot_id)

    def readback(self, snapshot_id: str) -> CandidateDecisionSnapshot:
        row = self._store.connection.execute(
            "SELECT "
            + ",".join(_SNAPSHOT_COLUMNS)
            + " FROM candidate_decision_snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            raise ValueError("candidate decision snapshot is unavailable")
        data = dict(zip(_SNAPSHOT_COLUMNS, row, strict=True))
        if (
            data["schema_version"] != 1
            or data["serializer_version"] != _SERIALIZER
            or not re.fullmatch(r"candidate_decision_snapshot_[0-9a-f]{32}", snapshot_id)
        ):
            raise ValueError("candidate decision snapshot version is unsupported")
        request_json, response_json = str(data["request_json"]), str(data["response_json"])
        if (
            _digest(request_json) != data["request_sha256"]
            or _digest(response_json) != data["response_sha256"]
        ):
            raise ValueError("candidate decision snapshot digest mismatch")
        try:
            request = CandidateDecisionRequestV1.model_validate_json(request_json)
            parsed_response: object = json.loads(response_json)
            if not isinstance(parsed_response, dict):
                raise ValueError("response must be an object")
            response_payload = cast("dict[str, object]", parsed_response)
            response = (
                CandidateDecisionGapV1.model_validate_json(response_json)
                if response_payload.get("response_kind") == "candidate_decision_gap_v1"
                else CandidateDecisionResponseV1.model_validate_json(response_json)
            )
            response.validate_against(request)
            candidate_ids: object = json.loads(str(data["candidate_ids_json"]))
            refs: object = json.loads(str(data["registry_refs_json"]))
        except (TypeError, ValueError) as error:
            raise ValueError("candidate decision snapshot payload is invalid") from error
        if (
            request_json != candidate_decision_request_json(request)
            or response_json != _canonical(response.model_dump(mode="json"))
            or request.case_id != CaseId(root=str(data["case_id"]))
            or request.state_version != int(data["epoch_state_version"])
            or request.correlation_id != data["correlation_id"]
            or candidate_ids != [item.candidate_id for item in request.available_candidates]
            or str(data["candidate_ids_json"]) != _canonical(candidate_ids)
            or data["candidate_manifest_sha256"] != request.candidate_manifest_sha256
        ):
            raise ValueError("candidate decision snapshot binding mismatch")
        frozen_at, captured_at = (
            _utc(str(data["request_frozen_at"])),
            _utc(str(data["captured_at"])),
        )
        if frozen_at > captured_at or not isinstance(refs, list):
            raise ValueError("candidate decision snapshot chronology or registry refs invalid")
        refs = cast("list[object]", refs)
        expected_refs = self._registry_refs(request, frozen_at)
        if (
            refs != expected_refs
            or str(data["registry_refs_json"]) != _canonical(refs)
            or _digest(_canonical(refs)) != data["registry_manifest_sha256"]
        ):
            raise ValueError("candidate decision registry custody mismatch")
        return CandidateDecisionSnapshot(
            snapshot_id=snapshot_id,
            case_id=request.case_id,
            epoch_state_version=request.state_version,
            request_frozen_at=frozen_at,
            captured_at=captured_at,
            request=request,
            response=response,
            request_sha256=str(data["request_sha256"]),
            response_sha256=str(data["response_sha256"]),
            candidate_ids=tuple(cast("list[str]", candidate_ids)),
            registry_manifest_sha256=str(data["registry_manifest_sha256"]),
        )

    def verify_selection(
        self,
        snapshot_id: str,
        case_id: CaseId,
        epoch_state_version: int,
        candidate_id: str,
        invocation_sha256: str,
    ) -> CandidateSnapshotSelection:
        """Verify frozen model proposal; caller must separately resolve and admit work."""

        if snapshot_id.startswith("frontier_decision_snapshot_"):
            snapshot = self.readback_frontier(snapshot_id)
            case = self._store.case(str(case_id))
            if (
                snapshot.case_id != case_id
                or snapshot.epoch_state_version != epoch_state_version
                or snapshot.candidate_id != candidate_id
                or case is None
                or case.status != "collecting"
                or case.state_version != epoch_state_version
                or _utc(self._clock().isoformat()) >= snapshot.request.deadline_at
            ):
                raise ValueError("frontier selection is not current")
            current_generation = (
                EvidenceRetriever(self._store)
                .discover(EvidenceCatalogQuery(case_id=case_id, limit=1))
                .case_evidence_generation
            )
            from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository

            bound_receipt = FrontierPacketReceiptRepository(self._store).bound_receipt(snapshot_id)
            if bound_receipt is None and any(
                item.versions.evidence != current_generation for item in snapshot.request.items
            ):
                raise ValueError("frontier evidence generation changed")
            candidate = next(
                ref for ref in snapshot.candidate_refs if ref.candidate_id == candidate_id
            )
            if candidate.invocation_sha256 != invocation_sha256:
                raise ValueError("frontier selection invocation digest mismatch")
            return CandidateSnapshotSelection(
                snapshot_id, candidate_id, case_id, epoch_state_version, invocation_sha256
            )
        return self._verify_selection_binding(
            snapshot_id,
            case_id,
            epoch_state_version,
            candidate_id,
            invocation_sha256,
            require_current_deadline=True,
        )

    def _verify_selection_binding(
        self,
        snapshot_id: str,
        case_id: CaseId,
        epoch_state_version: int,
        candidate_id: str,
        invocation_sha256: str,
        *,
        require_current_deadline: bool,
    ) -> CandidateSnapshotSelection:
        """A finished run uses its start time, not link time, for deadline proof."""

        snapshot = self.readback(snapshot_id)
        case = self._store.case(str(case_id))
        if (
            snapshot.case_id != case_id
            or snapshot.epoch_state_version != epoch_state_version
            or case is None
            or case.state_version != epoch_state_version
            or case.status != "collecting"
            or (
                require_current_deadline
                and _utc(self._clock().isoformat()) >= snapshot.request.deadline_at
            )
            or not isinstance(snapshot.response, CandidateDecisionResponseV1)
            or candidate_id not in (item.candidate_id for item in snapshot.response.proposals)
        ):
            raise ValueError("candidate selection is not a current frozen proposal")
        ref = next(
            item
            for item in snapshot.request.available_candidates
            if item.candidate_id == candidate_id
        )
        if ref.invocation_sha256 != invocation_sha256:
            raise ValueError("candidate selection invocation digest mismatch")
        return CandidateSnapshotSelection(
            snapshot_id, candidate_id, case_id, epoch_state_version, invocation_sha256
        )

    def link_execution(
        self,
        snapshot_id: str,
        candidate_id: str,
        execution_id: str,
        executed_invocation: ProbeInvocation,
    ) -> None:
        """Associate a persisted run with a candidate.

        Runtime must call this in the same transaction as execution insertion.
        SQLite transaction liveness alone cannot attest that caller ordering.
        """

        if not self._store.connection.in_transaction:
            raise ValueError("candidate execution link requires caller-owned transaction")
        invocation_json = _invocation_json(executed_invocation)
        snapshot = (
            self.readback_frontier(snapshot_id)
            if snapshot_id.startswith("frontier_decision_snapshot_")
            else self.readback(snapshot_id)
        )
        if isinstance(snapshot, FrontierCandidateSnapshot):
            if snapshot.candidate_id != candidate_id or not any(
                item.candidate_id == candidate_id
                and item.invocation_sha256 == _digest(invocation_json)
                for item in snapshot.candidate_refs
            ):
                raise ValueError("frontier execution differs from selected candidate")
        else:
            self._verify_selection_binding(
                snapshot_id,
                snapshot.case_id,
                snapshot.epoch_state_version,
                candidate_id,
                _digest(invocation_json),
                require_current_deadline=False,
            )
        registry = self._registry_row(candidate_id, snapshot.case_id, snapshot.epoch_state_version)
        if registry["invocation_json"] != invocation_json:
            raise ValueError("executed invocation differs from frozen registry candidate")
        execution = self._store.connection.execute(
            "SELECT case_id,probe_id,probe_version,parameters_json,state_version,"
            "started_at,finished_at "
            "FROM probe_executions WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
        if execution is None or execution[6] is None:
            raise ValueError("candidate execution must be persisted and finished")
        try:
            parameters: object = json.loads(str(execution[3]))
            started, finished = _utc(str(execution[5])), _utc(str(execution[6]))
        except (TypeError, ValueError) as error:
            raise ValueError("candidate execution payload is invalid") from error
        if (
            str(execution[0]) != str(snapshot.case_id)
            or str(execution[1]) != executed_invocation.probe_id
            or int(execution[2]) != executed_invocation.probe_version
            or parameters != executed_invocation.parameters
            or int(execution[4]) != snapshot.epoch_state_version
            or not snapshot.captured_at <= started < snapshot.request.deadline_at
            or not started <= finished
        ):
            raise ValueError("candidate execution does not match selected invocation")
        self._store.connection.execute(
            "INSERT INTO candidate_decision_execution_links ("
            "snapshot_id,candidate_id,execution_id,case_id,epoch_state_version,"
            "executed_invocation_json,executed_invocation_sha256,linked_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                snapshot_id,
                candidate_id,
                execution_id,
                str(snapshot.case_id),
                snapshot.epoch_state_version,
                invocation_json,
                _digest(invocation_json),
                _utc(self._clock().isoformat()).isoformat(),
            ),
        )

    def execution_links(self, snapshot_id: str) -> tuple[CandidateExecutionLink, ...]:
        snapshot = (
            self.readback_frontier(snapshot_id)
            if snapshot_id.startswith("frontier_decision_snapshot_")
            else self.readback(snapshot_id)
        )
        rows = self._store.connection.execute(
            "SELECT candidate_id,execution_id,case_id,epoch_state_version,"
            "executed_invocation_json,executed_invocation_sha256,linked_at "
            "FROM candidate_decision_execution_links WHERE snapshot_id=? "
            "ORDER BY linked_at,execution_id",
            (snapshot_id,),
        ).fetchall()
        links: list[CandidateExecutionLink] = []
        for row in rows:
            invocation_json = str(row[4])
            try:
                invocation = ProbeInvocation.model_validate_json(invocation_json)
            except ValueError as error:
                raise ValueError("candidate execution invocation is invalid") from error
            registry = self._registry_row(
                str(row[0]), snapshot.case_id, snapshot.epoch_state_version
            )
            execution = self._store.connection.execute(
                "SELECT case_id,probe_id,probe_version,parameters_json,state_version,"
                "started_at,finished_at "
                "FROM probe_executions WHERE execution_id=?",
                (str(row[1]),),
            ).fetchone()
            if execution is None or execution[6] is None:
                raise ValueError("candidate execution link has no finished execution")
            try:
                params: object = json.loads(str(execution[3]))
            except (TypeError, ValueError) as error:
                raise ValueError("candidate execution parameters invalid") from error
            if (
                str(row[2]) != str(snapshot.case_id)
                or int(row[3]) != snapshot.epoch_state_version
                or invocation_json != _invocation_json(invocation)
                or _digest(invocation_json) != row[5]
                or registry["invocation_json"] != invocation_json
                or str(execution[0]) != str(snapshot.case_id)
                or str(execution[1]) != invocation.probe_id
                or int(execution[2]) != invocation.probe_version
                or params != invocation.parameters
                or int(execution[4]) != snapshot.epoch_state_version
                or not snapshot.captured_at <= _utc(str(execution[5])) <= _utc(str(execution[6]))
                or _utc(str(row[6])) < _utc(str(execution[6]))
                or (
                    str(row[0]) != snapshot.candidate_id
                    if isinstance(snapshot, FrontierCandidateSnapshot)
                    else not isinstance(snapshot.response, CandidateDecisionResponseV1)
                    or str(row[0])
                    not in (item.candidate_id for item in snapshot.response.proposals)
                )
            ):
                raise ValueError("candidate execution link binding mismatch")
            links.append(
                CandidateExecutionLink(
                    snapshot_id,
                    str(row[0]),
                    str(row[1]),
                    snapshot.case_id,
                    snapshot.epoch_state_version,
                    invocation,
                )
            )
        return tuple(links)

    @staticmethod
    def _candidate_ref_from_row(row: dict[str, object]) -> AdmittedCandidateRefV1:
        return AdmittedCandidateRefV1(
            candidate_id=str(row["candidate_id"]),
            probe_id=str(row["probe_id"]),
            description=str(row["description"]),
            manifest_sha256=str(row["manifest_sha256"]),
            invocation_sha256=str(row["invocation_sha256"]),
            cost_ms=int(str(row["cost_ms"])),
            resource_class=ResourceClass(str(row["resource_class"])),
            safety_class=SafetyClass(str(row["safety_class"])),
        )

    def _registry_refs(
        self, request: CandidateDecisionRequestV1, frozen_at: datetime
    ) -> list[dict[str, str]]:
        return self._registry_refs_for(
            request.available_candidates, request.case_id, request.state_version, frozen_at
        )

    def _registry_refs_for(
        self,
        candidates: tuple[AdmittedCandidateRefV1, ...],
        case_id: CaseId,
        epoch: int,
        frozen_at: datetime,
    ) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        for candidate in candidates:
            row = self._registry_row(candidate.candidate_id, case_id, epoch)
            try:
                invocation_json = str(row["invocation_json"])
                invocation = ProbeInvocation.model_validate_json(invocation_json)
            except ValueError as error:
                raise ValueError("candidate registry invocation is invalid") from error
            expected = self._candidate_ref_from_row(row)
            if (
                expected != candidate
                or int(str(row["schema_version"])) != 1
                or invocation_json != _invocation_json(invocation)
                or _digest(invocation_json) != row["invocation_sha256"]
                or invocation.probe_id != row["probe_id"]
                or invocation.probe_version != int(str(row["manifest_version"]))
                or invocation.observable != row["observable"]
                or invocation.target_handle != row["target_handle"]
                or _digest(str(row["dependency_bindings_json"])) != row["dependency_sha256"]
                or not _utc(str(row["issued_at"])) <= frozen_at < _utc(str(row["expires_at"]))
            ):
                raise ValueError("candidate reference differs from frozen registry row")
            refs.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "registry_row_sha256": _digest(_canonical(row)),
                }
            )
        return refs

    def _registry_row(self, candidate_id: str, case_id: CaseId, epoch: int) -> dict[str, object]:
        row = self._store.connection.execute(
            "SELECT "
            + ",".join(_REGISTRY_COLUMNS)
            + " FROM case_measurement_candidates WHERE candidate_id=? AND case_id=? "
            "AND epoch_state_version=?",
            (candidate_id, str(case_id), epoch),
        ).fetchone()
        if row is None:
            raise ValueError("candidate is absent from the frozen case registry")
        return dict(zip(_REGISTRY_COLUMNS, row, strict=True))
