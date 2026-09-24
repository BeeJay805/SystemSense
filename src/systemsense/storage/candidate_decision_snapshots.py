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
    FrontierItemSemanticV1,
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
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.case_candidates import CandidateRecord, CaseCandidateRegistry
from systemsense.storage.search_frontier import SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore

_SERIALIZER = "candidate-decision-json-v1"
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
    candidate_id: str
    candidate_refs: tuple[AdmittedCandidateRefV1, ...]


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
        registry: CaseCandidateRegistry,
        retriever: EvidenceRetriever,
        frontier: SearchFrontierRepository,
        catalog_entries: tuple[EvidenceCatalogEntry, ...],
        candidate_refs: tuple[AdmittedCandidateRefV1, ...],
        selected_item_id: str,
        epoch_state_version: int,
        request_frozen_at: datetime,
        packet_receipt_id: str | None = None,
    ) -> FrontierCandidateSnapshot:
        """Freeze actual frontier bytes; only a ranked registered measurement qualifies."""

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
            or selected.reference.kind != "measure"
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
            item.reference.kind not in {"retrieve_evidence", "measure"} for item in request.items
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
            or selected.reference.kind != "measure"
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
            clipped = candidate.description[:170]
            limitations = ["registry_question_and_target_scope_not_recorded"]
            if len(candidate.description) > len(clipped):
                limitations.append("candidate_description_truncated_for_attention")
            expected_semantic = FrontierItemSemanticV1(
                item_id=item.item_id,
                case_id=request.case_id,
                reference_id=candidate_id,
                source_kind="capability_registry",
                source_record_sha256=_digest(_canonical(record.model_dump(mode="json"))),
                source_recorded_at=None,
                source_time_quality="not_available",
                quality="limited",
                limitations=tuple(limitations),
                information_goal=f"What would the registered measurement reveal: {clipped}?",
                target_scope="unknown",
                target_label="Registered measurement",
                measurement_window=invocation.window,
            )
            if (
                item.cost_ms != candidate.cost_ms
                or item.reference.window != invocation.window
                or semantic != expected_semantic
            ):
                raise ValueError("frontier semantic source differs from registry")
        candidate_id = selected.reference.candidate_id
        assert candidate_id is not None
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
