"""Exact worker-call drafts are local custody, not reviewed training examples."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest

from systemsense.application.frontier_policy import assemble_frontier_request, run_frontier_step
from systemsense.application.investigator import Investigator
from systemsense.domain.ids import EntityId
from systemsense.domain.time import utc_now
from systemsense.evidence.graph import AssertionStatus, EvidenceRelation, MemoryLayer, RelationKind
from systemsense.evidence.retrieval import (
    EvidenceCatalogQuery,
    EvidenceRelationRepository,
)
from systemsense.storage.candidate_decision_snapshots import (
    CandidateDecisionSnapshotRepository,
    _validated_worker_draft_bytes,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.search_frontier import FrontierReferenceV1
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_frontier_policy import (
    CASE,
    EPOCH,
    MODEL_SHA,
    PROVIDER,
    _branch_reference,  # pyright: ignore[reportPrivateUsage]
    _candidate_fixture,  # pyright: ignore[reportPrivateUsage]
    _issued_candidates,  # pyright: ignore[reportPrivateUsage]
    _ranker,  # pyright: ignore[reportPrivateUsage]
    _versions,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.evaluation.test_frontier_pilot_export import (
    _fixture_worker_capture,  # pyright: ignore[reportPrivateUsage]
    _snapshots,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.parametrize("kind", ["retrieve_evidence", "review_branch", "consult_deep"])
def test_exact_worker_draft_custody_for_nonmeasurement_selection(
    tmp_path: Path, kind: Literal["retrieve_evidence", "review_branch", "consult_deep"]
) -> None:
    with SQLiteStore(tmp_path / f"{kind}.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        checkpoint = store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(CASE),)
        ).fetchone()
        assert checkpoint is not None
        state = json.loads(str(checkpoint[0]))
        now = utc_now()
        state.update(
            objective="Game stutters",
            created_at=(now - timedelta(seconds=10)).isoformat(),
            updated_at=now.isoformat(),
            incident_start=(now - timedelta(minutes=1)).isoformat(),
            incident_end=now.isoformat(),
        )
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
            (json.dumps(state), str(CASE)),
        )
        candidate = _issued_candidates(registry)[0]
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        relation = EvidenceRelation(
            relation_id="rel_" + "a" * 32,
            source_entity_id=EntityId(root="entity_" + "1" * 32),
            target_entity_id=EntityId(root="entity_" + "2" * 32),
            relationship=RelationKind.USES_DRIVER,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(entry.evidence_id,),
        )
        EvidenceRelationRepository(store).append(relation)
        versions = _versions(retriever)
        source = f"{CASE}|Game stutters|{versions.objective}|{versions.evidence}"
        references = {
            "retrieve_evidence": FrontierReferenceV1(
                kind="retrieve_evidence", evidence_id=entry.evidence_id
            ),
            "review_branch": _branch_reference(relation),
            "consult_deep": FrontierReferenceV1(
                kind="consult_deep",
                question_id="question_v1_" + hashlib.sha256(source.encode()).hexdigest()[:32],
            ),
            "measure": FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
        }
        ordered_kinds = (kind, *(value for value in references if value != kind))
        items = tuple(
            frontier.upsert_item(
                CASE,
                references[value],
                versions,
                cost_ms=candidate.cost_ms if value == "measure" else 0,
            )
            for value in ordered_kinds
        )
        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=CASE,
            epoch_state_version=EPOCH,
            evidence_ids=(entry.evidence_id,),
            expected_generation=versions.evidence or 0,
        )
        frozen_at = utc_now()
        request = assemble_frontier_request(
            case_id=CASE,
            items=items,
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=frozen_at + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(entry,),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            evidence_packets=receipt.packets,
        )
        attention, calls = _fixture_worker_capture(request)
        ranking = (
            _ranker()
            .rank(request)
            .model_copy(
                update={
                    "ranking_source": "laya",
                    "model_abstained": False,
                    "coverage_complete": True,
                    "degraded_reason": None,
                    "ranked_item_ids": tuple(item.item_id for item in items),
                    "considered_item_ids": tuple(item.item_id for item in items),
                    "attention_notes": attention.attention_notes,
                    "presentation_trace": attention,
                }
            )
        )
        repo = CandidateDecisionSnapshotRepository(store)
        captured: dict[tuple[str, int], dict[str, object]] = {}

        class CapturedRanker:
            def rank(self, _request: object, *, capture_worker_batch: Any) -> object:
                for batch in attention.microbatches:
                    assert batch.worker_presentation is not None
                    key = (batch.phase, batch.batch_index)
                    capture_worker_batch(*key, calls[key], batch.worker_presentation)
                return ranking

        def record_call(phase: str, index: int, call: dict[str, object], _proof: object) -> None:
            captured[(phase, index)] = call

        step = run_frontier_step(
            case_id=CASE,
            items=items,
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=request.deadline_at,
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(entry,),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            evidence_packets=receipt.packets,
            packet_receipt_id=receipt.receipt_id,
            ranker=cast(Any, CapturedRanker()),
            capture_worker_batch=record_call,
            capture_selected_draft=True,
        )
        assert step.snapshot_id is not None
        snapshot = repo.readback_frontier(step.snapshot_id)
        assert snapshot.selected_kind == kind
        assert snapshot.candidate_id is None
        assert len(snapshot.candidate_refs) == 1
        draft = repo.capture_frontier_worker_draft(snapshot.snapshot_id, captured)
        assert repo.readback_frontier_worker_draft(snapshot.snapshot_id) == draft
        assert draft.captured_calls == calls
        assert draft.training_admissible is False
        status_before_recovery = frontier.readback(step.selected.item_id).status
        Investigator._reconcile_frontier_candidate_claims(  # pyright: ignore[reportPrivateUsage]
            cast(Investigator, SimpleNamespace(store=store)), CASE
        )
        assert frontier.readback(step.selected.item_id).status is status_before_recovery


def test_optional_retrieval_snapshot_failure_does_not_block_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "optional-snapshot.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        versions = _versions(retriever)
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=entry.evidence_id),
            versions,
        )
        frozen_at = utc_now()
        request = assemble_frontier_request(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=frozen_at + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(entry,),
            candidate_refs=(),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
        )
        attention, _calls = _fixture_worker_capture(request)
        ranking = (
            _ranker()
            .rank(request)
            .model_copy(
                update={
                    "ranking_source": "laya",
                    "model_abstained": False,
                    "coverage_complete": True,
                    "degraded_reason": None,
                    "considered_item_ids": (item.item_id,),
                    "attention_notes": attention.attention_notes,
                    "presentation_trace": attention,
                }
            )
        )

        class Ranker:
            def rank(self, _request: object) -> object:
                return ranking

        def unavailable(*_args: object, **_kwargs: object) -> None:
            raise sqlite3.OperationalError("capture storage unavailable")

        monkeypatch.setattr(CandidateDecisionSnapshotRepository, "capture_frontier", unavailable)
        with pytest.warns(RuntimeWarning, match="pilot is incomplete"):
            step = run_frontier_step(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="Game stutters",
                hypothesis_briefs=(),
                deadline_at=request.deadline_at,
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(entry,),
                candidate_refs=(),
                candidate_registry=registry,
                candidate_epoch=EPOCH,
                store=store,
                retriever=retriever,
                frontier=frontier,
                ranker=cast(Any, Ranker()),
                capture_selected_draft=True,
                defer_retrieval_satisfaction=True,
            )
        assert step.snapshot_id is None
        assert step.retrieval is not None and step.retrieval.evidence is not None
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_snapshots"
        ).fetchone() == (0,)


def test_exact_frontier_worker_draft_round_trips_as_unreviewed_immutable_bytes(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "worker-drafts.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repo = CandidateDecisionSnapshotRepository(store)
        snapshot = repo.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)

        captured = repo.capture_frontier_worker_draft(snapshot_id, calls)
        readback = repo.readback_frontier_worker_draft(snapshot_id)
        assert readback == captured
        assert readback.training_admissible is False
        assert readback.privacy_review_status == "unreviewed"
        assert readback.captured_calls == calls
        assert readback.capture_bytes == json.dumps(
            json.loads(readback.capture_bytes),
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        with pytest.raises(sqlite3.IntegrityError):
            repo.capture_frontier_worker_draft(snapshot_id, calls)
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            store.connection.execute(
                "UPDATE frontier_worker_capture_drafts SET capture_sha256=? WHERE snapshot_id=?",
                ("0" * 64, snapshot_id),
            )
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            store.connection.execute(
                "DELETE FROM frontier_worker_capture_drafts WHERE snapshot_id=?", (snapshot_id,)
            )


def test_worker_draft_rejects_incomplete_or_nonexact_callbacks(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "worker-drafts.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repo = CandidateDecisionSnapshotRepository(store)
        snapshot = repo.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        missing = {key: call for key, call in calls.items() if key != ("probe", 0)}
        with pytest.raises(ValueError, match="coverage"):
            repo.capture_frontier_worker_draft(snapshot_id, missing)
        changed = {**calls, ("probe", 0): {**calls[("probe", 0)], "model_input": None}}
        with pytest.raises(ValueError, match="model input"):
            repo.capture_frontier_worker_draft(snapshot_id, changed)
        malformed = {**calls, ("probe", 0): cast(dict[str, object], 3)}
        with pytest.raises(ValueError, match="schema-2"):
            repo.capture_frontier_worker_draft(snapshot_id, malformed)
        assert store.connection.execute(
            "SELECT count(*) FROM frontier_worker_capture_drafts"
        ).fetchone() == (0,)


def test_worker_draft_rejects_shape_valid_token_substitution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "worker-draft-token-binding.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repo = CandidateDecisionSnapshotRepository(store)
        snapshot = repo.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        substituted = deepcopy(calls)
        model_input = cast(dict[str, object], substituted[("probe", 0)]["model_input"])
        token_rows = cast(list[list[int]], model_input["input_ids"])
        token_rows[0][0] += 1

        with pytest.raises(ValueError, match="model input digest"):
            repo.capture_frontier_worker_draft(snapshot_id, substituted)

        assert store.connection.execute(
            "SELECT count(*) FROM frontier_worker_capture_drafts"
        ).fetchone() == (0,)


def test_worker_draft_accepts_ranked_considered_ids_with_full_offered_coverage(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "worker-draft-considered-order.db") as store:
        first_id, second_id = _snapshots(store, laya=True)
        repo = CandidateDecisionSnapshotRepository(store)
        first = repo.readback_frontier(first_id)
        second = repo.readback_frontier(second_id)
        offered_items = (first.request.items[0], second.request.items[0])
        offered_ids = tuple(item.item_id for item in offered_items)
        request = first.request.model_copy(update={"items": offered_items})
        attention, calls = _fixture_worker_capture(request)
        ranked_ids = tuple(reversed(offered_ids))
        ranked_attention = attention.model_copy(
            update={"ranked_probe_ids": ranked_ids, "considered_probe_ids": ranked_ids}
        )
        response = first.response.model_copy(
            update={
                "ranked_item_ids": ranked_ids,
                "considered_item_ids": offered_ids,
                "presentation_trace": ranked_attention,
            }
        )
        combined = replace(first, request=request, response=response)

        raw = _validated_worker_draft_bytes(combined, calls)

        assert raw


def test_worker_draft_readback_detects_byte_tamper(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "worker-drafts.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repo = CandidateDecisionSnapshotRepository(store)
        snapshot = repo.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        repo.capture_frontier_worker_draft(snapshot_id, calls)
        store.connection.execute("DROP TRIGGER frontier_worker_capture_drafts_no_update")
        store.connection.execute(
            "UPDATE frontier_worker_capture_drafts SET capture_bytes=? WHERE snapshot_id=?",
            (b"{}", snapshot_id),
        )
        with pytest.raises(ValueError, match="digest"):
            repo.readback_frontier_worker_draft(snapshot_id)


def test_worker_draft_readback_rejects_rehashed_token_substitution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "worker-draft-rehashed-token.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repo = CandidateDecisionSnapshotRepository(store)
        snapshot = repo.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        repo.capture_frontier_worker_draft(snapshot_id, calls)
        row = store.connection.execute(
            "SELECT capture_bytes FROM frontier_worker_capture_drafts WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        assert row is not None
        payload = cast(dict[str, object], json.loads(bytes(row[0])))
        batches = cast(list[dict[str, object]], payload["batches"])
        probe = next(batch for batch in batches if batch["phase"] == "probe")
        call = cast(dict[str, object], probe["call"])
        model_input = cast(dict[str, object], call["model_input"])
        token_rows = cast(list[list[int]], model_input["input_ids"])
        token_rows[0][0] += 1
        changed = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        store.connection.execute("DROP TRIGGER frontier_worker_capture_drafts_no_update")
        store.connection.execute(
            "UPDATE frontier_worker_capture_drafts SET capture_bytes=?,capture_sha256=? "
            "WHERE snapshot_id=?",
            (changed, hashlib.sha256(changed).hexdigest(), snapshot_id),
        )

        with pytest.raises(ValueError, match="payload or presentation") as rejected:
            repo.readback_frontier_worker_draft(snapshot_id)
        assert rejected.value.__cause__ is not None
        assert "model input digest" in str(rejected.value.__cause__)


def test_migration_035_is_applied_to_existing_database(tmp_path: Path) -> None:
    database = tmp_path / "migrating-worker-drafts.db"
    with SQLiteStore(database) as store:
        assert store.schema_version() == 35
        store.connection.execute("DROP TRIGGER frontier_worker_capture_drafts_no_update")
        store.connection.execute("DROP TRIGGER frontier_worker_capture_drafts_no_delete")
        store.connection.execute("DROP TABLE frontier_worker_capture_drafts")
        store.connection.execute("PRAGMA user_version = 34")
    with SQLiteStore(database) as migrated:
        assert migrated.schema_version() == 35
        assert "frontier_worker_capture_drafts" in migrated.table_names()
