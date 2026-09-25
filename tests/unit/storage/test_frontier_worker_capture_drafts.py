"""Exact worker-call drafts are local custody, not reviewed training examples."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from systemsense.storage.candidate_decision_snapshots import (
    CandidateDecisionSnapshotRepository,
    _validated_worker_draft_bytes,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.evaluation.test_frontier_pilot_export import (
    _fixture_worker_capture,  # pyright: ignore[reportPrivateUsage]
    _snapshots,  # pyright: ignore[reportPrivateUsage]
)


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
