"""A fixture pilot exports custody, not inferred preference labels."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path

import pytest

from systemsense.application.frontier_policy import assemble_frontier_request
from systemsense.domain.ids import EvidenceId
from systemsense.domain.time import utc_now
from systemsense.evaluation.frontier_pilot_export import (
    FixtureOutcome,
    OutcomeStatus,
    PilotFixtureCase,
    export_frontier_fixture_pilot,
    snapshot_payload_sha256,
)
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.search_frontier import FrontierReferenceV1
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_frontier_policy import (
    CASE,
    EPOCH,
    MODEL_SHA,
    PROVIDER,
    _candidate_fixture,  # pyright: ignore[reportPrivateUsage]
    _issued_candidates,  # pyright: ignore[reportPrivateUsage]
    _ranker,  # pyright: ignore[reportPrivateUsage]
    _versions,  # pyright: ignore[reportPrivateUsage]
)


def _snapshots(store: SQLiteStore) -> tuple[str, str]:
    registry, retriever, frontier = _candidate_fixture(store)
    row = store.connection.execute(
        "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(CASE),)
    ).fetchone()
    assert row is not None
    state = json.loads(str(row[0]))
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
    versions = _versions(retriever)
    ids: list[str] = []
    for candidate in _issued_candidates(registry)[:2]:
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )
        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=CASE,
            epoch_state_version=EPOCH,
            evidence_ids=(EvidenceId(root="ev_" + "9" * 32),),
            expected_generation=versions.evidence or 0,
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
            catalog_entries=(),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            evidence_packets=receipt.packets,
        )
        snapshot = CandidateDecisionSnapshotRepository(store).capture_frontier(
            request,
            _ranker().rank(request),
            registry=registry,
            retriever=retriever,
            frontier=frontier,
            catalog_entries=(),
            candidate_refs=(candidate,),
            selected_item_id=item.item_id,
            epoch_state_version=EPOCH,
            request_frozen_at=frozen_at,
            packet_receipt_id=receipt.receipt_id,
        )
        ids.append(snapshot.snapshot_id)
    return ids[0], ids[1]


def _case(
    snapshot_id: str, payload_sha: str, *, outcome: OutcomeStatus = "unrun"
) -> PilotFixtureCase:
    oracle = hashlib.sha256(b"independent fixture oracle").hexdigest()
    return PilotFixtureCase(
        snapshot_id=snapshot_id,
        split="pilot_holdout",
        machine_group="fixture-machine-1",
        software_group="fixture-build-1",
        fault_family="fixture-pressure",
        privacy_review_id="fixture-review-1",
        privacy_review_payload_sha256=payload_sha,
        consent_id="fixture-consent-1",
        selected_outcome=FixtureOutcome(
            status=outcome,
            oracle_receipt_sha256=oracle if outcome != "unrun" else None,
            checked_by="fixture-oracle" if outcome != "unrun" else None,
        ),
    )


def test_exact_persisted_packets_and_unrun_unknown(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshot_id, second_id = _snapshots(store)
        payload_sha = snapshot_payload_sha256(store, snapshot_id)
        corpus = export_frontier_fixture_pilot(
            store,
            (
                _case(snapshot_id, payload_sha),
                _case(second_id, snapshot_payload_sha256(store, second_id)),
            ),
            verify_privacy_review=lambda case: case.privacy_review_id == "fixture-review-1",
        )
        assert (
            corpus.examples[0].request_json
            == store.connection.execute(
                "SELECT request_json FROM candidate_decision_snapshots WHERE snapshot_id=?",
                (snapshot_id,),
            ).fetchone()[0]
        )
        assert corpus.examples[0].receipt_json is not None
        assert corpus.examples[0].selected_outcome.status == "unrun"
        assert corpus.examples[0].selected_outcome.utility == "unknown"
        assert corpus.training_admissible is False
        assert corpus.model_preference_labels is False
        assert corpus.worker_token_parity == "not_verified"


def test_pilot_rejects_unreviewed_oracle_and_privacy_mismatch(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot-negative.db") as store:
        snapshot_id, second_id = _snapshots(store)
        payload_sha = snapshot_payload_sha256(store, snapshot_id)
        case = _case(snapshot_id, payload_sha, outcome="useful")
        with pytest.raises(ValueError, match="oracle"):
            export_frontier_fixture_pilot(
                store,
                (case, _case(second_id, snapshot_payload_sha256(store, second_id))),
                verify_privacy_review=lambda case: True,
            )
        changed = _case(snapshot_id, "0" * 64)
        with pytest.raises(ValueError, match="privacy"):
            export_frontier_fixture_pilot(
                store,
                (changed, _case(second_id, snapshot_payload_sha256(store, second_id))),
                verify_privacy_review=lambda case: True,
            )


def test_checked_fixture_outcome_and_case_split_fence(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot-checked.db") as store:
        first_id, second_id = _snapshots(store)
        first = _case(first_id, snapshot_payload_sha256(store, first_id), outcome="useful")
        second = _case(second_id, snapshot_payload_sha256(store, second_id))
        expected_oracle = hashlib.sha256(b"independent fixture oracle").hexdigest()
        corpus = export_frontier_fixture_pilot(
            store,
            (first, second),
            verify_fixture_oracle=lambda outcome: (
                outcome.oracle_receipt_sha256 == expected_oracle
                and outcome.checked_by == "fixture-oracle"
            ),
            verify_privacy_review=lambda case: case.privacy_review_id == "fixture-review-1",
        )
        assert corpus.examples[0].selected_outcome.utility == "useful"
        assert corpus.examples[1].selected_outcome.utility == "unknown"
        assert (
            corpus.export_sha256
            == hashlib.sha256(
                json.dumps(
                    [asdict(example) for example in corpus.examples],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode()
            ).hexdigest()
        )
        with pytest.raises(ValueError, match="split leaks"):
            export_frontier_fixture_pilot(
                store,
                (first, replace(second, split="pilot_train")),
                verify_fixture_oracle=lambda outcome: True,
                verify_privacy_review=lambda case: True,
            )
