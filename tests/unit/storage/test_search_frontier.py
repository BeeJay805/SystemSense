"""Durable advisory search work is distinct from probe execution authority."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import MeasurementWindow
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierOutboxGapV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = "2026-09-23T12:00:00+00:00"


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(case_id=str(case_id), kind="general", symptom="slow PDF", created_at=_NOW)
    return case_id


def _versions(**changes: int) -> RelevantVersionsV1:
    return RelevantVersionsV1.model_validate(
        {"objective": 1, "evidence": 2, "hypotheses": 1, **changes}
    )


def _measurement(candidate: str, *, window: MeasurementWindow | None = None) -> FrontierReferenceV1:
    return FrontierReferenceV1(kind="measure", candidate_id=candidate, window=window)


def test_unchanged_item_deduplicates_but_target_and_window_are_distinct(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        first = repo.upsert_item(case_id, _measurement("cand_v1_" + "a" * 32), _versions())
        assert (
            repo.upsert_item(case_id, _measurement("cand_v1_" + "a" * 32), _versions()).item_id
            == first.item_id
        )
        other_target = repo.upsert_item(case_id, _measurement("cand_v1_" + "b" * 32), _versions())
        window = MeasurementWindow(
            start=datetime.fromisoformat("2026-09-23T11:00:00+00:00"),
            end=datetime.fromisoformat("2026-09-23T11:01:00+00:00"),
        )
        other_window = repo.upsert_item(
            case_id, _measurement("cand_v1_" + "a" * 32, window=window), _versions()
        )
        assert len({first.item_id, other_target.item_id, other_window.item_id}) == 3
        assert first.status is FrontierStatus.REQUESTED
        assert repo.readback(first.item_id) == first


def test_versioned_branch_reference_pins_relation_version_and_content(tmp_path: Path) -> None:
    from systemsense.storage import search_frontier

    reference_type = getattr(search_frontier, "FrontierBranchReferenceV2", None)
    assert reference_type is not None
    with SQLiteStore(tmp_path / "versioned-branch.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        relation_id = "rel_" + "b" * 32
        first_sha = "c" * 64
        second_sha = "d" * 64
        first_branch_id = (
            "branch_v2_" + hashlib.sha256(f"{relation_id}:1:{first_sha}".encode()).hexdigest()[:32]
        )
        second_branch_id = (
            "branch_v2_" + hashlib.sha256(f"{relation_id}:2:{second_sha}".encode()).hexdigest()[:32]
        )
        first = reference_type(
            branch_id=first_branch_id,
            relation_id=relation_id,
            relation_version=1,
            relation_sha256=first_sha,
        )
        second = reference_type(
            branch_id=second_branch_id,
            relation_id=relation_id,
            relation_version=2,
            relation_sha256=second_sha,
        )
        first_item = repo.upsert_item(case_id, first, _versions())
        second_item = repo.upsert_item(case_id, second, _versions())
        assert first_item.item_id != second_item.item_id
        assert repo.readback(first_item.item_id).reference == first
        assert repo.readback(second_item.item_id).reference == second


def test_reference_rejects_untyped_selectors_and_wrong_kind_fields() -> None:
    with pytest.raises(ValidationError):
        FrontierReferenceV1(kind="measure", candidate_id="https://example.com/run")
    with pytest.raises(ValidationError):
        FrontierReferenceV1(kind="measure", evidence_id=EvidenceId.new())
    with pytest.raises(ValidationError):
        FrontierReferenceV1(
            kind="retrieve_evidence",
            evidence_id=EvidenceId.new(),
            candidate_id="cand_v1_" + "a" * 32,
        )


def test_claim_rejects_changed_relevant_versions_and_prerequisite_not_satisfied(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        parent = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=EvidenceId.new()),
            _versions(),
        )
        child = repo.upsert_item(
            case_id,
            _measurement("cand_v1_" + "a" * 32),
            _versions(),
            prerequisite_ids=(parent.item_id,),
        )
        with pytest.raises(ValueError, match="relevant versions"):
            repo.claim_ready(parent.item_id, _versions(evidence=3))
        with pytest.raises(ValueError, match="prerequisite"):
            repo.claim_ready(child.item_id, _versions())
        claimed = repo.claim_ready(parent.item_id, _versions())
        assert claimed.status is FrontierStatus.CLAIMED
        assert (
            repo.transition(
                parent.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted"
            ).status
            is FrontierStatus.ADMITTED
        )
        repo.transition(parent.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "running")
        repo.transition(
            parent.item_id, FrontierStatus.RUNNING, FrontierStatus.SATISFIED, "retrieved"
        )
        assert repo.claim_ready(child.item_id, _versions()).status is FrontierStatus.CLAIMED


def test_invalid_transition_and_one_shot_interrupted_custody(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        item = repo.upsert_item(case_id, _measurement("cand_v1_" + "a" * 32), _versions())
        with pytest.raises(ValueError, match="invalid transition"):
            repo.transition(
                item.item_id, FrontierStatus.REQUESTED, FrontierStatus.RUNNING, "skip_admission"
            )
        repo.claim_ready(item.item_id, _versions())
        repo.transition(item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
        assert repo.interrupt_uncertain(case_id) == (item.item_id,)
        assert repo.readback(item.item_id).status is FrontierStatus.INTERRUPTED
        with pytest.raises(ValueError, match="not requested"):
            repo.claim_ready(item.item_id, _versions())
        assert repo.interrupt_uncertain(case_id) == ()


def test_result_event_is_atomic_idempotent_and_acknowledged(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with pytest.raises(ValueError, match="active transaction"):
            repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        with pytest.raises(RuntimeError, match="rollback"):
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=str(case_id),
                    evidence_id=str(evidence_id),
                    source_id="src_" + "a" * 64,
                    record_json='{"summary":"observed"}',
                    captured_at=_NOW,
                )
                repo.append_result_event(
                    case_id,
                    source_evidence_id=evidence_id,
                    source_execution_id=None,
                    versions=_versions(),
                )
                raise RuntimeError("rollback")
        assert repo.pending_events(case_id) == ()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id="src_" + "a" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            first = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
            second = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(first, FrontierEventV1)
        assert isinstance(second, FrontierEventV1)
        assert first.event_id == second.event_id
        assert repo.pending_events(case_id) == (first,)
        repo.ack_event(first.event_id)
        assert repo.pending_events(case_id) == ()
        assert repo.read_event(first.event_id) == first


def test_event_source_must_exist_and_belong_to_case(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        owner = _case(store)
        other = _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(owner),
                evidence_id=str(evidence_id),
                source_id="src_" + "b" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            with pytest.raises(ValueError, match=r"source.*case"):
                repo.append_result_event(
                    other,
                    source_evidence_id=evidence_id,
                    source_execution_id=None,
                    versions=_versions(),
                )
            with pytest.raises(ValueError, match=r"source.*case"):
                repo.append_result_event(
                    owner,
                    source_evidence_id=None,
                    source_execution_id=ExecutionId.new(),
                    versions=_versions(),
                )


def test_result_event_survives_raw_evidence_retention_as_unverifiable(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id="src_" + "e" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            event = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(event, FrontierEventV1)
        assert event.source_state == "present"
        assert event.source_record_sha256 is not None
        with store.transaction():
            store.connection.execute(
                "DELETE FROM evidence WHERE evidence_id=?", (str(evidence_id),)
            )
        retained = repo.read_event(event.event_id)
        assert retained.source_evidence_id == evidence_id
        assert retained.source_state == "missing_unverifiable"
        assert retained.source_record_sha256 == event.source_record_sha256
        assert repo.pending_events(case_id) == (retained,)


def test_outbox_capacity_gap_does_not_rollback_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("systemsense.storage.search_frontier._EVENT_LIMIT", 1)
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        first_id, second_id = EvidenceId.new(), EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(first_id),
                source_id="src_" + "c" * 64,
                record_json='{"summary":"first"}',
                captured_at=_NOW,
            )
            repo.append_result_event(
                case_id, source_evidence_id=first_id, source_execution_id=None, versions=_versions()
            )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(second_id),
                source_id="src_" + "d" * 64,
                record_json='{"summary":"second"}',
                captured_at=_NOW,
            )
            overflow = repo.append_result_event(
                case_id,
                source_evidence_id=second_id,
                source_execution_id=None,
                versions=_versions(evidence=3),
            )
        assert isinstance(overflow, FrontierOutboxGapV1)
        assert overflow.reason == "capacity_requires_catalog_rescan"
        assert store.evidence(case_id=str(case_id), evidence_id=str(second_id)) is not None
        assert repo.outbox_gap(case_id) == overflow
