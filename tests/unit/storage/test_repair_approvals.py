"""Durable admission of exact server-owned repair proposals and review claims."""

import json
import sqlite3
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest

from systemsense.actions.contracts import (
    ActionAuthorizationError,
    ActionCode,
    ActionKind,
    ActionOperation,
    DisruptionLevel,
    ExactTarget,
    ExpectedEffect,
    OperationParameter,
    Precondition,
    PreconditionCode,
    ProposalRisk,
    RepairProposal,
    RiskLevel,
    RollbackLimits,
    TargetKind,
    VerificationCheck,
    VerificationPlan,
)
from systemsense.domain.ids import CaseId, TargetId
from systemsense.storage.repair_approvals import RepairApprovalRepository, RepairApprovalState
from systemsense.storage.sqlite_store import SQLiteStore, StoreTransaction

NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)


def _proposal(case_id: CaseId) -> RepairProposal:
    target = ExactTarget(
        target_id=TargetId.new(),
        kind=TargetKind.WININET_USER_PROXY,
        locator="wininet_proxy:S-1-5-21-1000-2000-3000-1001",
    )
    return RepairProposal(
        proposal_id="proposal_0123456789abcdef0123456789abcdef",
        kind=ActionKind.REPAIR,
        case_id=case_id,
        case_state_version=4,
        plan_version="proxy-plan-1",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        operations=(
            ActionOperation(
                operation_id="disable_bad_proxy",
                code=ActionCode.DISABLE_WININET_PROXY,
                kind=ActionKind.REPAIR,
                target=target,
                parameters=(OperationParameter(name="new_proxy_enabled", value=False),),
            ),
        ),
        preconditions=(Precondition(code=PreconditionCode.TARGET_VERSION_MATCHES, target=target),),
        expected_effect=ExpectedEffect(summary="Restore connectivity", success_indicators=("204",)),
        risk=ProposalRisk(
            level=RiskLevel.MODERATE,
            disruption=DisruptionLevel.NETWORK_INTERRUPTION,
            summary="Current-user network interruption",
        ),
        verification=VerificationPlan(checks=(VerificationCheck(code="connectivity_restored"),)),
        rollback=RollbackLimits(supported=False, max_attempts=0, limits="Manual recovery"),
    )


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind="general",
        symptom="Exact user proxy is wrong",
        created_at=NOW.isoformat(),
        state_version=4,
    )
    return case_id


def _repo(store: SQLiteStore, *, now: datetime = NOW) -> RepairApprovalRepository:
    return RepairApprovalRepository(store, clock=lambda: now)


def test_same_revision_proposal_replaces_active_head_and_old_review_cannot_claim(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        first = _proposal(case_id)
        second = first.model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        repo = _repo(store)
        repo.register_server_proposal(first, current_plan_version="proxy-plan-1")
        first_head = repo.active_head(case_id)
        assert first_head is not None
        assert first_head.proposal_id == first.proposal_id
        assert first_head.proposal_digest == first.digest()
        assert first_head.case_state_version == 4

        repo.register_server_proposal(second, current_plan_version="proxy-plan-1")
        active_head = repo.active_head(case_id)
        assert active_head is not None
        assert active_head.proposal_id == second.proposal_id
        assert active_head.proposal_digest == second.digest()
        assert active_head.plan_version == first_head.plan_version == "proxy-plan-1"
        with pytest.raises(ActionAuthorizationError, match="active"):
            repo.claim_review(
                first.proposal_id, case_id=case_id, acknowledged_digest=first.digest()
            )
        claim = repo.claim_review(
            second.proposal_id, case_id=case_id, acknowledged_digest=second.digest()
        )
        assert claim.proposal_id == second.proposal_id


def test_v6_proposal_is_not_guessed_into_active_head_on_upgrade(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        assert "state_version" in store.column_names("probe_executions")

    # Remove only v7's head table to recreate the v6 schema. All earlier
    # migrations, including v5's Python column migration, ran through SQLiteStore.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE repair_plan_heads")
        connection.execute("PRAGMA user_version = 6")
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        assert "state_version" in {
            row[1] for row in connection.execute("PRAGMA table_info(probe_executions)")
        }
    with SQLiteStore(path) as store:
        repo = _repo(store)
        assert store.schema_version() == 7
        assert repo.proposal(proposal.proposal_id) == proposal
        assert repo.active_head(case_id) is None
        with pytest.raises(ActionAuthorizationError, match="active"):
            repo.claim_review(
                proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
            )


def test_failed_head_replacement_rolls_back_new_proposal(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        first = _proposal(case_id)
        second = first.model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        repo = _repo(store)
        repo.register_server_proposal(first, current_plan_version="proxy-plan-1")
        store.connection.execute(
            "CREATE TRIGGER block_head_replacement BEFORE UPDATE ON repair_plan_heads "
            "BEGIN SELECT RAISE(ABORT, 'blocked head replacement'); END"
        )
        with pytest.raises(ActionAuthorizationError, match="head binding"):
            repo.register_server_proposal(second, current_plan_version="proxy-plan-1")
        assert repo.proposal(second.proposal_id) is None
        head = repo.active_head(case_id)
        assert head is not None and head.proposal_id == first.proposal_id


@pytest.mark.parametrize(
    ("pragma", "required"),
    [
        ("PRAGMA synchronous = NORMAL", "FULL"),
        ("PRAGMA journal_mode = MEMORY", "WAL"),
        ("PRAGMA foreign_keys = OFF", "foreign_keys"),
    ],
)
def test_approval_store_refuses_weak_sqlite_durability(
    tmp_path: Path, pragma: str, required: str
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        store.connection.execute(pragma)
        with pytest.raises(RuntimeError, match=required):
            _repo(store)


@pytest.mark.parametrize(
    ("pragma", "required"),
    [
        ("PRAGMA synchronous = NORMAL", "FULL"),
        ("PRAGMA journal_mode = MEMORY", "WAL"),
        ("PRAGMA foreign_keys = OFF", "foreign_keys"),
    ],
)
def test_claim_refuses_durability_downgrade_after_repository_creation(
    tmp_path: Path, pragma: str, required: str
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        store.connection.execute(pragma)
        with pytest.raises(RuntimeError, match=required):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )
        assert repo.claim("claim_nonexistent") is None


def test_registered_proposal_is_canonical_immutable_and_bound_to_existing_case(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")

        assert store.schema_version() == 7
        assert repo.proposal(proposal.proposal_id) == proposal
        row = store.connection.execute(
            "SELECT proposal_json, proposal_digest FROM repair_proposals WHERE proposal_id = ?",
            (proposal.proposal_id,),
        ).fetchone()
        assert row == (
            json.dumps(proposal.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
            proposal.digest(),
        )
        with pytest.raises(ActionAuthorizationError, match="already registered"):
            repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        with pytest.raises(Exception, match="immutable"):
            store.connection.execute(
                "UPDATE repair_proposals SET plan_version='other' WHERE proposal_id=?",
                (proposal.proposal_id,),
            )


def test_claim_is_durable_single_use_and_exactly_bound(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
        assert claim.state is RepairApprovalState.CLAIMED
        assert claim.proposal_digest == proposal.digest()
        assert claim.consent_reference.startswith("consent_")
        assert claim.case_id == case_id
    with SQLiteStore(path) as reopened:
        repo = _repo(reopened)
        head = repo.active_head(case_id)
        assert head is not None and head.proposal_id == proposal.proposal_id
        assert repo.claim(claim.claim_id) == claim
        with pytest.raises(ActionAuthorizationError, match="already claimed"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )


def test_wrong_case_digest_and_stale_case_state_never_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        with pytest.raises(ActionAuthorizationError, match="case binding"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=CaseId.new(),
                acknowledged_digest=proposal.digest(),
            )
        with pytest.raises(ActionAuthorizationError, match="digest"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest="0" * 64,
            )
        store.connection.execute(
            "UPDATE cases SET state_version=5 WHERE case_id=?", (str(case_id),)
        )
        with pytest.raises(ActionAuthorizationError, match="stale"):
            repo.active_head(case_id)
        with pytest.raises(ActionAuthorizationError, match="stale"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_expired_proposal_cannot_register_or_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        expired_repo = _repo(store, now=NOW + timedelta(minutes=5))
        with pytest.raises(ActionAuthorizationError, match="expired"):
            expired_repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        with pytest.raises(ActionAuthorizationError, match="expired"):
            expired_repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )


def test_concurrent_claims_allow_exactly_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
    start = Barrier(2)

    def claim() -> str:
        with SQLiteStore(path) as store:
            start.wait(5)
            try:
                result = _repo(store).claim_review(
                    proposal.proposal_id,
                    case_id=case_id,
                    acknowledged_digest=proposal.digest(),
                )
            except ActionAuthorizationError:
                return "rejected"
            return result.claim_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(claim)
        second = pool.submit(claim)
        outcomes = (first.result(timeout=5), second.result(timeout=5))
    assert len([outcome for outcome in outcomes if outcome != "rejected"]) == 1
    assert outcomes.count("rejected") == 1


def test_interrupted_claim_is_explicit_and_never_reopened(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
    with SQLiteStore(path) as reopened:
        repo = _repo(reopened, now=NOW + timedelta(seconds=1))
        interrupted = repo.mark_interrupted(claim.claim_id)
        assert interrupted.state is RepairApprovalState.INTERRUPTED_UNCERTAIN
        assert repo.claim(claim.claim_id) == interrupted
        with pytest.raises(ActionAuthorizationError, match="already interrupted"):
            repo.mark_interrupted(claim.claim_id)
        with pytest.raises(ActionAuthorizationError, match="already claimed"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )


def test_claim_rechecks_expiry_after_acquiring_write_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        current = NOW
        original_transaction = store.transaction

        @contextmanager
        def delayed_transaction() -> Generator[StoreTransaction]:
            nonlocal current
            with original_transaction() as transaction:
                current = proposal.expires_at
                yield transaction

        monkeypatch.setattr(store, "transaction", delayed_transaction)
        repo = RepairApprovalRepository(store, clock=lambda: current)
        with pytest.raises(ActionAuthorizationError, match="expired"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_interruption_time_cannot_precede_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
        earlier = _repo(store, now=NOW - timedelta(seconds=1))
        with pytest.raises(ActionAuthorizationError, match="before claim"):
            earlier.mark_interrupted(claim.claim_id)
        assert repo.claim(claim.claim_id) == claim


def test_sql_cannot_rewrite_delete_or_duplicate_a_consumed_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
        with pytest.raises(sqlite3.DatabaseError, match="replayed or rewritten"):
            store.connection.execute(
                "UPDATE repair_approval_claims SET consent_reference='consent_other' "
                "WHERE claim_id=?",
                (claim.claim_id,),
            )
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            store.connection.execute(
                "DELETE FROM repair_approval_claims WHERE claim_id=?", (claim.claim_id,)
            )
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute(
                "INSERT INTO repair_approval_claims "
                "(claim_id, proposal_id, case_id, proposal_digest, consent_reference, "
                "state, claimed_at, updated_at) VALUES (?, ?, ?, ?, ?, 'claimed', ?, ?)",
                (
                    "claim_other",
                    proposal.proposal_id,
                    str(case_id),
                    proposal.digest(),
                    "consent_other",
                    NOW.isoformat(),
                    NOW.isoformat(),
                ),
            )


def test_sql_replace_cannot_overwrite_registered_proposal_or_consumed_claim(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        store.connection.execute("PRAGMA recursive_triggers = OFF")
        proposal_row = store.connection.execute(
            "SELECT proposal_id, case_id, case_state_version, plan_version, created_at, "
            "expires_at, proposal_digest, proposal_json FROM repair_proposals WHERE proposal_id=?",
            (proposal.proposal_id,),
        ).fetchone()
        assert proposal_row is not None
        with pytest.raises(sqlite3.DatabaseError):
            store.connection.execute(
                "INSERT OR REPLACE INTO repair_proposals VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (*proposal_row[:3], "altered-plan", *proposal_row[4:]),
            )
        assert repo.proposal(proposal.proposal_id) == proposal

        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )

        claim_row = store.connection.execute(
            "SELECT claim_id, proposal_id, case_id, proposal_digest, consent_reference, "
            "state, claimed_at, updated_at FROM repair_approval_claims WHERE claim_id=?",
            (claim.claim_id,),
        ).fetchone()
        assert claim_row is not None
        with pytest.raises(sqlite3.DatabaseError):
            store.connection.execute(
                "INSERT OR REPLACE INTO repair_approval_claims VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("claim_replayed", *claim_row[1:]),
            )
        assert repo.claim(claim.claim_id) == claim
