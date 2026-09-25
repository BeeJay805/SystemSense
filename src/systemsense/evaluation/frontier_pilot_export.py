"""Small, fixture-only export of exact persisted frontier decision packets.

This is a custody pilot, not a training admission decision. In particular the
database does not retain actual worker token IDs or a tokenizer/build receipt.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from typing import Literal

from systemsense.storage.candidate_decision_snapshots import (
    CandidateDecisionSnapshotRepository,
    FrontierCandidateSnapshot,
)
from systemsense.storage.frontier_packet_receipts import (
    FrontierPacketReceiptRepository,
    FrontierPacketReceiptV1,
)
from systemsense.storage.sqlite_store import SQLiteStore

OutcomeStatus = Literal["useful", "uninformative", "contradictory", "failed", "unrun"]
PilotSplit = Literal["pilot_train", "pilot_holdout"]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class FixtureOutcome:
    status: OutcomeStatus
    oracle_receipt_sha256: str | None = None
    checked_by: str | None = None

    @property
    def utility(self) -> str:
        return "unknown" if self.status == "unrun" else self.status


@dataclass(frozen=True)
class PilotFixtureCase:
    snapshot_id: str
    split: PilotSplit
    machine_group: str
    software_group: str
    fault_family: str
    privacy_review_id: str
    privacy_review_payload_sha256: str
    consent_id: str
    selected_outcome: FixtureOutcome


@dataclass(frozen=True)
class PilotItemOutcome:
    item_id: str
    status: OutcomeStatus
    utility: str
    oracle_receipt_sha256: str | None
    checked_by: str | None


@dataclass(frozen=True)
class FrontierPilotExample:
    snapshot_id: str
    case_id: str
    epoch_state_version: int
    split: PilotSplit
    machine_group: str
    software_group: str
    fault_family: str
    selected_item_id: str
    request_json: str
    request_sha256: str
    response_json: str
    response_sha256: str
    receipt_json: str
    receipt_sha256: str
    source_row_sha256: tuple[str, ...]
    payload_sha256: str
    privacy_review_id: str
    consent_id: str
    item_outcomes: tuple[PilotItemOutcome, ...]

    @property
    def selected_outcome(self) -> PilotItemOutcome:
        return next(item for item in self.item_outcomes if item.item_id == self.selected_item_id)


@dataclass(frozen=True)
class FrontierFixturePilot:
    schema_version: Literal[1]
    source_authenticity: Literal["controlled_fixture_only"]
    training_admissible: Literal[False]
    model_preference_labels: Literal[False]
    worker_token_parity: Literal["not_verified"]
    examples: tuple[FrontierPilotExample, ...]
    export_sha256: str

    def to_json(self) -> str:
        return _canonical(asdict(self))


def _payloads(
    store: SQLiteStore, snapshot_id: str
) -> tuple[FrontierCandidateSnapshot, FrontierPacketReceiptV1, str, str, str]:
    """Return persisted bytes only after repository custody checks pass."""
    with store.read_snapshot():
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_id)
        receipt = FrontierPacketReceiptRepository(store).bound_receipt(snapshot_id)
        if receipt is None:
            raise ValueError("frontier pilot requires a bound source receipt")
        row = store.connection.execute(
            "SELECT request_json,response_json FROM candidate_decision_snapshots "
            "WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        receipt_row = store.connection.execute(
            "SELECT receipt_json FROM frontier_packet_receipts WHERE receipt_id=?",
            (receipt.receipt_id,),
        ).fetchone()
        if row is None or receipt_row is None:
            raise ValueError("frontier pilot source payload disappeared")
        return snapshot, receipt, str(row[0]), str(row[1]), str(receipt_row[0])


def snapshot_payload_sha256(store: SQLiteStore, snapshot_id: str) -> str:
    """Privacy-review digest over exact stored request, response and receipt JSON."""
    _, _, request_json, response_json, receipt_json = _payloads(store, snapshot_id)
    return _sha(_canonical((request_json, response_json, receipt_json)))


def export_frontier_fixture_pilot(
    store: SQLiteStore,
    cases: Sequence[PilotFixtureCase],
    *,
    verify_fixture_oracle: Callable[[FixtureOutcome], bool] | None = None,
    verify_privacy_review: Callable[[PilotFixtureCase], bool] | None = None,
) -> FrontierFixturePilot:
    """Export two to four reviewed fixture snapshots, never model-derived labels.

    The oracle callback belongs to the controlled fixture harness, not to the
    ranker. A useful/failed/etc. label is rejected unless that external checker
    validates its receipt. This API does not establish real-world authenticity.
    """
    if not 2 <= len(cases) <= 4:
        raise ValueError("frontier pilot requires two to four examples")
    if len({case.snapshot_id for case in cases}) != len(cases):
        raise ValueError("frontier pilot repeats a snapshot")
    examples: list[FrontierPilotExample] = []
    split_groups: dict[tuple[str, str], PilotSplit] = {}
    for case in cases:
        if case.split not in {"pilot_train", "pilot_holdout"}:
            raise ValueError("frontier pilot split is invalid")
        if case.selected_outcome.status not in {
            "useful",
            "uninformative",
            "contradictory",
            "failed",
            "unrun",
        }:
            raise ValueError("frontier pilot outcome status is invalid")
        if not all(
            (
                case.machine_group,
                case.software_group,
                case.fault_family,
                case.privacy_review_id,
                case.consent_id,
            )
        ):
            raise ValueError("frontier pilot lacks fixture provenance, consent or privacy review")
        snapshot, receipt, request_json, response_json, receipt_json = _payloads(
            store, case.snapshot_id
        )
        payload_sha = _sha(_canonical((request_json, response_json, receipt_json)))
        if case.privacy_review_payload_sha256 != payload_sha:
            raise ValueError("frontier pilot privacy review does not bind exact payload")
        if verify_privacy_review is None or not verify_privacy_review(case):
            raise ValueError("frontier pilot privacy review was not independently checked")
        outcome = case.selected_outcome
        if outcome.status == "unrun":
            if outcome.oracle_receipt_sha256 is not None or outcome.checked_by is not None:
                raise ValueError("unrun outcome cannot claim an oracle result")
        elif (
            outcome.oracle_receipt_sha256 is None
            or re.fullmatch(r"[0-9a-f]{64}", outcome.oracle_receipt_sha256) is None
            or outcome.checked_by is None
            or verify_fixture_oracle is None
            or not verify_fixture_oracle(outcome)
        ):
            raise ValueError("frontier pilot outcome lacks an independently checked oracle")
        for group_type, group_value in (
            ("case", str(snapshot.case_id)),
            ("machine", case.machine_group),
            ("software", case.software_group),
            ("fault", case.fault_family),
        ):
            key = (group_type, group_value)
            if key in split_groups and split_groups[key] != case.split:
                raise ValueError("frontier pilot split leaks a case or fixture group")
            split_groups[key] = case.split
        outcomes = tuple(
            PilotItemOutcome(
                item_id=item.item_id,
                status=outcome.status if item.item_id == snapshot.selected_item_id else "unrun",
                utility=outcome.utility if item.item_id == snapshot.selected_item_id else "unknown",
                oracle_receipt_sha256=(
                    outcome.oracle_receipt_sha256
                    if item.item_id == snapshot.selected_item_id
                    else None
                ),
                checked_by=outcome.checked_by
                if item.item_id == snapshot.selected_item_id
                else None,
            )
            for item in snapshot.request.items
        )
        examples.append(
            FrontierPilotExample(
                snapshot_id=case.snapshot_id,
                case_id=str(snapshot.case_id),
                epoch_state_version=snapshot.epoch_state_version,
                split=case.split,
                machine_group=case.machine_group,
                software_group=case.software_group,
                fault_family=case.fault_family,
                selected_item_id=snapshot.selected_item_id,
                request_json=request_json,
                request_sha256=_sha(request_json),
                response_json=response_json,
                response_sha256=_sha(response_json),
                receipt_json=receipt_json,
                receipt_sha256=_sha(receipt_json),
                source_row_sha256=tuple(source.row_sha256 for source in receipt.sources),
                payload_sha256=payload_sha,
                privacy_review_id=case.privacy_review_id,
                consent_id=case.consent_id,
                item_outcomes=outcomes,
            )
        )
    export_sha = _sha(_canonical([asdict(example) for example in examples]))
    return FrontierFixturePilot(
        schema_version=1,
        source_authenticity="controlled_fixture_only",
        training_admissible=False,
        model_preference_labels=False,
        worker_token_parity="not_verified",
        examples=tuple(examples),
        export_sha256=export_sha,
    )
