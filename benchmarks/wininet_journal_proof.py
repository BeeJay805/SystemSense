"""Read an action journal independently of an investigator arm's claims.

This adapter binds the runner's durable record to the lab harness. It proves
that a particular journal row exists, not that a Windows fault was injected,
that an endpoint was independently operated, or that recovery occurred.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from benchmarks.lab_episodes import ActionJournalProof
from systemsense.actions.wininet_proxy import ProxyRepairJournal, ProxyRepairRecord
from systemsense.domain.ids import CaseId


def prove_wininet_action(
    journal: ProxyRepairJournal, case_id: str, action_execution_id: str
) -> ActionJournalProof | None:
    """Return a bound terminal journal proof, never accepting an arm-supplied row."""
    expected_case = CaseId(root=case_id)
    record = journal.record(action_execution_id)
    if (
        record is None
        or record.case_id != expected_case
        or record.target_digest is None
        or record.authorization_digest is None
    ):
        return None
    terminal: Literal["verified", "failed", "rolled_back"]
    if record.state == "verified":
        terminal = "verified"
    elif record.state == "precondition_failed":
        terminal = "failed"
    elif record.state == "rolled_back":
        terminal = "rolled_back"
    else:
        return None
    if record.state == "verified" and not _has_distinct_path_evidence(record):
        return None
    canonical = json.dumps(
        {
            "token_id": record.token_id,
            "case_id": str(record.case_id),
            "proposal_digest": record.proposal_digest,
            "target_digest": record.target_digest,
            "authorization_digest": record.authorization_digest,
            "state": record.state,
            "updated_at": record.updated_at.isoformat(),
            "before_evidence_id": str(record.before_evidence_id)
            if record.before_evidence_id is not None
            else None,
            "control_evidence_id": str(record.control_evidence_id)
            if record.control_evidence_id is not None
            else None,
            "after_evidence_id": str(record.after_evidence_id)
            if record.after_evidence_id is not None
            else None,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ActionJournalProof(
        case_id=str(record.case_id),
        action_execution_id=record.token_id,
        journal_record_sha256=hashlib.sha256(canonical).hexdigest(),
        authorization_digest=record.authorization_digest,
        proposal_digest=record.proposal_digest,
        target_digest=record.target_digest,
        terminal_outcome=terminal,
        completed_at=record.updated_at,
    )


def _has_distinct_path_evidence(record: ProxyRepairRecord) -> bool:
    identities = (
        record.before_evidence_id,
        record.control_evidence_id,
        record.after_evidence_id,
    )
    return (
        all(identity is not None for identity in identities)
        and len({str(identity) for identity in identities}) == 3
    )
