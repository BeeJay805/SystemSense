-- Repair proposals are server-created snapshots. Claims are admission records,
-- not proof that a person was authenticated or that any action executed.
CREATE TABLE repair_proposals (
    proposal_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    case_state_version INTEGER NOT NULL CHECK (case_state_version >= 0),
    plan_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    proposal_digest TEXT NOT NULL CHECK (
        length(proposal_digest) = 64
        AND proposal_digest NOT GLOB '*[^0-9a-f]*'
    ),
    proposal_json TEXT NOT NULL CHECK (json_valid(proposal_json))
) STRICT;

CREATE INDEX repair_proposals_case ON repair_proposals(case_id);

-- REPLACE deletes the conflicting row before inserting and, with SQLite's
-- default recursive_triggers=OFF, does not fire the delete trigger below.
CREATE TRIGGER repair_proposals_no_replace
BEFORE INSERT ON repair_proposals
WHEN EXISTS (SELECT 1 FROM repair_proposals WHERE proposal_id = NEW.proposal_id)
BEGIN
    SELECT RAISE(ABORT, 'repair proposal is immutable');
END;

CREATE TRIGGER repair_proposals_no_update
BEFORE UPDATE ON repair_proposals
BEGIN
    SELECT RAISE(ABORT, 'repair proposal is immutable');
END;

CREATE TRIGGER repair_proposals_no_delete
BEFORE DELETE ON repair_proposals
BEGIN
    SELECT RAISE(ABORT, 'repair proposal is immutable');
END;

CREATE TABLE repair_approval_claims (
    claim_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL UNIQUE REFERENCES repair_proposals(proposal_id) ON DELETE RESTRICT,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    proposal_digest TEXT NOT NULL,
    consent_reference TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('claimed', 'interrupted_uncertain')),
    claimed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX repair_approval_claims_case ON repair_approval_claims(case_id);

CREATE TRIGGER repair_approval_claims_no_replace
BEFORE INSERT ON repair_approval_claims
WHEN EXISTS (
    SELECT 1 FROM repair_approval_claims
    WHERE claim_id = NEW.claim_id
       OR proposal_id = NEW.proposal_id
       OR consent_reference = NEW.consent_reference
)
BEGIN
    SELECT RAISE(ABORT, 'repair approval claim cannot be replayed or rewritten');
END;

CREATE TRIGGER repair_approval_claims_only_interrupt
BEFORE UPDATE ON repair_approval_claims
WHEN OLD.state != 'claimed'
    OR NEW.state != 'interrupted_uncertain'
    OR NEW.claim_id != OLD.claim_id
    OR NEW.proposal_id != OLD.proposal_id
    OR NEW.case_id != OLD.case_id
    OR NEW.proposal_digest != OLD.proposal_digest
    OR NEW.consent_reference != OLD.consent_reference
    OR NEW.claimed_at != OLD.claimed_at
BEGIN
    SELECT RAISE(ABORT, 'repair approval claim cannot be replayed or rewritten');
END;

CREATE TRIGGER repair_approval_claims_no_delete
BEFORE DELETE ON repair_approval_claims
BEGIN
    SELECT RAISE(ABORT, 'repair approval claim is immutable');
END;

PRAGMA user_version = 6;
