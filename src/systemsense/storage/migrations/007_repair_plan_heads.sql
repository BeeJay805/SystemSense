-- No v6 proposal is promoted automatically: prior rows lack an authoritative
-- active-head decision and remain unclaimable until trusted re-proposal.
CREATE TABLE repair_plan_heads (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE RESTRICT,
    active_proposal_id TEXT NOT NULL UNIQUE REFERENCES repair_proposals(proposal_id) ON DELETE RESTRICT,
    active_proposal_digest TEXT NOT NULL CHECK (
        length(active_proposal_digest) = 64
        AND active_proposal_digest NOT GLOB '*[^0-9a-f]*'
    ),
    case_state_version INTEGER NOT NULL CHECK (case_state_version >= 0),
    activated_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER repair_plan_heads_insert_binding
BEFORE INSERT ON repair_plan_heads
WHEN EXISTS (SELECT 1 FROM repair_plan_heads WHERE case_id = NEW.case_id)
    OR NOT EXISTS (
        SELECT 1 FROM repair_proposals AS proposal
        JOIN cases AS case_record ON case_record.case_id = proposal.case_id
        WHERE proposal.proposal_id = NEW.active_proposal_id
          AND proposal.case_id = NEW.case_id
          AND proposal.case_state_version = NEW.case_state_version
          AND proposal.proposal_digest = NEW.active_proposal_digest
          AND case_record.state_version = NEW.case_state_version
    )
BEGIN
    SELECT RAISE(ABORT, 'repair plan head binding is invalid');
END;

CREATE TRIGGER repair_plan_heads_update_binding
BEFORE UPDATE ON repair_plan_heads
WHEN NEW.case_id != OLD.case_id
    OR NOT EXISTS (
        SELECT 1 FROM repair_proposals AS proposal
        JOIN cases AS case_record ON case_record.case_id = proposal.case_id
        WHERE proposal.proposal_id = NEW.active_proposal_id
          AND proposal.case_id = NEW.case_id
          AND proposal.case_state_version = NEW.case_state_version
          AND proposal.proposal_digest = NEW.active_proposal_digest
          AND case_record.state_version = NEW.case_state_version
    )
BEGIN
    SELECT RAISE(ABORT, 'repair plan head binding is invalid');
END;

CREATE TRIGGER repair_plan_heads_no_delete
BEFORE DELETE ON repair_plan_heads
BEGIN
    SELECT RAISE(ABORT, 'repair plan head cannot be deleted');
END;

PRAGMA user_version = 7;
