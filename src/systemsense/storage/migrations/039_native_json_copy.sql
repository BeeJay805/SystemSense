-- Repair receipts are separate from read-only probe executions.
CREATE TABLE json_copy_operations (
    operation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    proposal_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending','verified','failed','uncertain')),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    claimed_at TEXT NOT NULL,
    completed_at TEXT
) STRICT;
CREATE INDEX json_copy_case ON json_copy_operations(case_id, claimed_at);
CREATE TRIGGER json_copy_terminal_immutable BEFORE UPDATE ON json_copy_operations
WHEN OLD.status != 'pending' OR NEW.operation_id != OLD.operation_id
    OR NEW.case_id != OLD.case_id OR NEW.proposal_digest != OLD.proposal_digest
    OR NEW.claimed_at != OLD.claimed_at
BEGIN SELECT RAISE(ABORT, 'copy claim and terminal receipt are immutable'); END;
PRAGMA user_version = 39;
