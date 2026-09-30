-- Preserve V1 continuations byte-for-byte; permit explicitly versioned V2 rows.
-- The FK-safe migration runner disables FK enforcement for this parent rebuild,
-- runs foreign_key_check and integrity_check, and commits atomically.
DROP TRIGGER candidate_launch_continuations_no_update;
DROP TRIGGER candidate_launch_continuations_no_delete;
DROP INDEX candidate_launch_continuations_case_version;

CREATE TABLE candidate_launch_continuations_v41 (
    continuation_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
    admission_id TEXT NOT NULL UNIQUE REFERENCES candidate_dispatch_claims(admission_id),
    turn_id TEXT NOT NULL UNIQUE REFERENCES search_frontier_investigator_turns(turn_id),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    resulting_checkpoint_version INTEGER NOT NULL
        CHECK (resulting_checkpoint_version = epoch_state_version + 1),
    owner_started_version INTEGER NOT NULL CHECK (owner_started_version >= 1),
    task_id TEXT NOT NULL,
    invocation_sha256 TEXT NOT NULL CHECK (length(invocation_sha256) = 64),
    deadline_at TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

INSERT INTO candidate_launch_continuations_v41
SELECT * FROM candidate_launch_continuations;
DROP TABLE candidate_launch_continuations;
ALTER TABLE candidate_launch_continuations_v41 RENAME TO candidate_launch_continuations;

CREATE INDEX candidate_launch_continuations_case_version
ON candidate_launch_continuations(case_id, resulting_checkpoint_version);

CREATE TRIGGER candidate_launch_continuations_no_update
BEFORE UPDATE ON candidate_launch_continuations
BEGIN SELECT RAISE(ABORT, 'candidate launch continuation is immutable'); END;
CREATE TRIGGER candidate_launch_continuations_no_delete
BEFORE DELETE ON candidate_launch_continuations
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate launch continuation is immutable'); END;

PRAGMA user_version = 41;
