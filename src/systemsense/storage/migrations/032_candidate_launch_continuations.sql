-- A claimed candidate can continue across exactly one owner checkpoint save.
-- Creation occurs while the case is still at the admitted epoch. Consumption
-- is append-only and precedes host access, so a crash cannot replay a launch.
CREATE TABLE candidate_launch_continuations (
    continuation_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
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
CREATE INDEX candidate_launch_continuations_case_version
ON candidate_launch_continuations(case_id, resulting_checkpoint_version);

CREATE TABLE candidate_launch_consumptions (
    continuation_id TEXT PRIMARY KEY REFERENCES candidate_launch_continuations(continuation_id),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    consumed_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER candidate_launch_continuations_no_update
BEFORE UPDATE ON candidate_launch_continuations
BEGIN SELECT RAISE(ABORT, 'candidate launch continuation is immutable'); END;
CREATE TRIGGER candidate_launch_continuations_no_delete
BEFORE DELETE ON candidate_launch_continuations
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate launch continuation is immutable'); END;
CREATE TRIGGER candidate_launch_consumptions_no_update
BEFORE UPDATE ON candidate_launch_consumptions
BEGIN SELECT RAISE(ABORT, 'candidate launch consumption is immutable'); END;
CREATE TRIGGER candidate_launch_consumptions_no_delete
BEFORE DELETE ON candidate_launch_consumptions
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate launch consumption is immutable'); END;

PRAGMA user_version = 32;
