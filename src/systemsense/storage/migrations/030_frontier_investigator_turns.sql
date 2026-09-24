-- Reservations consume a turn even if inference never returns. Outcomes are
-- separate append-only records so an interrupted reservation remains visible.
CREATE TABLE search_frontier_investigator_turns (
    turn_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 8),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    reserved_at TEXT NOT NULL,
    UNIQUE (event_id, ordinal),
    FOREIGN KEY (event_id, case_id)
        REFERENCES search_frontier_investigator_sessions(event_id, case_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX search_frontier_investigator_turns_case_order
ON search_frontier_investigator_turns(case_id, reserved_at, turn_id);
CREATE UNIQUE INDEX search_frontier_investigator_turns_id_case
ON search_frontier_investigator_turns(turn_id, case_id);

CREATE TABLE search_frontier_investigator_turn_outcomes (
    turn_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    completed_at TEXT NOT NULL,
    FOREIGN KEY (turn_id, case_id)
        REFERENCES search_frontier_investigator_turns(turn_id, case_id) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX search_frontier_investigator_turn_outcomes_id_case
ON search_frontier_investigator_turn_outcomes(turn_id, case_id);

CREATE TABLE search_frontier_investigator_turn_closures (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    final_turn_id TEXT NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    closed_at TEXT NOT NULL,
    FOREIGN KEY (event_id, case_id)
        REFERENCES search_frontier_investigator_sessions(event_id, case_id) ON DELETE CASCADE,
    FOREIGN KEY (final_turn_id, case_id)
        REFERENCES search_frontier_investigator_turn_outcomes(turn_id, case_id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER search_frontier_investigator_turns_no_update
BEFORE UPDATE ON search_frontier_investigator_turns
BEGIN SELECT RAISE(ABORT, 'investigator turn is immutable'); END;
CREATE TRIGGER search_frontier_investigator_turns_no_delete
BEFORE DELETE ON search_frontier_investigator_turns
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator turn is immutable'); END;
CREATE TRIGGER search_frontier_investigator_turn_outcomes_no_update
BEFORE UPDATE ON search_frontier_investigator_turn_outcomes
BEGIN SELECT RAISE(ABORT, 'investigator turn outcome is immutable'); END;
CREATE TRIGGER search_frontier_investigator_turn_outcomes_no_delete
BEFORE DELETE ON search_frontier_investigator_turn_outcomes
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator turn outcome is immutable'); END;
CREATE TRIGGER search_frontier_investigator_turn_closures_no_update
BEFORE UPDATE ON search_frontier_investigator_turn_closures
BEGIN SELECT RAISE(ABORT, 'investigator turn closure is immutable'); END;
CREATE TRIGGER search_frontier_investigator_turn_closures_no_delete
BEFORE DELETE ON search_frontier_investigator_turn_closures
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator turn closure is immutable'); END;

DROP TRIGGER search_frontier_investigator_active_sessions_no_delete;
CREATE TRIGGER search_frontier_investigator_active_sessions_no_delete
BEFORE DELETE ON search_frontier_investigator_active_sessions
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
AND NOT EXISTS (
    SELECT 1 FROM search_frontier_investigator_terminals WHERE event_id=OLD.event_id
)
AND NOT EXISTS (
    SELECT 1 FROM search_frontier_investigator_turn_closures WHERE event_id=OLD.event_id
)
BEGIN SELECT RAISE(ABORT, 'investigator active session lacks terminal'); END;
PRAGMA user_version = 30;
