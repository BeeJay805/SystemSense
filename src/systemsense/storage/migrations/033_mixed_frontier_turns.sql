-- Add immutable v3 mixed-turn records; preserve exact v1/v2 JSON and readback.
-- The migration runner fences foreign keys during these two parent rebuilds.
CREATE TABLE search_frontier_investigator_turns_new (
    turn_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 8),
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2, 3)),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    reserved_at TEXT NOT NULL,
    UNIQUE (event_id, ordinal),
    FOREIGN KEY (event_id, case_id)
        REFERENCES search_frontier_investigator_sessions(event_id, case_id) ON DELETE CASCADE
) STRICT;
INSERT INTO search_frontier_investigator_turns_new
SELECT * FROM search_frontier_investigator_turns;
DROP TABLE search_frontier_investigator_turns;
ALTER TABLE search_frontier_investigator_turns_new
RENAME TO search_frontier_investigator_turns;
CREATE INDEX search_frontier_investigator_turns_case_order
ON search_frontier_investigator_turns(case_id, reserved_at, turn_id);
CREATE UNIQUE INDEX search_frontier_investigator_turns_id_case
ON search_frontier_investigator_turns(turn_id, case_id);
CREATE TRIGGER search_frontier_investigator_turns_no_update
BEFORE UPDATE ON search_frontier_investigator_turns
BEGIN SELECT RAISE(ABORT, 'investigator turn is immutable'); END;
CREATE TRIGGER search_frontier_investigator_turns_no_delete
BEFORE DELETE ON search_frontier_investigator_turns
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator turn is immutable'); END;

CREATE TABLE search_frontier_investigator_turn_outcomes_new (
    turn_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2, 3)),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    completed_at TEXT NOT NULL,
    FOREIGN KEY (turn_id, case_id)
        REFERENCES search_frontier_investigator_turns(turn_id, case_id) ON DELETE CASCADE
) STRICT;
INSERT INTO search_frontier_investigator_turn_outcomes_new
SELECT * FROM search_frontier_investigator_turn_outcomes;
DROP TABLE search_frontier_investigator_turn_outcomes;
ALTER TABLE search_frontier_investigator_turn_outcomes_new
RENAME TO search_frontier_investigator_turn_outcomes;
CREATE UNIQUE INDEX search_frontier_investigator_turn_outcomes_id_case
ON search_frontier_investigator_turn_outcomes(turn_id, case_id);
CREATE TRIGGER search_frontier_investigator_turn_outcomes_no_update
BEFORE UPDATE ON search_frontier_investigator_turn_outcomes
BEGIN SELECT RAISE(ABORT, 'investigator turn outcome is immutable'); END;
CREATE TRIGGER search_frontier_investigator_turn_outcomes_no_delete
BEFORE DELETE ON search_frontier_investigator_turn_outcomes
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator turn outcome is immutable'); END;

PRAGMA user_version = 33;
