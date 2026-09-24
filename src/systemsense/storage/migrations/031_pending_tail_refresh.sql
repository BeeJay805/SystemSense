-- Allow immutable v2 reservations while preserving all historical v1 rows.
-- The migration runner disables foreign keys for this atomic parent rebuild,
-- then checks every relationship and the database integrity before commit.
CREATE TABLE search_frontier_investigator_turns_new (
    turn_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 8),
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
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
