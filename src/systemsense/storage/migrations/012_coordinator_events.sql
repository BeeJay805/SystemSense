-- The coordinator's typed benchmark projection survives checkpoint replacement.
-- Export still requires linked raw evidence; retention of those rows closes the
-- export window. Whole-case deletion remains possible for retention.
CREATE TABLE coordinator_events (
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('probe', 'provider', 'evidence', 'coverage', 'terminal')),
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    source_record_id TEXT,
    source_observed_at TEXT,
    persisted_at TEXT NOT NULL,
    PRIMARY KEY (case_id, sequence),
    UNIQUE (case_id, event_id)
) STRICT;

CREATE TRIGGER coordinator_events_no_update
BEFORE UPDATE ON coordinator_events
BEGIN
    SELECT RAISE(ABORT, 'coordinator event is immutable');
END;

CREATE TRIGGER coordinator_events_no_delete
BEFORE DELETE ON coordinator_events
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id = OLD.case_id)
BEGIN
    SELECT RAISE(ABORT, 'coordinator event is immutable');
END;

PRAGMA user_version = 12;
