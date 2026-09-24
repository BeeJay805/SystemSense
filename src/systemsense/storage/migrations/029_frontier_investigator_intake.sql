-- Independent investigator custody of source events. Intake creates a bounded
-- durable trigger before acknowledging this consumer, without altering the
-- legacy follow-up acknowledgement stream.
CREATE UNIQUE INDEX search_frontier_events_id_case
ON search_frontier_events(event_id, case_id);

CREATE TABLE search_frontier_investigator_triggers (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    queued_at TEXT NOT NULL,
    FOREIGN KEY (event_id, case_id)
        REFERENCES search_frontier_events(event_id, case_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX search_frontier_investigator_triggers_case_order
ON search_frontier_investigator_triggers(case_id, queued_at, event_id);
CREATE UNIQUE INDEX search_frontier_investigator_triggers_id_case
ON search_frontier_investigator_triggers(event_id, case_id);

CREATE TABLE search_frontier_investigator_event_acks (
    event_id TEXT PRIMARY KEY REFERENCES search_frontier_investigator_triggers(event_id)
        ON DELETE CASCADE,
    acknowledged_at TEXT NOT NULL
) STRICT;

CREATE TABLE search_frontier_investigator_sessions (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    started_at TEXT NOT NULL,
    FOREIGN KEY (event_id, case_id)
        REFERENCES search_frontier_investigator_triggers(event_id, case_id) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX search_frontier_investigator_sessions_id_case
ON search_frontier_investigator_sessions(event_id, case_id);

CREATE TABLE search_frontier_investigator_active_sessions (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id, case_id)
        REFERENCES search_frontier_investigator_sessions(event_id, case_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE search_frontier_investigator_terminals (
    event_id TEXT PRIMARY KEY REFERENCES search_frontier_investigator_sessions(event_id)
        ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    terminal_at TEXT NOT NULL,
    FOREIGN KEY (event_id, case_id)
        REFERENCES search_frontier_investigator_sessions(event_id, case_id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER search_frontier_investigator_triggers_no_update
BEFORE UPDATE ON search_frontier_investigator_triggers
BEGIN SELECT RAISE(ABORT, 'investigator trigger is immutable'); END;
CREATE TRIGGER search_frontier_investigator_triggers_no_delete
BEFORE DELETE ON search_frontier_investigator_triggers
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator trigger is immutable'); END;
CREATE TRIGGER search_frontier_investigator_event_acks_no_update
BEFORE UPDATE ON search_frontier_investigator_event_acks
BEGIN SELECT RAISE(ABORT, 'investigator event acknowledgement is immutable'); END;
CREATE TRIGGER search_frontier_investigator_event_acks_no_delete
BEFORE DELETE ON search_frontier_investigator_event_acks
WHEN EXISTS (
    SELECT 1 FROM cases WHERE case_id=(
        SELECT case_id FROM search_frontier_investigator_triggers WHERE event_id=OLD.event_id
    )
)
BEGIN SELECT RAISE(ABORT, 'investigator event acknowledgement is immutable'); END;
CREATE TRIGGER search_frontier_investigator_sessions_no_update
BEFORE UPDATE ON search_frontier_investigator_sessions
BEGIN SELECT RAISE(ABORT, 'investigator session is immutable'); END;
CREATE TRIGGER search_frontier_investigator_sessions_no_delete
BEFORE DELETE ON search_frontier_investigator_sessions
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator session is immutable'); END;
CREATE TRIGGER search_frontier_investigator_active_sessions_no_update
BEFORE UPDATE ON search_frontier_investigator_active_sessions
BEGIN SELECT RAISE(ABORT, 'investigator active session is immutable'); END;
CREATE TRIGGER search_frontier_investigator_active_sessions_no_delete
BEFORE DELETE ON search_frontier_investigator_active_sessions
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
AND NOT EXISTS (
    SELECT 1 FROM search_frontier_investigator_terminals WHERE event_id=OLD.event_id
)
BEGIN SELECT RAISE(ABORT, 'investigator active session lacks terminal'); END;
CREATE TRIGGER search_frontier_investigator_terminals_no_update
BEFORE UPDATE ON search_frontier_investigator_terminals
BEGIN SELECT RAISE(ABORT, 'investigator terminal is immutable'); END;
CREATE TRIGGER search_frontier_investigator_terminals_no_delete
BEFORE DELETE ON search_frontier_investigator_terminals
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'investigator terminal is immutable'); END;
PRAGMA user_version = 29;
