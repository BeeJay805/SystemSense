-- Advisory work is durable but does not grant authority to execute a probe.
-- Item identity and transitions are append-only; the current status is the
-- verified tip of its transition chain, not a mutable flag.
CREATE TABLE search_frontier_items (
    item_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    identity_json TEXT NOT NULL CHECK (json_valid(identity_json)),
    identity_sha256 TEXT NOT NULL CHECK (length(identity_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (case_id, identity_sha256)
) STRICT;

CREATE INDEX search_frontier_items_case_created
ON search_frontier_items(case_id, created_at, item_id);

CREATE TABLE search_frontier_transitions (
    item_id TEXT NOT NULL REFERENCES search_frontier_items(item_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
    transition_hash TEXT NOT NULL CHECK (length(transition_hash) = 64),
    PRIMARY KEY (item_id, ordinal)
) STRICT;

CREATE TABLE search_frontier_events (
    event_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    -- Keep the immutable event after raw evidence retention. Its bound record
    -- digest remains, and readback reports the source as unverifiable.
    source_evidence_id TEXT,
    source_execution_id TEXT REFERENCES probe_executions(execution_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('observation_added', 'task_completed')),
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    event_sha256 TEXT NOT NULL CHECK (length(event_sha256) = 64),
    persisted_at TEXT NOT NULL,
    CHECK (source_evidence_id IS NOT NULL OR source_execution_id IS NOT NULL)
) STRICT;

CREATE INDEX search_frontier_events_case_order
ON search_frontier_events(case_id, persisted_at, event_id);

CREATE TABLE search_frontier_event_acks (
    event_id TEXT PRIMARY KEY REFERENCES search_frontier_events(event_id) ON DELETE CASCADE,
    acknowledged_at TEXT NOT NULL
) STRICT;

-- Once the bounded exact outbox fills, a durable one-shot marker requires the
-- consumer to re-discover case evidence rather than silently lose coverage.
CREATE TABLE search_frontier_event_overflows (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    marker_json TEXT NOT NULL CHECK (json_valid(marker_json)),
    marker_sha256 TEXT NOT NULL CHECK (length(marker_sha256) = 64),
    marked_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER search_frontier_items_no_update BEFORE UPDATE ON search_frontier_items
BEGIN SELECT RAISE(ABORT, 'frontier item is immutable'); END;
CREATE TRIGGER search_frontier_items_no_delete BEFORE DELETE ON search_frontier_items
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'frontier item is immutable'); END;
CREATE TRIGGER search_frontier_transitions_no_update BEFORE UPDATE ON search_frontier_transitions
BEGIN SELECT RAISE(ABORT, 'frontier transition is immutable'); END;
CREATE TRIGGER search_frontier_transitions_no_delete BEFORE DELETE ON search_frontier_transitions
WHEN EXISTS (SELECT 1 FROM search_frontier_items WHERE item_id=OLD.item_id)
BEGIN SELECT RAISE(ABORT, 'frontier transition is immutable'); END;
CREATE TRIGGER search_frontier_events_no_update BEFORE UPDATE ON search_frontier_events
BEGIN SELECT RAISE(ABORT, 'frontier event is immutable'); END;
CREATE TRIGGER search_frontier_events_no_delete BEFORE DELETE ON search_frontier_events
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'frontier event is immutable'); END;
CREATE TRIGGER search_frontier_event_acks_no_update BEFORE UPDATE ON search_frontier_event_acks
BEGIN SELECT RAISE(ABORT, 'frontier event acknowledgement is immutable'); END;
CREATE TRIGGER search_frontier_event_acks_no_delete BEFORE DELETE ON search_frontier_event_acks
WHEN EXISTS (SELECT 1 FROM search_frontier_events WHERE event_id=OLD.event_id)
BEGIN SELECT RAISE(ABORT, 'frontier event acknowledgement is immutable'); END;
CREATE TRIGGER search_frontier_event_overflows_no_update BEFORE UPDATE ON search_frontier_event_overflows
BEGIN SELECT RAISE(ABORT, 'frontier overflow marker is immutable'); END;
CREATE TRIGGER search_frontier_event_overflows_no_delete BEFORE DELETE ON search_frontier_event_overflows
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'frontier overflow marker is immutable'); END;

PRAGMA user_version = 21;
