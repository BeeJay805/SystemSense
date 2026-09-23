-- Distinguish the frozen provider input from the later durable write. Legacy
-- snapshots retain NULL: their freeze time is unknown, not the capture time.
ALTER TABLE decision_snapshots ADD COLUMN request_frozen_at TEXT;

-- Hash-only worker presentation provenance. The trace is metadata about what
-- the provider saw; it grants no probe authority and is not a training label.
CREATE TABLE decision_presentation_traces (
    snapshot_id TEXT PRIMARY KEY REFERENCES decision_snapshots(snapshot_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    provider_id TEXT NOT NULL,
    format_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    projection_sha256 TEXT NOT NULL CHECK (length(projection_sha256) = 64),
    trace_json TEXT NOT NULL CHECK (json_valid(trace_json)),
    trace_sha256 TEXT NOT NULL CHECK (length(trace_sha256) = 64)
) STRICT;

CREATE TRIGGER decision_presentation_traces_no_update
BEFORE UPDATE ON decision_presentation_traces
BEGIN
    SELECT RAISE(ABORT, 'decision presentation trace is immutable');
END;

CREATE TRIGGER decision_presentation_traces_no_delete
BEFORE DELETE ON decision_presentation_traces
WHEN EXISTS (SELECT 1 FROM decision_snapshots WHERE snapshot_id = OLD.snapshot_id)
BEGIN
    SELECT RAISE(ABORT, 'decision presentation trace is immutable');
END;

PRAGMA user_version = 15;
