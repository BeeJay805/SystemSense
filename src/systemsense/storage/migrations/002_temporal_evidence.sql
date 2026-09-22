ALTER TABLE cases ADD COLUMN status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE cases ADD COLUMN state_version INTEGER NOT NULL DEFAULT 0 CHECK (state_version >= 0);
ALTER TABLE cases ADD COLUMN time_window_start TEXT;
ALTER TABLE cases ADD COLUMN time_window_end TEXT;
ALTER TABLE cases ADD COLUMN time_window_basis TEXT NOT NULL DEFAULT 'unknown';

ALTER TABLE probe_executions ADD COLUMN state_version INTEGER NOT NULL DEFAULT 0
CHECK (state_version >= 0);

ALTER TABLE evidence RENAME TO evidence_v1;

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    observed_at TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    execution_id TEXT,
    dedupe_key TEXT NOT NULL,
    time_basis TEXT NOT NULL,
    time_quality TEXT NOT NULL,
    UNIQUE (case_id, dedupe_key)
) STRICT;

INSERT INTO evidence (
    evidence_id,
    case_id,
    source_id,
    record_json,
    observed_at,
    captured_at,
    execution_id,
    dedupe_key,
    time_basis,
    time_quality
)
SELECT
    evidence_id,
    case_id,
    source_id,
    record_json,
    captured_at,
    captured_at,
    NULL,
    source_id,
    'legacy_case_opened',
    'unknown'
FROM evidence_v1;

DROP TABLE evidence_v1;

CREATE INDEX evidence_case_observed
ON evidence(case_id, observed_at);

CREATE INDEX evidence_case_captured
ON evidence(case_id, captured_at);

ALTER TABLE inventory_current ADD COLUMN captured_at TEXT;
ALTER TABLE inventory_current ADD COLUMN time_basis TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE inventory_current ADD COLUMN time_quality TEXT NOT NULL DEFAULT 'unknown';
UPDATE inventory_current SET captured_at = observed_at WHERE captured_at IS NULL;

ALTER TABLE inventory_history ADD COLUMN captured_at TEXT;
ALTER TABLE inventory_history ADD COLUMN time_basis TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE inventory_history ADD COLUMN time_quality TEXT NOT NULL DEFAULT 'unknown';
UPDATE inventory_history SET captured_at = observed_at WHERE captured_at IS NULL;

ALTER TABLE audit_events ADD COLUMN occurred_at TEXT;
ALTER TABLE audit_events ADD COLUMN persisted_at TEXT;
UPDATE audit_events
SET occurred_at = created_at,
    persisted_at = created_at
WHERE occurred_at IS NULL OR persisted_at IS NULL;

PRAGMA user_version = 2;
