CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    symptom TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS probe_manifests (
    probe_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
    PRIMARY KEY (probe_id, version)
) STRICT;

CREATE TABLE IF NOT EXISTS probe_executions (
    execution_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    probe_id TEXT NOT NULL,
    probe_version INTEGER NOT NULL,
    status TEXT NOT NULL,
    parameters_json TEXT NOT NULL CHECK (json_valid(parameters_json)),
    started_at TEXT NOT NULL,
    finished_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    captured_at TEXT NOT NULL,
    UNIQUE (case_id, source_id)
) STRICT;

CREATE TABLE IF NOT EXISTS inventory_current (
    category TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    observed_at TEXT NOT NULL,
    PRIMARY KEY (category, fact_key)
) STRICT;

CREATE TABLE IF NOT EXISTS inventory_history (
    history_id INTEGER PRIMARY KEY,
    category TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    observed_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    case_id TEXT REFERENCES cases(case_id) ON DELETE SET NULL,
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS bookmarks (
    source TEXT PRIMARY KEY,
    position TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE,
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
    media_type TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS artifact_cases (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    PRIMARY KEY (artifact_id, case_id)
) STRICT;

CREATE INDEX IF NOT EXISTS evidence_case_captured
ON evidence(case_id, captured_at);

CREATE INDEX IF NOT EXISTS inventory_history_key_observed
ON inventory_history(category, fact_key, observed_at);

PRAGMA user_version = 1;
