-- One selected process identity per case. Source evidence can follow normal raw
-- retention; its digest and exact selection provenance remain in this row.
CREATE TABLE case_process_targets (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL UNIQUE,
    case_state_version INTEGER NOT NULL CHECK (case_state_version >= 0),
    evidence_id TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    pid INTEGER NOT NULL CHECK (pid > 0),
    creation_time TEXT NOT NULL,
    name TEXT NOT NULL,
    collection_started_at TEXT NOT NULL,
    collection_completed_at TEXT NOT NULL,
    omitted_process_count INTEGER NOT NULL CHECK (omitted_process_count >= 0),
    selected_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER case_process_targets_no_update
BEFORE UPDATE ON case_process_targets
BEGIN
    SELECT RAISE(ABORT, 'process target binding is immutable');
END;

PRAGMA user_version = 10;
