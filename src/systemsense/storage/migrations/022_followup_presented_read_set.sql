-- Bind the exact current-case evidence shown to a decision model to the
-- admission transaction. Unrelated case writes may advance the generation.
ALTER TABLE collection_followup_admissions
ADD COLUMN presented_read_set_required INTEGER NOT NULL DEFAULT 0
    CHECK (presented_read_set_required IN (0, 1));

CREATE TABLE collection_followup_read_set_checks (
    admission_id TEXT PRIMARY KEY REFERENCES collection_followup_admissions(admission_id)
        ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    decision_snapshot_id TEXT REFERENCES decision_snapshots(snapshot_id) ON DELETE CASCADE,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    read_set_json TEXT NOT NULL CHECK (json_valid(read_set_json)),
    read_set_sha256 TEXT NOT NULL CHECK (length(read_set_sha256) = 64),
    frozen_generation INTEGER NOT NULL CHECK (frozen_generation >= 1),
    checked_generation INTEGER NOT NULL CHECK (checked_generation >= frozen_generation),
    generation_advanced INTEGER NOT NULL CHECK (generation_advanced IN (0, 1)),
    unprotected_historical_count INTEGER NOT NULL
        CHECK (unprotected_historical_count BETWEEN 0 AND 256),
    checked_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER collection_followup_read_set_checks_no_update
BEFORE UPDATE ON collection_followup_read_set_checks
BEGIN SELECT RAISE(ABORT, 'follow-up read-set check is immutable'); END;

CREATE TRIGGER collection_followup_read_set_checks_no_delete
BEFORE DELETE ON collection_followup_read_set_checks
WHEN EXISTS (SELECT 1 FROM collection_followup_admissions
             WHERE admission_id=OLD.admission_id)
BEGIN SELECT RAISE(ABORT, 'follow-up read-set check is immutable'); END;

PRAGMA user_version = 22;
