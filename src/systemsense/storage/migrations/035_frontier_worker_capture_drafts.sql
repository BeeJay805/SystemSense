-- Private raw worker-call custody. These bytes have not passed privacy review,
-- tokenizer parity, independent outcome checking, or training admission.
CREATE TABLE frontier_worker_capture_drafts (
    snapshot_id TEXT PRIMARY KEY REFERENCES candidate_decision_snapshots(snapshot_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    capture_bytes BLOB NOT NULL CHECK (length(capture_bytes) BETWEEN 1 AND 2097152),
    capture_sha256 TEXT NOT NULL CHECK (length(capture_sha256) = 64),
    captured_at TEXT NOT NULL,
    privacy_review_status TEXT NOT NULL CHECK (privacy_review_status = 'unreviewed'),
    training_admissible INTEGER NOT NULL CHECK (training_admissible = 0)
) STRICT;

CREATE TRIGGER frontier_worker_capture_drafts_no_update
BEFORE UPDATE ON frontier_worker_capture_drafts
BEGIN SELECT RAISE(ABORT, 'frontier worker capture draft is immutable'); END;

CREATE TRIGGER frontier_worker_capture_drafts_no_delete
BEFORE DELETE ON frontier_worker_capture_drafts
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'frontier worker capture draft is immutable'); END;

PRAGMA user_version = 35;
