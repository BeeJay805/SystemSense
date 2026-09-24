-- Bind an exact candidate dispatch to the persisted observation that triggered it.
-- This append-only row is written with the one-shot candidate admission.
CREATE TABLE candidate_followup_parents (
    admission_id TEXT PRIMARY KEY REFERENCES candidate_dispatch_admissions(admission_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    trigger_execution_id TEXT NOT NULL REFERENCES probe_executions(execution_id),
    trigger_evidence_sha256 TEXT NOT NULL CHECK (length(trigger_evidence_sha256) = 64),
    bound_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER candidate_followup_parents_no_update
BEFORE UPDATE ON candidate_followup_parents
BEGIN SELECT RAISE(ABORT, 'candidate follow-up parent is immutable'); END;
CREATE TRIGGER candidate_followup_parents_no_delete
BEFORE DELETE ON candidate_followup_parents
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate follow-up parent is immutable'); END;

PRAGMA user_version = 34;
