-- A projected diagnostic result is bound to one immutable admission.
CREATE TABLE diagnostic_progress (
    admission_id TEXT PRIMARY KEY REFERENCES diagnostic_intent_admissions(admission_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    branch_id TEXT NOT NULL,
    terminal_sha256 TEXT NOT NULL CHECK(length(terminal_sha256)=64),
    admission_sha256 TEXT NOT NULL CHECK(length(admission_sha256)=64),
    record_json TEXT NOT NULL CHECK(json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256)=64),
    projected_at TEXT NOT NULL
) STRICT;
CREATE INDEX diagnostic_progress_case_branch ON diagnostic_progress(case_id, branch_id);
CREATE TRIGGER diagnostic_progress_no_update BEFORE UPDATE ON diagnostic_progress
BEGIN SELECT RAISE(ABORT, 'diagnostic progress is immutable'); END;
CREATE TRIGGER diagnostic_progress_no_delete BEFORE DELETE ON diagnostic_progress
WHEN EXISTS(SELECT 1 FROM diagnostic_intent_admissions WHERE admission_id=OLD.admission_id)
  OR EXISTS(SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'diagnostic progress is immutable'); END;
PRAGMA user_version = 27;
