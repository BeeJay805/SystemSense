-- An admitted read-only test is immutable; execution and evaluation append custody.
CREATE TABLE diagnostic_intent_admissions (
    admission_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    intent_id TEXT NOT NULL,
    epoch_state_version INTEGER NOT NULL CHECK(epoch_state_version >= 0),
    plan_instance_id TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK(json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256)=64),
    admitted_at TEXT NOT NULL,
    UNIQUE(case_id, intent_id),
    UNIQUE(case_id, epoch_state_version, plan_instance_id)
) STRICT;
CREATE TABLE diagnostic_intent_dispatch_claims (
    admission_id TEXT PRIMARY KEY REFERENCES diagnostic_intent_admissions(admission_id) ON DELETE CASCADE,
    claim_id TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL CHECK(json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256)=64),
    claimed_at TEXT NOT NULL
) STRICT;
CREATE TABLE diagnostic_intent_execution_links (
    admission_id TEXT PRIMARY KEY REFERENCES diagnostic_intent_admissions(admission_id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL UNIQUE REFERENCES probe_executions(execution_id),
    record_json TEXT NOT NULL CHECK(json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256)=64)
) STRICT;
CREATE TABLE diagnostic_intent_terminals (
    admission_id TEXT PRIMARY KEY REFERENCES diagnostic_intent_admissions(admission_id) ON DELETE CASCADE,
    record_json TEXT NOT NULL CHECK(json_valid(record_json)),
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256)=64)
) STRICT;
CREATE TRIGGER diagnostic_admissions_no_update BEFORE UPDATE ON diagnostic_intent_admissions
BEGIN SELECT RAISE(ABORT, 'diagnostic admission is immutable'); END;
CREATE TRIGGER diagnostic_admissions_no_delete BEFORE DELETE ON diagnostic_intent_admissions
WHEN EXISTS(SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'diagnostic admission is immutable'); END;
CREATE TRIGGER diagnostic_links_no_update BEFORE UPDATE ON diagnostic_intent_execution_links
BEGIN SELECT RAISE(ABORT, 'diagnostic execution link is immutable'); END;
CREATE TRIGGER diagnostic_claims_no_update BEFORE UPDATE ON diagnostic_intent_dispatch_claims
BEGIN SELECT RAISE(ABORT, 'diagnostic dispatch claim is immutable'); END;
CREATE TRIGGER diagnostic_claims_no_delete BEFORE DELETE ON diagnostic_intent_dispatch_claims
WHEN EXISTS(SELECT 1 FROM diagnostic_intent_admissions WHERE admission_id=OLD.admission_id)
BEGIN SELECT RAISE(ABORT, 'diagnostic dispatch claim is immutable'); END;
CREATE TRIGGER diagnostic_links_no_delete BEFORE DELETE ON diagnostic_intent_execution_links
WHEN EXISTS(SELECT 1 FROM diagnostic_intent_admissions WHERE admission_id=OLD.admission_id)
BEGIN SELECT RAISE(ABORT, 'diagnostic execution link is immutable'); END;
CREATE TRIGGER diagnostic_terminals_no_update BEFORE UPDATE ON diagnostic_intent_terminals
BEGIN SELECT RAISE(ABORT, 'diagnostic terminal is immutable'); END;
CREATE TRIGGER diagnostic_terminals_no_delete BEFORE DELETE ON diagnostic_intent_terminals
WHEN EXISTS(SELECT 1 FROM diagnostic_intent_admissions WHERE admission_id=OLD.admission_id)
BEGIN SELECT RAISE(ABORT, 'diagnostic terminal is immutable'); END;
PRAGMA user_version = 26;
