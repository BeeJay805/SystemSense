-- A candidate dispatch consumes a case budget reservation before worker access.
-- Admission and claim are append-only. Neither is model authority or a replay permit.
CREATE TABLE candidate_dispatch_admissions (
    admission_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    snapshot_id TEXT NOT NULL REFERENCES candidate_decision_snapshots(snapshot_id),
    candidate_id TEXT NOT NULL UNIQUE REFERENCES case_measurement_candidates(candidate_id),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    task_id TEXT NOT NULL,
    invocation_sha256 TEXT NOT NULL CHECK (length(invocation_sha256) = 64),
    cost_ms INTEGER NOT NULL CHECK (cost_ms > 0 AND cost_ms <= 120000),
    admitted_at TEXT NOT NULL,
    UNIQUE (case_id, epoch_state_version, task_id)
) STRICT;

CREATE INDEX candidate_dispatch_admissions_case_epoch
ON candidate_dispatch_admissions(case_id, epoch_state_version, admitted_at);

CREATE TABLE candidate_dispatch_claims (
    admission_id TEXT PRIMARY KEY REFERENCES candidate_dispatch_admissions(admission_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    task_id TEXT NOT NULL,
    invocation_sha256 TEXT NOT NULL CHECK (length(invocation_sha256) = 64),
    claimed_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER candidate_dispatch_admissions_no_update
BEFORE UPDATE ON candidate_dispatch_admissions
BEGIN SELECT RAISE(ABORT, 'candidate dispatch admission is immutable'); END;
CREATE TRIGGER candidate_dispatch_admissions_no_delete
BEFORE DELETE ON candidate_dispatch_admissions
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate dispatch admission is immutable'); END;
CREATE TRIGGER candidate_dispatch_claims_no_update
BEFORE UPDATE ON candidate_dispatch_claims
BEGIN SELECT RAISE(ABORT, 'candidate dispatch claim is immutable'); END;
CREATE TRIGGER candidate_dispatch_claims_no_delete
BEFORE DELETE ON candidate_dispatch_claims
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate dispatch claim is immutable'); END;

PRAGMA user_version = 20;
