-- Same-epoch model-directed follow-up is a distinct, append-only provenance lane.
-- An admission is not evidence that a collector ran. Missing outcome links stay
-- uncertain on recovery and never authorize replay.
CREATE TABLE collection_followup_admissions (
    admission_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    trigger_execution_id TEXT NOT NULL REFERENCES probe_executions(execution_id) ON DELETE CASCADE,
    evidence_generation INTEGER NOT NULL CHECK (evidence_generation >= 1),
    trigger_evidence_sha256 TEXT NOT NULL CHECK (length(trigger_evidence_sha256) = 64),
    decision_snapshot_id TEXT REFERENCES decision_snapshots(snapshot_id) ON DELETE CASCADE,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    invocation_json TEXT NOT NULL CHECK (json_valid(invocation_json)),
    invocation_sha256 TEXT NOT NULL CHECK (length(invocation_sha256) = 64),
    dedupe_key TEXT NOT NULL,
    task_id TEXT NOT NULL,
    estimated_cost_ms INTEGER NOT NULL CHECK (estimated_cost_ms > 0 AND estimated_cost_ms <= 120000),
    admitted_at TEXT NOT NULL,
    UNIQUE (case_id, epoch_state_version, task_id),
    UNIQUE (case_id, epoch_state_version, dedupe_key)
) STRICT;

CREATE INDEX collection_followup_admissions_case_epoch
ON collection_followup_admissions(case_id, epoch_state_version, admitted_at, admission_id);

CREATE TRIGGER collection_followup_admissions_no_update
BEFORE UPDATE ON collection_followup_admissions
BEGIN
    SELECT RAISE(ABORT, 'follow-up admission is immutable');
END;

CREATE TRIGGER collection_followup_admissions_no_delete
BEFORE DELETE ON collection_followup_admissions
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id = OLD.case_id)
BEGIN
    SELECT RAISE(ABORT, 'follow-up admission is immutable');
END;

ALTER TABLE probe_executions
ADD COLUMN followup_admission_id TEXT REFERENCES collection_followup_admissions(admission_id)
    ON DELETE CASCADE;

CREATE UNIQUE INDEX probe_executions_followup_admission_unique
ON probe_executions(followup_admission_id)
WHERE followup_admission_id IS NOT NULL;

CREATE TRIGGER probe_executions_followup_admission_no_update
BEFORE UPDATE OF followup_admission_id ON probe_executions
BEGIN
    SELECT RAISE(ABORT, 'follow-up execution identity is immutable');
END;

CREATE TABLE collection_followup_execution_links (
    admission_id TEXT PRIMARY KEY REFERENCES collection_followup_admissions(admission_id)
        ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    execution_id TEXT NOT NULL UNIQUE REFERENCES probe_executions(execution_id) ON DELETE CASCADE,
    linked_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER collection_followup_execution_links_no_update
BEFORE UPDATE ON collection_followup_execution_links
BEGIN
    SELECT RAISE(ABORT, 'follow-up outcome link is immutable');
END;

CREATE TRIGGER collection_followup_execution_links_no_delete
BEFORE DELETE ON collection_followup_execution_links
WHEN EXISTS (SELECT 1 FROM collection_followup_admissions WHERE admission_id = OLD.admission_id)
BEGIN
    SELECT RAISE(ABORT, 'follow-up outcome link is immutable');
END;

PRAGMA user_version = 17;
