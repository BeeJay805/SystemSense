-- Frozen candidate-ID model input/output and exact coordinator-owned execution custody.
-- These private rows are not dispatch permits, evidence of runner target/window use,
-- or training labels. They do not alter legacy decision_snapshots.
CREATE TABLE candidate_decision_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    serializer_version TEXT NOT NULL CHECK (serializer_version = 'candidate-decision-json-v1'),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    correlation_id TEXT NOT NULL,
    request_frozen_at TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    request_json TEXT NOT NULL CHECK (json_valid(request_json)),
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL CHECK (json_valid(response_json)),
    response_sha256 TEXT NOT NULL CHECK (length(response_sha256) = 64),
    candidate_ids_json TEXT NOT NULL CHECK (json_valid(candidate_ids_json)),
    candidate_manifest_sha256 TEXT NOT NULL CHECK (length(candidate_manifest_sha256) = 64),
    registry_refs_json TEXT NOT NULL CHECK (json_valid(registry_refs_json)),
    registry_manifest_sha256 TEXT NOT NULL CHECK (length(registry_manifest_sha256) = 64)
) STRICT;

CREATE INDEX candidate_decision_snapshots_case_epoch
ON candidate_decision_snapshots(case_id, epoch_state_version, captured_at);

CREATE TABLE candidate_decision_execution_links (
    snapshot_id TEXT NOT NULL REFERENCES candidate_decision_snapshots(snapshot_id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES case_measurement_candidates(candidate_id),
    execution_id TEXT NOT NULL UNIQUE REFERENCES probe_executions(execution_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    executed_invocation_json TEXT NOT NULL CHECK (json_valid(executed_invocation_json)),
    executed_invocation_sha256 TEXT NOT NULL CHECK (length(executed_invocation_sha256) = 64),
    linked_at TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, candidate_id),
    UNIQUE (candidate_id)
) STRICT;

CREATE TRIGGER candidate_decision_snapshots_no_update
BEFORE UPDATE ON candidate_decision_snapshots
BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
CREATE TRIGGER candidate_decision_snapshots_no_delete
BEFORE DELETE ON candidate_decision_snapshots
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
CREATE TRIGGER candidate_decision_execution_links_no_update
BEFORE UPDATE ON candidate_decision_execution_links
BEGIN SELECT RAISE(ABORT, 'candidate decision execution link is immutable'); END;
CREATE TRIGGER candidate_decision_execution_links_no_delete
BEFORE DELETE ON candidate_decision_execution_links
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate decision execution link is immutable'); END;

PRAGMA user_version = 19;
