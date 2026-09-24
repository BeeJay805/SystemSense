-- Widen snapshot custody in place. Admission and execution-link foreign keys
-- continue to reference this table name, including all existing v1 rows.
DROP TRIGGER candidate_decision_snapshots_no_update;
DROP TRIGGER candidate_decision_snapshots_no_delete;
DROP INDEX candidate_decision_snapshots_case_epoch;

CREATE TABLE candidate_decision_snapshots_v2 (
    snapshot_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
    serializer_version TEXT NOT NULL CHECK (
        (schema_version = 1 AND serializer_version = 'candidate-decision-json-v1') OR
        (schema_version = 2 AND serializer_version = 'frontier-rank-json-v1')
    ),
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

INSERT INTO candidate_decision_snapshots_v2 SELECT * FROM candidate_decision_snapshots;
DROP TABLE candidate_decision_snapshots;
ALTER TABLE candidate_decision_snapshots_v2 RENAME TO candidate_decision_snapshots;

CREATE INDEX candidate_decision_snapshots_case_epoch
ON candidate_decision_snapshots(case_id, epoch_state_version, captured_at);

CREATE TRIGGER candidate_decision_snapshots_no_update
BEFORE UPDATE ON candidate_decision_snapshots
BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
CREATE TRIGGER candidate_decision_snapshots_no_delete
BEFORE DELETE ON candidate_decision_snapshots
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
