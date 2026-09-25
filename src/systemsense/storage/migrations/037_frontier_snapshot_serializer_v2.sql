-- Preserve immutable v1 bytes while allowing new frontier representation v2.
-- Rebuild under the existing FK-safe migration runner; no row is rewritten.
DROP TRIGGER candidate_decision_snapshots_no_update;
DROP TRIGGER candidate_decision_snapshots_no_delete;
DROP TRIGGER frontier_packet_snapshot_bindings_no_delete;
DROP INDEX candidate_decision_snapshots_case_epoch;

CREATE TABLE candidate_decision_snapshots_v3 (
    snapshot_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
    serializer_version TEXT NOT NULL CHECK (
        (schema_version = 1 AND serializer_version = 'candidate-decision-json-v1') OR
        (schema_version = 2 AND serializer_version IN ('frontier-rank-json-v1', 'frontier-rank-json-v2'))
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

INSERT INTO candidate_decision_snapshots_v3 SELECT * FROM candidate_decision_snapshots;
DROP TABLE candidate_decision_snapshots;
ALTER TABLE candidate_decision_snapshots_v3 RENAME TO candidate_decision_snapshots;

CREATE INDEX candidate_decision_snapshots_case_epoch
ON candidate_decision_snapshots(case_id, epoch_state_version, captured_at);

CREATE TRIGGER candidate_decision_snapshots_no_update
BEFORE UPDATE ON candidate_decision_snapshots
BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
CREATE TRIGGER candidate_decision_snapshots_no_delete
BEFORE DELETE ON candidate_decision_snapshots
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
CREATE TRIGGER frontier_packet_snapshot_bindings_no_delete BEFORE DELETE ON frontier_packet_snapshot_bindings
WHEN EXISTS (SELECT 1 FROM candidate_decision_snapshots WHERE snapshot_id=OLD.snapshot_id)
BEGIN SELECT RAISE(ABORT, 'frontier packet binding is immutable'); END;

PRAGMA user_version = 37;
