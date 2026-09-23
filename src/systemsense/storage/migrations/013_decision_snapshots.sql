-- Case-scoped, append-only copies of the exact normalized next-probe request.
-- These are private training/replay inputs, not export-approved artifacts or outcomes.
CREATE TABLE decision_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    serializer_version TEXT NOT NULL CHECK (serializer_version = 'decision-request-json-v1'),
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    correlation_id TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    request_json TEXT NOT NULL CHECK (json_valid(request_json)),
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    candidate_probe_ids_json TEXT NOT NULL CHECK (json_valid(candidate_probe_ids_json)),
    probe_manifest_refs_json TEXT NOT NULL CHECK (json_valid(probe_manifest_refs_json)),
    laya_projection_version TEXT NOT NULL CHECK (laya_projection_version = 'laya-preworker-v1'),
    laya_state_json TEXT NOT NULL CHECK (json_valid(laya_state_json)),
    laya_evidence_json TEXT NOT NULL CHECK (json_valid(laya_evidence_json)),
    laya_candidates_json TEXT NOT NULL CHECK (json_valid(laya_candidates_json)),
    laya_projection_sha256 TEXT NOT NULL CHECK (length(laya_projection_sha256) = 64)
) STRICT;

CREATE INDEX decision_snapshots_case_capture
ON decision_snapshots(case_id, captured_at, snapshot_id);

CREATE TRIGGER decision_snapshots_no_update
BEFORE UPDATE ON decision_snapshots
BEGIN
    SELECT RAISE(ABORT, 'decision snapshot is immutable');
END;

CREATE TRIGGER decision_snapshots_no_delete
BEFORE DELETE ON decision_snapshots
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id = OLD.case_id)
BEGIN
    SELECT RAISE(ABORT, 'decision snapshot is immutable');
END;

PRAGMA user_version = 13;
