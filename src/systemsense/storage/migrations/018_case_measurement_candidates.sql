-- A case-scoped candidate is an immutable local lookup, never a host action or
-- replay permission. A later dispatcher must still revalidate and admit work.
CREATE TABLE case_measurement_candidates (
    candidate_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    probe_id TEXT NOT NULL,
    manifest_version INTEGER NOT NULL CHECK (manifest_version >= 1),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
    invocation_json TEXT NOT NULL CHECK (json_valid(invocation_json)),
    invocation_sha256 TEXT NOT NULL CHECK (length(invocation_sha256) = 64),
    observable TEXT NOT NULL,
    target_handle TEXT,
    source_evidence_id TEXT NOT NULL,
    source_evidence_sha256 TEXT NOT NULL CHECK (length(source_evidence_sha256) = 64),
    dependency_bindings_json TEXT NOT NULL CHECK (json_valid(dependency_bindings_json)),
    dependency_sha256 TEXT NOT NULL CHECK (length(dependency_sha256) = 64),
    binding_sha256 TEXT NOT NULL CHECK (length(binding_sha256) = 64),
    cost_ms INTEGER NOT NULL CHECK (cost_ms > 0 AND cost_ms <= 120000),
    resource_class TEXT NOT NULL,
    safety_class TEXT NOT NULL CHECK (safety_class IN ('R0', 'R1')),
    description TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE (case_id, epoch_state_version, binding_sha256)
) STRICT;

CREATE INDEX case_measurement_candidates_case_epoch
ON case_measurement_candidates(case_id, epoch_state_version, issued_at, candidate_id);

CREATE TRIGGER case_measurement_candidates_no_update
BEFORE UPDATE ON case_measurement_candidates
BEGIN
    SELECT RAISE(ABORT, 'measurement candidate is immutable');
END;

CREATE TRIGGER case_measurement_candidates_no_delete
BEFORE DELETE ON case_measurement_candidates
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id = OLD.case_id)
BEGIN
    SELECT RAISE(ABORT, 'measurement candidate is immutable');
END;

PRAGMA user_version = 18;
