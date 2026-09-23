-- Explicit provenance from a frozen next-probe decision to an actual persisted run.
-- An unlinked candidate has no observed outcome; no timestamp or state-version join
-- may infer that it was executed. A linked run is not a model selection or a
-- useful-probe training label; another coordinator branch may have chosen it.
CREATE TABLE decision_execution_links (
    snapshot_id TEXT NOT NULL REFERENCES decision_snapshots(snapshot_id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL REFERENCES probe_executions(execution_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    probe_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    PRIMARY KEY (snapshot_id, execution_id),
    UNIQUE (execution_id)
) STRICT;

CREATE INDEX decision_execution_links_case_snapshot
ON decision_execution_links(case_id, snapshot_id);

CREATE TRIGGER decision_execution_links_no_update
BEFORE UPDATE ON decision_execution_links
BEGIN
    SELECT RAISE(ABORT, 'decision execution link is immutable');
END;

CREATE TRIGGER decision_execution_links_no_delete
BEFORE DELETE ON decision_execution_links
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id = OLD.case_id)
BEGIN
    SELECT RAISE(ABORT, 'decision execution link is immutable');
END;

PRAGMA user_version = 14;
