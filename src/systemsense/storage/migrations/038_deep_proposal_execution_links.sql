-- A deep mailbox response caused an exact registered run only when the
-- coordinator carries its accepted proposal into the persisted plan instance.
CREATE TABLE deep_proposal_execution_links (
    case_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
    proposal_sha256 TEXT NOT NULL CHECK(length(proposal_sha256)=64),
    accepted_state_version INTEGER NOT NULL CHECK(accepted_state_version>=1),
    selected_state_version INTEGER NOT NULL CHECK(selected_state_version>=accepted_state_version),
    plan_instance_id TEXT NOT NULL,
    execution_id TEXT NOT NULL REFERENCES probe_executions(execution_id) ON DELETE CASCADE,
    probe_id TEXT NOT NULL,
    probe_version INTEGER NOT NULL CHECK(probe_version>=1),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64),
    manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
    invocation_json TEXT NOT NULL CHECK(json_valid(invocation_json)),
    invocation_sha256 TEXT NOT NULL CHECK(length(invocation_sha256)=64),
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    PRIMARY KEY(execution_id),
    FOREIGN KEY(case_id,request_sha256) REFERENCES deep_mailbox(case_id,request_sha256) ON DELETE CASCADE
) STRICT;
CREATE INDEX deep_proposal_execution_links_case_source
ON deep_proposal_execution_links(case_id,request_sha256);
CREATE TRIGGER deep_proposal_execution_links_no_update
BEFORE UPDATE ON deep_proposal_execution_links
BEGIN SELECT RAISE(ABORT,'deep proposal execution link is immutable'); END;
CREATE TRIGGER deep_proposal_execution_links_no_delete
BEFORE DELETE ON deep_proposal_execution_links
WHEN EXISTS(SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT,'deep proposal execution link is immutable'); END;
PRAGMA user_version = 38;
