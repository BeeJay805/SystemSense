-- Immutable advisory requests and bounded, coordinator-owned delivery state.
CREATE TABLE deep_mailbox (
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
    basis_sha256 TEXT NOT NULL CHECK(length(basis_sha256)=64),
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    task_json TEXT NOT NULL CHECK(json_valid(task_json)),
    status TEXT NOT NULL CHECK(status IN ('running','applied','rejected','cancelled','interrupted','failed')),
    result_json TEXT CHECK(result_json IS NULL OR json_valid(result_json)),
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(case_id, request_sha256),
    UNIQUE(case_id, basis_sha256)
) STRICT;
CREATE UNIQUE INDEX deep_mailbox_one_running ON deep_mailbox(case_id) WHERE status='running';
CREATE TRIGGER deep_mailbox_immutable_basis BEFORE UPDATE ON deep_mailbox
WHEN NEW.case_id<>OLD.case_id OR NEW.request_sha256<>OLD.request_sha256
 OR NEW.basis_sha256<>OLD.basis_sha256 OR NEW.task_json<>OLD.task_json
 OR NEW.schema_version<>OLD.schema_version OR NEW.created_at<>OLD.created_at
BEGIN SELECT RAISE(ABORT, 'deep task basis is immutable'); END;
CREATE TRIGGER deep_mailbox_terminal BEFORE UPDATE ON deep_mailbox
WHEN OLD.status<>'running'
BEGIN SELECT RAISE(ABORT, 'deep mailbox terminal record is immutable'); END;
CREATE TRIGGER deep_mailbox_no_delete BEFORE DELETE ON deep_mailbox
WHEN EXISTS(SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'deep mailbox custody is immutable'); END;
PRAGMA user_version = 25;
