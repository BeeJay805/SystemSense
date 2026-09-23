-- A terminal record is evidence of a separately authorized reconciliation, not
-- permission to repeat an execution. No existing v8 execution is unlocked.
CREATE TABLE repair_execution_terminals (
    execution_id TEXT PRIMARY KEY REFERENCES repair_execution_claims(execution_id) ON DELETE RESTRICT,
    claim_id TEXT NOT NULL REFERENCES repair_approval_claims(claim_id) ON DELETE RESTRICT,
    proposal_id TEXT NOT NULL REFERENCES repair_proposals(proposal_id) ON DELETE RESTRICT,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    proposal_digest TEXT NOT NULL,
    case_state_version INTEGER NOT NULL CHECK (case_state_version >= 0),
    target_scope_digest TEXT NOT NULL,
    target_key TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    authorization_digest TEXT NOT NULL,
    journal_state TEXT NOT NULL,
    journal_digest TEXT NOT NULL,
    executor_stop_digest TEXT NOT NULL,
    executor_stopped_at TEXT NOT NULL,
    setting_evidence_id TEXT NOT NULL,
    setting_evidence_digest TEXT NOT NULL,
    setting_observed_at TEXT NOT NULL,
    affected_evidence_id TEXT NOT NULL,
    affected_evidence_digest TEXT NOT NULL,
    affected_observed_at TEXT NOT NULL,
    direct_evidence_id TEXT NOT NULL,
    direct_evidence_digest TEXT NOT NULL,
    direct_observed_at TEXT NOT NULL,
    setting_observed TEXT NOT NULL CHECK (setting_observed IN ('original', 'intended', 'diverged', 'unavailable')),
    symptom_outcome TEXT NOT NULL CHECK (symptom_outcome IN ('recovered', 'not_recovered', 'unavailable')),
    affected_route_proven INTEGER NOT NULL CHECK (affected_route_proven IN (0, 1)),
    direct_control_healthy INTEGER NOT NULL CHECK (direct_control_healthy IN (0, 1)),
    outcome TEXT NOT NULL CHECK (outcome IN ('recovered', 'applied_unverified', 'original_observed', 'diverged', 'uncertain')),
    reviewer_id TEXT NOT NULL,
    reviewer_sid_digest TEXT NOT NULL,
    terminal_approval_id TEXT NOT NULL UNIQUE,
    terminal_approval_digest TEXT NOT NULL,
    assessment_digest TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    CHECK (length(target_scope_digest) = 64 AND length(target_key) = 64),
    CHECK (length(proposal_digest) = 64 AND length(authorization_digest) = 64),
    CHECK (length(journal_digest) = 64 AND length(executor_stop_digest) = 64),
    CHECK (length(setting_evidence_digest) = 64 AND length(affected_evidence_digest) = 64),
    CHECK (length(direct_evidence_digest) = 64 AND length(reviewer_sid_digest) = 64),
    CHECK (length(terminal_approval_digest) = 64 AND length(assessment_digest) = 64),
    CHECK (setting_evidence_id != affected_evidence_id AND setting_evidence_id != direct_evidence_id
        AND affected_evidence_id != direct_evidence_id),
    CHECK (outcome != 'recovered' OR (
        setting_observed = 'intended' AND symptom_outcome = 'recovered'
        AND affected_route_proven = 1 AND direct_control_healthy = 1
    ))
) STRICT;

CREATE TRIGGER repair_execution_terminals_exact_binding
BEFORE INSERT ON repair_execution_terminals
WHEN NOT EXISTS (
    SELECT 1 FROM repair_execution_claims AS execution
    JOIN repair_execution_target_locks AS target ON target.execution_id = execution.execution_id
    JOIN repair_plan_heads AS head ON head.case_id = execution.case_id
    JOIN cases AS case_record ON case_record.case_id = execution.case_id
    WHERE execution.execution_id = NEW.execution_id
      AND execution.state IN ('prepared', 'applying', 'interrupted_uncertain')
      AND execution.claim_id = NEW.claim_id
      AND execution.proposal_id = NEW.proposal_id
      AND execution.case_id = NEW.case_id
      AND execution.proposal_digest = NEW.proposal_digest
      AND execution.case_state_version = NEW.case_state_version
      AND execution.target_scope_digest = NEW.target_scope_digest
      AND execution.authorization_id = NEW.authorization_id
      AND execution.authorization_digest = NEW.authorization_digest
      AND target.target_key = NEW.target_key
      AND head.active_proposal_id = NEW.proposal_id
      AND head.active_proposal_digest = NEW.proposal_digest
      AND head.case_state_version = NEW.case_state_version
      AND case_record.state_version = NEW.case_state_version
)
BEGIN
    SELECT RAISE(ABORT, 'repair terminal exact binding is invalid');
END;

CREATE TRIGGER repair_execution_terminals_no_update
BEFORE UPDATE ON repair_execution_terminals
BEGIN
    SELECT RAISE(ABORT, 'repair terminal is immutable');
END;
CREATE TRIGGER repair_execution_terminals_no_delete
BEFORE DELETE ON repair_execution_terminals
BEGIN
    SELECT RAISE(ABORT, 'repair terminal is immutable');
END;

-- Replace v8's permanent-reservation trigger with a terminal-record gate.
DROP TRIGGER repair_execution_target_locks_no_delete;
CREATE TRIGGER repair_execution_target_locks_terminal_delete
BEFORE DELETE ON repair_execution_target_locks
WHEN NOT EXISTS (
    SELECT 1 FROM repair_execution_terminals AS terminal
    WHERE terminal.execution_id = OLD.execution_id AND terminal.target_key = OLD.target_key
)
BEGIN
    SELECT RAISE(ABORT, 'repair target lock has no exact terminal record');
END;

DROP TRIGGER repair_plan_heads_execution_fence;
CREATE TRIGGER repair_plan_heads_execution_fence
BEFORE UPDATE ON repair_plan_heads
WHEN EXISTS (
    SELECT 1 FROM repair_execution_claims AS execution
    WHERE execution.proposal_id = OLD.active_proposal_id
      AND NOT EXISTS (SELECT 1 FROM repair_execution_terminals AS terminal
                      WHERE terminal.execution_id = execution.execution_id)
)
BEGIN
    SELECT RAISE(ABORT, 'repair plan head has unresolved execution');
END;

DROP TRIGGER cases_repair_execution_state_fence;
CREATE TRIGGER cases_repair_execution_state_fence
BEFORE UPDATE OF state_version ON cases
WHEN NEW.state_version != OLD.state_version AND EXISTS (
    SELECT 1 FROM repair_execution_claims AS execution
    WHERE execution.case_id = OLD.case_id
      AND NOT EXISTS (SELECT 1 FROM repair_execution_terminals AS terminal
                      WHERE terminal.execution_id = execution.execution_id)
)
BEGIN
    SELECT RAISE(ABORT, 'case has unresolved repair execution');
END;

PRAGMA user_version = 9;
