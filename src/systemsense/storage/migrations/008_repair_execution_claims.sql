-- An applying row is committed before any external effect. Both applying and
-- interrupted_uncertain reserve their exact target scope until a future,
-- separately authorized reconciliation flow exists. No legacy claim is promoted.
CREATE TABLE repair_execution_claims (
    execution_id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL UNIQUE REFERENCES repair_approval_claims(claim_id) ON DELETE RESTRICT,
    proposal_id TEXT NOT NULL UNIQUE REFERENCES repair_proposals(proposal_id) ON DELETE RESTRICT,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    proposal_digest TEXT NOT NULL,
    case_state_version INTEGER NOT NULL CHECK (case_state_version >= 0),
    target_scope_digest TEXT NOT NULL CHECK (length(target_scope_digest) = 64),
    authorization_id TEXT NOT NULL UNIQUE,
    authorization_digest TEXT NOT NULL CHECK (length(authorization_digest) = 64),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'applying', 'interrupted_uncertain')),
    claimed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER repair_execution_claims_no_replace
BEFORE INSERT ON repair_execution_claims
WHEN EXISTS (
    SELECT 1 FROM repair_execution_claims
    WHERE execution_id = NEW.execution_id OR claim_id = NEW.claim_id
       OR proposal_id = NEW.proposal_id OR authorization_id = NEW.authorization_id
)
BEGIN
    SELECT RAISE(ABORT, 'repair execution claim cannot be replayed or rewritten');
END;

CREATE TRIGGER repair_execution_claims_only_interrupt
BEFORE UPDATE ON repair_execution_claims
WHEN NOT (
    (OLD.state = 'prepared' AND NEW.state IN ('applying', 'interrupted_uncertain'))
    OR (OLD.state = 'applying' AND NEW.state = 'interrupted_uncertain')
)
    OR NEW.execution_id != OLD.execution_id OR NEW.claim_id != OLD.claim_id
    OR NEW.proposal_id != OLD.proposal_id OR NEW.case_id != OLD.case_id
    OR NEW.proposal_digest != OLD.proposal_digest
    OR NEW.case_state_version != OLD.case_state_version
    OR NEW.target_scope_digest != OLD.target_scope_digest
    OR NEW.authorization_id != OLD.authorization_id
    OR NEW.authorization_digest != OLD.authorization_digest
    OR NEW.claimed_at != OLD.claimed_at
BEGIN
    SELECT RAISE(ABORT, 'repair execution claim cannot be replayed or rewritten');
END;

CREATE TRIGGER repair_execution_claims_no_delete
BEFORE DELETE ON repair_execution_claims
BEGIN
    SELECT RAISE(ABORT, 'repair execution claim is immutable');
END;

-- The key deliberately excludes random target_id: two cases naming the same
-- Windows locator must not concurrently admit a write to it.
CREATE TABLE repair_execution_target_locks (
    target_key TEXT PRIMARY KEY CHECK (length(target_key) = 64),
    execution_id TEXT NOT NULL REFERENCES repair_execution_claims(execution_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER repair_execution_target_locks_no_replace
BEFORE INSERT ON repair_execution_target_locks
WHEN EXISTS (SELECT 1 FROM repair_execution_target_locks WHERE target_key = NEW.target_key)
BEGIN
    SELECT RAISE(ABORT, 'repair target remains reserved');
END;

CREATE TRIGGER repair_execution_target_locks_no_update
BEFORE UPDATE ON repair_execution_target_locks
BEGIN
    SELECT RAISE(ABORT, 'repair target lock is immutable');
END;

CREATE TRIGGER repair_execution_target_locks_no_delete
BEFORE DELETE ON repair_execution_target_locks
BEGIN
    SELECT RAISE(ABORT, 'repair target lock is immutable');
END;

CREATE TRIGGER repair_plan_heads_execution_fence
BEFORE UPDATE ON repair_plan_heads
WHEN EXISTS (
    SELECT 1 FROM repair_execution_claims
    WHERE proposal_id = OLD.active_proposal_id
      AND state IN ('prepared', 'applying', 'interrupted_uncertain')
)
BEGIN
    SELECT RAISE(ABORT, 'repair plan head has unresolved execution');
END;

CREATE TRIGGER cases_repair_execution_state_fence
BEFORE UPDATE OF state_version ON cases
WHEN NEW.state_version != OLD.state_version AND EXISTS (
    SELECT 1 FROM repair_execution_claims
    WHERE case_id = OLD.case_id
      AND state IN ('prepared', 'applying', 'interrupted_uncertain')
)
BEGIN
    SELECT RAISE(ABORT, 'case has unresolved repair execution');
END;

PRAGMA user_version = 8;
