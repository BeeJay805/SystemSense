-- Coordinator-owned, append-only source receipts frozen before frontier inference.
-- A binding is created only when a v2 measurement snapshot captures that input.
CREATE TABLE frontier_packet_receipts (
    receipt_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 64),
    frozen_at TEXT NOT NULL
) STRICT;

CREATE TABLE frontier_packet_snapshot_bindings (
    snapshot_id TEXT PRIMARY KEY REFERENCES candidate_decision_snapshots(snapshot_id) ON DELETE CASCADE,
    receipt_id TEXT NOT NULL UNIQUE REFERENCES frontier_packet_receipts(receipt_id),
    bound_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER frontier_packet_receipts_no_update BEFORE UPDATE ON frontier_packet_receipts
BEGIN SELECT RAISE(ABORT, 'frontier packet receipt is immutable'); END;
CREATE TRIGGER frontier_packet_receipts_no_delete BEFORE DELETE ON frontier_packet_receipts
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'frontier packet receipt is immutable'); END;
CREATE TRIGGER frontier_packet_snapshot_bindings_no_update BEFORE UPDATE ON frontier_packet_snapshot_bindings
BEGIN SELECT RAISE(ABORT, 'frontier packet binding is immutable'); END;
CREATE TRIGGER frontier_packet_snapshot_bindings_no_delete BEFORE DELETE ON frontier_packet_snapshot_bindings
WHEN EXISTS (SELECT 1 FROM candidate_decision_snapshots WHERE snapshot_id=OLD.snapshot_id)
BEGIN SELECT RAISE(ABORT, 'frontier packet binding is immutable'); END;

PRAGMA user_version = 24;
