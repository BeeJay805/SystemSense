-- A focus delivery and its SATISFIED transition commit together. The case
-- checkpoint may follow later, so recovery can identify an interrupted focus.
CREATE TABLE search_frontier_focus_delivery_receipts (
    item_id TEXT PRIMARY KEY REFERENCES search_frontier_items(item_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 64),
    committed_at TEXT NOT NULL
) STRICT;

CREATE INDEX search_frontier_focus_delivery_receipts_case
ON search_frontier_focus_delivery_receipts(case_id, committed_at, item_id);

CREATE TRIGGER search_frontier_focus_delivery_receipts_no_update
BEFORE UPDATE ON search_frontier_focus_delivery_receipts
BEGIN SELECT RAISE(ABORT, 'focus delivery receipt is immutable'); END;

CREATE TRIGGER search_frontier_focus_delivery_receipts_no_delete
BEFORE DELETE ON search_frontier_focus_delivery_receipts
WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
BEGIN SELECT RAISE(ABORT, 'focus delivery receipt is immutable'); END;

PRAGMA user_version = 36;
