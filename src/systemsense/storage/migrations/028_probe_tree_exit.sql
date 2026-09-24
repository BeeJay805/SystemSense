-- Historical executions have no worker-tree custody claim. The default must
-- not silently turn those rows into verified exits or assert no worker existed.
ALTER TABLE probe_executions
ADD COLUMN tree_exit_status TEXT NOT NULL DEFAULT 'not_recorded'
CHECK (tree_exit_status IN ('not_recorded', 'not_tracked', 'verified_empty', 'unknown'));

PRAGMA user_version = 28;
