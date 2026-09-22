-- Migration 005 is applied by SQLiteStore's schema-aware migration hook.
-- Historical version-4 databases exist both with and without this column, so
-- an unconditional ALTER TABLE would reject one of the two valid inputs.
PRAGMA user_version = 5;
