CREATE TABLE audit_heads (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    head_hash TEXT NOT NULL CHECK (
        length(head_hash) = 64
        AND head_hash NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE _migration_003_audit_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

WITH ordered AS (
    SELECT
        event_id,
        case_id,
        event_json,
        created_at,
        occurred_at,
        persisted_at,
        ROW_NUMBER() OVER (
            PARTITION BY case_id
            ORDER BY sequence
        ) AS case_sequence,
        LAG(json_extract(event_json, '$.event_hash')) OVER (
            PARTITION BY case_id
            ORDER BY sequence
        ) AS previous_event_hash
    FROM audit_events
    WHERE case_id IS NOT NULL
), invalid AS (
    SELECT 1
    FROM ordered
    WHERE systemsense_audit_event_hash(
        event_json,
        event_id,
        case_id,
        created_at,
        occurred_at,
        persisted_at
    ) IS NULL
       OR json_extract(event_json, '$.sequence') != case_sequence
       OR json_extract(event_json, '$.previous_hash') != COALESCE(
            previous_event_hash,
            '0000000000000000000000000000000000000000000000000000000000000000'
       )
    LIMIT 1
)
INSERT INTO _migration_003_audit_guard (valid)
SELECT CASE WHEN EXISTS (SELECT 1 FROM invalid) THEN 0 ELSE 1 END;

WITH ranked AS (
    SELECT
        case_id,
        json_extract(event_json, '$.sequence') AS case_sequence,
        json_extract(event_json, '$.event_hash') AS event_hash,
        ROW_NUMBER() OVER (
            PARTITION BY case_id
            ORDER BY sequence DESC
        ) AS reverse_position
    FROM audit_events
    WHERE case_id IS NOT NULL
)
INSERT INTO audit_heads (case_id, sequence, head_hash)
SELECT case_id, case_sequence, event_hash
FROM ranked
WHERE reverse_position = 1;

DROP TABLE _migration_003_audit_guard;

PRAGMA user_version = 3;
