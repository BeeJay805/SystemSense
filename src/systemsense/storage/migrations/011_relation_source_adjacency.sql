-- Bounded directed graph traversal must seek by source entity, not scan
-- every stored relation JSON before applying its result LIMIT.
CREATE INDEX IF NOT EXISTS evidence_relations_source_entity_id
ON evidence_relations(json_extract(record_json, '$.source_entity_id'));

PRAGMA user_version = 11;
