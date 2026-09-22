CREATE TABLE evidence_relations (
    relation_id TEXT NOT NULL,
    relation_version INTEGER NOT NULL CHECK (relation_version >= 1),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    PRIMARY KEY (relation_id, relation_version)
) STRICT;

CREATE TABLE evidence_relation_evidence (
    relation_id TEXT NOT NULL,
    relation_version INTEGER NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    PRIMARY KEY (relation_id, relation_version, evidence_id),
    FOREIGN KEY (relation_id, relation_version)
        REFERENCES evidence_relations(relation_id, relation_version)
        ON DELETE CASCADE
) STRICT;

CREATE TABLE evidence_relation_sources (
    relation_id TEXT NOT NULL,
    relation_version INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    PRIMARY KEY (relation_id, relation_version, source_id),
    FOREIGN KEY (relation_id, relation_version)
        REFERENCES evidence_relations(relation_id, relation_version)
        ON DELETE CASCADE
) STRICT;

CREATE INDEX evidence_relation_evidence_id
ON evidence_relation_evidence(evidence_id);

CREATE INDEX evidence_relation_source_id
ON evidence_relation_sources(source_id);

-- A relation is a typed assertion over its complete provenance set. If an exact
-- cited observation expires, remove the assertion rather than retain a record
-- whose JSON claims provenance that no longer exists.
CREATE TRIGGER evidence_relation_cleanup_before_evidence_delete
BEFORE DELETE ON evidence
BEGIN
    DELETE FROM evidence_relations
    WHERE EXISTS (
        SELECT 1
        FROM evidence_relation_evidence AS link
        WHERE link.relation_id = evidence_relations.relation_id
          AND link.relation_version = evidence_relations.relation_version
          AND link.evidence_id = OLD.evidence_id
    )
    OR (
        NOT EXISTS (
            SELECT 1
            FROM evidence AS remaining
            WHERE remaining.source_id = OLD.source_id
              AND remaining.evidence_id != OLD.evidence_id
        )
        AND EXISTS (
            SELECT 1
            FROM evidence_relation_sources AS link
            WHERE link.relation_id = evidence_relations.relation_id
              AND link.relation_version = evidence_relations.relation_version
              AND link.source_id = OLD.source_id
        )
    );
END;

CREATE TABLE investigation_checkpoints (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
) STRICT;

CREATE TABLE investigation_steps (
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    PRIMARY KEY (case_id, state_version)
) STRICT;

PRAGMA user_version = 4;
