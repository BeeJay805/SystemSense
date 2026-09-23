-- A case-scoped change token for keyset discovery. Seed above the legacy
-- MAX(rowid) marker so a persisted v2 catalog cursor is reset after upgrade.
CREATE TABLE evidence_case_generations (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation >= 1)
) STRICT;

INSERT INTO evidence_case_generations (case_id, generation)
SELECT cases.case_id,
       COALESCE((SELECT MAX(rowid) FROM evidence WHERE evidence.case_id = cases.case_id), 0) + 1
FROM cases;

CREATE TRIGGER cases_evidence_generation_insert
AFTER INSERT ON cases
BEGIN
    INSERT INTO evidence_case_generations (case_id, generation)
    VALUES (NEW.case_id, 1);
END;

CREATE TRIGGER evidence_case_generation_insert
AFTER INSERT ON evidence
BEGIN
    UPDATE evidence_case_generations
    SET generation = generation + 1
    WHERE case_id = NEW.case_id;
END;

CREATE TRIGGER evidence_case_generation_delete
AFTER DELETE ON evidence
BEGIN
    UPDATE evidence_case_generations
    SET generation = generation + 1
    WHERE case_id = OLD.case_id;
END;

CREATE TRIGGER evidence_case_generation_update
AFTER UPDATE ON evidence
BEGIN
    UPDATE evidence_case_generations
    SET generation = generation + 1
    WHERE case_id = OLD.case_id;
    UPDATE evidence_case_generations
    SET generation = generation + 1
    WHERE case_id = NEW.case_id AND NEW.case_id <> OLD.case_id;
END;

PRAGMA user_version = 16;
