-- Ground-truth revisions: the second axis of reproducible measurement.
--
-- Recall used to change silently whenever a vuln was added to an app, because
-- the denominator was read live at request time. Retroactive re-scoring is the
-- DESIRED behaviour (a vuln that existed all along and was missed is a real
-- miss), but it has to be visible and reproducible.
--
-- Two fields per vuln, and they mean different things:
--   existed_since_revision — when the flaw was present in the application.
--                            Drives scope: prior scans take the miss.
--   known_since_revision   — when we learned about it. Audit only.
-- Promoting a discovery finding forces the operator to choose between
-- "existed all along" (existed_since = 1) and "introduced by a code change"
-- (existed_since = N). That choice is the whole point of the split.

CREATE TABLE IF NOT EXISTS ground_truth_revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    revision   INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    notes      TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, revision)
);

CREATE INDEX IF NOT EXISTS idx_gt_revisions_app ON ground_truth_revisions(app_id);

-- reason is one of: new_prior_vuln, weight_change, vuln_invalidated, corpus_change.

ALTER TABLE vulnerabilities ADD COLUMN existed_since_revision  INTEGER DEFAULT 1;
ALTER TABLE vulnerabilities ADD COLUMN known_since_revision    INTEGER DEFAULT 1;
ALTER TABLE vulnerabilities ADD COLUMN invalidated_at_revision INTEGER;

-- The corpus revision a scan was scored against when it ran ("as-run").
ALTER TABLE scans ADD COLUMN corpus_revision INTEGER;

-- Every existing app starts at revision 1 with everything in scope.
INSERT INTO ground_truth_revisions (app_id, revision, reason, notes)
SELECT id, 1, 'corpus_change', 'Initial revision (backfilled by migration 025)'
FROM apps
WHERE NOT EXISTS (
    SELECT 1 FROM ground_truth_revisions r WHERE r.app_id = apps.id AND r.revision = 1
);

UPDATE vulnerabilities SET existed_since_revision = 1 WHERE existed_since_revision IS NULL;
UPDATE vulnerabilities SET known_since_revision   = 1 WHERE known_since_revision   IS NULL;
UPDATE scans          SET corpus_revision         = 1 WHERE corpus_revision        IS NULL;
