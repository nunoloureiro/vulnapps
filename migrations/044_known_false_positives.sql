-- Known false positives: a per-app corpus of non-issues scanners keep flagging.
--
-- An FP used to exist only on the finding that was marked, so every new scan
-- that flagged the same non-issue landed in Pending and was dismissed again by
-- hand, with a fresh free-text fp_group and a fresh penalty. Planted decoys
-- (TaintedPort D1-D7) are ground truth just like the TP-* vulns but had
-- nowhere to live.
--
-- Linking a finding to a known FP copies the entry's fp_id into the finding's
-- fp_group and its penalty_weight into fp_impact_weight (see
-- app/services/known_fps.py), so the scorer needs no change: every finding on
-- one known FP counts as one FP group, at one penalty, in every scan. Editing
-- the entry propagates to its linked findings.
--
-- source: 'decoy' = planted in the app and catalogued (D-n ids);
--         'reviewed' = remembered from a reviewer's FP decision (FP-NNN ids).

CREATE TABLE IF NOT EXISTS known_false_positives (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    fp_id           TEXT NOT NULL,
    title           TEXT NOT NULL,
    vuln_type       TEXT,
    http_method     TEXT,
    url             TEXT,
    parameter       TEXT,
    filename        TEXT,
    -- What a scanner reports AND why it is not real; the debunk is what a
    -- reviewer (and later the importer's mapper) judges a finding against.
    description     TEXT,
    penalty_weight  INTEGER CHECK (penalty_weight IS NULL OR penalty_weight IN (1, 3, 9, 27)),
    source          TEXT NOT NULL DEFAULT 'reviewed' CHECK (source IN ('decoy', 'reviewed')),
    created_from_finding_id INTEGER REFERENCES scan_findings(id) ON DELETE SET NULL,
    created_by      INTEGER REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, fp_id)
);

CREATE INDEX IF NOT EXISTS idx_known_fps_app ON known_false_positives(app_id);

ALTER TABLE scan_findings ADD COLUMN known_fp_id INTEGER
    REFERENCES known_false_positives(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_findings_known_fp ON scan_findings(known_fp_id);

-- Widen audit_log.entity_type for known-FP events. SQLite cannot ALTER a CHECK
-- constraint, so the table is rebuilt (same as migration 037).
CREATE TABLE audit_log_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('scan_finding', 'vulnerability', 'chain', 'known_fp')),
    entity_id   INTEGER,
    scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    app_id      INTEGER REFERENCES apps(id) ON DELETE CASCADE,
    action      TEXT NOT NULL,
    actor_id    INTEGER NOT NULL REFERENCES users(id),
    message     TEXT NOT NULL,
    details     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO audit_log_new SELECT * FROM audit_log;
DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

CREATE INDEX IF NOT EXISTS idx_audit_log_scan ON audit_log(scan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_app  ON audit_log(app_id, created_at);
