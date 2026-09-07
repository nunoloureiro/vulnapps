-- Widen audit_log.entity_type to allow 'chain' events (chain_created,
-- chain_updated, chain_deleted -- see app/services/chains.py). SQLite has no
-- ALTER TABLE for CHECK constraints, so the table is rebuilt.

CREATE TABLE audit_log_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('scan_finding', 'vulnerability', 'chain')),
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
