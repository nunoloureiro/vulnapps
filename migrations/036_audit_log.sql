-- Human-readable, append-only history of operations on scan findings and on
-- app vulnerabilities (ground truth). Scoped to exactly two consumers today:
-- ScanDetail's "History Log" (queries by scan_id) and AppDetail's "History
-- Log" (queries by app_id). The message is rendered ONCE, at write time --
-- see tasks/audit-log-plan.md SS3.2 for why (actor names, entity titles, and
-- vuln_id slugs can all change after the fact; the log must not reflect that).

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('scan_finding', 'vulnerability')),
    entity_id   INTEGER,                                   -- finding/vuln id; NULL for bulk/aggregate events (rematch, import)
    scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,   -- set for entity_type='scan_finding'
    app_id      INTEGER REFERENCES apps(id) ON DELETE CASCADE,    -- set for entity_type='vulnerability'
    action      TEXT NOT NULL,                              -- e.g. finding_matched, finding_unmatched, finding_marked_fp,
                                                              -- finding_marked_ignored, finding_unignored, finding_promoted,
                                                              -- scan_rematched, vuln_created, vuln_updated, vuln_deleted,
                                                              -- vuln_invalidated, vulns_imported, revision_opened
    actor_id    INTEGER NOT NULL REFERENCES users(id),
    message     TEXT NOT NULL,                               -- pre-rendered, human-readable
    details     TEXT,                                         -- optional JSON blob for future filtering/tooling
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_scan ON audit_log(scan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_app  ON audit_log(app_id, created_at);
