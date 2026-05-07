-- Migrate authenticated flag to a label, then drop the column

-- 1. Create the "Authenticated" label if it doesn't exist
INSERT OR IGNORE INTO labels (name, color) VALUES ('Authenticated', '#22c55e');

-- 2. Add the label to all scans that have authenticated=1
INSERT OR IGNORE INTO scan_labels (scan_id, label_id)
SELECT scans.id, labels.id
FROM scans, labels
WHERE scans.authenticated = 1 AND labels.name = 'Authenticated';

-- 3. Recreate scans table without the authenticated column
PRAGMA foreign_keys=OFF;

CREATE TABLE scans_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    scanner_name  TEXT NOT NULL,
    scan_date     TEXT NOT NULL,
    is_public     INTEGER NOT NULL DEFAULT 1,
    notes         TEXT,
    cost          REAL,
    tokens        INTEGER,
    duration      INTEGER,
    submitted_by  INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO scans_new (id, app_id, scanner_name, scan_date, is_public, notes, cost, tokens, duration, submitted_by, created_at)
SELECT id, app_id, scanner_name, scan_date, is_public, notes, cost, tokens, duration, submitted_by, created_at
FROM scans;

DROP TABLE scans;
ALTER TABLE scans_new RENAME TO scans;

CREATE INDEX IF NOT EXISTS idx_scans_app ON scans(app_id);

PRAGMA foreign_keys=ON;
