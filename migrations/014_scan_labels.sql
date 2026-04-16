-- Scan labels: user-defined color-coded labels for scans

CREATE TABLE IF NOT EXISTS labels (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL UNIQUE,
    color TEXT NOT NULL DEFAULT '#f97316'
);

CREATE TABLE IF NOT EXISTS scan_labels (
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    label_id INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, label_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_labels_scan ON scan_labels(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_labels_label ON scan_labels(label_id);
