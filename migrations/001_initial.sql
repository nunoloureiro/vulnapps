PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','contributor','admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS apps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    category    TEXT,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    vuln_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
    vuln_type     TEXT,
    http_method   TEXT,
    url           TEXT,
    parameter     TEXT,
    description   TEXT,
    code_location TEXT,
    poc           TEXT,
    remediation   TEXT,
    created_by    INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, vuln_id)
);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id         INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    scanner_name   TEXT NOT NULL,
    scan_date      TEXT NOT NULL,
    authenticated  INTEGER NOT NULL DEFAULT 0,
    is_public      INTEGER NOT NULL DEFAULT 1,
    notes          TEXT,
    submitted_by   INTEGER NOT NULL REFERENCES users(id),
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type       TEXT NOT NULL,
    http_method     TEXT,
    url             TEXT NOT NULL,
    parameter       TEXT,
    matched_vuln_id INTEGER REFERENCES vulnerabilities(id),
    is_false_positive INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_vulns_app ON vulnerabilities(app_id);
CREATE INDEX IF NOT EXISTS idx_scans_app ON scans(app_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id);
