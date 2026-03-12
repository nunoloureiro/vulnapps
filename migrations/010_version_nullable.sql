-- SQLite can't ALTER column constraints, so recreate the table
PRAGMA foreign_keys=OFF;

CREATE TABLE apps_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT,
    description TEXT,
    url         TEXT,
    category    TEXT,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    visibility  TEXT NOT NULL DEFAULT 'public',
    team_id     INTEGER REFERENCES teams(id)
);

INSERT INTO apps_new SELECT * FROM apps;
DROP TABLE apps;
ALTER TABLE apps_new RENAME TO apps;

PRAGMA foreign_keys=ON;
