-- Add viewer role to users table
-- SQLite cannot ALTER CHECK constraints, so we recreate the table
PRAGMA foreign_keys=OFF;

CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('viewer','user','contributor','admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO users_new (id, name, email, password_hash, role, created_at)
    SELECT id, name, email, password_hash, role, created_at FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

PRAGMA foreign_keys=ON;
