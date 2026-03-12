-- Permissions redesign: collapse 4 account roles to 2, expand team roles to 3.
-- Account roles: user, admin (viewer/contributor merged into user)
-- Team roles: admin, contributor, view (member becomes contributor)

-- Step 1: Collapse account roles
UPDATE users SET role = 'user' WHERE role IN ('viewer', 'contributor');

-- Step 2: Recreate users table with new CHECK constraint
DROP TABLE IF EXISTS users_new;
CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
);

INSERT INTO users_new (id, name, email, password_hash, role, created_at, last_login)
SELECT id, name, email, password_hash, role, created_at, last_login FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Step 3: Migrate team roles (member -> contributor)
UPDATE team_members SET role = 'contributor' WHERE role = 'member';

-- Step 4: Recreate team_members with new CHECK constraint
DROP TABLE IF EXISTS team_members_new;
CREATE TABLE team_members_new (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id  INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT NOT NULL DEFAULT 'view' CHECK(role IN ('admin','contributor','view')),
    UNIQUE(team_id, user_id)
);

INSERT INTO team_members_new (id, team_id, user_id, role)
SELECT id, team_id, user_id, role FROM team_members;

DROP TABLE team_members;
ALTER TABLE team_members_new RENAME TO team_members;

-- Step 5: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
