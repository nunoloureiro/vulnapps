CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    key_hash   TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT 'default',
    scope      TEXT NOT NULL DEFAULT 'read' CHECK(scope IN ('read','vuln-mapper','full')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used  TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
