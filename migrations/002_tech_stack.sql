CREATE TABLE IF NOT EXISTS app_technologies (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id  INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tech_app ON app_technologies(app_id);
