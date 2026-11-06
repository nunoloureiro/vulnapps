-- A name for each chain (migration 045: a chain = the paths sharing a sink).
-- Paths carry their own titles; the chain they belong to had none, so the UI
-- could only label it by its sink vuln's title, which reads as a vuln rather
-- than an outcome ("Pass-the-hash account takeover"). Keyed by sink, so every
-- path ending on that step shows the same name. Presentation only: no effect
-- on scoring, so editing it opens no revision.
CREATE TABLE IF NOT EXISTS chain_names (
    app_id       INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    sink_vuln_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    PRIMARY KEY (app_id, sink_vuln_id)
);
