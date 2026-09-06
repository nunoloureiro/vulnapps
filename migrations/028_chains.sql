-- Exploit chains.
--
-- A chain is its own ground-truth entity with its own weight; its members keep
-- their individual weights. The partial double-count is deliberate —
-- demonstrating a chain end to end is worth more than finding its parts
-- separately, and that is exactly the difference the metric has to see between
-- a scanner with a chat interface and an agent that pivots.
--
-- Chains participate in the revision scope rule exactly as vulns do.

CREATE TABLE IF NOT EXISTS chains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    chain_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    impact_weight INTEGER NOT NULL,
    description   TEXT,
    existed_since_revision  INTEGER DEFAULT 1,
    invalidated_at_revision INTEGER,
    UNIQUE(app_id, chain_id)
);

CREATE TABLE IF NOT EXISTS chain_members (
    chain_pk   INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
    vuln_id    INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    step_order INTEGER NOT NULL,
    PRIMARY KEY (chain_pk, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_chains_app ON chains(app_id);

-- A chain is credited (full weight) only when every member vuln is matched
-- in-scope; otherwise it is credited 0. Whether a chain was "walked end to
-- end" is inferred from its members alone — there is no separate per-chain
-- milestone tracking.
