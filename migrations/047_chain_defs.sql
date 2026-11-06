-- Chains get identifiers (CH-01) and attack paths get theirs (CH-01.1).
--
-- Since migration 045 a chain is the set of attack paths (`chains` rows) that
-- end on the same step, but only the paths had ids (CHAIN-###), so the UI
-- labelled paths as chains and the chain itself had only a name (046). This
-- makes the chain a real row: its code, its name, and the step every one of
-- its attack paths ends on (one chain per end step, as scoring groups them).
-- Paths keep their old CHAIN-### id in legacy_chain_id once renumbered, so
-- catalog text, finding reasoning and audit history still resolve.
CREATE TABLE IF NOT EXISTS chain_defs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id       INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    code         TEXT NOT NULL,
    name         TEXT NOT NULL,
    sink_vuln_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    UNIQUE (app_id, code),
    UNIQUE (app_id, sink_vuln_id)
);

-- One chain per (app, end step) already in use; named from 046, else from its
-- first path. Codes follow end-step order here; curators renumber as needed.
INSERT OR IGNORE INTO chain_defs (app_id, code, name, sink_vuln_id)
SELECT app_id,
       'CH-' || printf('%02d', ROW_NUMBER() OVER (PARTITION BY app_id ORDER BY sink_vuln_id)),
       name, sink_vuln_id
FROM (
    SELECT c.app_id, c.sink_vuln_id,
           COALESCE(n.name, MIN(c.title)) AS name
    FROM chains c
    LEFT JOIN chain_names n ON n.app_id = c.app_id AND n.sink_vuln_id = c.sink_vuln_id
    WHERE c.sink_vuln_id IS NOT NULL
    GROUP BY c.app_id, c.sink_vuln_id
);

DROP TABLE IF EXISTS chain_names;

ALTER TABLE chains ADD COLUMN legacy_chain_id TEXT;
