-- Explicit, human-adjudicated chain credit.
--
-- compute_metrics() used to infer chain credit purely from "every member
-- vuln matched" (migration 028's original design). In practice this credits
-- a chain whenever a scanner's report happens to contain two unrelated
-- findings that each independently match a member -- confirmed on real scan
-- data where a scanner's own finding text explicitly denied the connection
-- ("independent of SQL injection") and still got full chain credit. Matching
-- every member is necessary but not sufficient: it is not evidence the
-- scanner ever recognized the members combine into anything.
--
-- So a chain now credits 0 by default, always, until a reviewer reads the
-- scan's actual finding text and explicitly confirms it demonstrates that
-- specific chain end to end. This is the same shape as is_false_positive /
-- promotion: adjudication is a human call, not an inference from field
-- matching, because inference from matching is exactly the mistake here.

CREATE TABLE IF NOT EXISTS scan_chain_credits (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    chain_pk    INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
    credited_by INTEGER NOT NULL REFERENCES users(id),
    credited_at TEXT NOT NULL DEFAULT (datetime('now')),
    notes       TEXT,
    PRIMARY KEY (scan_id, chain_pk)
);

CREATE INDEX IF NOT EXISTS idx_scan_chain_credits_scan ON scan_chain_credits(scan_id);
