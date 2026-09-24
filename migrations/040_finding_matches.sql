-- One finding can demonstrate more than one piece of ground truth.
--
-- Until now a finding had a single matched_vuln_id and a single
-- matched_chain_id (mutually exclusive), so it could be credited for exactly
-- one thing. Two real gaps followed, both hit on live scan data:
--
-- 1. Scan 330 (TaintedPort): three separate findings -- path traversal, SSRF
--    and directory listing -- each explicitly read api/config/jwt.php and
--    quoted the hardcoded HS256 secret. All three were matched to their own
--    access vuln (TP-014 / TP-027 / TP-013), so CODE-001 scored as MISSED
--    even though the scan demonstrated it three times over. Fixing it by hand
--    meant re-pointing one finding, which cost TP-013 a piece of its evidence
--    -- a trade, not a fix.
--
-- 2. A scan that reports ONE clean chain narrative naming its three members
--    gets either the chain or one member, never the chain plus its members --
--    while a scan that redundantly re-reports each member separately gets all
--    four. Same discovery, different score, purely because of how the report
--    was written up.
--
-- Matches become additive instead of a single slot, which also removes the
-- need for the awkward "only credit the chain's member if no other finding
-- already covers it" rule: nothing is being stolen, so nothing needs that
-- conditional.
--
-- Note the CHECK constraint migration 039 said it could not add: it lamented
-- that SQLite cannot add a CHECK via ALTER TABLE, so mutual exclusivity of
-- the two columns lived only in the write paths. On a fresh table it is
-- expressible, so the invariant is now enforced by the database: each row
-- points at exactly one of a vuln or a chain.

CREATE TABLE IF NOT EXISTS finding_matches (
    finding_id INTEGER NOT NULL REFERENCES scan_findings(id) ON DELETE CASCADE,
    vuln_id    INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    chain_id   INTEGER REFERENCES chains(id) ON DELETE CASCADE,
    CHECK ((vuln_id IS NOT NULL) + (chain_id IS NOT NULL) = 1)
);

-- Partial uniques: a finding may match many vulns and many chains, but never
-- the same one twice, so set-replacement writes stay idempotent.
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_matches_vuln
    ON finding_matches(finding_id, vuln_id) WHERE vuln_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_matches_chain
    ON finding_matches(finding_id, chain_id) WHERE chain_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_finding_matches_finding
    ON finding_matches(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_matches_vuln_lookup
    ON finding_matches(vuln_id);

-- Backfill. OR IGNORE so a re-run after a partial failure is harmless
-- (migrations are tracked by filename and only recorded on success).
INSERT OR IGNORE INTO finding_matches (finding_id, vuln_id)
    SELECT id, matched_vuln_id FROM scan_findings WHERE matched_vuln_id IS NOT NULL;
INSERT OR IGNORE INTO finding_matches (finding_id, chain_id)
    SELECT id, matched_chain_id FROM scan_findings WHERE matched_chain_id IS NOT NULL;

-- Drop the old single-slot columns LAST, so everything above is already done
-- if this fails. They go rather than staying as dead mirrors: a second source
-- of truth for the same fact is how the bugs above went unnoticed, and every
-- reader moves to finding_matches in the same change, so a missed one fails
-- loudly instead of silently reading stale data. Recovery if a deploy has to
-- roll back to code that still reads these: restore the pre-deploy snapshot
-- (aws/setup-ec2.sh takes one before container replacement).
ALTER TABLE scan_findings DROP COLUMN matched_vuln_id;
ALTER TABLE scan_findings DROP COLUMN matched_chain_id;
