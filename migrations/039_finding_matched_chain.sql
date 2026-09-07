-- A finding can be matched directly to a chain, not just to an individual
-- vuln, when the scanner's OWN report contains a single finding that
-- explicitly narrates combining >=2 chain members into a bigger impact
-- (e.g. "SSRF used to read jwt.php and extract the signing secret to forge
-- an admin token" as one finding, not two unrelated ones).
--
-- This is the automatic counterpart to scan_chain_credits (migration 038):
-- that table is a human override for when no single finding says it
-- clearly; this column is the direct signal when one does. Either grants
-- credit — see app/scoring.py::compute_metrics. Mutually exclusive with
-- matched_vuln_id in practice (a finding matches one or the other), but not
-- enforced by a CHECK constraint since SQLite can't add one via ALTER TABLE
-- and the write paths already treat them as exclusive.

ALTER TABLE scan_findings ADD COLUMN matched_chain_id INTEGER REFERENCES chains(id);
