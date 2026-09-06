-- Flag hand-curated apps and hand-reviewed vulns.
--
-- Migration 024 backfilled impact_weight from severity for ~55k vulns across
-- 217 apps. Those derived values are fine for apps nobody is curating, but any
-- comparison that treats an app's ground truth as authoritative must be able to
-- tell hand-verified data apart from an untouched backfill.

-- An app whose vulns have actually been reviewed (weights/tiers hand-set, not
-- just backfilled). Set via the UI (App edit → "Benchmark corpus") or PUT
-- /api/apps/{id} — never inferred from name/version, since this database
-- contains duplicate app names (e.g. two 'TaintedPort' v1.0 rows, ids 1 and 3,
-- from migration 010 rebuilding `apps` without its original UNIQUE constraint).
ALTER TABLE apps ADD COLUMN benchmark_verified INTEGER NOT NULL DEFAULT 0;

-- A single vuln whose contextual severity and difficulty tier have been
-- hand-reviewed, as opposed to still carrying the 024 backfill/placeholder.
-- Set to 1 by any write path that states severity or tier explicitly.
ALTER TABLE vulnerabilities ADD COLUMN weight_verified INTEGER NOT NULL DEFAULT 0;
