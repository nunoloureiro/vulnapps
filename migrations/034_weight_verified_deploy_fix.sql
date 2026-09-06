-- Re-apply 032's column adds under a filename production has never seen.
--
-- 032_benchmark_corpus.sql was edited in place after it had already been deployed
-- to production under its original column names (is_benchmark_corpus,
-- scoring_reviewed). The migration runner tracks applied files by filename only, so
-- the edited content (benchmark_verified, weight_verified) never replayed there --
-- production is stuck on the pre-rename schema no matter how many times it's
-- redeployed. This file exists purely to get a fresh filename onto production.
--
-- Safe everywhere else too: run_migrations() now tolerates "duplicate column name"
-- as a no-op, so this is a harmless no-op on any environment (local dev, a fresh
-- install) that already has these columns from 032 running normally.

ALTER TABLE apps ADD COLUMN benchmark_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vulnerabilities ADD COLUMN weight_verified INTEGER NOT NULL DEFAULT 0;
