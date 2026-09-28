-- Who imported and mapped a scan, and the run details the importer already sends.
--
-- The importer has sent its mapping model, a hash of its mapping prompt and the
-- run's configuration (model version, reasoning effort, seed, ...) for a long
-- time, and the server stored none of it: the submit route read eight named
-- fields and dropped the rest. The run-detail columns existed only on the live
-- database, leftovers of migrations removed in the scoring prune, so a fresh
-- database never had them. Those are re-declared here; on a database that
-- already has one, the runner skips just that statement (see
-- app/database.py _run_migration_script).
--
-- Provenance is new: which tool put the findings in and which version of it,
-- and which models extracted and mapped them. Ten TaintedPort scans arrived
-- pre-mapped by a scanner's own publishing step, and nothing on the scan said
-- so; a null imported_by is now exactly that signal.
ALTER TABLE scans ADD COLUMN imported_by TEXT;
ALTER TABLE scans ADD COLUMN importer_version TEXT;
ALTER TABLE scans ADD COLUMN importer_commit TEXT;
ALTER TABLE scans ADD COLUMN extractor_version TEXT;
ALTER TABLE scans ADD COLUMN extractor_prompt_sha256 TEXT;
ALTER TABLE scans ADD COLUMN matcher_version TEXT;
ALTER TABLE scans ADD COLUMN matcher_prompt_sha256 TEXT;
ALTER TABLE scans ADD COLUMN model TEXT;
ALTER TABLE scans ADD COLUMN model_version TEXT;
ALTER TABLE scans ADD COLUMN reasoning_effort TEXT;
ALTER TABLE scans ADD COLUMN harness_version TEXT;
ALTER TABLE scans ADD COLUMN token_budget INTEGER;
ALTER TABLE scans ADD COLUMN seed INTEGER;
ALTER TABLE scans ADD COLUMN run_group TEXT;
ALTER TABLE scans ADD COLUMN trial_index INTEGER;
