-- Sink-based chain credit (see app/scoring.py::compute_metrics).
--
-- A chain is identified by its SINK: the vulnerability its path ends on, as
-- actually executed. Every `chains` row is one PATH; rows sharing a sink are
-- alternative paths of ONE chain and are credited once per scan, at the
-- highest weight among the paths it demonstrated. Stored explicitly, never
-- inferred from step_order: CHAIN-005 lists #43 + #44 but runs #44 first.
-- NULL = the row is its own chain, which is exactly the pre-045 behaviour.
ALTER TABLE chains ADD COLUMN sink_vuln_id INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL;

-- A scanner-reported chain that matches no registered path (a "novel path")
-- is credited to the chain of its sink when that sink is a known one. The
-- sink is the last step the finding executed — set by the importer or a
-- reviewer, never guessed at scoring time.
ALTER TABLE scan_findings ADD COLUMN chain_sink_vuln_id INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL;

-- A reviewer rejected the finding as a novel path (e.g. a bundle of
-- independent bugs, or one vuln plus its own impact). Removes its chain
-- credit; its vuln matches are untouched.
ALTER TABLE scan_findings ADD COLUMN novel_chain_rejected INTEGER NOT NULL DEFAULT 0;
