-- Persist the LLM mapper's own justification for a match/non-match decision.
--
-- The scan importer (tools/import_scan.py) already asks the LLM for a
-- `reasoning` field per finding and prints it to the terminal, but never
-- sent it to the API -- the one artifact that would let a human audit *why*
-- the mapper thought a finding belonged (or didn't belong) to a given known
-- vuln was being generated and then discarded. See tasks/scanimport-resilience.md.

ALTER TABLE scan_findings ADD COLUMN reasoning TEXT;
