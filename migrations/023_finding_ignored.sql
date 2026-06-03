-- "Ignore" validation state for scan findings.
--
-- A finding that's a real-ish issue but irrelevant in context — not a known
-- vuln of the app, and not a false positive. Ignored findings are neutral:
-- excluded from the Pending tally and the severity pills, and counted as
-- neither TP nor FP, so precision/recall/F1 are unaffected. Mutually exclusive
-- with matched_vuln_id and is_false_positive. Additive/nullable-default — no
-- impact on existing scans/findings.

ALTER TABLE scan_findings ADD COLUMN is_ignored INTEGER NOT NULL DEFAULT 0;
