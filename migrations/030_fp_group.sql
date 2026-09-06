-- False-positive clustering.
--
-- TP and FP were counted at different granularities: tp = COUNT(DISTINCT
-- matched_vuln_id) dedupes to the vulnerability, while fp counted every
-- finding. Three findings describing one real vuln scored 1 TP; three findings
-- describing one bogus issue scored 3 FP. That systematically depressed
-- precision for verbose scanners and made precision non-comparable across
-- tools with different reporting granularity.
--
-- `fp_group` is the FP-side equivalent of matched_vuln_id: findings that
-- describe the same non-issue share a group key. Precision counts distinct
-- groups; an ungrouped FP counts as one.

ALTER TABLE scan_findings ADD COLUMN fp_group TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_fp_group ON scan_findings(scan_id, fp_group);
