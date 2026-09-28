-- Chains get a severity, and findings record whether they are chain reports.
--
-- Chains only ever stored impact_weight, so there was no way to say "this chain
-- is High": every registered chain read as Critical by construction. Vulns
-- already work the other way round -- severity is what a curator sets and the
-- weight derives 1:1 from it -- so chains now match.
ALTER TABLE chains ADD COLUMN severity TEXT;
UPDATE chains SET severity = CASE impact_weight
    WHEN 27 THEN 'critical'
    WHEN 9  THEN 'high'
    WHEN 3  THEN 'medium'
    ELSE 'low'
END WHERE severity IS NULL;

-- Whether the finding presents itself as a multi-step chain. Decided from what
-- the finding says, never from which folder of the report it came from --
-- scanners mix chain write-ups in with single-vuln findings. A chain report
-- that matches no registered chain used to be indistinguishable from any other
-- unmatched finding, which is how three real chains ended up marked FP.
ALTER TABLE scan_findings ADD COLUMN is_chain INTEGER NOT NULL DEFAULT 0;
UPDATE scan_findings SET is_chain = 1
 WHERE id IN (SELECT finding_id FROM finding_matches WHERE chain_id IS NOT NULL);
