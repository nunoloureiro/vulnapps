-- Severity weighting and difficulty tiers for benchmark-grade scoring.
--
-- `impact_weight` is the SCORING field; `severity` remains the DISPLAY field.
-- The two are allowed to diverge when realized impact in the target app
-- differs from the label. Scale is 1/3/9/27 — log spacing is deliberate: with
-- linear weights nine informational findings would outscore two criticals.
--
-- `difficulty_tier` is a REPORTING axis (commodity | business_logic | chained),
-- never a multiplier. Folding it into the weight would produce one opaque
-- number and destroy the diagnostic value of the tier matrix.
--
-- SQLite cannot add CHECK constraints via ALTER TABLE, so both fields are
-- validated in the service layer (app/scoring.py).

ALTER TABLE vulnerabilities ADD COLUMN impact_weight   INTEGER;
ALTER TABLE vulnerabilities ADD COLUMN difficulty_tier TEXT;

-- Backfill from severity. This is a STARTING POINT only; weights need hand
-- correction per app (a "high" label on a vuln that is unexploitable in the
-- target app is not worth 9 points).
UPDATE vulnerabilities SET impact_weight = CASE lower(severity)
    WHEN 'critical' THEN 27
    WHEN 'high'     THEN 9
    WHEN 'medium'   THEN 3
    WHEN 'low'      THEN 1
    ELSE 1
END WHERE impact_weight IS NULL;

-- Placeholder tier. Everything starts as commodity; business_logic / chained
-- must be assigned deliberately, otherwise the tier matrix lies about where on
-- the difficulty curve a configuration performs.
UPDATE vulnerabilities SET difficulty_tier = 'commodity' WHERE difficulty_tier IS NULL;
