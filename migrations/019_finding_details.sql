-- Finding-level vuln details (for discovery-mode imports).
--
-- When a scan finds something the platform doesn't yet know about as a vuln,
-- the importer can attach the scanner's full description so the finding can
-- later be promoted into a vulnerability with one click. All fields are
-- nullable — existing scans/findings remain unaffected.

ALTER TABLE scan_findings ADD COLUMN title         TEXT;
ALTER TABLE scan_findings ADD COLUMN severity      TEXT;
ALTER TABLE scan_findings ADD COLUMN description   TEXT;
ALTER TABLE scan_findings ADD COLUMN poc           TEXT;
ALTER TABLE scan_findings ADD COLUMN remediation   TEXT;
ALTER TABLE scan_findings ADD COLUMN code_location TEXT;
