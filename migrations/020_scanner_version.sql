-- Optional scanner version string (e.g. "2.14.0", "v8.1.2")

ALTER TABLE scans ADD COLUMN scanner_version TEXT;
