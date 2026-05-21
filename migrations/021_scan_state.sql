-- Optional scanner state blob (zip of the source directory used by scanimport).
-- File lives on disk at <STATE_DIR>/<scan_id>.zip; columns hold metadata.

ALTER TABLE scans ADD COLUMN state_filename TEXT;
ALTER TABLE scans ADD COLUMN state_size INTEGER;
ALTER TABLE scans ADD COLUMN state_sha256 TEXT;
