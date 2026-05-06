-- Token count field on scans (private, like cost)

ALTER TABLE scans ADD COLUMN tokens INTEGER;
