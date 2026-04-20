-- Optional cost field on scans (private: only shown to owner, team members, admin)

ALTER TABLE scans ADD COLUMN cost REAL;
