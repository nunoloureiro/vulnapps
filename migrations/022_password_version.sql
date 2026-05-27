-- Used to invalidate outstanding JWTs when a user changes their password.
-- The JWT carries a `pv` claim; on every authenticated request the value is
-- compared against this column and the token is rejected if it is older
-- (see app/dependencies.py::_password_version_ok). (vuln-0019)
ALTER TABLE users ADD COLUMN password_version INTEGER NOT NULL DEFAULT 0;
