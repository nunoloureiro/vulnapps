"""Regression tests for the heuristic auto-matcher (app/matching.py).

A pass-the-hash login finding, a 2FA-enrollment-without-reauth finding, a
TOTP-replay finding, and a "client-supplied TOTP secret" finding — four
unrelated bugs — all auto-matched to an unrelated "JWT none-algorithm
accepted" known vuln (id 42) on TaintedPort; a "default nginx credentials"
finding and a "hardcoded admin credentials in UI" finding both auto-matched
to "Missing Security Headers" (id 47). All are real, live incidents
(confirmed via the Vulnapps API against app_id=3), not synthetic examples.

Root cause: vulns 42/43/47 are scoped to "any endpoint" (url="/*"). The
matcher's vuln_type hard-gate (50 points) plus the flat wildcard-URL bonus
(10 points) alone reaches the 60-point match threshold for ANY finding
sharing that broad category, regardless of whether the underlying mechanism
has anything to do with the known vuln — and even without the wildcard
bonus, a same-category finding can still cross the threshold on a
coincidental http_method match alone.

A blanket "never auto-match a wildcard-URL vuln" fix stops all of the above,
but a replay of the entire real TaintedPort corpus (338 findings across 11
scans) through it showed it also silently drops ~20 *genuine* matches to
these same three vulns (real "JWT none-algorithm" / "JWT signature not
verified" / "Missing Security Headers" findings, which legitimately do
apply to any endpoint). The fix therefore requires the finding's own title
and the vuln's title to share a real keyword before allowing a wildcard
match — every real incident found so far shares zero meaningful words with
the vuln it was wrongly matched to; every genuine match shares at least one.
See tasks/scanimport-resilience.md for the full investigation.
"""

from app.matching import match_finding


_JWT_NONE_ALG = {
    "id": 42, "title": "JWT 'none' Algorithm Accepted",
    "vuln_type": "Broken Authentication", "url": "/*",
    "http_method": "GET", "parameter": "Authorization", "filename": None,
}
_JWT_SIG_NOT_VERIFIED = {
    "id": 43, "title": "JWT Signature Not Verified",
    "vuln_type": "Broken Authentication", "url": "/*",
    "http_method": "GET", "parameter": "Authorization", "filename": None,
}
_MISSING_HEADERS = {
    "id": 47, "title": "Missing Security Headers",
    "vuln_type": "Security Misconfiguration", "url": "/*",
    "http_method": "GET", "parameter": None, "filename": None,
}
_WILDCARD_VULNS = [_JWT_NONE_ALG, _JWT_SIG_NOT_VERIFIED, _MISSING_HEADERS]


def test_real_incidents_no_longer_auto_match():
    """None of the real mismatched findings should auto-match anymore."""
    pass_the_hash = {
        "title": "Login accepts stored bcrypt hash as the password (pass-the-hash)",
        "vuln_type": "Broken Authentication", "url": "/api/auth/login",
        "http_method": "POST", "parameter": "password", "filename": None,
    }
    two_fa_no_reauth = {
        "title": "2FA enrollment requires no password, letting session hijacker lock out account owner",
        "vuln_type": "Broken Authentication", "url": "/api/auth/2fa/enable",
        "http_method": "POST", "parameter": "totp_secret", "filename": None,
    }
    totp_replay = {
        "title": "TOTP verification lacks replay protection; codes reusable within validity window",
        "vuln_type": "Broken Authentication", "url": "/api/auth/login",
        "http_method": "POST", "parameter": "", "filename": None,
    }
    client_supplied_totp = {
        "title": "Client-supplied TOTP secret accepted at /auth/2fa/enable",
        "vuln_type": "Broken Authentication", "url": "/api/auth/2fa/enable",
        "http_method": "POST", "parameter": "totp_secret", "filename": None,
    }
    default_creds = {
        "title": "Default nginx credentials",
        "vuln_type": "Security Misconfiguration", "url": "/a/vulns/data",
        "http_method": "GET", "parameter": "", "filename": None,
    }
    hardcoded_creds_ui = {
        "title": "Hardcoded admin credentials in UI",
        "vuln_type": "Security Misconfiguration", "url": "/login",
        "http_method": "GET", "parameter": "", "filename": None,
    }

    assert match_finding(pass_the_hash, _WILDCARD_VULNS) == (None, 0)
    assert match_finding(two_fa_no_reauth, _WILDCARD_VULNS) == (None, 0)
    assert match_finding(totp_replay, _WILDCARD_VULNS) == (None, 0)
    assert match_finding(client_supplied_totp, _WILDCARD_VULNS) == (None, 0)
    # This one used to still match even with the wildcard bonus removed —
    # http_method (GET) coincidentally agreed and pushed the score to 65.
    assert match_finding(default_creds, _WILDCARD_VULNS) == (None, 0)
    assert match_finding(hardcoded_creds_ui, _WILDCARD_VULNS) == (None, 0)


def test_genuine_wildcard_matches_are_preserved():
    """The whole point of requiring title confirmation instead of a blanket
    ban: real findings about the actual vuln must still auto-match."""
    jwt_none_alg_finding = {
        "title": "JWT 'none' Algorithm Accepted",
        "vuln_type": "Broken Authentication", "url": "/api/orders/1",
        "http_method": "GET", "parameter": "", "filename": None,
    }
    jwt_sig_finding = {
        "title": "JWT Signature Not Verified - Tampered Payload Accepted",
        "vuln_type": "Broken Authentication", "url": "/api/admin/users",
        "http_method": "GET", "parameter": "", "filename": None,
    }
    missing_headers_finding = {
        "title": "Missing Security Hardening Headers and X-Powered-By Information Disclosure",
        "vuln_type": "Security Misconfiguration", "url": "/",
        "http_method": "GET", "parameter": "", "filename": None,
    }

    assert match_finding(jwt_none_alg_finding, _WILDCARD_VULNS) == (42, 0)
    assert match_finding(jwt_sig_finding, _WILDCARD_VULNS) == (43, 0)
    assert match_finding(missing_headers_finding, _WILDCARD_VULNS) == (47, 0)


def test_wildcard_match_requires_a_title_on_both_sides():
    """No title on the finding (or the vuln) means "can't confirm", not
    "allow" — falling back to the vuln_type category would defeat the
    whole point, since that's exactly the coarse signal being guarded
    against."""
    untitled_finding = {
        "vuln_type": "Broken Authentication", "url": "/api/auth/login",
        "http_method": "GET", "parameter": "", "filename": None,
    }
    assert match_finding(untitled_finding, _WILDCARD_VULNS) == (None, 0)

    untitled_vuln = {
        "id": 999, "vuln_type": "Broken Authentication", "url": "/*",
        "http_method": "GET", "parameter": "", "filename": None,
    }
    titled_finding = {
        "title": "JWT 'none' Algorithm Accepted",
        "vuln_type": "Broken Authentication", "url": "/api/auth/login",
        "http_method": "GET", "parameter": "", "filename": None,
    }
    assert match_finding(titled_finding, [untitled_vuln]) == (None, 0)


def test_legit_exact_url_match_still_works():
    """The fix must not break real matching for vulns with an actual URL."""
    vuln = {
        "id": 32, "vuln_type": "SQL Injection", "url": "/auth/login",
        "http_method": "POST", "parameter": "email", "filename": None,
    }
    finding = {
        "vuln_type": "SQL Injection", "url": "/auth/login",
        "http_method": "POST", "parameter": "email", "filename": None,
    }
    assert match_finding(finding, [vuln]) == (32, 0)


def test_legit_sast_filename_match_still_works():
    """The wildcard branch lives before the URL/filename split — confirm
    SAST (filename-based) matching against a real vuln is untouched."""
    vuln = {
        "id": 90, "vuln_type": "Hardcoded Secret", "url": None,
        "http_method": None, "parameter": None, "filename": "config/jwt.php",
    }
    finding = {
        "vuln_type": "Hardcoded Secret", "url": "", "http_method": "",
        "parameter": "", "filename": "config/jwt.php",
    }
    assert match_finding(finding, [vuln]) == (90, 0)


def test_no_matching_vuln_type_never_matches():
    """Unrelated vuln_type must still hard-gate regardless of URL shape."""
    finding = {
        "title": "JWT 'none' Algorithm Accepted",
        "vuln_type": "XSS", "url": "/api/auth/login",
        "http_method": "POST", "parameter": "password", "filename": None,
    }
    assert match_finding(finding, _WILDCARD_VULNS) == (None, 0)


def _as_sqlite_row(d: dict):
    """Build a real ``sqlite3.Row`` from *d* -- unlike a dict, it has no
    ``.get()``, only bracket access. Every production caller of
    ``match_finding`` passes ``known_vulns`` fetched straight from
    ``aiosqlite`` (same interface as ``sqlite3.Row``), so a test fixture
    that only ever uses plain dicts can't catch a `.get()` call slipping
    into the wildcard-vuln branch -- which is exactly what happened."""
    import sqlite3
    keys = list(d.keys())
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(f"CREATE TABLE t ({', '.join(keys)})")
    con.execute(f"INSERT INTO t VALUES ({', '.join(['?'] * len(keys))})", [d[k] for k in keys])
    row = con.execute("SELECT * FROM t").fetchone()
    con.close()
    return row


def test_wildcard_match_works_with_a_real_db_row_not_just_a_dict():
    """Regression test for a real incident: known_vulns in production is a
    list of aiosqlite.Row objects (from `SELECT * FROM vulnerabilities`),
    which support `row["key"]` but not `row.get("key")`. The wildcard-vuln
    branch called `.get("title")` on the vuln, which crashed with
    `AttributeError: 'sqlite3.Row' object has no attribute 'get'` on every
    scan submission where a finding's vuln_type matched any wildcard-scoped
    (url="/*") known vuln -- i.e. most real scans against TaintedPort."""
    jwt_none_alg_finding = {
        "title": "JWT 'none' Algorithm Accepted",
        "vuln_type": "Broken Authentication", "url": "/api/orders/1",
        "http_method": "GET", "parameter": "", "filename": None,
    }
    row_vulns = [_as_sqlite_row(v) for v in _WILDCARD_VULNS]
    assert match_finding(jwt_none_alg_finding, row_vulns) == (42, 0)
