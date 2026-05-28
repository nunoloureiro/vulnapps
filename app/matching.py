from __future__ import annotations

import re
from functools import lru_cache

# ---------------------------------------------------------------------------
# Vuln type aliases — map common scanner names to canonical forms.
# ---------------------------------------------------------------------------
_VULN_TYPE_ALIASES: dict = {}

_VULN_TYPE_GROUPS = [
    ["sqli", "sql injection", "sql-injection", "sql_injection"],
    ["xss", "cross-site scripting", "cross site scripting", "reflected xss",
     "stored xss", "dom xss", "dom-based xss",
     "reflected cross-site scripting", "stored cross-site scripting",
     "dom-based cross-site scripting", "dom based cross-site scripting"],
    ["idor", "bola", "insecure direct object reference",
     "broken object level authorization"],
    ["broken authentication", "authentication bypass", "auth bypass"],
    ["broken access control", "bfla", "broken function level authorization",
     "access control", "missing access control"],
    ["information disclosure", "directory listing", "directory browsing",
     "information exposure", "information leakage", "sensitive data exposure"],
    ["path traversal", "directory traversal", "lfi", "local file inclusion",
     "file inclusion"],
    ["open redirect", "url redirect", "unvalidated redirect",
     "unvalidated redirect and forward"],
    ["security misconfiguration", "misconfiguration", "missing security headers",
     "hsts header not enforced", "missing hsts", "strict-transport-security missing",
     "missing content security policy header", "missing csp header",
     "content security policy missing",
     "missing clickjacking protection", "x-frame-options missing",
     "browser content sniffing allowed", "x-content-type-options missing",
     "referrer policy not defined", "missing referrer policy",
     "weak cipher suites enabled", "weak ciphers", "weak ssl ciphers",
     "deprecated tls protocol version 1.0 supported",
     "deprecated tls protocol version 1.1 supported",
     "tls 1.0 supported", "tls 1.1 supported"],
    ["privilege escalation", "mass assignment", "vertical privilege escalation"],
    ["data exposure", "excessive data exposure", "bopla",
     "broken object property level authorization"],
    ["business logic", "business logic flaw", "business logic error"],
    ["csrf", "cross-site request forgery", "cross site request forgery"],
    ["ssrf", "server-side request forgery", "server side request forgery"],
    ["rce", "remote code execution", "command injection", "os command injection"],
    ["xxe", "xml external entity"],
    ["ssti", "server-side template injection", "template injection"],
    ["nosql injection", "nosqli", "mongodb injection"],
    ["prototype pollution"],
    ["http header injection", "header injection", "crlf injection"],
    ["insecure deserialization", "object injection"],
    ["file upload", "unrestricted file upload", "arbitrary file upload"],
    ["cors misconfiguration", "cors",
     "cross origin resource sharing: arbitrary origin trusted",
     "cors: arbitrary origin trusted",
     "cross-origin resource sharing misconfiguration"],
    ["clickjacking", "ui redressing"],
    ["jwt", "jwt vulnerability", "insecure jwt"],
    ["weak cryptography", "weak crypto", "broken cryptography"],
    ["hardcoded secret", "hardcoded credential", "hardcoded password",
     "embedded secret", "secret in source"],
]

for _group in _VULN_TYPE_GROUPS:
    _canonical = _group[0]
    for _alias in _group:
        _VULN_TYPE_ALIASES[_alias] = _canonical


def _normalize_vuln_type(vt: str) -> str:
    """Normalize a vuln type string to a canonical form."""
    vt = vt.strip().lower()
    return _VULN_TYPE_ALIASES.get(vt, vt)


# ---------------------------------------------------------------------------
# URL pattern → regex compilation (cached)
# ---------------------------------------------------------------------------

# Matches placeholder segments: :id, {id}, (id), <id>, [id]
_PARAM_PLACEHOLDER_RE = re.compile(
    r'(?::[a-zA-Z_]\w*|\{[a-zA-Z_]\w*\}|\([a-zA-Z_]\w*\)|<[a-zA-Z_]\w*>|\[[a-zA-Z_]\w*\])'
)


def _strip_query_string(url: str) -> str:
    """Remove query string from URL, keeping only the path."""
    idx = url.find('?')
    return url[:idx] if idx != -1 else url


def _path_only(url: str) -> str:
    """Reduce a possibly-absolute URL to its path component.

    Known vuln URLs are stored as paths (``/wines/:id``); DAST scanners
    (Probely, ZAP, …) often report absolute URLs (``https://host/wines/2``).
    Without this normalisation the regex anchored at ``^/`` never matches.
    """
    if not url:
        return url
    # scheme://host/path  →  /path
    if "://" in url:
        rest = url.split("://", 1)[1]
        slash = rest.find("/")
        return rest[slash:] if slash != -1 else "/"
    return url


@lru_cache(maxsize=512)
def _url_to_regex(known_url: str) -> re.Pattern | None:
    """Convert a known vuln URL pattern to a compiled regex.

    Handles:
    - Placeholder segments (:id, {id}, (id), <id>, [id]) -> ([^/]+)
    - Trailing /* -> (/.*)? (matches zero or more trailing segments)
    - Standalone /* -> ^/.*$ (matches anything starting with /)
    - Literal segments -> re.escape()
    """
    url = known_url.strip()
    if not url:
        return None

    # Strip trailing slash (except root)
    if url != '/' and url.endswith('/'):
        url = url.rstrip('/')

    # Global wildcard: /* alone matches everything
    if url == '/*':
        return re.compile(r'^/.*$', re.IGNORECASE)

    # Check for trailing /* glob
    has_trailing_glob = url.endswith('/*')
    if has_trailing_glob:
        url = url[:-2]  # remove /*

    # Split into segments and build regex parts
    segments = url.split('/')
    regex_parts = []
    for seg in segments:
        if not seg:
            continue
        if _PARAM_PLACEHOLDER_RE.fullmatch(seg):
            regex_parts.append(r'([^/]+)')
        else:
            regex_parts.append(re.escape(seg))

    pattern = '^/' + '/'.join(regex_parts)

    if has_trailing_glob:
        pattern += r'(/.*)?'

    pattern += '$'

    return re.compile(pattern, re.IGNORECASE)


def _count_placeholders(known_url: str) -> int:
    """Count placeholder segments in a URL pattern."""
    return len(_PARAM_PLACEHOLDER_RE.findall(known_url))


def _url_match_score(finding_url: str, known_url: str) -> int:
    """Score how well a finding URL matches a known vuln URL pattern.

    Returns:
      100  — exact match
      80-5*N — regex/placeholder match (N = number of placeholders)
      40   — prefix glob match (trailing /*)
      10   — global wildcard (/* matches everything)
      0    — no match
    """
    if not finding_url or not known_url:
        return 0

    f_url = _path_only(_strip_query_string(finding_url).strip()).lower()
    k_url = _path_only(known_url.strip()).lower()

    # Normalize trailing slashes
    if f_url != '/' and f_url.endswith('/'):
        f_url = f_url.rstrip('/')
    if k_url != '/' and k_url.endswith('/'):
        k_url = k_url.rstrip('/')

    # Global wildcard — match anything (used for origin-wide vulns).
    if k_url == '/*':
        return 10

    # Build candidate finding paths so a finding URL of /api/foo can still
    # match a known vuln stored as /foo. DAST scanners report whatever the
    # public route looks like, but vulns in the registry are usually keyed
    # by the backend route.
    candidates = [f_url]
    if f_url.startswith('/api/'):
        candidates.append(f_url[4:])  # /api/foo → /foo

    regex = _url_to_regex(known_url)
    best = 0
    for cand in candidates:
        if cand == k_url:
            return 100
        if regex and regex.match(cand):
            if known_url.strip().rstrip('/').endswith('/*'):
                best = max(best, 40)
            else:
                n = _count_placeholders(known_url)
                best = max(best, max(80 - 5 * n, 50))
    return best


def _param_match_score(finding_param: str, known_param: str) -> int:
    """Score how well finding parameter matches known vuln parameter.

    Returns:
      20  — exact match (case-insensitive)
      10  — substring containment (one contains the other)
      0   — no match
    """
    if not finding_param or not known_param:
        return 0

    fp = finding_param.strip().lower()
    kp = known_param.strip().lower()

    if not fp or not kp:
        return 0

    if fp == kp:
        return 20

    if fp in kp or kp in fp:
        return 10

    return 0


# ---------------------------------------------------------------------------
# Main matching function
# ---------------------------------------------------------------------------

_MATCH_THRESHOLD = 60


def match_finding(finding: dict, known_vulns: list) -> tuple:
    """Match a scan finding against known vulnerabilities using scoring.

    Returns (matched_vuln_id, is_false_positive):
    - Match found (score >= threshold): (vuln_id, 0)  — True Positive
    - No match: (None, 0)  — Pending (awaiting manual review)

    Scoring:
    - vuln_type match: 50 points (REQUIRED — hard gate)
    - URL exact: 100, URL pattern: 80-5*N, URL prefix glob: 40, URL wildcard: 10
    - http_method match: 15
    - parameter exact: 20, parameter substring: 10

    Minimum threshold: 60 points.
    """
    f_vuln_type = _normalize_vuln_type(finding.get("vuln_type") or "")
    f_url = (finding.get("url") or "").strip()
    f_filename = (finding.get("filename") or "").strip()
    f_http_method = (finding.get("http_method") or "").lower().strip()
    f_parameter = (finding.get("parameter") or "").lower().strip()

    best_score = 0
    best_vuln_id = None

    for v in known_vulns:
        # Hard gate: vuln_type must match
        v_vuln_type = _normalize_vuln_type(v["vuln_type"] or "")
        if v_vuln_type != f_vuln_type:
            continue

        score = 50  # vuln_type match base score

        if f_url:
            # DAST matching
            v_url = (v["url"] or "").strip()
            if v_url:
                url_score = _url_match_score(f_url, v_url)
                if url_score == 0:
                    continue  # URL present on both sides but no match — skip
                score += url_score

            # http_method bonus
            v_method = (v["http_method"] or "").lower().strip()
            if v_method and f_http_method and v_method == f_http_method:
                score += 15

            # parameter bonus
            v_param = (v["parameter"] or "").lower().strip()
            if v_param or f_parameter:
                score += _param_match_score(f_parameter, v_param)

        elif f_filename:
            # SAST matching
            v_filename = (v["filename"] or "").strip()
            if v_filename and v_filename.lower() == f_filename.lower():
                score += 100  # exact filename match is strong
            else:
                continue  # no filename match — skip

        if score > best_score:
            best_score = score
            best_vuln_id = v["id"]

    if best_score >= _MATCH_THRESHOLD and best_vuln_id is not None:
        return best_vuln_id, 0

    # No match above threshold — return Pending (not FP)
    return None, 0
