# Vulnapps - Application Builder Spec

Complete specification to build the Vulnapps application from scratch.

---

## Overview

Vulnerability registry app where users register known vulnerable applications with their vulnerabilities, then submit scan results to measure scanner accuracy (TP, FP, FN, precision, recall, F1).

**Stack:** FastAPI + SQLite (aiosqlite) + Jinja2 templates + JWT auth (bcrypt + pyjwt)
**Target:** AWS t2.nano (512MB RAM) — must be lightweight
**Python:** >=3.8 (use `from __future__ import annotations` for type union syntax)

---

## Visual Design

Dark theme with orange accents:
- **Background:** Near-black (`#0a0a0a`), dark panels (`#18181b`)
- **Borders:** Dark gray (`#27272a`), hover (`#3f3f46`)
- **Primary accent:** Orange (`#f97316`), hover (`#fb923c`), dim (`rgba(249,115,22,0.15)`)
- **Text:** White (`#fafafa`) headings, `#a1a1aa` secondary, `#71717a` muted
- **Success/Error:** Green `#22c55e` for TP/good, Red `#ef4444` for FP/FN/bad
- **Severity badges:** critical=red, high=orange, medium=yellow, low=green, info=blue
- **Role badges:** user=gray, contributor=orange, admin=red
- Custom CSS (no framework) — Tailwind-inspired utility classes, hand-written for minimal footprint
- Font: system font stack, monospace for code/IDs

---

## User Roles & Permissions

| Role | Can do |
|------|--------|
| **viewer** | Browse apps/vulns/scans (read-only) |
| **user** (default) | Everything viewer + submit scan results, create teams |
| **contributor** | Everything user + create/edit apps and their vulnerabilities |
| **admin** | Everything + manage all users, manage all teams |

- First registered user automatically becomes **admin**
- Subsequent users register as **user** by default
- Admin grants contributor/admin access via `/admin/users`

---

## Project Structure

```
vulnapps/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, lifespan, static/template config, middleware, router includes
│   ├── config.py             # Settings from env vars (SECRET_KEY, DATABASE_PATH, TOKEN_EXPIRY_HOURS)
│   ├── database.py           # aiosqlite connection (Row factory), migration runner
│   ├── auth.py               # bcrypt hash/verify, JWT create/decode (HS256)
│   ├── dependencies.py       # get_current_user, require_user, require_active_user, require_contributor, require_admin
│   ├── matching.py           # Shared scan finding matching logic (DAST + SAST)
│   ├── visibility.py         # App visibility filter (public/team/private)
│   ├── models.py             # Pydantic schemas (UserCreate, UserLogin, AppCreate, VulnCreate, ScanCreate, FindingCreate)
│   ├── templating.py         # Shared Jinja2Templates instance (breaks circular import)
│   ├── seed.py               # TaintedPort seed data (25 vulns, auto-seeded on first admin registration)
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth_routes.py    # /auth — login, register, logout
│   │   ├── apps.py           # /apps — app CRUD (web)
│   │   ├── vulns.py          # /apps/{id}/vulns — vulnerability CRUD (web)
│   │   ├── scans.py          # /scans, /apps/{id}/scans — scan submission + metrics (web)
│   │   ├── admin.py          # /admin — user management with inline editing (web)
│   │   ├── teams.py          # /teams — team CRUD, member management (web)
│   │   └── api.py            # /api/v1 — REST API (JSON)
│   ├── templates/
│   │   ├── base.html         # Layout: navbar, alerts, content block
│   │   ├── home.html         # Hero landing page
│   │   ├── auth/
│   │   │   ├── login.html
│   │   │   └── register.html
│   │   ├── apps/
│   │   │   ├── list.html     # Card grid with search
│   │   │   ├── detail.html   # App info + vulns table + scan link
│   │   │   └── form.html     # Create/edit form
│   │   ├── vulns/
│   │   │   ├── detail.html   # Full vuln detail with PoC
│   │   │   └── form.html     # Create/edit form
│   │   ├── scans/
│   │   │   ├── list.html     # Scans table with TP/FP counts
│   │   │   ├── detail.html   # Metrics dashboard + findings table + missed vulns
│   │   │   ├── submit.html   # Scan form with dynamic JS finding rows
│   │   │   └── compare.html  # Scan comparison: selector + metrics table + detection matrix
│   │   ├── admin/
│   │   │   └── users.html    # User table with inline editing + delete
│   │   └── teams/
│   │       ├── list.html     # Teams table
│   │       ├── form.html     # Create team form
│   │       └── detail.html   # Team detail + member management
│   └── static/
│       ├── style.css         # Full dark theme CSS
│       └── logo.svg          # Shield + crosshair SVG logo (orange on dark)
├── migrations/
│   ├── 001_initial.sql       # Schema with all tables and indexes
│   ├── 002_tech_stack.sql    # App technologies table
│   ├── 003_rename_username_to_name.sql  # Rename username → name
│   ├── 004_static_scan_support.sql      # Add filename to vulns + findings
│   ├── 005_viewer_role.sql              # Add viewer role to users
│   ├── 006_teams.sql                    # Teams + team_members tables
│   └── 007_app_visibility.sql           # App visibility + team_id
├── tests/
│   └── __init__.py
├── tasks/
│   └── todo.md
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .env.example
├── DeployInstructions.txt
├── aws/
│   └── setup-ec2.sh
└── docker/
    └── nginx-host-vulnapps.conf
```

---

## Dependencies

```
fastapi
uvicorn[standard]
jinja2
python-multipart
aiosqlite
pyjwt
bcrypt
python-dotenv
httpx
pytest
pytest-asyncio
```

---

## Configuration (`app/config.py`)

Environment variables with defaults:
- `SECRET_KEY` — JWT signing key (default: `"change-me-in-production"`)
- `DATABASE_PATH` — SQLite file path (default: `"vulnapps.db"`)
- `TOKEN_EXPIRY_HOURS` — JWT token lifetime (default: `24`)

Uses `python-dotenv` to load `.env` file.

---

## Database Schema (migrations 001–007)

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('viewer','user','contributor','admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS apps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    category    TEXT,                                   -- Legacy, not used in UI
    created_by  INTEGER NOT NULL REFERENCES users(id),
    visibility  TEXT NOT NULL DEFAULT 'public',  -- public, team, private
    team_id     INTEGER REFERENCES teams(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    vuln_id       TEXT NOT NULL,                -- Custom ID e.g. "VULN-001"
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
    vuln_type     TEXT,                         -- e.g. "XSS", "SQLi", "SSRF"
    http_method   TEXT,                         -- GET, POST, etc.
    url           TEXT,                         -- Affected URL/endpoint
    parameter     TEXT,                         -- Affected parameter (DAST)
    filename      TEXT,                         -- Affected file (SAST)
    description   TEXT,
    code_location TEXT,
    poc           TEXT,                         -- Proof of concept
    remediation   TEXT,
    created_by    INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, vuln_id)
);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id         INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    scanner_name   TEXT NOT NULL,               -- "ZAP", "Burp", etc.
    scan_date      TEXT NOT NULL,
    authenticated  INTEGER NOT NULL DEFAULT 0,
    is_public      INTEGER NOT NULL DEFAULT 1,
    notes          TEXT,
    submitted_by   INTEGER NOT NULL REFERENCES users(id),
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type       TEXT NOT NULL,
    http_method     TEXT,
    url             TEXT,
    parameter       TEXT,
    filename        TEXT,                         -- SAST finding filename
    matched_vuln_id INTEGER REFERENCES vulnerabilities(id),
    is_false_positive INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_vulns_app ON vulnerabilities(app_id);
CREATE INDEX IF NOT EXISTS idx_scans_app ON scans(app_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id);

-- 002_tech_stack.sql
CREATE TABLE IF NOT EXISTS app_technologies (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id  INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tech_app ON app_technologies(app_id);

-- 006_teams.sql
CREATE TABLE IF NOT EXISTS teams (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS team_members (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id  INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member','admin')),
    UNIQUE(team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
```

### Tech Stack
Apps have a one-to-many relationship with `app_technologies`. Each row stores a single technology name (e.g., "PHP", "Next.js"). In the web form, users enter comma-separated values which are parsed and stored as individual rows. The `category` column in `apps` is legacy and not used in the UI.

---

## Architecture Patterns

### Circular Import Prevention
`app/templating.py` holds the shared `Jinja2Templates` instance. Both `main.py` and all routers import from `app.templating`, NOT from `app.main`. This breaks the circular dependency since `main.py` imports routers at module level.

### Database Access in Routes
Routes use manual connection management (not FastAPI dependency injection):
```python
db = await get_connection()
try:
    # ... queries using db.execute() with parameterized SQL ...
finally:
    await db.close()
```
`get_connection()` returns an `aiosqlite.Connection` with `row_factory = aiosqlite.Row` (dict-like access) and `PRAGMA foreign_keys=ON`.

### Migration Runner
On startup (via FastAPI lifespan), all `.sql` files in `migrations/` are executed in sorted order using `executescript()`. Tracks applied migrations in a `_migrations` table to avoid re-running non-idempotent migrations (e.g., ALTER TABLE). Uses `CREATE TABLE IF NOT EXISTS` for idempotency in schema-creation migrations.

### Auth Flow
- **Login:** email + password (not username)
- **Register:** name (display name) + email + password
- **Web:** JWT stored in httponly cookie named `token`, set on login/register, deleted on logout
- **API:** JWT in `Authorization: Bearer <token>` header
- `get_current_user` middleware checks cookie first, then header, injects result into `request.state.user`
- Role-based auth functions raise HTTPException 401/403:
  - `require_user` — any authenticated user
  - `require_active_user` — any non-viewer (rejects viewers with 403)
  - `require_contributor` — contributor or admin
  - `require_admin` — admin only
- Password hashing: bcrypt
- JWT payload: `{ sub: user_id, name, role, exp }`
- 24h token expiry, no refresh tokens

### First User = Admin + Seed Data
In `auth_routes.py`, the register handler checks `SELECT COUNT(*) FROM users`. If 0, the new user gets `role='admin'`. All subsequent users get `role='user'`.

When the first admin registers, `seed_taintedport(db, user_id)` is called to populate the database with the TaintedPort app and all 25 known vulnerabilities. The seed function is idempotent — it checks if TaintedPort already exists before inserting.

### Seed Data: TaintedPort (`app/seed.py`)
Pre-populated app: **TaintedPort v1.0** — intentionally vulnerable wine store (PHP + Next.js + SQLite).

25 vulnerabilities seeded with full details (description, code_location, poc, remediation):

| ID | Title | Severity | Type |
|----|-------|----------|------|
| TP-001 | SQL Injection - Login Email | high | SQLi |
| TP-002 | SQL Injection - Wine Detail (ID in URL) | high | SQLi |
| TP-003 | SQL Injection - Wine Search | high | SQLi |
| TP-004 | SQL Injection - Wine Reviews | high | SQLi |
| TP-005 | Blind SQL Injection - Order Status Filter | high | SQLi |
| TP-006 | Reflected XSS - Login Email | medium | XSS |
| TP-007 | Reflected XSS - Wine Search | medium | XSS |
| TP-008 | Stored XSS - User Name (Profile) | medium | XSS |
| TP-009 | Stored XSS - Shipping Name (Checkout) | medium | XSS |
| TP-010 | Stored XSS - Wine Review Comment | medium | XSS |
| TP-011 | JWT 'none' Algorithm Accepted | high | Broken Authentication |
| TP-012 | JWT Signature Not Verified | high | Broken Authentication |
| TP-013 | Directory Listing | medium | Information Disclosure |
| TP-014 | Path Traversal - Wine Export | high | Path Traversal |
| TP-015 | Open Redirect on Login | medium | Open Redirect |
| TP-016 | Missing Security Headers | low | Security Misconfiguration |
| TP-017 | BOLA (IDOR) on Order Details | high | IDOR |
| TP-018 | BOLA / Mass Assignment on Profile Update | high | IDOR |
| TP-019 | Price Manipulation on Cart | high | Business Logic |
| TP-020 | Broken Access Control on 2FA Disable | high | Broken Access Control |
| TP-021 | Discount Code Bypass | high | Business Logic |
| TP-022 | Privilege Escalation via Mass Assignment on Registration | critical | Privilege Escalation |
| TP-023 | Privilege Escalation via JWT Claim Forgery | critical | Privilege Escalation |
| TP-024 | BOPLA - Excessive Data Exposure on Order Details | high | Data Exposure |
| TP-025 | BFLA - Broken Function Level Authorization on Order Status | high | Broken Access Control |

Source: `/Users/nuno/dev/TaintedPort/KnownVulnerabilities.txt`

---

## Web Routes

### Auth (`/auth`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/login` | None | Login form |
| POST | `/auth/login` | None | Verify credentials, set cookie, redirect to `/` |
| GET | `/auth/register` | None | Register form |
| POST | `/auth/register` | None | Create user (first=admin), set cookie, redirect to `/` |
| GET | `/auth/logout` | None | Delete cookie, redirect to `/` |

### Apps (`/apps`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/apps` | None | List apps with search (`?q=`). Query joins users for creator_name, subquery for vuln_count |
| GET | `/apps/new` | Contributor+ | Create app form |
| POST | `/apps/new` | Contributor+ | Insert app, redirect to `/apps/{id}` |
| GET | `/apps/{id}` | None | App detail with vulns table, scan count |
| GET | `/apps/{id}/edit` | Contributor+ | Edit app form |
| POST | `/apps/{id}/edit` | Contributor+ | Update app, redirect to `/apps/{id}` |

### Vulnerabilities (`/apps/{id}/vulns`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/apps/{id}/vulns/new` | Contributor+ | Create vuln form |
| POST | `/apps/{id}/vulns` | Contributor+ | Insert vuln, redirect to app detail |
| GET | `/apps/{id}/vulns/{vid}` | None | Vuln detail (vid = DB id, not custom vuln_id) |
| GET | `/apps/{id}/vulns/{vid}/edit` | Contributor+ | Edit vuln form |
| POST | `/apps/{id}/vulns/{vid}/edit` | Contributor+ | Update vuln, redirect to vuln detail |
| POST | `/apps/{id}/vulns/{vid}/delete` | Contributor+ | Delete vuln, redirect to app detail |
| POST | `/apps/{id}/vulns/{vid}/inline` | Contributor+ | AJAX inline update (JSON body with field:value) |

### Scans
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/scans` | None | List scans (public + own private). Joins app name, subqueries for tp_count/fp_count |
| GET | `/scans/example/json` | None | Download example JSON findings file |
| GET | `/scans/example/csv` | None | Download example CSV findings file |
| GET | `/apps/{id}/scans` | Active User+ | Scan submission form (file upload + manual) |
| POST | `/apps/{id}/scans` | Active User+ | Process scan: file upload or form, match findings, redirect to detail |
| GET | `/scans/{id}` | User+ | Scan detail with metrics dashboard, findings table, missed vulns |
| POST | `/scans/{id}/rematch` | Active User+ | Re-run automatic matching for all findings, return updated count |
| GET | `/apps/{id}/compare` | None | Scan comparison — selector when no params, results when `?scans=1,2,3` |

### Admin (`/admin`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/admin/users` | Admin | List all users with inline editing |
| POST | `/admin/users/{id}/role` | Admin | Update user role (viewer, user, or contributor) |
| POST | `/admin/users/{id}/inline` | Admin | AJAX inline update name/email/role |
| POST | `/admin/users/{id}/delete` | Admin | Delete user (cannot delete self or admins) |

### Teams (`/teams`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/teams` | User+ | List teams (own teams; admin sees all) |
| GET | `/teams/new` | Active User+ | Create team form |
| POST | `/teams/new` | Active User+ | Create team (creator becomes team admin) |
| GET | `/teams/{id}` | Team member or admin | Team detail + member list |
| POST | `/teams/{id}/members` | Team admin or app admin | Add member by email |
| POST | `/teams/{id}/members/{uid}/remove` | Team admin or app admin | Remove member |
| POST | `/teams/{id}/members/{uid}/role` | Team admin or app admin | Toggle member/admin role |
| POST | `/teams/{id}/delete` | Team admin or app admin | Delete team |

---

## REST API Routes (`/api/v1`)

All return JSON. Auth via `Authorization: Bearer <token>` header.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/apps` | None | List all apps |
| GET | `/api/v1/apps/{id}` | None | App detail with vulns |
| GET | `/api/v1/apps/{id}/vulns` | None | List vulns for app |
| POST | `/api/v1/apps` | Contributor+ | Create app (JSON body) |
| POST | `/api/v1/apps/{id}/vulns` | Contributor+ | Create vuln (JSON body) |
| GET | `/api/v1/scans` | None | List scans (visibility filtered) |
| GET | `/api/v1/scans/{id}` | User+ | Scan detail with metrics |
| POST | `/api/v1/apps/{id}/scans` | User+ | Submit scan with findings (JSON body) |
| GET | `/api/v1/apps/{id}/compare?scans=1,2,3` | None | Compare up to 7 scans (JSON metrics + detection matrix) |

---

## Scan Submission & Matching

### Web Form Field Naming
Findings submitted as indexed arrays: `findings[0][vuln_type]`, `findings[0][url]`, `findings[0][http_method]`, `findings[0][parameter]`, `findings[1][vuln_type]`, etc.

Router parses by incrementing index in a while loop:
```python
i = 0
while True:
    vt = form.get(f"findings[{i}][vuln_type]")
    if vt is None:
        break
    findings_data.append({...})
    i += 1
```

Dynamic rows added via JavaScript in `submit.html` — clones a template row, increments the index counter.

### API JSON Body
```json
{
  "scanner_name": "ZAP",
  "scan_date": "2026-03-09",
  "authenticated": false,
  "is_public": true,
  "notes": "optional",
  "findings": [
    {"vuln_type": "XSS", "http_method": "GET", "url": "/search", "parameter": "q"}
  ]
}
```

### Matching Logic (`app/matching.py`)

Shared `match_finding(finding, known_vulns)` function used by both web routes and API.

Uses a **scoring-based system** instead of binary matching. Each known vuln is scored against the finding; the highest score above a threshold (60) wins.

**vuln_type match is a hard gate** — candidates that don't match on vuln_type (via canonical aliases) are excluded entirely. This prevents matching an XSS finding to an SQLi vuln just because the URL matches.

**Scoring table:**
| Factor | Points | Notes |
|---|---|---|
| vuln_type match | 50 | Required — no match without this |
| URL exact match | 100 | Strongest signal |
| URL pattern match (placeholders) | 80 - 5*N | N = number of placeholder segments; min 50 |
| URL prefix glob (`/admin/*`) | 40 | Moderate signal |
| URL global wildcard (`/*`) | 10 | Weak — matches everything |
| http_method match | 15 | Scanners sometimes differ |
| parameter exact match | 20 | Strong differentiator |
| parameter substring match | 10 | Handles `user_email` containing `email` |
| SAST filename exact match | 100 | Strong signal for file-level findings |

**URL pattern handling:**
- Placeholder segments (`:id`, `{id}`, `(id)`, `<id>`, `[id]`) compiled to `([^/]+)` regex
- Trailing `/*` compiled to `(/.*)?` (matches zero or more trailing segments)
- `/*` alone compiled to `^/.*$` (matches any path)
- Query strings stripped from finding URLs before comparison
- Compiled regexes cached via `@lru_cache`

**Vuln type aliases** — expanded groups covering: SQLi, XSS, IDOR, auth bypass, access control, info disclosure, path traversal, open redirect, security misconfiguration, privilege escalation, data exposure, business logic, CSRF, SSRF, RCE, XXE, SSTI, NoSQL injection, prototype pollution, HTTP header injection, insecure deserialization, file upload, CORS, clickjacking, JWT, weak crypto, hardcoded secrets.

**Three finding states:**
| State | matched_vuln_id | is_false_positive | Meaning |
|---|---|---|---|
| **TP** | set | 0 | Confident match (auto or manual) |
| **Pending** | null | 0 | No auto-match, awaiting manual review |
| **FP** | null | 1 | User explicitly marked as false positive |

- **Automatic matching**: Score >= 60 → TP. Score < 60 → **Pending** (not FP)
- **Manual mapping** (existing UI): User maps pending finding to known vuln → TP
- **Mark FP** (button on scan detail): User explicitly marks as FP → `POST /scans/{id}/findings/{fid}/mark-fp`
- **Metrics**: Pending findings are **excluded** from TP/FP/precision/recall calculations
- **Compare page**: Pending findings excluded from FP matrix

Two matching modes based on finding content:

**DAST matching** (when finding has `url`):
Score based on vuln_type + URL pattern + http_method + parameter. If both finding and known vuln have URLs but they don't match, that candidate is skipped.

**SAST matching** (when finding has `filename` but no `url`):
Score based on vuln_type + filename exact match (case-insensitive).

### File Upload for Scan Submission

Scans can be submitted via file upload (JSON or CSV) in addition to manual form entry. If a file is uploaded, manual findings are ignored.

**JSON format:**
```json
{"findings": [{"vuln_type": "XSS", "http_method": "GET", "url": "/search", "parameter": "q"}, {"vuln_type": "Hardcoded Secret", "filename": "src/config.py"}]}
```

**CSV format:**
```
vuln_type,http_method,url,parameter,filename
XSS,GET,/search,q,
Hardcoded Secret,,,,src/config.py
```

Example files downloadable at `GET /scans/example/json` and `GET /scans/example/csv`.

### Metrics Computation (on scan detail view)
```
TP      = count of UNIQUE matched vulns (not finding count) — multiple findings matching the same vuln count as 1 TP
FP      = count of findings where is_false_positive = 1
Pending = count of findings where matched_vuln_id IS NULL AND is_false_positive = 0
FN      = known vulns for the app NOT matched by any finding in this scan

precision = TP / (TP + FP)     if (TP + FP) > 0 else 0
recall    = TP / (TP + FN)     if (TP + FN) > 0 else 0
f1        = 2 * P * R / (P+R)  if (P + R) > 0 else 0
```

**TP counts unique vulns, not findings.** If 3 scanner findings all match the same known vuln, TP=1. This prevents inflated precision when scanners report the same vuln multiple times (e.g., "Missing CSP", "Missing HSTS", "Missing X-Frame-Options" all matching TP-016 "Missing Security Headers"). In the scan list SQL, this uses `COUNT(DISTINCT matched_vuln_id)`.

**Duplicate indicator:** When multiple findings match the same vuln, a badge shows "N findings" next to the matched vuln link. Computed via `Counter(matched_vuln_id for matched findings)` and passed as `vuln_finding_counts` dict to template.

Pending findings are excluded from precision/recall calculations — they haven't been classified yet.

Displayed in a metrics-grid: TP (green), FP (red), Pending (yellow), FN (red), Precision/Recall/F1 (orange, as percentages).

### Rematch Endpoint

`POST /scans/{scan_id}/rematch` — Re-runs automatic matching for all findings in a scan. Requires active user (non-viewer). Re-matches ALL findings including manually mapped and manually marked FP ones. Returns `{"ok": true, "updated": count}`.

Use case: After splitting a coarse-grained vuln into finer ones, re-match picks up the new vulns. The UI shows a "Re-match All" button next to the Findings heading (contributor+ only) with a confirmation dialog.

### Split/Refine Workflow

The "+ Vuln" button appears on ALL findings (not just unmatched), allowing users to create fine-grained vulns from any finding — including ones already matched to a coarse vuln. After creating new vulns, "Re-match All" re-runs matching so findings map to the more specific vulns.

---

## Inline Editing Pattern

Used in vuln table (app detail) and user table (admin). Each editable cell has:
- `class="cell-editable"` — pointer cursor, orange highlight on hover
- `data-field` — field name for API call
- `data-value` — current value
- `data-type="select"` — optional, renders dropdown instead of text input

On click: replace cell content with input/select. Save on Enter/change/blur, cancel on Escape.
Save via `fetch POST` to `/{resource}/{id}/inline` with JSON `{field: value}`.
On success, update `data-value` and re-render display (badges for severity/role, links for titles).

CSS: `.cell-editable`, `.cell-editable:hover`, `.inline-input`

Actions column has pencil icon (link to full edit form) and trashcan icon (form POST to delete with confirm).
CSS: `.btn-icon`, `.btn-icon:hover`, `.btn-icon-danger:hover`, `.vuln-row:hover`

---

## App Visibility

Apps have a `visibility` field: `public` (default), `team`, or `private`.

- **public**: visible to everyone (including unauthenticated users)
- **team**: visible only to members of the assigned team + creator + admin
- **private**: visible only to creator + admin

`app/visibility.py` provides `app_visibility_filter(user)` which returns a SQL WHERE clause and params for filtering. Applied in app list and app detail queries.

App form includes visibility dropdown and conditional team selector (shown only when visibility="team").

---

## Teams

Users can create teams and add members by email. Team creator becomes team admin.
Team admins (and app admins) can add/remove members and change member roles (member/admin).

Nav bar shows "Teams" link for all authenticated users. Viewers cannot create teams.

---

## Scan Visibility

- `scans.is_public` defaults to `1` (visible to all)
- User can set to `0` (private) — only visible to the submitter and admins
- List/detail views filter: `WHERE scans.is_public=1 OR scans.submitted_by=?`

---

## Template Details

### base.html
- Sticky top navbar: logo (SVG shield+crosshair, 28x28) + brand "vulnapps" (orange), nav links (Apps, Scans), auth buttons
- Favicon: `/static/logo.svg`
- Scans link only shown to logged-in users
- Teams link only shown to logged-in users
- Admin link only shown to admin role
- Alert blocks for `error` and `success` template variables
- Content block for page-specific content

### Scan Detail Template (`scans/detail.html`)
- Detail grid: scanner, app (linked), date, authenticated, submitted_by, notes
- Metrics grid (7 cards): TP, FP, Pending, FN, Precision%, Recall%, F1%
- Findings table: type, method, url, parameter, filename, status badge (TP green / FP red / Pending yellow)
- Status: TP = matched_vuln_id set, FP = is_false_positive=1, Pending = neither
- Pending findings show "Mark FP" button for contributors/admins
- Manual mapping dropdown: maps pending → TP (or unmaps TP → Pending, not FP)
- Missed Vulnerabilities (FN) table: vuln_id, title (linked), type, severity, url

### Scan Submit Template (`scans/submit.html`)
- File upload section (JSON/CSV) with example download links
- Manual finding rows as fallback (used when no file uploaded)
- JavaScript for dynamic finding rows with add/remove
- Prevents removing the last row
- Each row: vuln_type (text), http_method (select), url (text, DAST), parameter (text, DAST), filename (text, SAST)
- Form uses `enctype="multipart/form-data"`

### App Detail Template (`apps/detail.html`)
- Contributors see: Edit App, Add Vulnerability buttons
- Non-viewer authenticated users see: Submit Scan button
- Shows app visibility badge in detail grid
- Shows `creator_name` (joined from users table) or falls back to `created_by` ID
- **Tech Stack:** Displayed as `badge-info` badges (from `app_technologies` table)
- **Vulnerability Summary:** Before the vulns table, shows total count in header and a `metrics-grid` with severity-colored badge counts (only severities with >0 vulns shown)

### App Form Template (`apps/form.html`)
- Tech Stack field: comma-separated text input with hint text, parsed server-side into individual `app_technologies` rows
- Visibility dropdown: public (default), team, private
- Team selector: shown only when visibility is "team", populated with user's teams

### App List Template (`apps/list.html`)
- Each card shows tech stack badges instead of category
- Shows visibility badge (team/private) when not public
- Template receives `apps` as list of `{"app": row, "tech": [names]}` dicts
- Apps filtered by visibility (via `app_visibility_filter`)

### Scan Comparison Template (`scans/compare.html`)
Two-mode template controlled by `comparison` variable:

**Selector mode** (`comparison` is None):
- Table of available scans for the app with checkboxes
- JavaScript enforces min 2, max 7 selection — disables unchecked boxes at 7
- Submit builds URL: `/apps/{id}/compare?scans=1,2,3`

**Results mode** (`comparison` is set):
- **Metrics Comparison Table**: Rows = metrics (TP, FP, FN, Precision, Recall, F1, Detection Rate), Columns = scanners. Color-coded: green >=70%, yellow >=40%, red <40%
- **Detection Matrix**: Rows = known vulnerabilities, Columns = scanners. Cells show green checkmark (found) or gray X (missed). Last column shows "Found by N/M scanners" with color coding (all=green, none=red, partial=yellow)
- **False Positives Table**: Grouped by scanner with rowspan. Each FP shows vuln_type (red), method, URL, parameter. Scanner name column shows FP count. Only shown if any scanner has FPs.
- "Compare Scans" button appears on app detail page when `scan_count >= 2`

CSS: `.text-center`, `.matrix-hit` (green checkmark), `.matrix-miss` (gray X), `.matrix-table`, `.matrix-header`

---

## CSS Classes Reference

**Layout:** `.container`, `.page-header`, `.page-title`, `.card`, `.card-grid`, `.card-header`, `.card-title`
**Buttons:** `.btn`, `.btn-primary` (orange), `.btn-outline`, `.btn-danger`, `.btn-sm`
**Forms:** `.form-group`, `.form-label`, `.form-input`, `.form-select`, `.form-textarea`, `.form-row` (2-col grid), `.form-check`
**Tables:** `.table-wrap`, `table`, `th`, `td`
**Badges:** `.badge`, `.badge-critical`, `.badge-high`, `.badge-medium`, `.badge-low`, `.badge-info`, `.badge-pending`, `.badge-user`, `.badge-contributor`, `.badge-admin`, `.badge-viewer`, `.badge-member`
**Metrics:** `.metrics-grid`, `.metric-card`, `.metric-value`, `.metric-label`
**Text:** `.text-success`, `.text-error`, `.text-warning`, `.text-accent`, `.text-muted`, `.text-secondary`, `.text-sm`, `.text-xs`, `.font-mono`
**Alerts:** `.alert`, `.alert-error`, `.alert-success`
**Inline Edit:** `.cell-editable`, `.inline-input`, `.btn-icon`, `.btn-icon-danger`, `.btn-save`, `.vuln-row`
**Other:** `.detail-grid`, `.detail-label`, `.detail-value`, `.search-box`, `.empty-state`, `.hero`, `.hero-actions`, `.pagination`
**Spacing:** `.mt-1`/`.mt-2`/`.mt-3`, `.mb-1`/`.mb-2`, `.flex`, `.items-center`, `.gap-1`/`.gap-2`, `.justify-between`

---

## Running (Local Development)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

First registered user becomes admin. Database auto-creates on startup.

---

## Docker Deployment

### Files

**`Dockerfile`**
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
COPY migrations/ migrations/
VOLUME /data
ENV DATABASE_PATH=/data/vulnapps.db
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**`docker-compose.yml`**
```yaml
services:
  vulnapps:
    build: .
    container_name: vulnapps
    restart: unless-stopped
    ports:
      - "8000:8000"
    volumes:
      - vulnapps-data:/data
    env_file:
      - .env
    environment:
      - DATABASE_PATH=/data/vulnapps.db

volumes:
  vulnapps-data:
```

**`.env.example`** (copy to `.env` and customize)
```
SECRET_KEY=change-me-to-a-random-string
DATABASE_PATH=/data/vulnapps.db
TOKEN_EXPIRY_HOURS=24
```

**`.dockerignore`** — Excludes `__pycache__/`, `*.py[cod]`, `venv/`, `.venv/`, `.git/`, `*.db`, `*.sqlite3`, `.env`, `.env.local`, `.coverage`, `htmlcov/`, `.pytest_cache/`, `.DS_Store`, `*.pem`, `*.log`, `tasks/`, `tests/`, `CLAUDE.md`, `AppBuilder.md`, `LICENSE`, `README.md`

### Deploy to EC2

```bash
# First time setup
git clone <repo-url> vulnapps && cd vulnapps
cp .env.example .env
# Edit .env — set a strong SECRET_KEY
docker compose up -d --build
```

### Update Workflow

```bash
cd vulnapps
git pull
docker compose up -d --build
```

The named volume `vulnapps-data` persists the SQLite database across container rebuilds. Data survives `docker compose down` — only `docker volume rm vulnapps_vulnapps-data` would delete it.

### Production Deployment (EC2 alongside TaintedPort)

Same pattern as TaintedPort: build locally for linux/amd64, push to Docker Hub, pull on EC2.

- **Container port:** `8001` on host (TaintedPort uses `8080`)
- **Docker Hub image:** `nunoloureiro/vulnapps:latest`
- **Host nginx** proxies domain to `127.0.0.1:8001` (`docker/nginx-host-vulnapps.conf`)
- **Data persists** via named volume `vulnapps-data`

**`aws/setup-ec2.sh`** — Installs Docker (if needed), pulls image from Docker Hub, creates data volume, runs container on `127.0.0.1:8001` with auto-generated SECRET_KEY.

**`docker/nginx-host-vulnapps.conf`** — Host nginx virtual host config. Server name set to `vulnapps.net`.

**`DeployInstructions.txt`** — Quick reference for local build/push and EC2 update commands.

#### Local Build & Push
```bash
docker build --platform linux/amd64 -t nunoloureiro/vulnapps:latest .
docker push nunoloureiro/vulnapps:latest
```

#### EC2 Update
```bash
sudo docker pull nunoloureiro/vulnapps:latest
sudo docker stop vulnapps; sudo docker rm vulnapps
sudo docker run -d --name vulnapps --restart unless-stopped \
    -p 127.0.0.1:8001:8000 -v vulnapps-data:/data \
    -e SECRET_KEY="YOUR_SECRET_KEY" -e DATABASE_PATH=/data/vulnapps.db \
    vulnapps:latest
```
