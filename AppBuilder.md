# Vulnapps - Application Builder Spec

Complete specification to build the Vulnapps application from scratch.

---

## Overview

Vulnerability registry app where users register known vulnerable applications with their vulnerabilities, then submit scan results to measure scanner accuracy (TP, FP, FN, precision, recall, F1).

**Stack:** FastAPI (API-first) + SQLite (aiosqlite) + React SPA (Vite) + JWT auth (bcrypt + pyjwt)
**Target:** AWS t2.nano (512MB RAM) — must be lightweight
**Python:** >=3.8 (use `from __future__ import annotations` for type union syntax)

---

## Architecture

### API-First Design

The application follows an API-first architecture. All functionality is exposed through JSON REST endpoints under `/api`. The old Jinja2 template-based web routes are removed. A React SPA serves the frontend.

**Backend layers:**
1. **Route handlers** (`app/routers/api/`) — Thin JSON wrappers. Parse request, call service, return JSON or raise HTTPException.
2. **Service layer** (`app/services/`) — All business logic, database queries, permission checks. Services receive a `db` connection and `user` dict.
3. **Shared modules** — `matching.py`, `visibility.py`, `dependencies.py`, `auth.py` provide cross-cutting concerns.

**Frontend:** React SPA in `frontend/` built with Vite. Communicates exclusively via `/api` endpoints. JWT stored in `localStorage`.

**SPA serving:** FastAPI serves the built React app. Non-API, non-static paths that return 404 serve `frontend/dist/index.html` for client-side routing.

---

## Visual Design

Dark theme with orange accents:
- **Background:** Near-black (`#0a0a0a`), dark panels (`#18181b`)
- **Borders:** Dark gray (`#27272a`), hover (`#3f3f46`)
- **Primary accent:** Orange (`#f97316`), hover (`#fb923c`), dim (`rgba(249,115,22,0.15)`)
- **Text:** White (`#fafafa`) headings, `#a1a1aa` secondary, `#71717a` muted
- **Success/Error:** Green `#22c55e` for TP/good, Red `#ef4444` for FP/FN/bad
- **Severity badges:** critical=red, high=orange, medium=yellow, low=green, info=blue
- **Role badges:** user=gray, admin=red. Team roles: admin=red, contributor=orange, view=gray
- Custom CSS (no framework) — Tailwind-inspired utility classes, hand-written for minimal footprint
- Font: system font stack, monospace for code/IDs

---

## User Roles & Permissions

### Account-Level Roles (2)
| Role | Can do |
|------|--------|
| **user** (default) | Create private/team apps, submit scans on own apps, manage teams |
| **admin** | Everything + manage public apps/vulns/scans, manage users, manage labels |

- First registered user automatically becomes **admin**
- Subsequent users register as **user** by default
- Admin grants admin access via admin panel

### Team-Level Roles (3)
| Role | Can do within team |
|------|--------|
| **admin** | Manage team members, full control of team apps/vulns/scans |
| **contributor** | Create/edit apps, vulns, scans within the team |
| **view** | Read-only access to team apps, vulns, and scans |

### Authorization Rules

**Read access:**
- Unauthenticated: public apps, vulns, public scans on public apps
- Logged in: + own private apps/scans, team apps/scans (any team role)
- Admin: everything

**Write access to apps/vulns:**
- Public apps: admin only
- Private apps: app creator only
- Team apps: team admin or team contributor, or app creator

**Scan submission:**
- Public apps: admin only (users must clone to private first)
- Private apps: app creator
- Team apps: team admin or contributor

**Scan modification (match, FP, rematch, delete):**
- Scan submitter (owns the scan)
- Team admin/contributor (for team app scans)
- Admin (always)

### App Cloning
Any logged-in user can clone any app they can read. Cloning creates a private copy with all vulns (not scans).

---

## Project Structure

```
vulnapps/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, lifespan, SPA serving, middleware, API router includes
│   ├── config.py             # Settings from env vars (SECRET_KEY, DATABASE_PATH, TOKEN_EXPIRY_HOURS)
│   ├── database.py           # aiosqlite connection (Row factory), migration runner
│   ├── auth.py               # bcrypt hash/verify, JWT create/decode (HS256)
│   ├── dependencies.py       # get_current_user, require_user, require_admin, require_app_write, require_scan_write, get_team_role, require_scope
│   ├── matching.py           # Shared scan finding matching logic (DAST + SAST)
│   ├── visibility.py         # App/scan visibility filter (public/team/private)
│   ├── models.py             # Pydantic schemas
│   ├── templating.py         # Legacy — Jinja2Templates instance (kept for compatibility)
│   ├── seed.py               # TaintedPort seed data (25+ vulns, auto-seeded on first admin registration)
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── api/              # API-first route handlers (thin JSON wrappers)
│   │   │   ├── __init__.py
│   │   │   ├── auth.py       # /api/auth — login, register, me
│   │   │   ├── account.py    # /api/account — profile, name, password, API keys
│   │   │   ├── apps.py       # /api/apps — app CRUD
│   │   │   ├── vulns.py      # /api/apps/{id}/vulns — vulnerability CRUD + import
│   │   │   ├── scans.py      # /api/scans — scan CRUD, findings, labels, compare, submit
│   │   │   ├── teams.py      # /api/teams — team CRUD, member management
│   │   │   └── admin.py      # /api/admin — user management, label management
│   │   ├── api_legacy.py     # Legacy /api/v1 routes (kept for backward compatibility)
│   │   ├── auth_routes.py    # Legacy web auth routes
│   │   ├── apps.py           # Legacy web app routes
│   │   ├── vulns.py          # Legacy web vuln routes
│   │   ├── scans.py          # Legacy web scan routes
│   │   ├── admin.py          # Legacy web admin routes
│   │   └── teams.py          # Legacy web team routes
│   ├── services/             # Business logic layer
│   │   ├── __init__.py
│   │   ├── auth.py           # Login, register, me, API key management, password/name updates
│   │   ├── apps.py           # App CRUD, cloning, visibility checks
│   │   ├── vulns.py          # Vulnerability CRUD, import (JSON/CSV)
│   │   ├── scans.py          # Scan CRUD, submit, matching, compare, metrics
│   │   ├── labels.py         # Label CRUD, scan-label association, admin label management
│   │   ├── teams.py          # Team CRUD, member management
│   │   └── users.py          # Admin user management (list, update, delete, profiles)
│   └── static/
│       ├── style.css         # Full dark theme CSS (shared by React SPA)
│       └── logo.svg          # Shield + crosshair SVG logo (orange on dark)
├── frontend/                 # React SPA (Vite)
│   ├── index.html            # HTML entry point
│   ├── package.json          # Dependencies: react, react-dom, react-router-dom
│   ├── vite.config.js        # Vite config with dev proxy to backend
│   ├── dist/                 # Built output (served by FastAPI in production)
│   └── src/
│       ├── main.jsx          # React entry point
│       ├── App.jsx           # Router with all 19 page routes
│       ├── api/
│       │   └── client.js     # API client: fetch wrapper with JWT auth, auto-redirect on 401
│       ├── context/
│       │   └── AuthContext.jsx  # Auth state provider (login, register, logout, refreshUser)
│       ├── components/
│       │   ├── Navbar.jsx    # Top nav with auth-aware links
│       │   ├── Badge.jsx     # Severity/role badge component
│       │   ├── LabelBadge.jsx  # Color-coded scan label badge
│       │   ├── ConfirmButton.jsx  # Button with confirmation dialog
│       │   └── EmptyState.jsx    # Empty state placeholder
│       └── pages/
│           ├── Home.jsx          # Landing page
│           ├── Login.jsx         # Login form
│           ├── Register.jsx      # Registration form
│           ├── Account.jsx       # Account settings (name, password, API keys)
│           ├── AppsList.jsx      # App listing with search and filters
│           ├── AppDetail.jsx     # App detail with vulns table, scan count
│           ├── AppForm.jsx       # Create/edit app form (with clone support)
│           ├── VulnDetail.jsx    # Vulnerability detail
│           ├── VulnForm.jsx      # Create/edit vulnerability form
│           ├── ScansList.jsx     # Scans listing with filters (scanner, app, label, auth status)
│           ├── ScanDetail.jsx    # Scan detail with metrics, findings, missed vulns
│           ├── ScanSubmit.jsx    # Scan submission form (JSON/CSV upload or manual entry)
│           ├── ScanCompare.jsx   # Scan comparison with metrics and detection matrix
│           ├── TeamsList.jsx     # Teams listing
│           ├── TeamDetail.jsx    # Team detail with member management
│           ├── TeamForm.jsx      # Create team form
│           ├── AdminUsers.jsx    # Admin user management
│           └── AdminLabels.jsx   # Admin label management
├── migrations/
│   ├── 001_initial.sql       # Schema with all tables and indexes
│   ├── 002_tech_stack.sql    # App technologies table
│   ├── 003_rename_username_to_name.sql  # Rename username → name
│   ├── 004_static_scan_support.sql      # Add filename to vulns + findings
│   ├── 005_viewer_role.sql              # Add viewer role to users
│   ├── 006_teams.sql                    # Teams + team_members tables
│   ├── 007_app_visibility.sql           # App visibility + team_id
│   ├── ...                              # 008-011: incremental changes
│   ├── 012_permissions_redesign.sql     # Collapse roles to user/admin, team roles to admin/contributor/view
│   ├── 013_api_keys.sql                 # API keys table with scopes
│   ├── 014_scan_labels.sql              # Labels + scan_labels junction table
│   ├── 015_scan_cost.sql                # cost REAL column on scans
│   └── 016_scan_tokens.sql              # tokens INTEGER column on scans
├── tools/
│   └── import_scan.py                  # CLI scan importer with LLM-assisted vuln mapping
├── tests/
│   └── __init__.py
├── tasks/
│   └── todo.md
├── requirements.txt
├── pyproject.toml
├── Dockerfile                          # Multi-stage build (Node 20 + Python 3.12)
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

### Backend (`requirements.txt`)
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
anthropic[vertex]
pytest
pytest-asyncio
```

### Frontend (`frontend/package.json`)
```json
{
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.28.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.4",
    "vite": "^5.4.11"
  }
}
```

---

## Configuration (`app/config.py`)

Environment variables with defaults:
- `SECRET_KEY` — JWT signing key (default: `"change-me-in-production"`)
- `DATABASE_PATH` — SQLite file path (default: `"vulnapps.db"`)
- `TOKEN_EXPIRY_HOURS` — JWT token lifetime (default: `24`)

Uses `python-dotenv` to load `.env` file.

---

## Database Schema (migrations 001-016)

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
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
    cost           REAL,                        -- Private: scan cost in USD (migration 015)
    tokens         INTEGER,                     -- Private: LLM token count (migration 016)
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
    role     TEXT NOT NULL DEFAULT 'view' CHECK(role IN ('admin','contributor','view')),
    UNIQUE(team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);

-- Migration 013: API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    key_hash   TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT 'default',
    scope      TEXT NOT NULL DEFAULT 'read' CHECK(scope IN ('read','vuln-mapper','full')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used  TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);

-- Migration 014: Scan labels
CREATE TABLE IF NOT EXISTS labels (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL UNIQUE,
    color TEXT NOT NULL DEFAULT '#f97316'
);

CREATE TABLE IF NOT EXISTS scan_labels (
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    label_id INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, label_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_labels_scan ON scan_labels(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_labels_label ON scan_labels(label_id);
```

### Tech Stack
Apps have a one-to-many relationship with `app_technologies`. Each row stores a single technology name (e.g., "PHP", "Next.js"). In the form, users enter comma-separated values which are parsed and stored as individual rows. The `category` column in `apps` is legacy and not used in the UI.

### Scan Labels
Labels are user-defined, color-coded tags for scans. A many-to-many junction table (`scan_labels`) links scans to labels. Labels can be added/removed per-scan by anyone with scan write access. Admin can manage labels globally (CRUD) via `/api/admin/labels`. Labels are displayed as color-coded badges in the scans list and scan detail. The scans list supports filtering by label.

### Scan Cost & Tokens
Private fields on scans (`cost REAL`, `tokens INTEGER`). Only visible to the scan owner, team members of the app's team, and admins. Used to track LLM-based scanner costs. The CLI auto-captures token count from the LLM response if `--tokens` is not explicitly set.

---

## Architecture Patterns

### Service Layer Pattern
All business logic lives in `app/services/`. Route handlers in `app/routers/api/` are thin JSON wrappers:
1. Parse request (query params, JSON body)
2. Call service function with `db`, `user`, and parsed args
3. Return JSON result or raise HTTPException for errors

Services raise `ValueError` (mapped to 400/404) or `PermissionError` (mapped to 403) — route handlers catch and convert to HTTP errors.

### Database Access
Routes and services use manual connection management:
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
- **Frontend (React SPA):** JWT stored in `localStorage`, sent as `Authorization: Bearer <token>` header
- **API:** JWT or API key in `Authorization: Bearer <token>` header
- **API Keys:** Format `va_` + 32 hex chars. Stored as SHA-256 hash. Users generate/revoke from Account page.
  - Scopes: `read` (GET only), `vuln-mapper` (read + submit scans + match findings), `full` (all ops)
  - `get_current_user` detects `va_` prefix → looks up in `api_keys` table → loads user with `api_key_scope`
  - `require_scope(user, min_scope)` enforces scope hierarchy on all write endpoints. JWT users bypass scope checks.
- `get_current_user` middleware checks Bearer header (JWT or API key), injects result into `request.state.user`
- Role-based auth functions raise HTTPException 401/403:
  - `require_user` — any authenticated user
  - `require_admin` — admin only
  - `require_app_write(request, db, app)` — admin, creator, or team contributor+
  - `require_scan_write(request, db, scan, app)` — admin, submitter, or team contributor+
  - `get_team_role(db, user_id, team_id)` — returns team role or None
  - `require_scope(user, min_scope)` — API key scope check
- Password hashing: bcrypt
- JWT payload: `{ sub: user_id, name, role, exp }`
- 24h token expiry, no refresh tokens

### Security
- Password hashes are excluded from the admin user list endpoint
- API key scope enforcement on all write endpoints
- All write operations check both authentication and authorization

### First User = Admin + Seed Data
In the register service, when user count is 0, the new user gets `role='admin'`. All subsequent users get `role='user'`.

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
| TP-027 | SSRF via Wine Import URL | high | SSRF |
| TP-028 | SQLi -> TOTP Secret Extraction -> 2FA Bypass -> Account Takeover | critical | SQLi |
| TP-029 | Reflected XSS - Contact Form Preview (Server-Side) | medium | XSS |

Source: `/Users/nuno/dev/TaintedPort/KnownVulnerabilities.txt`

---

## API Routes (`/api`)

All endpoints return JSON. Auth via `Authorization: Bearer <token>` header (JWT or API key). Auto-generated Swagger UI at `/api/docs`, ReDoc at `/api/redoc`, OpenAPI spec at `/api/openapi.json`.

### API Root (`/api`)
`GET /api` — Returns API info and endpoint listing. Redirects to Swagger UI if `Accept: text/html`.

### Auth (`/api/auth`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| POST | `/api/auth/login` | None | Login with `{email, password}`, returns `{token, user}` |
| POST | `/api/auth/register` | None | Register with `{name, email, password}`, returns `{token, user}` |
| GET | `/api/auth/me` | User+ | Get current user profile |

### Apps (`/api/apps`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/apps` | None / read | List apps (visibility filtered). Query: `?q=`, `?filter=` |
| GET | `/api/apps/{id}` | None / read | App detail with vulns, tech stack, permissions |
| POST | `/api/apps` | User+ / full | Create app. Body: `{name, version, description, url, visibility, team_id, tech_stack, clone_from}` |
| PUT | `/api/apps/{id}` | App write / full | Update app |
| DELETE | `/api/apps/{id}` | App write / full | Delete app |

### Vulnerabilities (`/api/apps/{id}/vulns`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/apps/{id}/vulns` | None / read | List vulns for app |
| GET | `/api/apps/{id}/vulns/{vid}` | None / read | Vuln detail |
| POST | `/api/apps/{id}/vulns` | App write / full | Create vuln |
| PUT | `/api/apps/{id}/vulns/{vid}` | App write / full | Update vuln |
| DELETE | `/api/apps/{id}/vulns/{vid}` | App write / full | Delete vuln |
| POST | `/api/apps/{id}/vulns/import` | App write / full | Import vulns from JSON/CSV (file upload or JSON body) |

### Scans (`/api/scans` + `/api/apps/{id}/scans`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/scans` | None / read | List scans with filters: `?app_id=`, `?scanner=`, `?latest=`, `?q=`, `?authenticated=`, `?label=`, `?filter=`. Returns scans, scan_labels_map, scanners list, apps list, all labels |
| GET | `/api/scans/{id}` | Varies / read | Scan detail with metrics, findings, missed vulns, labels |
| PUT | `/api/scans/{id}` | Scan write / vuln-mapper | Update scan metadata: `{scanner_name, scan_date, authenticated, notes}` |
| DELETE | `/api/scans/{id}` | Scan write | Delete scan |
| POST | `/api/apps/{id}/scans` | User+ / vuln-mapper | Submit scan. Body: `{scanner_name, scan_date, authenticated, is_public, notes, cost, tokens, findings, labels}` |
| POST | `/api/scans/{id}/findings/{fid}/match` | Scan write / vuln-mapper | Map finding to vuln: `{vuln_id: int\|null}` |
| POST | `/api/scans/{id}/findings/{fid}/mark-fp` | Scan write / vuln-mapper | Mark finding as false positive |
| POST | `/api/scans/{id}/rematch` | Scan write / vuln-mapper | Re-run automatic matching for all findings |
| POST | `/api/scans/{id}/labels` | Scan write | Add label to scan: `{name, color}`. Upserts label, links to scan |
| DELETE | `/api/scans/{id}/labels/{label_id}` | Scan write | Remove label from scan |

### Scan Comparison (`/api/apps/{id}/compare`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/apps/{id}/compare` | None / read | Without `?scans=`: returns available scans. With `?scans=1,2,3`: returns comparison metrics + detection matrix |

### Labels (`/api/labels`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/labels` | None | List all labels (name, color) |

### Teams (`/api/teams`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/teams` | User+ | List teams (own teams; admin sees all) |
| GET | `/api/teams/{id}` | Team member+ | Team detail with members |
| POST | `/api/teams` | User+ | Create team (creator becomes team admin) |
| DELETE | `/api/teams/{id}` | Team admin+ | Delete team |
| POST | `/api/teams/{id}/members` | Team admin+ | Add member: `{email, role}` |
| PUT | `/api/teams/{id}/members/{uid}` | Team admin+ | Change member role: `{role}` |
| DELETE | `/api/teams/{id}/members/{uid}` | Team admin+ | Remove member |

### Account (`/api/account`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/account` | User+ | Account info + API keys |
| PUT | `/api/account/name` | User+ | Update display name: `{name}`. Returns new JWT token |
| PUT | `/api/account/password` | User+ | Change password: `{current_password, new_password}` |
| POST | `/api/account/api-keys` | User+ | Generate API key: `{name, scope}` — returns full key once |
| DELETE | `/api/account/api-keys/{id}` | User+ | Revoke API key (must own it) |

### Admin (`/api/admin`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/admin/users` | Admin | List all users (password hashes excluded) |
| PUT | `/api/admin/users/{id}` | Admin | Update user (name, email, role) |
| DELETE | `/api/admin/users/{id}` | Admin | Delete user (cannot delete self or admins) |
| GET | `/api/admin/labels` | Admin | List labels with scan_count |
| POST | `/api/admin/labels` | Admin | Create label: `{name, color}` |
| PUT | `/api/admin/labels/{id}` | Admin | Update label: `{name, color}` |
| DELETE | `/api/admin/labels/{id}` | Admin | Delete label and all associations |

---

## React SPA Frontend

### Technology
- **Framework:** React 18 with Vite 5
- **Routing:** React Router DOM v6
- **Styling:** Reuses existing `style.css` from `/static/style.css` (no CSS framework)
- **Auth:** JWT stored in `localStorage`, sent as `Authorization: Bearer` header
- **API Client:** `frontend/src/api/client.js` — thin fetch wrapper with auto-401 redirect

### Vite Configuration
Dev server proxies `/api` and `/static` to `http://127.0.0.1:8000`. Build output goes to `frontend/dist/`.

### Auth Context (`AuthContext.jsx`)
React context providing `{user, loading, login, register, logout, refreshUser}`. On mount, checks for stored token and calls `/api/auth/me` to restore session.

### Page Routes (19 pages)
| Route | Component | Description |
|-------|-----------|-------------|
| `/` | Home | Landing page |
| `/login` | Login | Login form |
| `/register` | Register | Registration form |
| `/account` | Account | Settings: name, password, API keys |
| `/apps` | AppsList | App listing with search |
| `/apps/new` | AppForm | Create app (supports `?clone_from=`) |
| `/apps/:id` | AppDetail | App detail + vulns table + scan/compare links |
| `/apps/:id/edit` | AppForm | Edit app |
| `/apps/:appId/vulns/new` | VulnForm | Create vulnerability |
| `/apps/:appId/vulns/:id` | VulnDetail | Vulnerability detail |
| `/apps/:appId/vulns/:id/edit` | VulnForm | Edit vulnerability |
| `/apps/:id/scans/new` | ScanSubmit | Submit scan (file upload or manual) |
| `/apps/:id/compare` | ScanCompare | Scan comparison |
| `/scans` | ScansList | All scans with filters |
| `/scans/:id` | ScanDetail | Scan metrics + findings + FN |
| `/teams` | TeamsList | Teams listing |
| `/teams/new` | TeamForm | Create team |
| `/teams/:id` | TeamDetail | Team detail + member management |
| `/admin/users` | AdminUsers | Admin user management |
| `/admin/labels` | AdminLabels | Admin label management |

### Shared Components
- **Navbar** — Auth-aware nav: Apps, Scans (logged-in), Teams (logged-in), Admin (admin), Account/Login/Register
- **Badge** — Severity/role colored badges
- **LabelBadge** — Color-coded scan label badge with optional remove button
- **ConfirmButton** — Button that shows confirmation dialog before action
- **EmptyState** — Placeholder for empty lists

---

## Scan Submission & Matching

### API JSON Body
```json
{
  "scanner_name": "ZAP",
  "scan_date": "2026-03-09",
  "authenticated": false,
  "is_public": true,
  "notes": "optional",
  "cost": 0.05,
  "tokens": 12500,
  "labels": ["label-name"],
  "findings": [
    {"vuln_type": "XSS", "http_method": "GET", "url": "/search", "parameter": "q"}
  ]
}
```

### Matching Logic (`app/matching.py`)

Shared `match_finding(finding, known_vulns)` function used by the scan service.

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
- **Manual mapping**: User maps pending finding to known vuln → TP
- **Mark FP**: User explicitly marks as FP → `POST /api/scans/{id}/findings/{fid}/mark-fp`
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

### Metrics Computation
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

**Duplicate indicator:** When multiple findings match the same vuln, a badge shows "N findings" next to the matched vuln link.

Pending findings are excluded from precision/recall calculations — they haven't been classified yet.

Displayed in a metrics-grid: TP (green), FP (red), Pending (yellow), FN (red), Precision/Recall/F1 (orange, as percentages).

### Editable Scan Metadata

`PUT /api/scans/{id}` allows updating `scanner_name`, `scan_date`, `authenticated`, and `notes` on an existing scan. Requires scan write access and `vuln-mapper` API key scope.

### Rematch Endpoint

`POST /api/scans/{id}/rematch` — Re-runs automatic matching for all findings in a scan. Requires scan write access. Re-matches ALL findings including manually mapped and manually marked FP ones. Returns `{"ok": true, "updated": count}`.

Use case: After splitting a coarse-grained vuln into finer ones, re-match picks up the new vulns.

### Split/Refine Workflow

Users can create fine-grained vulns from any finding — including ones already matched to a coarse vuln. After creating new vulns, "Re-match All" re-runs matching so findings map to the more specific vulns.

---

## Scan Comparison

Comparison page at `/apps/:id/compare` (API: `GET /api/apps/{id}/compare?scans=1,2,3`).

**Features:**
- No scan limit for comparison (select any number of scans)
- Severity filter toggles that recalculate metrics dynamically
- Horizontal scroll with sticky columns for the detection matrix
- Cost/tokens shown in comparison when available (private, only shown to authorized users)
- Scans ordered by date in the selector

**Comparison data includes:**
- **Metrics Table**: TP, FP, FN, Precision, Recall, F1, Detection Rate per scanner. Color-coded: green >=70%, yellow >=40%, red <40%
- **Detection Matrix**: Rows = known vulnerabilities, Columns = scanners. Green checkmark (found) or gray X (missed). Coverage summary per vuln.
- **False Positives Table**: FPs grouped by scanner with vuln_type, method, URL, parameter.
- Scanner names in comparison link to scan detail page

---

## Scan Labels

User-defined, color-coded tags for organizing scans.

- **Labels table**: `id`, `name` (unique), `color` (hex, default orange)
- **Junction table**: `scan_labels(scan_id, label_id)` — many-to-many
- **Badge display**: Color-coded badges in scans list and scan detail
- **Filtering**: Scans list supports `?label=` filter
- **Management**: Admin can CRUD labels via `/api/admin/labels`. Non-admin users can add/remove labels on scans they have write access to.
- **CLI support**: `--labels` flag on import_scan.py for auto-labeling (labels auto-created if they don't exist)

---

## App Visibility

Apps have a `visibility` field: `public` (default), `team`, or `private`.

- **public**: visible to everyone (including unauthenticated users)
- **team**: visible only to members of the assigned team + creator + admin
- **private**: visible only to creator + admin

`app/visibility.py` provides `app_visibility_filter(user)` which returns a SQL WHERE clause and params for filtering. Applied in app list and app detail queries.

---

## Teams

Users can create teams and add members by email. Team creator becomes team admin.
Team admins (and app admins) can add/remove members and change member roles (admin/contributor/view).

---

## Scan Visibility

- `scans.is_public` defaults to `1` (visible to all)
- User can set to `0` (private) — only visible to the submitter, team members, and admins
- `app/visibility.py` provides `scan_visibility_filter(user)` which includes:
  - Unauthenticated: public scans on public apps only
  - Logged in: public scans + own scans + scans on team apps
  - Admin: all scans

---

## CSS Classes Reference

**Layout:** `.container`, `.page-header`, `.page-title`, `.card`, `.card-grid`, `.card-header`, `.card-title`
**Buttons:** `.btn`, `.btn-primary` (orange), `.btn-outline`, `.btn-danger`, `.btn-sm`
**Forms:** `.form-group`, `.form-label`, `.form-input`, `.form-select`, `.form-textarea`, `.form-row` (2-col grid), `.form-check`
**Tables:** `.table-wrap`, `table`, `th`, `td`
**Badges:** `.badge`, `.badge-critical`, `.badge-high`, `.badge-medium`, `.badge-low`, `.badge-info`, `.badge-pending`, `.badge-user`, `.badge-admin`, `.badge-contributor`, `.badge-view`, `.badge-member` (legacy)
**Metrics:** `.metrics-grid`, `.metric-card`, `.metric-value`, `.metric-label`
**Text:** `.text-success`, `.text-error`, `.text-warning`, `.text-accent`, `.text-muted`, `.text-secondary`, `.text-sm`, `.text-xs`, `.font-mono`
**Alerts:** `.alert`, `.alert-error`, `.alert-success`
**Inline Edit:** `.cell-editable`, `.inline-input`, `.btn-icon`, `.btn-icon-danger`, `.btn-save`, `.vuln-row`
**Other:** `.detail-grid`, `.detail-label`, `.detail-value`, `.search-box`, `.empty-state`, `.hero`, `.hero-actions`, `.pagination`
**Spacing:** `.mt-1`/`.mt-2`/`.mt-3`, `.mb-1`/`.mb-2`, `.flex`, `.items-center`, `.gap-1`/`.gap-2`, `.justify-between`

---

## CLI Scan Importer (`tools/import_scan.py`)

LLM-assisted CLI tool to import scan results (.md files) into Vulnapps.

**Usage:**
```bash
python tools/import_scan.py --url https://vulnapps.example.com \
    --api-key va_... --app-id 1 --dir ./scan-results/
```

**Features:**
- Reads one or more `.md` scan result files (combines into single scan via `--dir`)
- Sends scan content + known vulns to Claude for mapping
- Displays colored mapping table (matched, unmatched, FP)
- Submits scan and applies LLM match corrections
- Auto-captures LLM token count from response
- Supports `--labels` for auto-labeling scans

**Key flags:**
| Flag | Description |
|------|-------------|
| `--url` | Vulnapps instance URL (required) |
| `--api-key` | API key (or `VULNAPPS_API_KEY` env var) |
| `--app-id` | Target app ID (required) |
| `--dir` | Directory with `.md` files (combined into one scan) |
| `--file` | Single `.md` file to import |
| `--scanner` | Override LLM-detected scanner name |
| `--scan-date` | Override LLM-detected date (YYYY-MM-DD) |
| `--authenticated` | Mark scan as authenticated (overrides LLM detection) |
| `--unauthenticated` | Mark scan as unauthenticated (overrides LLM detection) |
| `--public` | Make scan public (default: private) |
| `--labels` | Comma-separated labels (auto-created if missing) |
| `--confirm` | Ask for confirmation before submitting (default: auto-submit) |
| `--cost` | Scan cost in USD (private field) |
| `--tokens` | Token count (auto-captured from LLM if not set) |
| `--notes` | Notes to attach to the scan |
| `--model` | Claude model (default: `claude-sonnet-4-20250514`) |
| `--provider` | `anthropic` or `vertex` (auto-detected from `CLAUDE_CODE_USE_VERTEX=1`) |
| `--vertex-region` | Vertex AI region (or `ANTHROPIC_VERTEX_LOCATION`) |
| `--vertex-project` | GCP project ID (or `ANTHROPIC_VERTEX_PROJECT_ID`) |
| `--dry-run` | Show mapping without submitting |

**LLM provider:** Supports both Anthropic direct API and Google Vertex AI. Auto-detects from `CLAUDE_CODE_USE_VERTEX=1` env var.

---

## Running (Local Development)

### Backend
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend (development)
```bash
cd frontend
npm install
npm run dev
```
Vite dev server runs on port 5173 and proxies `/api` and `/static` to the backend on port 8000.

### Frontend (production build)
```bash
cd frontend
npm run build
```
Output goes to `frontend/dist/`, which FastAPI serves automatically.

First registered user becomes admin. Database auto-creates on startup.

---

## Docker Deployment

### Dockerfile (Multi-Stage Build)

```dockerfile
# Stage 1: Build React frontend
FROM node:20-slim AS frontend
WORKDIR /frontend
COPY frontend/package*.json .
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Python backend + built frontend
FROM python:3.12-slim
WORKDIR /app

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/
COPY migrations/ migrations/

# Copy built frontend from Stage 1
COPY --from=frontend /frontend/dist frontend/dist

# Data volume for SQLite persistence
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
