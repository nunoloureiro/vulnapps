# Vulnapps

A vulnerability registry for benchmarking security scanners. Register known-vulnerable applications, define their vulnerabilities, submit scan results, and measure scanner accuracy with precision, recall, and F1 metrics.

Comes pre-seeded with **TaintedPort** — an intentionally vulnerable wine store app with 28 known vulnerabilities (SQL injection, XSS, IDOR, broken auth, etc.) ready for testing.

## Quick Start

```bash
# Clone and configure
cp .env.example .env
# Edit .env — set SECRET_KEY to something random

# Run with Docker Compose
docker compose up -d
```

The app is available at `http://localhost:8000`. The first user to register is automatically promoted to admin and the TaintedPort seed data is loaded.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run locally
uvicorn app.main:app --reload --port 8000
```

Database migrations run automatically on startup.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing key | (required) |
| `DATABASE_PATH` | Path to SQLite database | `/data/vulnapps.db` |
| `TOKEN_EXPIRY_HOURS` | JWT token lifetime | `24` |

## How It Works

1. **Register apps** with known vulnerabilities (type, URL, HTTP method, parameter, severity)
2. **Submit scan results** — findings are matched to known vulns via heuristic scoring (vuln type, URL pattern, method, parameter)
3. **Review metrics** — each scan shows TP, FP, FN, precision, recall, and F1
4. **Compare scanners** — side-by-side detection matrix across multiple scans

### Matching

Findings are matched to known vulnerabilities using a scoring system:

- **Vulnerability type** — must match (hard gate). Types are canonicalized (e.g., "SQLi" → "SQL Injection")
- **URL** — exact match (100pts), regex/placeholder (80pts), prefix (40pts), wildcard (10pts)
- **HTTP method** — +15pts if matching
- **Parameter** — exact (+20pts), substring (+10pts)
- Threshold: 60 points. Below → pending for manual review

## LLM Scan Importer

A CLI tool that uses Claude to semantically map scan findings to known vulnerabilities — better than heuristic matching for cases like grouping "Missing CSP", "Missing HSTS", and "Missing X-Frame-Options" under a single "Missing Security Headers" vuln.

```bash
# Dry run — preview mapping
python tools/import_scan.py \
  --url https://vulnapps.example.com \
  --app-id 1 \
  --dir ./scan-results/ \
  --dry-run

# Import a scan
python tools/import_scan.py \
  --url https://vulnapps.example.com \
  --app-id 1 \
  --file ./scan-results/zap-scan.md
```

Requires a Vulnapps API key with `vuln-mapper` scope (generate from Account > API Keys) and Claude access via Anthropic API or Google Vertex AI.

Full documentation: [`tools/README.md`](tools/README.md)

## API

REST API at `/api/v1` with JWT or API key authentication (Bearer token).

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/apps` | List visible apps |
| `GET` | `/api/v1/apps/{id}` | App detail + vulnerabilities |
| `POST` | `/api/v1/apps` | Create app |
| `POST` | `/api/v1/apps/{id}/scans` | Submit scan |
| `GET` | `/api/v1/scans/{id}` | Scan detail + findings + metrics |
| `GET` | `/api/v1/apps/{id}/compare?scans=1,2,3` | Compare scans |
| `POST` | `/api/v1/scans/{id}/findings/{fid}/match` | Match finding to vuln |
| `POST` | `/api/v1/scans/{id}/findings/{fid}/mark-fp` | Mark finding as false positive |

### API Key Scopes

| Scope | Permissions |
|-------|-------------|
| `read` | GET endpoints only |
| `vuln-mapper` | Read + submit scans + match findings |
| `full` | All operations |

## Auth & Permissions

- **Account roles**: `user` (default), `admin` (first registered user)
- **Team roles**: `admin`, `contributor`, `view`
- **Visibility**: public (admin only), team, or private
- Passwords hashed with bcrypt, JWTs signed with HS256

## Building & Deploying

### Build and push Docker image

```bash
./build.sh           # Run tests, build, push to Docker Hub
./build.sh --prune   # Same + prune unused Docker images
```

The image is pushed to `nunoloureiro/vulnapps:latest` (linux/amd64).

### Database snapshots

```bash
./snapshot.sh --local                          # Snapshot from local container
./snapshot.sh --remote                         # Fetch snapshot from EC2
./snapshot.sh --remote --restore <file>        # Restore snapshot to EC2
```

Snapshots are saved to `./snapshots/vulnapps-<timestamp>.db`.

## Project Structure

```
app/
├── main.py              # FastAPI app, lifespan, middleware
├── auth.py              # bcrypt + JWT + API key auth
├── dependencies.py      # Auth middleware, scope checks
├── matching.py          # Heuristic finding→vuln matching
├── visibility.py        # Public/team/private visibility filters
├── seed.py              # TaintedPort seed data (28 vulns)
├── routers/
│   ├── api.py           # REST API (/api/v1)
│   ├── apps.py          # App CRUD (web)
│   ├── vulns.py         # Vulnerability CRUD (web)
│   ├── scans.py         # Scan submission + metrics (web)
│   ├── teams.py         # Team management (web)
│   ├── admin.py         # User admin (web)
│   └── auth_routes.py   # Login, register, API keys (web)
│
├── templates/           # Jinja2 templates (dark theme)
└── static/              # CSS + logo

migrations/              # Auto-applied SQLite migrations
tools/                   # CLI tools (LLM scan importer)
```

## Tech Stack

- **Backend**: FastAPI + Uvicorn
- **Database**: SQLite (aiosqlite)
- **Templates**: Jinja2
- **Auth**: bcrypt + PyJWT
- **Target**: AWS t2.nano (512MB RAM)
