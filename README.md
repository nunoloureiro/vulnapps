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

### Automatic deployment

The [GitHub Actions workflow](.github/workflows/deploy.yml) tests and builds pull
requests. Pushes to `main` in `nunoloureiro/vulnapps` also publish to Docker Hub
and deploy to the existing EC2 host. **Actions → Test and deploy → Run workflow**
on `main` deploys manually. Other branches and forks cannot publish or deploy.

In `nunoloureiro/vulnapps`, open **Settings → Secrets and variables → Actions**.
Choose **New repository secret** for each required value below. Enter each value
directly, without shell `export` or enclosing quotes:

- `DOCKERHUB_USERNAME`: Docker Hub account with push access to `nunoloureiro/vulnapps`.
- `DOCKERHUB_TOKEN`: its Docker Hub access token.
- `DEPLOY_HOST`: EC2 hostname or IPv4 address, without a URL scheme.
- `DEPLOY_USER`: SSH user, typically `ubuntu` or `ec2-user`.
- `DEPLOY_SSH_KEY`: private SSH key for that user, without a passphrase.
- `SECRET_KEY`: the existing production application signing key.

SSH accepts the first host key seen in each deployment and rejects changes during
that run. The temporary known-hosts file is discarded afterward, so host identity
is not verified against a key saved between deployments.

Optional repository secrets can be changed individually:

- `DEPLOY_PORT`: SSH port; defaults to `22`.
- `TOKEN_EXPIRY_HOURS`: positive integer; defaults to `24` hours.
- `MAX_STATE_SIZE`: positive integer; defaults to `104857600` bytes (100 MiB).

The workflow assembles the application env-file automatically. There is no
`VULNAPPS_ENV_FILE` secret to maintain. After changing a secret, run **Actions →
Test and deploy → Run workflow** on `main` to apply it; changing a secret alone
does not redeploy the app. Enable GitHub Actions for the repository if disabled.

Keep the existing signing key when adopting CI/CD. If the current host uses
`~/.env.vulnapps` with `VULN_SECRET`, put that same value in the `SECRET_KEY`
repository secret. `DATABASE_PATH` and `STATE_DIR` are fixed by the deployment
script to `/data/vulnapps.db` and `/data/scan-state` so data stays on the volume.

The host must already have Docker running, passwordless `sudo docker` for the
SSH user, and SSH access from the GitHub runner. The existing nginx/TLS setup
continues to forward to `127.0.0.1:8001`. Host provisioning and DNS/TLS configuration
remain one-time setup using `aws/setup-ec2.sh` and `DeployInstructions.txt`.
The Docker Hub image must be public, or the host's root Docker client must
already be signed in with pull access.

The app footer shows the deployment time in UTC and the deployed commit. The same
values are available at `/api/deployment` with caching disabled. The EC2 script
sets the timestamp when starting the replacement container and verifies that the
running app returns its timestamp and revision before declaring success. This
checks the container locally; it does not verify the public nginx/TLS route.

CI runs the self-contained pytest suite, builds the image (including the React
frontend), and checks its API and homepage on an empty database. It excludes
`tests/test_api_endpoints.py`, which requires a local production database and
specific existing records. No production database is copied into CI.

Deployments reuse [`aws/setup-ec2.sh`](aws/setup-ec2.sh) and are serialized. The script pulls the exact image
digest before stopping the old container, snapshots the database using SQLite's
backup API, then recreates `vulnapps` with the existing `vulnapps-data` volume and
checks API startup. There is a short interruption during replacement. The
`latest` tag is updated only after successful deployment. Secrets travel over
SSH in a private temporary directory and are removed after the run; Docker
retains the application environment as part of its container configuration.

The same script can run directly: `VULNAPPS_IMAGE=image bash aws/setup-ec2.sh
/path/to/app.env`. Omitting the env-file retains the original setup behavior:
use the shell's `SECRET_KEY`, or generate a key when it is unset. Always supply
the existing key or env-file when updating a deployment.

If pulling or snapshotting fails, the existing service remains running. If
replacement or startup fails, the workflow fails and requires operator recovery;
it does not automatically roll back database migrations. Inspect `sudo docker
logs vulnapps` on the host. Snapshots are stored in the data volume under
`/data/deploy-backups/`; retain or remove them according to your backup policy.
Before reverting an image, stop the failed container and restore the selected
snapshot with no database writers active (including removing stale `-wal` and
`-shm` files), then start the previous image using the existing deployment
instructions. A snapshot predates the restart, so restoration can discard writes
made after it. Deployment snapshots supplement your off-host backups.

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
