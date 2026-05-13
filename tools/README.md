# Vulnapps Scan Importer

CLI tool that imports security scan results (`.md` files) into Vulnapps using an LLM to semantically map findings to known vulnerabilities.

The key advantage over heuristic matching: the LLM understands that "Missing CSP header", "Missing HSTS", and "Missing X-Frame-Options" all map to a single "Missing Security Headers" vulnerability — something rule-based matching can't do.

## Prerequisites

- Python 3.8+
- A Vulnapps API key:
  - **`vuln-mapper` scope** — submit scans, match findings, promote findings to vulns
  - **`full` scope** — required additionally if you want this tool to *create* the target app on the fly via `--app-name` (instead of pre-creating it and passing `--app-id`)
- Access to Claude via either:
  - **Anthropic API key** (`sk-ant-...` from [console.anthropic.com](https://console.anthropic.com))
  - **Google Vertex AI** with `gcloud` auth

Install dependencies:

```bash
pip install httpx "anthropic[vertex]"
```

## Configuration

### Vulnapps URL and API Key

Point the tool at your Vulnapps instance and authenticate with an API key.
Generate the key from your Vulnapps account page (Account > API Keys) — pick the
`vuln-mapper` scope to submit scans and match findings, or `full` if you also
want the tool to create the target app on the fly via `--app-name`.

```bash
export VULNAPPS_URL="https://vulnapps.example.com"
export VULNAPPS_API_KEY="va_..."
```

The examples below assume both are set. You can override either per-invocation
with `--url` / `--api-key`.

### LLM Provider

The tool supports two providers for Claude access:

#### Option A: Anthropic API (direct)

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

#### Option B: Google Vertex AI

If you use Claude through Vertex (e.g., same setup as Claude Code):

```bash
export CLAUDE_CODE_USE_VERTEX=1
export ANTHROPIC_VERTEX_PROJECT_ID="your-gcp-project-id"
export ANTHROPIC_VERTEX_LOCATION="global"  # or us-east5, europe-west1, etc.
```

Authenticate with Google Cloud (one-time):

```bash
gcloud auth application-default login
```

The tool auto-detects Vertex when `CLAUDE_CODE_USE_VERTEX=1` is set — no extra flags needed.

## Usage

```
python tools/import_scan.py --app-id <id> --dir <scan-results-dir>
```

Or, for discovery-mode scanning where you want the tool to create the target app
on the fly:

```
python tools/import_scan.py \
  --app-name "WordPress" --app-version "6.4" \
  --dir <scan-results-dir>
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--url` | Vulnapps instance URL | (required) |
| `--api-key` | Vulnapps API key | `$VULNAPPS_API_KEY` |
| `--app-id` | Target app ID in Vulnapps | *(required unless `--app-name` is given)* |
| `--app-name` | App name to look up or create when `--app-id` is omitted | |
| `--app-version` | App version used together with `--app-name` for lookup/creation | `""` |
| `--app-url` | App URL — only used when creating a new app | |
| `--app-description` | App description — only used when creating a new app | |
| `--app-tech` | Comma-separated tech stack — only used when creating a new app | |
| `--app-visibility` | `public`, `private`, or `team` — only used when creating | `private` |
| `--dir` | Directory containing `.md` scan files | (required if no `--file`/`--probely`) |
| `--file` | Single `.md` file (instead of `--dir`) | |
| `--scanner` | Scanner name (overrides LLM-detected name) | |
| `--scan-date` | Scan date in YYYY-MM-DD (overrides LLM-detected date) | |
| `--model` | Claude model to use | `claude-sonnet-4-20250514` |
| `--provider` | `anthropic` or `vertex` | auto-detected |
| `--vertex-region` | Vertex AI region | `$ANTHROPIC_VERTEX_LOCATION` |
| `--vertex-project` | GCP project ID | `$ANTHROPIC_VERTEX_PROJECT_ID` |
| `--public` | Make the scan public | private by default |
| `--labels` | Comma-separated labels (auto-created if missing) | |
| `--confirm` | Ask for confirmation before submitting each scan | |
| `--notes` | Notes to attach to the scan | |
| `--dry-run` | Show LLM mapping without submitting | |

When `--app-id` is omitted, the tool looks up an existing app by exact
`name`+`version`. If none is found, it creates one (requires `full` API-key
scope) using `--app-url`, `--app-description`, `--app-tech`, and
`--app-visibility`.

## Examples

### Dry run — preview mapping without submitting

```bash
python tools/import_scan.py \
  --app-id 1 \
  --dir ./scan-results/ \
  --dry-run
```

### Import a single scan file

```bash
python tools/import_scan.py \
  --app-id 1 \
  --file ./scan-results/zap-scan-2026-03-15.md
```

### Import all scans from a directory

```bash
python tools/import_scan.py \
  --app-id 1 \
  --dir ./scan-results/ \
  --notes "Q1 2026 scan batch"
```

### Import as public scan with labels using Vertex AI

```bash
export CLAUDE_CODE_USE_VERTEX=1
export ANTHROPIC_VERTEX_PROJECT_ID=my-project-123
export ANTHROPIC_VERTEX_LOCATION=global

python tools/import_scan.py \
  --app-id 1 \
  --dir ./scan-results/ \
  --public \
  --labels "baseline,quarterly"
```

### Use a specific model

```bash
python tools/import_scan.py \
  --app-id 1 \
  --dir ./scan-results/ \
  --model claude-opus-4-20250514
```

### Discovery-mode: scan a popular app, creating it on the fly

When you're hunting 0-days in a third-party app that doesn't exist in Vulnapps
yet, the tool can create it for you. Findings that don't map to anything (which
is most of them, since the app has no known vulns) get extra context — title,
severity, description, PoC, remediation, code location — which you can later
one-click "Promote to vuln" on the scan page.

```bash
python tools/import_scan.py \
  --app-name "WordPress" --app-version "6.4.2" \
  --app-url "https://wordpress.org" \
  --app-tech "PHP,MySQL" \
  --app-visibility private \
  --dir ./wp-scan/ \
  --labels "discovery"
```

If an app named "WordPress" version "6.4.2" already exists, it's reused.
Otherwise it's created (requires `full` scope on the API key).

## How It Works

For each `.md` file:

1. Resolves the target app — either `--app-id` directly, or by looking up (and
   optionally creating) by `--app-name`+`--app-version`
2. Fetches the app's known vulnerabilities from the Vulnapps API
3. Sends the scan report + vulnerability list to Claude
4. Claude extracts findings and semantically maps each one to a known
   vulnerability (or marks it as unmatched/false positive). For unmapped
   findings, Claude also emits rich detail (severity, description, PoC,
   remediation, code location) so you can promote them later
5. Displays the mapping in the terminal for review
6. On confirmation, submits the scan to Vulnapps (heuristic matching runs
   first, then LLM corrections are applied on top)

## Scan Report Format

The `.md` files can be in any format — the LLM parses them. That said, including these details helps accuracy:

- Scanner name and scan date
- Whether the scan was authenticated
- For each finding: type/category, affected URL, HTTP method, parameter, severity
- Any notes about false positives

Example structure:

```markdown
# ZAP Scan — MyApp — 2026-03-15

Unauthenticated scan.

## Findings

### 1. SQL Injection
- **URL:** POST /api/wines?id=1
- **Parameter:** id
- **Severity:** High
- Evidence: `1 OR 1=1` returns all records

### 2. Missing Content-Security-Policy
- **URL:** GET /
- **Severity:** Medium
- No CSP header present in response

### 3. Missing HSTS Header
- **URL:** GET /
- **Severity:** Low
- Strict-Transport-Security header not set
```
