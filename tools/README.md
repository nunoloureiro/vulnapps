# Vulnapps Scan Importer

CLI tool that imports security scan results (`.md` files) into Vulnapps using an LLM to semantically map findings to known vulnerabilities.

The key advantage over heuristic matching: the LLM understands that "Missing CSP header", "Missing HSTS", and "Missing X-Frame-Options" all map to a single "Missing Security Headers" vulnerability — something rule-based matching can't do.

## Prerequisites

- Python 3.8+
- A Vulnapps API key (generate from Account > API Keys with `vuln-mapper` scope)
- Access to Claude via either:
  - **Anthropic API key** (`sk-ant-...` from [console.anthropic.com](https://console.anthropic.com))
  - **Google Vertex AI** with `gcloud` auth

Install dependencies:

```bash
pip install httpx "anthropic[vertex]"
```

## Configuration

### Vulnapps API Key

Generate one from your Vulnapps account page (Account > API Keys). Choose the `vuln-mapper` scope — it grants read access plus the ability to submit scans and match findings.

```bash
export VULNAPPS_API_KEY="va_..."
```

Or pass it directly with `--api-key`.

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
python tools/import_scan.py --url <vulnapps-url> --app-id <id> --dir <scan-results-dir>
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--url` | Vulnapps instance URL | (required) |
| `--api-key` | Vulnapps API key | `$VULNAPPS_API_KEY` |
| `--app-id` | Target app ID in Vulnapps | (required) |
| `--dir` | Directory containing `.md` scan files | (required) |
| `--file` | Single `.md` file (instead of `--dir`) | |
| `--scanner` | Scanner name (overrides LLM-detected name) | |
| `--scan-date` | Scan date in YYYY-MM-DD (overrides LLM-detected date) | |
| `--authenticated` / `--unauthenticated` | Mark scan as authenticated / unauthenticated (overrides LLM detection) | |
| `--model` | Claude model to use | `claude-sonnet-4-20250514` |
| `--provider` | `anthropic` or `vertex` | auto-detected |
| `--vertex-region` | Vertex AI region | `$ANTHROPIC_VERTEX_LOCATION` |
| `--vertex-project` | GCP project ID | `$ANTHROPIC_VERTEX_PROJECT_ID` |
| `--public` | Make the scan public | private by default |
| `--labels` | Comma-separated labels (auto-created if missing) | |
| `--confirm` | Ask for confirmation before submitting each scan | |
| `--notes` | Notes to attach to the scan | |
| `--dry-run` | Show LLM mapping without submitting | |

## Examples

### Dry run — preview mapping without submitting

```bash
python tools/import_scan.py \
  --url https://vulnapps.example.com \
  --app-id 1 \
  --dir ./scan-results/ \
  --dry-run
```

### Import a single scan file

```bash
python tools/import_scan.py \
  --url https://vulnapps.example.com \
  --app-id 1 \
  --file ./scan-results/zap-scan-2026-03-15.md
```

### Import all scans from a directory

```bash
python tools/import_scan.py \
  --url https://vulnapps.example.com \
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
  --url https://vulnapps.example.com \
  --app-id 1 \
  --dir ./scan-results/ \
  --public \
  --labels "baseline,quarterly"
```

### Use a specific model

```bash
python tools/import_scan.py \
  --url https://vulnapps.example.com \
  --app-id 1 \
  --dir ./scan-results/ \
  --model claude-opus-4-20250514
```

## How It Works

For each `.md` file:

1. Fetches the app's known vulnerabilities from the Vulnapps API
2. Sends the scan report + vulnerability list to Claude
3. Claude extracts findings and semantically maps each one to a known vulnerability (or marks it as unmatched/false positive)
4. Displays the mapping in the terminal for review
5. On confirmation, submits the scan to Vulnapps (heuristic matching runs first, then LLM corrections are applied on top)

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
