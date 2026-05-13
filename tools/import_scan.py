#!/usr/bin/env python3
"""
CLI tool to import scan results (.md files) into Vulnapps using LLM-assisted
vulnerability mapping.

Usage:
    python tools/import_scan.py --url https://vulnapps.example.com \
        --api-key va_... --app-id 1 --dir ./scan-results/

Requires: ANTHROPIC_API_KEY environment variable for Claude API access.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import threading
from pathlib import Path

import httpx


# ── ANSI colors ──────────────────────────────────────────────

class C:
    """ANSI color codes. Disabled when not a TTY."""
    RESET = ""
    BOLD = ""
    DIM = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    MAGENTA = ""
    CYAN = ""
    ORANGE = ""
    GRAY = ""

    @classmethod
    def init(cls):
        if sys.stdout.isatty():
            cls.RESET = "\033[0m"
            cls.BOLD = "\033[1m"
            cls.DIM = "\033[2m"
            cls.RED = "\033[31m"
            cls.GREEN = "\033[32m"
            cls.YELLOW = "\033[33m"
            cls.BLUE = "\033[34m"
            cls.MAGENTA = "\033[35m"
            cls.CYAN = "\033[36m"
            cls.ORANGE = "\033[38;5;208m"
            cls.GRAY = "\033[90m"


SEVERITY_COLORS = {
    "critical": "RED",
    "high": "ORANGE",
    "medium": "YELLOW",
    "low": "GREEN",
    "info": "BLUE",
}


def colored(text: str, color: str) -> str:
    c = getattr(C, color, "")
    return f"{c}{text}{C.RESET}" if c else text


def severity_colored(text: str, severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    return colored(text, color) if color else text


# ── Spinner ──────────────────────────────────────────────────

class Spinner:
    """Animated spinner for long-running operations."""
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str):
        self.message = message
        self._stop = threading.Event()
        self._thread = None

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write(f"\r  {C.CYAN}{frame}{C.RESET} {self.message}")
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.08)
        sys.stdout.write(f"\r  {' ' * (len(self.message) + 4)}\r")
        sys.stdout.flush()

    def __enter__(self):
        if sys.stdout.isatty():
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"  {self.message}")
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._thread:
            self._thread.join()


# ── Prompt ───────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a vulnerability mapping assistant for a security testing platform.

You will be given:
1. A list of KNOWN VULNERABILITIES for an application (with their database IDs)
2. A security scan report in markdown format

Your job is to:
1. Extract each distinct finding from the scan report
2. Map each finding to the most appropriate known vulnerability, if one exists
3. Mark findings as false positives if the report indicates they are not real issues

IMPORTANT RULES:
- Multiple scan findings can map to the SAME known vulnerability. For example, \
"Missing CSP header", "Missing HSTS header", and "Missing X-Frame-Options" could \
all map to a single known vulnerability called "Missing Security Headers".
- Only map a finding to a vulnerability if there is a genuine semantic match. \
Do not force matches.
- If a finding does not match any known vulnerability, set matched_vuln_db_id to null.
- Use the database `id` field (integer) for matched_vuln_db_id, NOT the `vuln_id` string.
- Extract the scanner name and scan date from the report if available.
- For vuln_type, use a short canonical type (e.g., "XSS", "SQLi", "IDOR", \
"Missing Security Headers", "CSRF", etc.)
- For findings that do NOT map to a known vulnerability (matched_vuln_db_id=null) \
and are NOT false positives, fill in the rich detail fields below from the scan \
report (description, severity, poc, remediation, code_location). These let the \
user one-click "promote" the finding into a documented vulnerability later. \
Leave them empty for findings that already match a known vulnerability.
- severity must be one of: "critical", "high", "medium", "low", "info".

Respond with ONLY valid JSON (no markdown fencing) in this exact format:
{
    "scanner_name": "string",
    "scan_date": "YYYY-MM-DD",
    "findings": [
        {
            "vuln_type": "string - canonical vulnerability type",
            "title": "string - brief finding title from the report",
            "http_method": "GET/POST/etc or empty string",
            "url": "string - affected URL/path or empty string",
            "parameter": "string - affected parameter or empty string",
            "filename": "string - affected source file or empty string",
            "matched_vuln_db_id": 123 or null,
            "is_false_positive": false,
            "reasoning": "string - brief explanation of why this maps (or doesn't) to the known vuln",
            "severity": "critical|high|medium|low|info — required for unmapped findings, empty otherwise",
            "description": "string — what the issue is, why it matters (unmapped only)",
            "poc": "string — proof-of-concept / reproduction steps (unmapped only)",
            "remediation": "string — how to fix (unmapped only)",
            "code_location": "string — file:line or function name if known (unmapped only)"
        }
    ]
}"""


# ── API Client ───────────────────────────────────────────────

class VulnappsClient:
    """HTTP client for the Vulnapps API."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0,
        )

    def get_app(self, app_id: int) -> dict:
        resp = self.client.get(f"/api/apps/{app_id}")
        resp.raise_for_status()
        return resp.json()

    def find_app(self, name: str, version: str) -> dict | None:
        """Return the first app matching name+version exactly, else None."""
        resp = self.client.get("/api/apps", params={"q": name})
        resp.raise_for_status()
        for a in resp.json().get("apps", []):
            if a.get("name") == name and (a.get("version") or "") == (version or ""):
                return a
        return None

    def create_app(self, payload: dict) -> dict:
        resp = self.client.post("/api/apps", json=payload)
        resp.raise_for_status()
        return resp.json()["app"]

    def get_vulns(self, app_id: int) -> list:
        resp = self.client.get(f"/api/apps/{app_id}/vulns")
        resp.raise_for_status()
        return resp.json()["vulnerabilities"]

    def submit_scan(self, app_id: int, scan_data: dict) -> dict:
        resp = self.client.post(f"/api/apps/{app_id}/scans", json=scan_data)
        resp.raise_for_status()
        return resp.json()

    def get_scan(self, scan_id: int) -> dict:
        resp = self.client.get(f"/api/scans/{scan_id}")
        resp.raise_for_status()
        return resp.json()

    def match_finding(self, scan_id: int, finding_id: int, vuln_id: int | None) -> dict:
        resp = self.client.post(
            f"/api/scans/{scan_id}/findings/{finding_id}/match",
            json={"vuln_id": vuln_id},
        )
        resp.raise_for_status()
        return resp.json()

    def mark_fp(self, scan_id: int, finding_id: int) -> dict:
        resp = self.client.post(
            f"/api/scans/{scan_id}/findings/{finding_id}/mark-fp",
        )
        resp.raise_for_status()
        return resp.json()

    def get_labels(self) -> list:
        resp = self.client.get("/api/labels")
        resp.raise_for_status()
        return resp.json()["labels"]

    def add_label(self, scan_id: int, name: str, color: str = "#f97316") -> dict:
        resp = self.client.post(
            f"/api/scans/{scan_id}/labels",
            json={"name": name, "color": color},
        )
        resp.raise_for_status()
        return resp.json()


# ── Formatting ───────────────────────────────────────────────

def format_vulns_for_prompt(vulns: list) -> str:
    """Format known vulnerabilities for the LLM prompt."""
    lines = []
    for v in vulns:
        parts = [f"  DB ID: {v['id']}", f"  Vuln ID: {v['vuln_id']}", f"  Title: {v['title']}"]
        parts.append(f"  Severity: {v['severity']}")
        if v.get("vuln_type"):
            parts.append(f"  Type: {v['vuln_type']}")
        if v.get("url"):
            parts.append(f"  URL: {v.get('http_method', '')} {v['url']}")
        if v.get("parameter"):
            parts.append(f"  Parameter: {v['parameter']}")
        if v.get("description"):
            parts.append(f"  Description: {v['description'][:200]}")
        lines.append("\n".join(parts))
    return "\n---\n".join(lines)


def create_anthropic_client(provider: str, region: str | None, project_id: str | None):
    """Create the appropriate Anthropic client based on provider.

    For Vertex, uses Google Application Default Credentials (ADC).
    Run `gcloud auth application-default login` to authenticate.
    """
    import anthropic

    if provider == "vertex":
        if not region or not project_id:
            print(f"  {colored('Error:', 'RED')} --vertex-region and --vertex-project are required with --provider vertex", file=sys.stderr)
            sys.exit(1)
        return anthropic.AnthropicVertex(region=region, project_id=project_id)
    return anthropic.Anthropic()


def run_llm_mapping(scan_content: str, vulns: list, model: str, client) -> dict:
    """Send scan content and known vulns to Claude for mapping."""

    vulns_text = format_vulns_for_prompt(vulns)
    user_message = f"""## Known Vulnerabilities for this Application

{vulns_text}

## Scan Report

{scan_content}"""

    with Spinner("Analyzing scan with Claude..."):
        response = client.messages.create(
            model=model,
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

    text = response.content[0].text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text[:-3]
    result = json.loads(text)
    # Attach LLM usage stats
    if hasattr(response, "usage") and response.usage:
        result["_llm_tokens"] = response.usage.input_tokens + response.usage.output_tokens
    return result


def run_llm_mapping_cli(scan_content: str, vulns: list) -> dict:
    """Use Claude Code CLI as fallback when no API key is available."""
    import subprocess
    import shutil

    if not shutil.which("claude"):
        print(f"  {colored('Error:', 'RED')} No LLM available. Set ANTHROPIC_API_KEY or install Claude Code CLI.", file=sys.stderr)
        sys.exit(1)

    vulns_text = format_vulns_for_prompt(vulns)
    prompt = f"""{SYSTEM_PROMPT}

## Known Vulnerabilities for this Application

{vulns_text}

## Scan Report

{scan_content}

Respond with ONLY valid JSON (no markdown fencing)."""

    with Spinner("Analyzing scan with Claude CLI..."):
        result = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "json", "--max-turns", "1"],
            capture_output=True, text=True, timeout=300
        )

    if result.returncode != 0:
        print(f"  {colored('Error:', 'RED')} Claude CLI failed: {result.stderr[:200]}", file=sys.stderr)
        sys.exit(1)

    # Parse the CLI output - it returns JSON with a "result" field
    try:
        cli_output = json.loads(result.stdout)
        # Claude CLI with --output-format json wraps the response
        text = cli_output.get("result", result.stdout) if isinstance(cli_output, dict) else result.stdout
        if isinstance(text, str):
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                if text.endswith("```"):
                    text = text[:-3]
            return json.loads(text)
        return text
    except (json.JSONDecodeError, KeyError):
        # Try parsing stdout directly as the LLM response
        text = result.stdout.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text[:-3]
        return json.loads(text)


def print_header(text: str, width: int = 60):
    """Print a styled section header."""
    line = colored("─" * width, "GRAY")
    print(f"\n{line}")
    print(f"  {C.BOLD}{text}{C.RESET}")
    print(line)


def print_mapping_table(mapping: dict, vulns: list):
    """Print a readable summary of the LLM mapping."""
    vuln_lookup = {v["id"]: v for v in vulns}

    scanner = mapping.get("scanner_name", "unknown")
    date = mapping.get("scan_date", "unknown")
    findings = mapping.get("findings", [])

    print(f"\n  {C.DIM}Scanner:{C.RESET}  {colored(scanner, 'CYAN')}")
    print(f"  {C.DIM}Date:{C.RESET}     {date}")
    print(f"  {C.DIM}Findings:{C.RESET} {colored(str(len(findings)), 'BOLD')}")

    matched = [f for f in findings if f.get("matched_vuln_db_id")]
    unmatched = [f for f in findings if not f.get("matched_vuln_db_id") and not f.get("is_false_positive")]
    fps = [f for f in findings if f.get("is_false_positive")]

    if matched:
        print(f"\n  {colored('MATCHED', 'GREEN')} {C.DIM}({len(matched)}){C.RESET}")
        for f in matched:
            vuln = vuln_lookup.get(f["matched_vuln_db_id"], {})
            vuln_title = vuln.get("title", f"DB#{f['matched_vuln_db_id']}")
            vuln_id = vuln.get("vuln_id", "?")
            severity = vuln.get("severity", "")

            sev_badge = severity_colored(f"[{severity}]", severity) if severity else ""
            print(f"    {colored('>', 'GREEN')} {C.BOLD}{f.get('title', f['vuln_type'])}{C.RESET}")
            print(f"      {colored('→', 'GRAY')} {vuln_title} {C.DIM}({vuln_id}){C.RESET} {sev_badge}")
            print(f"      {C.DIM}{f.get('reasoning', '')}{C.RESET}")

    if unmatched:
        print(f"\n  {colored('UNMATCHED', 'YELLOW')} {C.DIM}({len(unmatched)}){C.RESET}")
        for f in unmatched:
            url_str = f" {C.DIM}{f.get('url', '')}{C.RESET}" if f.get("url") else ""
            print(f"    {colored('?', 'YELLOW')} {C.BOLD}{f.get('title', f['vuln_type'])}{C.RESET}{url_str}")
            print(f"      {C.DIM}{f.get('reasoning', '')}{C.RESET}")

    if fps:
        print(f"\n  {colored('FALSE POSITIVES', 'RED')} {C.DIM}({len(fps)}){C.RESET}")
        for f in fps:
            print(f"    {colored('x', 'RED')} {f.get('title', f['vuln_type'])} {C.DIM}{f.get('url', '')}{C.RESET}")

    # Summary bar
    parts = []
    if matched:
        parts.append(colored(f"{len(matched)} matched", "GREEN"))
    if unmatched:
        parts.append(colored(f"{len(unmatched)} unmatched", "YELLOW"))
    if fps:
        parts.append(colored(f"{len(fps)} FP", "RED"))
    print(f"\n  {C.DIM}Summary:{C.RESET} {' / '.join(parts)}")


def submit_to_vulnapps(client: VulnappsClient, app_id: int, mapping: dict, is_public: bool, notes: str, cost: float | None = None, tokens: int | None = None, duration: int | None = None):
    """Submit the scan and apply LLM-corrected matches."""
    findings_payload = []
    for f in mapping.get("findings", []):
        item = {
            "vuln_type": f.get("vuln_type", ""),
            "http_method": f.get("http_method", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "filename": f.get("filename", ""),
        }
        for k in ("title", "severity", "description", "poc", "remediation", "code_location"):
            v = f.get(k)
            if v:
                item[k] = v
        findings_payload.append(item)

    scan_data = {
        "scanner_name": mapping.get("scanner_name", "unknown"),
        "scan_date": mapping.get("scan_date", ""),
        "is_public": is_public,
        "notes": notes,
        "findings": findings_payload,
    }
    if cost is not None:
        scan_data["cost"] = cost
    if tokens is not None:
        scan_data["tokens"] = tokens
    if duration is not None:
        scan_data["duration"] = duration

    with Spinner("Submitting scan..."):
        result = client.submit_scan(app_id, scan_data)
    scan_id = result["scan_id"]
    print(f"  {colored('✓', 'GREEN')} Scan created: {colored(f'ID {scan_id}', 'BOLD')}")

    # Get scan details to see findings with their IDs
    scan_detail = client.get_scan(scan_id)
    server_findings = scan_detail["findings"]

    # Match server findings to LLM findings by position (same order)
    llm_findings = mapping.get("findings", [])
    corrections = 0
    fp_marks = 0

    with Spinner("Applying LLM match corrections..."):
        for i, sf in enumerate(server_findings):
            if i >= len(llm_findings):
                break
            lf = llm_findings[i]

            if lf.get("is_false_positive"):
                client.mark_fp(scan_id, sf["id"])
                fp_marks += 1
            elif lf.get("matched_vuln_db_id") is not None:
                if sf.get("matched_vuln_id") != lf["matched_vuln_db_id"]:
                    client.match_finding(scan_id, sf["id"], lf["matched_vuln_db_id"])
                    corrections += 1

    if corrections or fp_marks:
        print(f"  {colored('✓', 'GREEN')} Applied {colored(str(corrections), 'CYAN')} match corrections, {colored(str(fp_marks), 'CYAN')} FP marks")
    else:
        print(f"  {colored('✓', 'GREEN')} Heuristic matching was already correct")

    return scan_id


# ── Probely ──────────────────────────────────────────────────

class ProbelyClient:
    """HTTP client for the Probely/Snyk API & Web API."""

    def __init__(self, api_key: str):
        self.client = httpx.Client(
            base_url="https://api.probely.com",
            headers={"Authorization": f"JWT {api_key}"},
            timeout=30.0,
        )

    def get_scan(self, scan_id: str) -> dict:
        # Try direct scan endpoint first
        resp = self.client.get(f"/scans/{scan_id}/")
        resp.raise_for_status()
        return resp.json()

    def get_findings(self, target_id: str, scan_id: str) -> list:
        """Fetch all findings for a scan, handling pagination."""
        findings = []
        page = 1
        while True:
            resp = self.client.get(
                f"/targets/{target_id}/findings/",
                params={"scan": scan_id, "length": 100, "page": page, "state": "notfixed"}
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            findings.extend(results)
            if len(results) < 100 or page >= data.get("page_total", 1):
                break
            page += 1
        return findings


def fetch_probely_scan(probely_client, scan_id: str) -> dict:
    """Fetch scan metadata and findings from Probely."""
    with Spinner(f"Fetching scan {scan_id} from Probely..."):
        scan = probely_client.get_scan(scan_id)

    target_id = scan.get("target", {}).get("id", "")
    if not target_id:
        print(f"  {colored('Error:', 'RED')} Could not determine target ID for scan {scan_id}", file=sys.stderr)
        sys.exit(1)

    with Spinner(f"Fetching findings for scan {scan_id}..."):
        findings = probely_client.get_findings(target_id, scan_id)

    return {"scan": scan, "findings": findings}


def probely_to_vulnapps_findings(probely_findings: list) -> list:
    """Convert Probely findings to Vulnapps finding format."""
    findings = []
    seen = set()

    for f in probely_findings:
        vuln_type = f.get("definition", {}).get("name", f.get("name", "Unknown"))
        method = f.get("method", "")
        url = f.get("url", "")
        parameter = f.get("parameter", "")

        # Deduplicate by vuln_type + url + parameter
        key = (vuln_type.lower(), method.lower(), url.lower(), parameter.lower())
        if key in seen:
            continue
        seen.add(key)

        findings.append({
            "vuln_type": vuln_type,
            "http_method": method,
            "url": url,
            "parameter": parameter,
            "filename": "",
        })

    return findings


def merge_probely_scans(scan_data_list: list) -> dict:
    """Merge findings from multiple Probely scans into one."""
    all_findings = []
    scan_dates = []
    durations = []

    for sd in scan_data_list:
        scan = sd["scan"]
        all_findings.extend(sd["findings"])

        started = scan.get("started", "")
        if started:
            scan_dates.append(started[:10])  # YYYY-MM-DD

        # Calculate duration from started/completed
        completed = scan.get("completed", "")
        if started and completed:
            from datetime import datetime as _dt
            try:
                t_start = _dt.fromisoformat(started.replace("Z", "+00:00"))
                t_end = _dt.fromisoformat(completed.replace("Z", "+00:00"))
                dur = int((t_end - t_start).total_seconds())
                durations.append(dur)
            except (ValueError, TypeError):
                pass

    # Convert and deduplicate findings
    vulnapps_findings = probely_to_vulnapps_findings(all_findings)

    return {
        "findings": vulnapps_findings,
        "scan_date": min(scan_dates) if scan_dates else "",
        "duration": max(durations) if durations else None,
        "scanner_name": "Probely",
    }


# ── Main ─────────────────────────────────────────────────────

def main():
    C.init()

    parser = argparse.ArgumentParser(
        description="Import scan results into Vulnapps with LLM-assisted vulnerability mapping"
    )
    parser.add_argument("--url", default=os.getenv("VULNAPPS_URL"), help="Vulnapps instance URL (or set VULNAPPS_URL)")
    parser.add_argument("--api-key", default=os.getenv("VULNAPPS_API_KEY"), help="API key (or set VULNAPPS_API_KEY)")
    parser.add_argument("--app-id", type=int, default=None,
                        help="Target app ID. If omitted, --app-name is required and the app is looked up by name+version (created if missing).")
    parser.add_argument("--app-name", default=None,
                        help="App name for lookup/creation when --app-id is omitted")
    parser.add_argument("--app-version", default="",
                        help="App version for lookup/creation (default: empty)")
    parser.add_argument("--app-url", default=None, help="App URL (used only when creating)")
    parser.add_argument("--app-description", default=None, help="App description (used only when creating)")
    parser.add_argument("--app-tech", default="", help="Comma-separated tech stack (used only when creating)")
    parser.add_argument("--app-visibility", default="private",
                        choices=["public", "private", "team"],
                        help="Visibility when creating the app (default: private)")
    parser.add_argument("--dir", default=None, help="Directory with .md scan result files")
    parser.add_argument("--file", help="Single .md file to import (instead of --dir)")
    parser.add_argument("--probely", default=None, help="Import from Probely: scan ID(s), comma-separated (max 2). Requires PROBELY_API_KEY env var.")
    parser.add_argument("--scanner", default=None, help="Scanner name (overrides LLM-detected name)")
    parser.add_argument("--scan-date", default=None, help="Scan date in YYYY-MM-DD (overrides LLM-detected date)")
    parser.add_argument("--public", action="store_true", help="Make scan public (default: private)")
    parser.add_argument("--labels", default="", help="Comma-separated labels (auto-created if missing)")
    parser.add_argument("--confirm", action="store_true", help="Ask for confirmation before submitting each scan")
    parser.add_argument("--cost", type=float, default=None, help="Scan cost in USD (optional, private — for LLM-based scanners)")
    parser.add_argument("--tokens", type=int, default=None, help="Token count (optional, private — auto-captured from LLM if not set)")
    parser.add_argument("--duration", type=int, default=None, help="Scan duration in seconds (optional, private)")
    parser.add_argument("--notes", default="", help="Notes to attach to the scan")
    parser.add_argument("--model", default=None, help="Claude model (default: claude-sonnet-4-20250514)")
    parser.add_argument("--provider", choices=["anthropic", "vertex"], default=None,
                        help="LLM provider. Auto-detected from CLAUDE_CODE_USE_VERTEX=1 env var")
    parser.add_argument("--vertex-region", default=os.getenv("ANTHROPIC_VERTEX_LOCATION", "us-east5"),
                        help="Vertex AI region (or set ANTHROPIC_VERTEX_LOCATION)")
    parser.add_argument("--vertex-project", default=os.getenv("ANTHROPIC_VERTEX_PROJECT_ID"),
                        help="Google Cloud project ID (or set ANTHROPIC_VERTEX_PROJECT_ID)")
    parser.add_argument("--dry-run", action="store_true", help="Show mapping without submitting")
    args = parser.parse_args()

    if not args.url:
        print(f"  {colored('Error:', 'RED')} --url or VULNAPPS_URL environment variable required", file=sys.stderr)
        sys.exit(1)

    if not args.api_key:
        print(f"  {colored('Error:', 'RED')} --api-key or VULNAPPS_API_KEY environment variable required", file=sys.stderr)
        sys.exit(1)

    if not args.dir and not args.file and not args.probely:
        print(f"  {colored('Error:', 'RED')} One of --dir, --file, or --probely is required", file=sys.stderr)
        sys.exit(1)

    if args.app_id is None and not args.app_name:
        print(f"  {colored('Error:', 'RED')} Either --app-id or --app-name is required", file=sys.stderr)
        sys.exit(1)

    # Validate --scan-date format
    if args.scan_date:
        try:
            from datetime import datetime as _dt
            _dt.strptime(args.scan_date, "%Y-%m-%d")
        except ValueError:
            print(f"  {colored('Error:', 'RED')} --scan-date must be in YYYY-MM-DD format", file=sys.stderr)
            sys.exit(1)

    # Determine LLM mode
    use_cli = False
    llm_client = None

    if args.provider is None:
        args.provider = "vertex" if os.getenv("CLAUDE_CODE_USE_VERTEX") == "1" else "anthropic"

    if not args.model:
        args.model = "claude-sonnet-4-20250514"

    # Only need LLM for markdown import (not for --probely)
    need_llm = not args.probely

    if need_llm:
        if args.provider == "vertex" and args.vertex_project:
            llm_client = create_anthropic_client("vertex", args.vertex_region, args.vertex_project)
        elif args.provider == "anthropic" and os.getenv("ANTHROPIC_API_KEY"):
            llm_client = create_anthropic_client("anthropic", None, None)
        else:
            # Fallback to Claude CLI
            import shutil
            if shutil.which("claude"):
                use_cli = True
            else:
                print(f"  {colored('Error:', 'RED')} No LLM available. Set ANTHROPIC_API_KEY, configure Vertex, or install Claude Code CLI.", file=sys.stderr)
                sys.exit(1)

    is_public = args.public

    # Connect to Vulnapps
    client = VulnappsClient(args.url, args.api_key)

    # Banner
    print(f"\n  {colored('vulnapps', 'ORANGE')} {C.DIM}scan importer{C.RESET}")
    print(f"  {C.DIM}{'─' * 40}{C.RESET}")

    if use_cli:
        print(f"  {colored('✓', 'GREEN')} LLM: {colored('Claude CLI', 'CYAN')}")
    elif llm_client:
        provider_label = f"vertex/{args.vertex_region}" if args.provider == "vertex" else "anthropic"
        print(f"  {colored('✓', 'GREEN')} LLM: {colored(args.model, 'CYAN')} {C.DIM}via {provider_label}{C.RESET}")

    # Resolve app_id: lookup or create from --app-name if not given explicitly
    if args.app_id is None:
        try:
            with Spinner(f"Looking up app '{args.app_name}'..."):
                existing = client.find_app(args.app_name, args.app_version)
        except httpx.HTTPStatusError as e:
            print(f"  {colored('✗', 'RED')} App lookup failed: {e.response.status_code}", file=sys.stderr)
            sys.exit(1)

        if existing:
            args.app_id = existing["id"]
            print(f"  {colored('✓', 'GREEN')} Found existing app: {colored(args.app_name, 'BOLD')} {C.DIM}(id {args.app_id}){C.RESET}")
        else:
            payload = {
                "name": args.app_name,
                "version": args.app_version,
                "visibility": args.app_visibility,
                "tech_stack": args.app_tech,
            }
            if args.app_url:
                payload["url"] = args.app_url
            if args.app_description:
                payload["description"] = args.app_description
            try:
                with Spinner(f"Creating app '{args.app_name}'..."):
                    new_app = client.create_app(payload)
                args.app_id = new_app["id"]
                print(f"  {colored('✓', 'GREEN')} Created app: {colored(args.app_name, 'BOLD')} {C.DIM}(id {args.app_id}){C.RESET}")
            except httpx.HTTPStatusError as e:
                print(f"  {colored('✗', 'RED')} App creation failed: {e.response.status_code} {e.response.text}", file=sys.stderr)
                sys.exit(1)

    # Verify access and get app info
    try:
        with Spinner("Connecting to Vulnapps..."):
            app_info = client.get_app(args.app_id)
        app = app_info["app"]
        print(f"  {colored('✓', 'GREEN')} App: {colored(app['name'], 'BOLD')} {C.DIM}(v{app.get('version', '?')}){C.RESET}")
    except httpx.HTTPStatusError as e:
        print(f"  {colored('✗', 'RED')} Failed to access app {args.app_id}: {e.response.status_code}", file=sys.stderr)
        sys.exit(1)

    # Get known vulnerabilities
    vulns = client.get_vulns(args.app_id)
    print(f"  {colored('✓', 'GREEN')} Known vulns: {colored(str(len(vulns)), 'BOLD')}")

    # Resolve labels (new ones will be created at submission time)
    label_names = [l.strip() for l in args.labels.split(",") if l.strip()] if args.labels else []
    if label_names:
        existing_labels = {l["name"]: l for l in client.get_labels()}
        new_labels = [n for n in label_names if n not in existing_labels]
        if new_labels:
            print(f"  {colored('✓', 'GREEN')} Labels:      {colored(', '.join(label_names), 'CYAN')} {C.DIM}(new: {', '.join(new_labels)}){C.RESET}")
        else:
            print(f"  {colored('✓', 'GREEN')} Labels:      {colored(', '.join(label_names), 'CYAN')}")

    if args.dry_run:
        print(f"  {colored('⚑', 'YELLOW')} Dry run mode — no changes will be made")

    if args.probely:
        # ── Probely import flow ──
        probely_key = os.getenv("PROBELY_API_KEY")
        if not probely_key:
            print(f"  {colored('Error:', 'RED')} PROBELY_API_KEY environment variable required for --probely", file=sys.stderr)
            sys.exit(1)

        scan_ids = [s.strip() for s in args.probely.split(",") if s.strip()]
        if len(scan_ids) > 2:
            print(f"  {colored('Error:', 'RED')} --probely accepts at most 2 scan IDs", file=sys.stderr)
            sys.exit(1)

        probely_client = ProbelyClient(probely_key)
        print(f"  {colored('✓', 'GREEN')} Probely:     {colored(', '.join(scan_ids), 'CYAN')}")

        # Fetch scan data from Probely
        scan_data_list = []
        for sid in scan_ids:
            try:
                sd = fetch_probely_scan(probely_client, sid)
                n = len(sd["findings"])
                print(f"  {colored('✓', 'GREEN')} Scan {colored(sid, 'BOLD')}: {colored(str(n), 'BOLD')} findings")
                scan_data_list.append(sd)
            except httpx.HTTPStatusError as e:
                print(f"  {colored('✗', 'RED')} Failed to fetch scan {sid}: {e.response.status_code}", file=sys.stderr)
                sys.exit(1)

        # Merge findings
        merged = merge_probely_scans(scan_data_list)

        # Build mapping (same structure as LLM output, but without LLM)
        mapping = {
            "scanner_name": args.scanner or merged["scanner_name"],
            "scan_date": args.scan_date or merged["scan_date"],
            "findings": [
                {**f, "matched_vuln_db_id": None, "is_false_positive": False, "reasoning": "Direct import from Probely"}
                for f in merged["findings"]
            ],
        }

        duration = args.duration or merged.get("duration")

        print_header(f"Probely Import — {len(merged['findings'])} findings")
        print_mapping_table(mapping, vulns)

        if args.dry_run:
            print(f"\n  {colored('⚑', 'YELLOW')} Dry run — skipping submission\n")
            return

        if args.confirm:
            try:
                answer = input(f"\n  {colored('?', 'CYAN')} Submit this scan? [{colored('y', 'GREEN')}/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(f"\n  {colored('⏭', 'YELLOW')} Aborted")
                return
            if answer != "y":
                print(f"  {colored('⏭', 'YELLOW')} Skipped")
                return

        try:
            scan_id = submit_to_vulnapps(client, args.app_id, mapping, is_public, args.notes, args.cost, args.tokens, duration)
            for label_name in label_names:
                client.add_label(scan_id, label_name)
            if label_names:
                print(f"  {colored('✓', 'GREEN')} Labels: {colored(', '.join(label_names), 'CYAN')}")
            print(f"  {colored('🔗', 'BLUE')} {args.url}/scans/{scan_id}")
        except httpx.HTTPStatusError as e:
            print(f"  {colored('✗', 'RED')} Submit failed: {e.response.status_code} {e.response.text}", file=sys.stderr)
            sys.exit(1)

        print(f"\n  {colored('Done.', 'GREEN')}\n")
        return  # Skip the markdown processing below

    # ── Markdown import flow (existing) ──

    # Collect .md files
    if args.file:
        md_files = [Path(args.file)]
    else:
        scan_dir = Path(args.dir)
        if not scan_dir.is_dir():
            print(f"  {colored('Error:', 'RED')} {args.dir} is not a directory", file=sys.stderr)
            sys.exit(1)
        md_files = sorted(scan_dir.glob("*.md"))

    if not md_files:
        print(f"  {colored('Error:', 'RED')} No .md files found.", file=sys.stderr)
        sys.exit(1)

    print(f"  {colored('✓', 'GREEN')} Scan files:  {colored(str(len(md_files)), 'BOLD')}")

    # Combine all .md files into one scan report (one LLM call, one scan)
    parts = []
    for md_file in md_files:
        content = md_file.read_text()
        if not content.strip():
            continue
        if len(md_files) > 1:
            parts.append(f"# ── {md_file.name} ──\n\n{content}")
        else:
            parts.append(content)
    combined_content = "\n\n".join(parts)

    if not combined_content.strip():
        print(f"  {colored('✗', 'RED')} All scan files are empty", file=sys.stderr)
        sys.exit(1)

    print_header(f"Processing {len(md_files)} file(s)")

    # Run LLM mapping
    try:
        if use_cli:
            mapping = run_llm_mapping_cli(combined_content, vulns)
        else:
            mapping = run_llm_mapping(combined_content, vulns, args.model, llm_client)
    except json.JSONDecodeError as e:
        print(f"  {colored('✗', 'RED')} LLM returned invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Catch API errors from anthropic (may not be imported) or subprocess errors
        if "anthropic" in type(e).__module__ if hasattr(type(e), '__module__') else False:
            print(f"  {colored('✗', 'RED')} Claude API error: {e}", file=sys.stderr)
        else:
            print(f"  {colored('✗', 'RED')} LLM error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.scanner:
        mapping["scanner_name"] = args.scanner
    if args.scan_date:
        mapping["scan_date"] = args.scan_date

    print_mapping_table(mapping, vulns)

    if args.dry_run:
        print(f"\n  {colored('⚑', 'YELLOW')} Dry run — skipping submission\n")
        return

    # Confirm before submitting (only if --confirm)
    if args.confirm:
        try:
            answer = input(f"\n  {colored('?', 'CYAN')} Submit this scan? [{colored('y', 'GREEN')}/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {colored('⏭', 'YELLOW')} Aborted")
            return
        if answer != "y":
            print(f"  {colored('⏭', 'YELLOW')} Skipped")
            return

    try:
        tokens = args.tokens or mapping.get("_llm_tokens")
        scan_id = submit_to_vulnapps(client, args.app_id, mapping, is_public, args.notes, args.cost, tokens, args.duration)
        for label_name in label_names:
            client.add_label(scan_id, label_name)
        if label_names:
            print(f"  {colored('✓', 'GREEN')} Labels: {colored(', '.join(label_names), 'CYAN')}")
        print(f"  {colored('🔗', 'BLUE')} {args.url}/scans/{scan_id}")
    except httpx.HTTPStatusError as e:
        print(f"  {colored('✗', 'RED')} Submit failed: {e.response.status_code} {e.response.text}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  {colored('Done.', 'GREEN')}\n")


if __name__ == "__main__":
    main()
