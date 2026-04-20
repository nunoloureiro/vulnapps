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

import anthropic
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

Respond with ONLY valid JSON (no markdown fencing) in this exact format:
{
    "scanner_name": "string",
    "scan_date": "YYYY-MM-DD",
    "authenticated": false,
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
            "reasoning": "string - brief explanation of why this maps (or doesn't) to the known vuln"
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
        resp = self.client.get(f"/api/v1/apps/{app_id}")
        resp.raise_for_status()
        return resp.json()

    def get_vulns(self, app_id: int) -> list:
        resp = self.client.get(f"/api/v1/apps/{app_id}/vulns")
        resp.raise_for_status()
        return resp.json()["vulnerabilities"]

    def submit_scan(self, app_id: int, scan_data: dict) -> dict:
        resp = self.client.post(f"/api/v1/apps/{app_id}/scans", json=scan_data)
        resp.raise_for_status()
        return resp.json()

    def get_scan(self, scan_id: int) -> dict:
        resp = self.client.get(f"/api/v1/scans/{scan_id}")
        resp.raise_for_status()
        return resp.json()

    def match_finding(self, scan_id: int, finding_id: int, vuln_id: int | None) -> dict:
        resp = self.client.post(
            f"/api/v1/scans/{scan_id}/findings/{finding_id}/match",
            json={"vuln_id": vuln_id},
        )
        resp.raise_for_status()
        return resp.json()

    def mark_fp(self, scan_id: int, finding_id: int) -> dict:
        resp = self.client.post(
            f"/api/v1/scans/{scan_id}/findings/{finding_id}/mark-fp",
        )
        resp.raise_for_status()
        return resp.json()

    def get_labels(self) -> list:
        resp = self.client.get("/labels/autocomplete")
        resp.raise_for_status()
        return resp.json()["labels"]

    def add_label(self, scan_id: int, name: str, color: str = "#f97316") -> dict:
        resp = self.client.post(
            f"/scans/{scan_id}/labels",
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


STATUS_COLORS = {
    "submitted": "GREEN",
    "dry-run":   "YELLOW",
    "skipped":   "GRAY",
    "aborted":   "GRAY",
    "empty":     "GRAY",
    "failed":    "RED",
    "error":     "RED",
}


def print_summary_table(rows: list):
    """Print a summary table of all processed files."""
    if not rows:
        return

    print_header("Summary", width=72)

    # Columns: File, Scanner, Total, Matched, Unmatched, FP, Status
    headers = ["File", "Scanner", "Total", "TP", "Unmatched", "FP", "Status"]
    widths = [len(h) for h in headers]

    data_rows = []
    for r in rows:
        row = [
            r.get("file", ""),
            r.get("scanner", "-"),
            str(r.get("total", "-")),
            str(r.get("matched", "-")),
            str(r.get("unmatched", "-")),
            str(r.get("fp", "-")),
            r.get("status", "-"),
        ]
        data_rows.append(row)
        for i, v in enumerate(row):
            widths[i] = max(widths[i], len(v))

    # Header
    header_line = "  " + "  ".join(f"{C.BOLD}{h.ljust(widths[i])}{C.RESET}" for i, h in enumerate(headers))
    sep = "  " + "  ".join(colored("─" * w, "GRAY") for w in widths)
    print(header_line)
    print(sep)

    # Rows
    totals = {"total": 0, "matched": 0, "unmatched": 0, "fp": 0}
    for r, row in zip(rows, data_rows):
        status = r.get("status", "-")
        status_colored_s = colored(status.ljust(widths[6]), STATUS_COLORS.get(status, ""))
        cells = [
            row[0].ljust(widths[0]),
            colored(row[1].ljust(widths[1]), "CYAN"),
            colored(row[2].rjust(widths[2]), "BOLD"),
            colored(row[3].rjust(widths[3]), "GREEN"),
            colored(row[4].rjust(widths[4]), "YELLOW"),
            colored(row[5].rjust(widths[5]), "RED"),
            status_colored_s,
        ]
        print("  " + "  ".join(cells))

        if isinstance(r.get("total"), int):
            totals["total"] += r["total"]
            totals["matched"] += r.get("matched", 0)
            totals["unmatched"] += r.get("unmatched", 0)
            totals["fp"] += r.get("fp", 0)

    # Totals row
    print(sep)
    print(
        "  "
        + f"{C.BOLD}Total{C.RESET}".ljust(widths[0] + len(C.BOLD) + len(C.RESET))
        + "  "
        + " " * widths[1]
        + "  "
        + colored(str(totals["total"]).rjust(widths[2]), "BOLD")
        + "  "
        + colored(str(totals["matched"]).rjust(widths[3]), "GREEN")
        + "  "
        + colored(str(totals["unmatched"]).rjust(widths[4]), "YELLOW")
        + "  "
        + colored(str(totals["fp"]).rjust(widths[5]), "RED")
    )


def submit_to_vulnapps(client: VulnappsClient, app_id: int, mapping: dict, is_public: bool, notes: str, cost: float | None = None):
    """Submit the scan and apply LLM-corrected matches."""
    findings_payload = []
    for f in mapping.get("findings", []):
        findings_payload.append({
            "vuln_type": f.get("vuln_type", ""),
            "http_method": f.get("http_method", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "filename": f.get("filename", ""),
        })

    scan_data = {
        "scanner_name": mapping.get("scanner_name", "unknown"),
        "scan_date": mapping.get("scan_date", ""),
        "authenticated": mapping.get("authenticated", False),
        "is_public": is_public,
        "notes": notes,
        "findings": findings_payload,
    }
    if cost is not None:
        scan_data["cost"] = cost

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


# ── Main ─────────────────────────────────────────────────────

def main():
    C.init()

    parser = argparse.ArgumentParser(
        description="Import scan results into Vulnapps with LLM-assisted vulnerability mapping"
    )
    parser.add_argument("--url", required=True, help="Vulnapps instance URL")
    parser.add_argument("--api-key", default=os.getenv("VULNAPPS_API_KEY"), help="API key (or set VULNAPPS_API_KEY)")
    parser.add_argument("--app-id", type=int, required=True, help="Target app ID")
    parser.add_argument("--dir", required=True, help="Directory with .md scan result files")
    parser.add_argument("--file", help="Single .md file to import (instead of --dir)")
    parser.add_argument("--scanner", default=None, help="Scanner name (overrides LLM-detected name)")
    parser.add_argument("--public", action="store_true", help="Make scan public (default: private)")
    parser.add_argument("--labels", default="", help="Comma-separated labels (must already exist in Vulnapps)")
    parser.add_argument("--cost", type=float, default=None, help="Scan cost in USD (optional, private — for LLM-based scanners)")
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

    if not args.api_key:
        print(f"  {colored('Error:', 'RED')} --api-key or VULNAPPS_API_KEY environment variable required", file=sys.stderr)
        sys.exit(1)

    # Auto-detect Vertex from env (same vars as Claude Code)
    if args.provider is None:
        args.provider = "vertex" if os.getenv("CLAUDE_CODE_USE_VERTEX") == "1" else "anthropic"

    # Set default model
    if not args.model:
        args.model = "claude-sonnet-4-20250514"

    # Validate LLM provider config
    if args.provider == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        print(f"  {colored('Error:', 'RED')} ANTHROPIC_API_KEY required (or use --provider vertex)", file=sys.stderr)
        sys.exit(1)
    if args.provider == "vertex" and not args.vertex_project:
        print(f"  {colored('Error:', 'RED')} ANTHROPIC_VERTEX_PROJECT_ID or --vertex-project required", file=sys.stderr)
        sys.exit(1)

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

    is_public = args.public

    # Connect to Vulnapps
    client = VulnappsClient(args.url, args.api_key)

    # Create LLM client
    llm_client = create_anthropic_client(args.provider, args.vertex_region, args.vertex_project)

    # Banner
    provider_label = f"vertex/{args.vertex_region}" if args.provider == "vertex" else "anthropic"
    print(f"\n  {colored('vulnapps', 'ORANGE')} {C.DIM}scan importer{C.RESET}")
    print(f"  {C.DIM}{'─' * 40}{C.RESET}")
    print(f"  {colored('✓', 'GREEN')} LLM: {colored(args.model, 'CYAN')} {C.DIM}via {provider_label}{C.RESET}")

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
    print(f"  {colored('✓', 'GREEN')} Scan files:  {colored(str(len(md_files)), 'BOLD')}")

    # Validate labels
    label_names = [l.strip() for l in args.labels.split(",") if l.strip()] if args.labels else []
    if label_names:
        existing_labels = {l["name"]: l for l in client.get_labels()}
        unknown = [n for n in label_names if n not in existing_labels]
        if unknown:
            print(f"  {colored('✗', 'RED')} Unknown labels: {', '.join(unknown)}", file=sys.stderr)
            print(f"    {C.DIM}Available: {', '.join(sorted(existing_labels.keys())) or '(none)'}{C.RESET}", file=sys.stderr)
            sys.exit(1)
        print(f"  {colored('✓', 'GREEN')} Labels:      {colored(', '.join(label_names), 'CYAN')}")

    if args.dry_run:
        print(f"  {colored('⚑', 'YELLOW')} Dry run mode — no changes will be made")

    # Collect per-file results for end-of-run summary
    summary_rows = []

    for idx, md_file in enumerate(md_files, 1):
        print_header(f"[{idx}/{len(md_files)}] {md_file.name}")

        content = md_file.read_text()
        if not content.strip():
            print(f"  {colored('⏭', 'YELLOW')} Skipping empty file")
            summary_rows.append({"file": md_file.name, "status": "empty"})
            continue

        # Run LLM mapping
        try:
            mapping = run_llm_mapping(content, vulns, args.model, llm_client)
        except json.JSONDecodeError as e:
            print(f"  {colored('✗', 'RED')} LLM returned invalid JSON: {e}", file=sys.stderr)
            summary_rows.append({"file": md_file.name, "status": "error"})
            continue
        except anthropic.APIError as e:
            print(f"  {colored('✗', 'RED')} Claude API error: {e}", file=sys.stderr)
            summary_rows.append({"file": md_file.name, "status": "error"})
            continue

        if args.scanner:
            mapping["scanner_name"] = args.scanner

        print_mapping_table(mapping, vulns)

        findings = mapping.get("findings", [])
        matched = sum(1 for f in findings if f.get("matched_vuln_db_id"))
        unmatched = sum(1 for f in findings if not f.get("matched_vuln_db_id") and not f.get("is_false_positive"))
        fps = sum(1 for f in findings if f.get("is_false_positive"))
        row = {
            "file": md_file.name,
            "scanner": mapping.get("scanner_name", "unknown"),
            "date": mapping.get("scan_date", ""),
            "total": len(findings),
            "matched": matched,
            "unmatched": unmatched,
            "fp": fps,
        }

        if args.dry_run:
            print(f"\n  {colored('⚑', 'YELLOW')} Dry run — skipping submission")
            row["status"] = "dry-run"
            summary_rows.append(row)
            continue

        # Confirm before submitting
        try:
            answer = input(f"\n  {colored('?', 'CYAN')} Submit this scan? [{colored('y', 'GREEN')}/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {colored('⏭', 'YELLOW')} Aborted")
            row["status"] = "aborted"
            summary_rows.append(row)
            break
        if answer != "y":
            print(f"  {colored('⏭', 'YELLOW')} Skipped")
            row["status"] = "skipped"
            summary_rows.append(row)
            continue

        try:
            scan_id = submit_to_vulnapps(client, args.app_id, mapping, is_public, args.notes, args.cost)
            # Apply labels
            for label_name in label_names:
                client.add_label(scan_id, label_name)
            if label_names:
                print(f"  {colored('✓', 'GREEN')} Labels: {colored(', '.join(label_names), 'CYAN')}")
            print(f"  {colored('🔗', 'BLUE')} {args.url}/scans/{scan_id}")
            row["status"] = "submitted"
            row["scan_id"] = scan_id
        except httpx.HTTPStatusError as e:
            print(f"  {colored('✗', 'RED')} Submit failed: {e.response.status_code} {e.response.text}", file=sys.stderr)
            row["status"] = "failed"
        summary_rows.append(row)

    print_summary_table(summary_rows)
    print(f"\n  {colored('Done.', 'GREEN')}\n")


if __name__ == "__main__":
    main()
