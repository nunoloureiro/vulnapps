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


class LLMCallError(Exception):
    """Raised by run_llm_mapping* on a recoverable failure (subprocess
    non-zero exit, API error, malformed JSON). Caller decides whether to
    retry or surface the error to the user."""


# ── Prompt ───────────────────────────────────────────────────

SYSTEM_PROMPT_MAP = """\
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


SYSTEM_PROMPT_EXTRACT = """\
You are a vulnerability extraction assistant for a security testing platform.

You will be given a security scan report in markdown format. There are no
known vulnerabilities to compare against — every finding will be a NEW
documented vulnerability for this application.

Your job is to:
1. Extract each distinct finding from the scan report
2. Capture every detail useful for triage and remediation (severity,
   description, proof-of-concept, remediation, code location)
3. Mark findings as false positives only when the report explicitly says so

IMPORTANT RULES:
- Do NOT attempt to consolidate or "map" findings — keep each distinct
  finding as its own entry. The platform can group them later.
- Extract the scanner name and scan date from the report if available.
- For vuln_type, use a short canonical type (e.g., "XSS", "SQLi", "IDOR",
  "Missing Security Headers", "CSRF").
- severity must be one of: "critical", "high", "medium", "low", "info".
- description, severity, poc, remediation, and code_location are REQUIRED
  for every non-FP finding (since each one will become a documented vuln).

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
            "is_false_positive": false,
            "severity": "critical|high|medium|low|info",
            "description": "string — what the issue is, why it matters",
            "poc": "string — proof-of-concept / reproduction steps",
            "remediation": "string — how to fix",
            "code_location": "string — file:line or function name if known"
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

    def get_teams(self) -> list:
        resp = self.client.get("/api/teams")
        resp.raise_for_status()
        return resp.json().get("teams", [])

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

    def upload_scan_state(self, scan_id: int, zip_path: Path, filename: str) -> dict:
        with open(zip_path, "rb") as fh:
            data = fh.read()
        resp = self.client.post(
            f"/api/scans/{scan_id}/state",
            content=data,
            headers={"Content-Type": "application/zip", "X-Filename": filename},
            timeout=120.0,
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


def run_llm_mapping(scan_content: str, vulns: list, model: str, client, spinner_msg: str | None = None) -> dict:
    """Send scan content (optionally with known vulns) to Claude.

    When `vulns` is empty the prompt switches to extraction-only mode — no
    mapping language, all findings flow through as promote-candidates.
    """
    if vulns:
        system = SYSTEM_PROMPT_MAP
        user_message = f"""## Known Vulnerabilities for this Application

{format_vulns_for_prompt(vulns)}

## Scan Report

{scan_content}"""
    else:
        system = SYSTEM_PROMPT_EXTRACT
        user_message = f"""## Scan Report

{scan_content}"""

    with Spinner(spinner_msg or "Analyzing scan with Claude..."):
        response = client.messages.create(
            model=model,
            max_tokens=8192,
            system=system,
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


def run_llm_mapping_cli(scan_content: str, vulns: list, spinner_msg: str | None = None) -> dict:
    """Run extraction/mapping via the local `claude` CLI. Used when --use-cli
    is set, or as a fallback when no API key/Vertex config is available.

    When `vulns` is empty the prompt switches to extraction-only mode.
    """
    import subprocess
    import shutil

    if not shutil.which("claude"):
        print(f"  {colored('Error:', 'RED')} No LLM available. Set ANTHROPIC_API_KEY or install Claude Code CLI.", file=sys.stderr)
        sys.exit(1)

    if vulns:
        prompt = f"""{SYSTEM_PROMPT_MAP}

## Known Vulnerabilities for this Application

{format_vulns_for_prompt(vulns)}

## Scan Report

{scan_content}

Respond with ONLY valid JSON (no markdown fencing)."""
    else:
        prompt = f"""{SYSTEM_PROMPT_EXTRACT}

## Scan Report

{scan_content}

Respond with ONLY valid JSON (no markdown fencing)."""

    with Spinner(spinner_msg or "Analyzing scan with Claude CLI..."):
        result = subprocess.run(
            ["claude", "-p", prompt,
             "--output-format", "json",
             "--max-turns", "1",
             "--allowedTools", "Read,Glob,Grep"],
            capture_output=True, text=True, timeout=300
        )

    if result.returncode != 0:
        # The CLI with --output-format json puts errors in the stdout JSON
        # envelope (is_error / result fields), not stderr.
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        msg = None
        try:
            env = json.loads(stdout) if stdout else None
            if isinstance(env, dict):
                msg = env.get("result") or env.get("error") or env.get("message")
        except json.JSONDecodeError:
            pass
        detail = (str(msg)[:1000] if msg else (stderr[:2000] or stdout[:2000] or ""))
        raise LLMCallError(f"Claude CLI failed (exit {result.returncode}): {detail}")

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


def submit_to_vulnapps(client: VulnappsClient, app_id: int, mapping: dict, is_public: bool, notes: str, cost: float | None = None, tokens: int | None = None, duration: int | None = None, scanner_version: str | None = None):
    """Submit the scan and apply LLM-corrected matches. `duration` is in SECONDS."""
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
    if scanner_version:
        scan_data["scanner_version"] = scanner_version
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


def probely_findings_to_markdown(findings: list, scan_ids: list[str]) -> str:
    """Render Probely findings as a markdown report suitable for LLM mapping.

    The LLM mapping prompt expects a scan-report-style document; Probely
    gives us a structured list, so we render it back into a form the same
    prompt can consume. Each finding becomes its own section with the
    fields the prompt uses to decide a match (vuln_type, url, method,
    parameter, severity, description, evidence).
    """
    lines = [
        "# Probely DAST Scan",
        "",
        f"Source scan IDs: {', '.join(scan_ids)}",
        "",
        f"## Findings ({len(findings)})",
        "",
    ]
    # Probely returns numeric severity codes; map to the canonical string set
    # used by the rest of the pipeline. 0=info, 10=low, 20=medium, 30=high,
    # 40=critical — observed in the Probely API; unknown values pass through.
    _PROBELY_SEV = {0: "info", 10: "low", 20: "medium", 30: "high", 40: "critical"}

    def _norm_sev(value) -> str:
        if isinstance(value, int):
            return _PROBELY_SEV.get(value, "")
        if isinstance(value, str):
            v = value.strip().lower()
            return _PROBELY_SEV.get(int(v), v) if v.isdigit() else v
        return ""

    for i, f in enumerate(findings, 1):
        defn = f.get("definition") or {}
        name = defn.get("name") or f.get("name") or "Unknown"
        severity = _norm_sev(f.get("severity"))
        method = f.get("method") or ""
        url = f.get("url") or ""
        parameter = f.get("parameter") or ""
        evidence = f.get("evidence") or ""
        description = (defn.get("description") or f.get("description") or "").strip()
        labs_url = f.get("labs_url") or f.get("url") or ""

        lines.append(f"### Finding {i}: {name}")
        lines.append("")
        if severity:
            lines.append(f"- Severity: {severity}")
        if method or url:
            lines.append(f"- Endpoint: {method} {url}".strip())
        if parameter:
            lines.append(f"- Parameter: {parameter}")
        if labs_url and labs_url != url:
            lines.append(f"- Reference: {labs_url}")
        if description:
            lines.append("")
            lines.append(description[:1500])
        if evidence:
            lines.append("")
            lines.append("Evidence:")
            lines.append("```")
            lines.append(str(evidence)[:800])
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


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


# ── Helpers ──────────────────────────────────────────────────

def parse_create_app(s: str) -> dict:
    """Parse --create-app: a JSON object string.

    Example: '{"name":"Test","version":"1.1","url":"http://example.com"}'
    """
    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        raise ValueError(f"--create-app must be a JSON object: {e}")


def _human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} GiB"


def _discover_findings_dir(root: Path) -> Path:
    """Pick the directory we should read .md files from.

    Rules (the user often passes the project/run root, not the findings dir):
      1. If `root` itself has any *.md → use root.
      2. Else walk immediate children: first child that contains *.md wins.
      3. Else: first child whose name (or contained filename) matches *report* wins.
      4. Else: fall back to root and let the "no .md files" error fire.

    Hidden/private/system children (names starting with '.' or '_') are skipped.
    """
    if any(root.glob("*.md")):
        return root
    children = sorted(c for c in root.iterdir()
                      if c.is_dir() and not c.name.startswith((".", "_")))
    # Pass 1: a child containing .md files.
    for child in children:
        if any(child.glob("*.md")):
            return child
    # Pass 2: a child with *report* anywhere in its tree.
    for child in children:
        if "report" in child.name.lower():
            return child
        for entry in child.iterdir():
            if entry.is_file() and "report" in entry.name.lower():
                return child
    return root


def _zip_directory(src: Path, dest: Path) -> int:
    """Create a zip of *src* at *dest*. Excludes the scanimport checkpoint and
    any hidden (dot-prefixed) files/directories. Returns the zip's size in bytes.
    """
    import zipfile
    src = src.resolve()
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            rel = path.relative_to(src)
            # Skip dotfiles/dotdirs and our own checkpoint.
            if any(part.startswith(".") for part in rel.parts):
                continue
            if rel.name == ".scanimport-checkpoint.json":
                continue
            if path.is_file():
                zf.write(path, arcname=str(rel))
    return dest.stat().st_size


def parse_scan_start(s: str) -> str:
    """Parse --scan-start. Accepts 'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD'.
    Returns a normalized 'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD' string.
    """
    from datetime import datetime as _dt
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return _dt.strptime(s, fmt).strftime(fmt)
        except ValueError:
            continue
    raise ValueError(f"--scan-start must be 'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD' (got {s!r})")


# ── Help ─────────────────────────────────────────────────────

def show_pretty_help():
    """Colored, grouped help — printed when called with no args or --help."""
    b, d, r = C.BOLD, C.DIM, C.RESET
    g, c, y, o = C.GREEN, C.CYAN, C.YELLOW, C.ORANGE
    print(f"""
  {b}{c}🛡 Vulnapps Scan Importer{r}
  {d}─────────────────────────{r}

  {b}Usage:{r} ./scanimport.sh {d}[options]{r}

  {b}Target app{r} {d}(one of){r}{b}:{r}
    {c}--app-id{r} {d}<id>{r}              Existing app ID in Vulnapps
    {c}--create-app{r} {d}<json>{r}        Look up by name+version, create if missing.
                              {d}JSON keys: name (required), version, url, description,{r}
                              {d}tech, visibility (default: private), team (id or name —{r}
                              {d}auto-promotes visibility to "team" if set).{r}
                              {d}Example:{r} {o}'{{"name":"Test","version":"1.1","team":"COS-Core"}}'{r}

  {b}Scan source{r} {d}(one of){r}{b}:{r}
    {c}--dir{r} {d}<path>{r}               Directory containing .md scan files
    {c}--file{r} {d}<path>{r}              Single .md file
    {c}--probely{r} {d}<ids>{r}            Probely scan ID(s), comma-separated (max 2)

  {b}Connection:{r}
    {c}--url{r} {d}<url>{r}                Vulnapps URL (default: $VULNAPPS_URL)
    {c}--api-key{r} {d}<key>{r}            API key (default: $VULNAPPS_API_KEY)

  {b}Scan metadata:{r}
    {c}--scanner{r} {d}<name>{r}           Override LLM-detected scanner name
    {c}--scanner-version{r} {d}<v>{r}      Scanner version, e.g. "2.14.0"
    {c}--scan-start{r} {d}<when>{r}        Scan start: 'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD'
    {c}--public{r}                    Make scan public (default: private)
    {c}--labels{r} {d}<list>{r}            Comma-separated labels {d}(auto-created if missing){r}
                              {d}Conventions:{r}
                                {d}methodology:{r} {c}blackbox{r}, {c}greybox{r}
                                {d}model:{r}       {c}claude-opus-4-6{r}, {c}claude-opus-4-7{r},
                                              {c}gpt-5.5-cyber-preview{r}, {c}gpt-5.4-cyber{r}
                                {d}judge:{r}       {c}judge-claude-opus-4-7{r}
                                {d}thinking:{r}    {c}thinking-medium{r}, {c}thinking-high{r}
                                {d}tools:{r}       {c}used-dast{r}, {c}used-sast{r}
    {c}--notes{r} {d}<text>{r}             Notes to attach to the scan
    {c}--cost{r} {d}<usd>{r}               Scan cost in USD {d}(private, for LLM-based scans){r}
    {c}--tokens{r} {d}<n>{r}               Token count {d}(private, auto-captured if omitted){r}
    {c}--duration{r} {d}<min>{r}           Scan duration in minutes {d}(private){r}

  {b}LLM mapping{r} {d}(used by the importer to map findings to known vulns){r}{b}:{r}
    {c}--model{r} {d}<model>{r}            Claude model used by the importer for mapping/extraction
                              {d}(default: claude-haiku-4-5 for extract-only, claude-{r}
                              {d}sonnet-4-20250514 for mapping). This is NOT the model{r}
                              {d}used to run the scan itself — record that with a label.{r}
    {c}--provider{r} {d}<p>{r}             anthropic|vertex {d}(default: auto from CLAUDE_CODE_USE_VERTEX){r}
    {c}--vertex-region{r} {d}<r>{r}        Vertex region (default: $ANTHROPIC_VERTEX_LOCATION or us-east5)
    {c}--vertex-project{r} {d}<p>{r}       GCP project ID (default: $ANTHROPIC_VERTEX_PROJECT_ID)
    {c}--use-cli{r}                   Force local {y}claude{r} CLI for mapping {d}(--allowedTools{r}
                              {d}Read,Glob,Grep). No API key required.{r}

  {b}Flow:{r}
    {c}--dry-run{r}                   Preview the LLM mapping without submitting
    {c}--confirm{r}                   Ask for confirmation before submitting
    {c}--workers{r} {d}<n>{r}              Parallel LLM calls when chunking by file
                              {d}(default: 4; set to 1 if rate-limited){r}
    {c}--resume{r}                    Resume a partial chunked import from
                              {d}<dir>/.scanimport-checkpoint.json{r}

  {b}Environment:{r}
    {d}VULNAPPS_URL{r}                  Vulnapps instance URL
    {d}VULNAPPS_API_KEY{r}              API key (vuln-mapper scope)
    {d}ANTHROPIC_API_KEY{r}             Anthropic API key
    {d}CLAUDE_CODE_USE_VERTEX=1{r}      Use Vertex AI instead
    {d}ANTHROPIC_VERTEX_PROJECT_ID{r}   GCP project for Vertex
    {d}ANTHROPIC_VERTEX_LOCATION{r}     Vertex region
    {d}PROBELY_API_KEY{r}               Probely API key (required for --probely)

  {b}Examples:{r}
    ./scanimport.sh --dry-run --app-id 1 --dir ./scan-results/
    ./scanimport.sh --app-id 1 --file ./zap-scan.md
    ./scanimport.sh --create-app {o}'{{"name":"juice-shop","version":"14"}}'{r} --file ./scan.md
    ./scanimport.sh --app-id 1 --dir ./scans/ --labels {o}"claude-opus-4-7,greybox,used-sast"{r}
    ./scanimport.sh --app-id 1 --probely abc123,def456
""")


# ── Main ─────────────────────────────────────────────────────

def main():
    C.init()

    # Intercept no-args and --help/-h so we can show a colored grouped help
    # (argparse's default formatter is plain and ungrouped).
    if len(sys.argv) == 1 or any(a in ("-h", "--help") for a in sys.argv[1:]):
        show_pretty_help()
        return

    parser = argparse.ArgumentParser(
        description="Import scan results into Vulnapps with LLM-assisted vulnerability mapping"
    )
    parser.add_argument("--url", default=os.getenv("VULNAPPS_URL"), help="Vulnapps instance URL (or set VULNAPPS_URL)")
    parser.add_argument("--api-key", default=os.getenv("VULNAPPS_API_KEY"), help="API key (or set VULNAPPS_API_KEY)")
    parser.add_argument("--app-id", type=int, default=None,
                        help="Target app ID. If omitted, --create-app is required and the app is looked up by name+version (created if missing).")
    parser.add_argument("--create-app", default=None,
                        help='Look-up-or-create app from a JSON object, e.g. '
                             '\'{"name":"Test","version":"1.1","url":"http://example.com",'
                             '"description":"...","tech":"php,mysql","visibility":"private","team":"COS-Core"}\'. '
                             'Keys: name (required), version, url, description, tech, '
                             'visibility (public|private|team, default private), '
                             'team (id or name; auto-promotes visibility to "team" if set).')
    parser.add_argument("--dir", default=None, help="Directory with .md scan result files")
    parser.add_argument("--file", help="Single .md file to import (instead of --dir)")
    parser.add_argument("--probely", default=None, help="Import from Probely: scan ID(s), comma-separated (max 2). Requires PROBELY_API_KEY env var.")
    parser.add_argument("--scanner", default=None, help="Scanner name (overrides LLM-detected name)")
    parser.add_argument("--scanner-version", default=None, help="Scanner version, e.g. '2.14.0'")
    parser.add_argument("--scan-start", default=None,
                        help="Scan start time in 'YYYY-MM-DD HH:MM' (overrides LLM-detected date). "
                             "Plain 'YYYY-MM-DD' also accepted.")
    parser.add_argument("--public", action="store_true", help="Make scan public (default: private)")
    parser.add_argument("--labels", default="",
                        help="Comma-separated labels (auto-created if missing). "
                             "Suggested conventions: "
                             "methodology — blackbox, greybox; "
                             "model — claude-opus-4-6, claude-opus-4-7, "
                             "gpt-5.5-cyber-preview, gpt-5.4-cyber; "
                             "judge — judge-claude-opus-4-7; "
                             "thinking budget — thinking-medium, thinking-high; "
                             "tools — used-dast, used-sast.")
    parser.add_argument("--confirm", action="store_true", help="Ask for confirmation before submitting each scan")
    parser.add_argument("--cost", type=float, default=None, help="Scan cost in USD (optional, private — for LLM-based scanners)")
    parser.add_argument("--tokens", type=int, default=None, help="Token count (optional, private — auto-captured from LLM if not set)")
    parser.add_argument("--duration", type=float, default=None, help="Scan duration in minutes (optional, private)")
    parser.add_argument("--notes", default="", help="Notes to attach to the scan")
    parser.add_argument("--model", default=None,
                        help="Claude model used by the importer (default: auto — "
                             "claude-haiku-4-5 for extract-only mode, "
                             "claude-sonnet-4-20250514 for mapping mode). NOT the "
                             "model used to run the scan itself — record that with "
                             "a label, e.g. --labels claude-opus-4-6,greybox.")
    parser.add_argument("--provider", choices=["anthropic", "vertex"], default=None,
                        help="LLM provider. Auto-detected from CLAUDE_CODE_USE_VERTEX=1 env var")
    parser.add_argument("--use-cli", action="store_true",
                        help="Force using the local `claude` CLI for mapping (with "
                             "--allowedTools Read,Glob,Grep) instead of the Anthropic/Vertex "
                             "API. Useful when you don't want to use an API key.")
    parser.add_argument("--vertex-region", default=os.getenv("ANTHROPIC_VERTEX_LOCATION", "us-east5"),
                        help="Vertex AI region (or set ANTHROPIC_VERTEX_LOCATION)")
    parser.add_argument("--vertex-project", default=os.getenv("ANTHROPIC_VERTEX_PROJECT_ID"),
                        help="Google Cloud project ID (or set ANTHROPIC_VERTEX_PROJECT_ID)")
    parser.add_argument("--dry-run", action="store_true", help="Show mapping without submitting")
    parser.add_argument("--workers", type=int, default=4,
                        help="Parallel LLM calls when chunking by file (default: 4). "
                             "Set to 1 for sequential (e.g. when rate-limited).")
    parser.add_argument("--skip-state", action="store_true",
                        help="Don't zip and upload the source directory as scan state. "
                             "By default the entire --dir is zipped and attached to the scan.")
    parser.add_argument("--resume", action="store_true",
                        help="Resume a partial chunked import. Looks for "
                             "<dir>/.scanimport-checkpoint.json, written after every "
                             "chunk in multi-file mode and deleted on successful "
                             "submission. Already-processed files are skipped.")
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

    if args.app_id is None and not args.create_app:
        print(f"  {colored('Error:', 'RED')} Either --app-id or --create-app is required", file=sys.stderr)
        sys.exit(1)

    # Parse --create-app dict (and validate `name` is present)
    create_app = None
    if args.create_app:
        try:
            create_app = parse_create_app(args.create_app)
        except (ValueError, json.JSONDecodeError) as e:
            print(f"  {colored('Error:', 'RED')} --create-app: {e}", file=sys.stderr)
            sys.exit(1)
        if not create_app.get("name"):
            print(f"  {colored('Error:', 'RED')} --create-app requires 'name' key", file=sys.stderr)
            sys.exit(1)
        vis = create_app.get("visibility", "private")
        if vis not in ("public", "private", "team"):
            print(f"  {colored('Error:', 'RED')} --create-app visibility must be public|private|team (got {vis!r})", file=sys.stderr)
            sys.exit(1)

    # Validate and normalize --scan-start
    if args.scan_start:
        try:
            args.scan_start = parse_scan_start(args.scan_start)
        except ValueError as e:
            print(f"  {colored('Error:', 'RED')} {e}", file=sys.stderr)
            sys.exit(1)

    # Determine LLM mode
    use_cli = False
    llm_client = None

    if args.provider is None:
        args.provider = "vertex" if os.getenv("CLAUDE_CODE_USE_VERTEX") == "1" else "anthropic"

    # Defer the default model until we know whether we'll be in extract-only
    # mode (no known vulns) — Haiku is fast and adequate for extraction.
    explicit_model = args.model is not None

    # Every import path (markdown, file, Probely) maps findings to known
    # vulns via the LLM, so the LLM is always required.
    need_llm = True

    if need_llm:
        if args.use_cli:
            import shutil
            if not shutil.which("claude"):
                print(f"  {colored('Error:', 'RED')} --use-cli requested but `claude` binary not found on PATH.", file=sys.stderr)
                sys.exit(1)
            use_cli = True
        elif args.provider == "vertex" and args.vertex_project:
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
        model_label = args.model if args.model else "auto (haiku for extract / sonnet for mapping)"
        print(f"  {colored('✓', 'GREEN')} LLM: {colored(model_label, 'CYAN')} {C.DIM}via {provider_label}{C.RESET}")

    # Resolve app_id: lookup or create from --create-app if not given explicitly
    if args.app_id is None:
        app_name = create_app["name"]
        app_version = create_app.get("version", "")
        try:
            with Spinner(f"Looking up app '{app_name}'..."):
                existing = client.find_app(app_name, app_version)
        except httpx.HTTPStatusError as e:
            print(f"  {colored('✗', 'RED')} App lookup failed: {e.response.status_code}", file=sys.stderr)
            sys.exit(1)

        if existing:
            args.app_id = existing["id"]
            print(f"  {colored('✓', 'GREEN')} Found existing app: {colored(app_name, 'BOLD')} {C.DIM}(id {args.app_id}){C.RESET}")
        else:
            # Resolve team (accepts numeric ID or team name).
            team_id = None
            team_raw = create_app.get("team")
            if team_raw not in (None, ""):
                if isinstance(team_raw, int) or (isinstance(team_raw, str) and team_raw.isdigit()):
                    team_id = int(team_raw)
                else:
                    try:
                        teams = client.get_teams()
                    except httpx.HTTPStatusError as e:
                        print(f"  {colored('✗', 'RED')} Team lookup failed: {e.response.status_code}", file=sys.stderr)
                        sys.exit(1)
                    match = next((t for t in teams if t.get("name") == team_raw), None)
                    if not match:
                        names = ", ".join(t["name"] for t in teams) or "(none visible)"
                        print(f"  {colored('✗', 'RED')} Team '{team_raw}' not found. Visible: {names}", file=sys.stderr)
                        sys.exit(1)
                    team_id = match["id"]

            # If team is set and visibility wasn't explicitly given, promote to "team".
            visibility = create_app.get("visibility")
            if team_id and not visibility:
                visibility = "team"
            elif not visibility:
                visibility = "private"

            payload = {
                "name": app_name,
                "version": app_version,
                "visibility": visibility,
                "tech_stack": create_app.get("tech", ""),
            }
            if team_id:
                payload["team_id"] = team_id
            if create_app.get("url"):
                payload["url"] = create_app["url"]
            if create_app.get("description"):
                payload["description"] = create_app["description"]
            try:
                with Spinner(f"Creating app '{app_name}'..."):
                    new_app = client.create_app(payload)
                args.app_id = new_app["id"]
                team_suffix = f" {C.DIM}[team {team_id}]{C.RESET}" if team_id else ""
                print(f"  {colored('✓', 'GREEN')} Created app: {colored(app_name, 'BOLD')} {C.DIM}(id {args.app_id}){C.RESET}{team_suffix}")
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

    # Now that we know whether we're in extract-only mode, finalize the model
    # choice. Haiku is roughly 3× faster than Sonnet and adequate for the
    # mechanical "pull findings out of the report" task.
    if not explicit_model:
        args.model = "claude-haiku-4-5" if not vulns else "claude-sonnet-4-20250514"
        if not use_cli and llm_client:
            mode_word = "extract-only" if not vulns else "mapping"
            print(f"  {C.DIM}Model auto-picked for {mode_word}: {args.model}{C.RESET}")

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

        # Hand the Probely findings to the same LLM mapper the markdown flow
        # uses. Without this, every Probely finding lands as "Pending"
        # because the CLI has no client-side matcher of its own.
        raw_findings = []
        for sd in scan_data_list:
            raw_findings.extend(sd["findings"])
        scan_md = probely_findings_to_markdown(raw_findings, scan_ids)
        try:
            if use_cli:
                llm_out = run_llm_mapping_cli(scan_md, vulns, spinner_msg="Mapping Probely findings with Claude CLI...")
            else:
                llm_out = run_llm_mapping(scan_md, vulns, args.model, llm_client, spinner_msg="Mapping Probely findings with Claude...")
        except (LLMCallError, json.JSONDecodeError) as e:
            print(f"  {colored('✗', 'RED')} LLM mapping failed: {e}", file=sys.stderr)
            sys.exit(1)

        mapping = {
            "scanner_name": args.scanner or llm_out.get("scanner_name") or merged["scanner_name"],
            "scan_date": args.scan_start or llm_out.get("scan_date") or merged["scan_date"],
            "findings": llm_out.get("findings", []) or [],
        }

        # --duration is minutes; backend expects seconds. Probely auto-capture is already seconds.
        duration = int(args.duration * 60) if args.duration is not None else merged.get("duration")

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
            scan_id = submit_to_vulnapps(client, args.app_id, mapping, is_public, args.notes, args.cost, args.tokens, duration, args.scanner_version)
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

    # state_root = the directory the user passed (we'll zip the whole thing
    # for scan state). findings_dir = the directory we actually pull .md
    # files from — may be a subfolder discovered below.
    state_root: Path | None = None
    findings_dir: Path | None = None

    if args.file:
        md_files = [Path(args.file)]
    else:
        state_root = Path(args.dir).resolve()
        if not state_root.is_dir():
            print(f"  {colored('Error:', 'RED')} {args.dir} is not a directory", file=sys.stderr)
            sys.exit(1)
        findings_dir = _discover_findings_dir(state_root)
        if findings_dir != state_root:
            rel = findings_dir.relative_to(state_root)
            print(f"  {colored('→', 'CYAN')} Findings dir: {colored(str(rel) + '/', 'BOLD')} {C.DIM}(under {state_root.name}/){C.RESET}")
        md_files = sorted(findings_dir.glob("*.md"))

    if not md_files:
        print(f"  {colored('Error:', 'RED')} No .md files found.", file=sys.stderr)
        sys.exit(1)

    print(f"  {colored('✓', 'GREEN')} Scan files:  {colored(str(len(md_files)), 'BOLD')}")

    # Read all files into (name, content) tuples; drop empties.
    file_parts: list[tuple[str, str]] = []
    for md_file in md_files:
        content = md_file.read_text()
        if content.strip():
            file_parts.append((md_file.name, content))

    if not file_parts:
        print(f"  {colored('✗', 'RED')} All scan files are empty", file=sys.stderr)
        sys.exit(1)

    # Multiple files → one LLM call per file, merge findings. Keeps the
    # per-call context small even on huge scan dumps. Each finding's mapping
    # decision is independent (the LLM needs the known-vulns list + the
    # finding text; not other findings), so chunking applies in both
    # extract-only mode and mapping mode.
    chunked = len(file_parts) > 1

    if chunked:
        print_header(f"Processing {len(file_parts)} file(s) — one LLM call per file")
    else:
        print_header(f"Processing {len(file_parts)} file(s)")

    def _call_llm_once(content: str, spinner_msg: str | None = None) -> dict:
        """Single attempt — raises LLMCallError on any failure."""
        try:
            if use_cli:
                return run_llm_mapping_cli(content, vulns, spinner_msg=spinner_msg)
            return run_llm_mapping(content, vulns, args.model, llm_client, spinner_msg=spinner_msg)
        except LLMCallError:
            raise
        except json.JSONDecodeError as e:
            raise LLMCallError(f"LLM returned invalid JSON: {e}")
        except Exception as e:
            cls = type(e)
            mod = getattr(cls, "__module__", "") or ""
            label = "Claude API error" if "anthropic" in mod else "LLM error"
            raise LLMCallError(f"{label}: {e}")

    def _call_llm(content: str, spinner_msg: str | None = None) -> dict:
        """One retry after a 30s backoff on any LLMCallError. Rate limits
        and transient network blips usually clear in that window."""
        import time as _time
        try:
            return _call_llm_once(content, spinner_msg=spinner_msg)
        except LLMCallError as e:
            print(f"  {colored('⚠', 'YELLOW')} {e}", file=sys.stderr)
            print(f"  {C.DIM}Retrying once in 30s...{C.RESET}", file=sys.stderr)
            _time.sleep(30)
            try:
                return _call_llm_once(content, spinner_msg=(spinner_msg or "") + " (retry)")
            except LLMCallError as e2:
                # Re-raise so the chunked path can checkpoint + exit cleanly.
                raise

    # Checkpoint path (chunked mode only; only --dir creates multiple files).
    checkpoint_path = None
    if chunked and findings_dir is not None:
        checkpoint_path = findings_dir / ".scanimport-checkpoint.json"

    if chunked:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading

        mapping = {"scanner_name": "", "scan_date": "", "findings": [], "_llm_tokens": 0}
        processed: set[str] = set()
        lock = threading.Lock()

        # Load checkpoint if --resume.
        if args.resume and checkpoint_path and checkpoint_path.exists():
            try:
                ck = json.loads(checkpoint_path.read_text())
                mapping = ck.get("mapping") or mapping
                processed = set(ck.get("processed_files") or [])
                print(f"  {colored('↻', 'CYAN')} Resumed: {colored(str(len(processed)), 'BOLD')} file(s) already processed, "
                      f"{colored(str(len(mapping.get('findings') or [])), 'BOLD')} finding(s) carried over")
            except (json.JSONDecodeError, OSError) as e:
                print(f"  {colored('⚠', 'YELLOW')} Could not read checkpoint at {checkpoint_path}: {e}", file=sys.stderr)
                print(f"  {C.DIM}Starting fresh.{C.RESET}", file=sys.stderr)

        pending = [(fname, content) for (fname, content) in file_parts if fname not in processed]
        skipped = len(file_parts) - len(pending)
        if skipped:
            print(f"  {colored('⏭', 'CYAN')} Skipping {skipped} file(s) already in checkpoint")

        if not pending:
            print(f"  {colored('✓', 'GREEN')} Nothing to do — all files already processed")
        else:
            workers = max(1, min(args.workers, len(pending)))
            print(f"  {C.DIM}Running {len(pending)} LLM call(s) with {workers} worker(s)...{C.RESET}")

            done_count = [0]  # mutable closure for thread-safe counter
            fail_lock = threading.Lock()
            first_failure = [None]  # holds (fname, LLMCallError)

            def _process(fname: str, content: str):
                # Don't run more work if another thread already failed —
                # short-circuit so we exit fast on the first error.
                with fail_lock:
                    if first_failure[0] is not None:
                        return
                try:
                    partial = _call_llm(content)
                except LLMCallError as e:
                    with fail_lock:
                        if first_failure[0] is None:
                            first_failure[0] = (fname, e)
                    return

                with lock:
                    if not mapping["scanner_name"] and partial.get("scanner_name"):
                        mapping["scanner_name"] = partial["scanner_name"]
                    if not mapping["scan_date"] and partial.get("scan_date"):
                        mapping["scan_date"] = partial["scan_date"]
                    mapping["findings"].extend(partial.get("findings", []) or [])
                    mapping["_llm_tokens"] += partial.get("_llm_tokens") or 0
                    processed.add(fname)
                    done_count[0] += 1
                    n_findings = len(partial.get("findings") or [])
                    print(f"  {colored('✓', 'GREEN')} {fname} ({done_count[0]}/{len(pending)}): {n_findings} finding(s)")
                    if checkpoint_path:
                        try:
                            checkpoint_path.write_text(json.dumps({
                                "processed_files": sorted(processed),
                                "mapping": mapping,
                            }, indent=2))
                        except OSError as e:
                            print(f"  {colored('⚠', 'YELLOW')} Could not write checkpoint: {e}", file=sys.stderr)

            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(_process, fname, content) for fname, content in pending]
                # Drain so exceptions surface (none expected — _process catches its own)
                for _ in as_completed(futs):
                    pass

            if first_failure[0]:
                fname, err = first_failure[0]
                print(f"  {colored('✗', 'RED')} {fname}: {err}", file=sys.stderr)
                if checkpoint_path:
                    print(
                        f"  {C.DIM}Partial results saved to {checkpoint_path} "
                        f"({len(processed)}/{len(file_parts)} file(s) done).{C.RESET}\n"
                        f"  {C.DIM}Resume with: ./scanimport.sh ... --resume{C.RESET}",
                        file=sys.stderr,
                    )
                sys.exit(1)

        print(f"  {colored('✓', 'GREEN')} Extracted {colored(str(len(mapping['findings'])), 'BOLD')} findings across {len(file_parts)} file(s)")
    else:
        # Single-call path (only one file present).
        combined = file_parts[0][1]
        try:
            mapping = _call_llm(combined)
        except LLMCallError as e:
            print(f"  {colored('✗', 'RED')} {e}", file=sys.stderr)
            sys.exit(1)

    if args.scanner:
        mapping["scanner_name"] = args.scanner
    if args.scan_start:
        mapping["scan_date"] = args.scan_start

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
        # --duration is minutes; backend expects seconds.
        duration_s = int(args.duration * 60) if args.duration is not None else None
        scan_id = submit_to_vulnapps(client, args.app_id, mapping, is_public, args.notes, args.cost, tokens, duration_s, args.scanner_version)
        for label_name in label_names:
            client.add_label(scan_id, label_name)
        if label_names:
            print(f"  {colored('✓', 'GREEN')} Labels: {colored(', '.join(label_names), 'CYAN')}")
        print(f"  {colored('🔗', 'BLUE')} {args.url}/scans/{scan_id}")
    except httpx.HTTPStatusError as e:
        print(f"  {colored('✗', 'RED')} Submit failed: {e.response.status_code} {e.response.text}", file=sys.stderr)
        sys.exit(1)

    # Upload scan state (zip of the originally passed --dir). Only when --dir
    # is the source: --file and --probely have no directory of context to zip.
    if state_root is not None and not args.skip_state:
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(prefix="scan-state-", suffix=".zip", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            with Spinner(f"Zipping {state_root.name}/ ..."):
                size = _zip_directory(state_root, tmp_path)
            zip_name = f"{state_root.name}.zip"
            with Spinner(f"Uploading scan state ({_human_size(size)})..."):
                client.upload_scan_state(scan_id, tmp_path, zip_name)
            print(f"  {colored('✓', 'GREEN')} Scan state uploaded: {colored(zip_name, 'BOLD')} {C.DIM}({_human_size(size)}){C.RESET}")
        except httpx.HTTPStatusError as e:
            print(f"  {colored('⚠', 'YELLOW')} Scan state upload failed: {e.response.status_code} {e.response.text[:200]}", file=sys.stderr)
        except Exception as e:
            print(f"  {colored('⚠', 'YELLOW')} Scan state upload failed: {e}", file=sys.stderr)
        finally:
            try:
                tmp_path.unlink()
            except (NameError, OSError):
                pass

    # Successful submission — clear checkpoint so a future run starts fresh.
    if checkpoint_path and checkpoint_path.exists():
        try:
            checkpoint_path.unlink()
        except OSError:
            pass

    print(f"\n  {colored('Done.', 'GREEN')}\n")


if __name__ == "__main__":
    main()
