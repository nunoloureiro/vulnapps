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
import hashlib
import json
import os
import re
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


class AmbiguousAppError(Exception):
    """More than one app matches a name+version lookup.

    The `apps` table lost its UNIQUE(name, version) in migration 010, so a
    name+version pair can resolve to several rows with different ground truth and
    different scan histories. Guessing means a scan is scored against a corpus
    the operator did not choose.
    """

    def __init__(self, name, version, matches):
        self.name = name
        self.version = version
        self.matches = matches
        super().__init__(f"{len(matches)} apps match '{name}' version '{version or ''}'")


class LLMCallError(Exception):
    """Raised by run_llm_mapping* on a recoverable failure (subprocess
    non-zero exit, API error, malformed JSON). Caller decides whether to
    retry or surface the error to the user."""


# Output cap for the mapping/extraction call. A detail-rich report (20+
# findings, each with description/evidence/remediation/code_location) easily
# overruns the old 8192 cap, which truncates the JSON mid-finding and trips a
# JSONDecodeError. 16384 leaves comfortable headroom.
MAX_OUTPUT_TOKENS = 16384

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
- Same endpoint does NOT imply same vulnerability. The attack class \
(vuln_type) must match. For example: a "Path Traversal" finding does NOT map \
to an "SSRF" known vuln even if both hit /wines/import-url; a "CSRF" finding \
does NOT map to an "XSS" known vuln on the same form. If no known vuln has \
the same attack class, set matched_vuln_db_id to null.
- The reverse error is just as easy to make and just as wrong: sharing a \
broad category or theme (e.g. both are "Broken Authentication", both are \
"Security Misconfiguration") is NOT sufficient grounds for a match on its \
own. The specific MECHANISM — what the attacker actually does, and why the \
code allows it — must match, not just the category label. A finding about \
a stolen password hash being accepted as a login credential, one about 2FA \
enrollment skipping reauthentication, and one about a JWT signature never \
being checked can all share a "Broken Authentication" vuln_type while being \
three completely unrelated bugs in different code paths. When you write \
`reasoning` for a match, name the actual shared mechanism (e.g. "both stem \
from the JWT decoder never validating the signature"), not just the shared \
category — if you cannot name a shared mechanism, matched_vuln_db_id must \
be null.
- If a finding does not match any known vulnerability, set matched_vuln_db_id to null.
- Use the database `id` field (integer) for matched_vuln_db_id, NOT the `vuln_id` string.
- Extract the scanner name and scan date from the report if available. \
`scan_date` is when the scan STARTED: use `YYYY-MM-DD`, or \
`YYYY-MM-DD HH:MM` (24-hour) when the report states a start time.
- Also extract scan-run metadata when the report states it: total cost in \
USD (`cost`), total tokens used by the scanner (`tokens`), and wall-clock \
duration in seconds (`duration_seconds`). These describe the scan run itself, \
NOT this mapping step. Use null for any the report does not provide.
- If the report states which AI model or engine PERFORMED the scan (e.g. an \
LLM identifier like `claude-sonnet-4-6`, `claude-opus-4-7`, or `gpt-5`), \
return it as `scan_model` — a short, label-friendly string. This is distinct \
from `scanner_name` (the tool/methodology, e.g. "Claude Code Security"). Use \
null when the report does not state the model.
- For vuln_type, use a short canonical type (e.g., "XSS", "SQLi", "IDOR", \
"Missing Security Headers", "CSRF", etc.)
- ALWAYS fill in the rich detail fields (description, severity, poc, \
remediation, code_location) for every finding when the report provides that \
information, regardless of whether the finding mapped to a known vuln. The \
user reads these fields to confirm the mapping was correct and to spot \
forced/wrong matches. Only leave a field empty when the report itself gives \
no value for it.
- `severity` is MANDATORY for EVERY finding, mapped or unmapped. This is not \
one of the fields you may skip for a matched finding — a mapped finding \
without a severity is a measurement lost, because the platform compares the \
severity the tool assigned against the severity the flaw actually carries in \
that application.
- `severity` must be the severity THE REPORT ASSIGNS, transcribed, not your own \
assessment of how bad the issue is. If the report says "Low" for something you \
would call critical, record "low" — the disagreement is the signal being \
measured. Only when the report states no severity at all for a finding may you \
infer one from the report's own language (e.g. an explicit "Critical findings" \
section heading); if there is genuinely nothing to go on, leave it empty rather \
than substituting your judgement.
- severity must be one of: "critical", "high", "medium", "low", "info".
- For every finding that maps to a known vulnerability, report which \
MILESTONES the report actually evidences for it. Judge only from what the \
report demonstrates — never from what a scanner could plausibly have done:
    * `surface`: the report locates the vulnerable surface (endpoint, \
parameter, file) — it knows WHERE.
    * `flaw`: the report identifies the actual flaw and why the code is wrong \
— it knows WHAT.
    * `poc`: the report contains a concrete, reproducible proof of concept — a \
request, payload or command that triggers it. A description of how one might \
exploit it is NOT a PoC.
    * `impact`: the report demonstrates realized impact — data actually \
extracted, an account actually taken over, a privilege actually gained. \
Speculation about impact ("could allow an attacker to...") is NOT impact.
  Milestones are cumulative in practice but judge each independently, and set \
all four explicitly to true or false. Omit the object for unmapped findings.
- When several findings describe the SAME non-issue and are false positives, \
give them an identical short `fp_group` slug (e.g. "missing-headers") so they \
count as one false positive rather than three. Leave `fp_group` empty for a \
false positive that stands alone.

Respond with ONLY valid JSON (no markdown fencing) in this exact format:
{
    "scanner_name": "string",
    "scan_date": "YYYY-MM-DD or YYYY-MM-DD HH:MM",
    "scan_model": "claude-sonnet-4-6" or null,
    "cost": 4.56 or null,
    "tokens": 1234567 or null,
    "duration_seconds": 754 or null,
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
            "fp_group": "string - shared slug for false positives describing the same non-issue, else empty",
            "reasoning": "string - brief explanation of why this maps (or doesn't) to the known vuln",
            "severity": "critical|high|medium|low|info — MANDATORY, transcribed from the report, for mapped and unmapped findings alike",
            "description": "string — what the issue is, why it matters (always when the report has it)",
            "poc": "string — proof-of-concept / reproduction steps (always when the report has it)",
            "remediation": "string — how to fix (always when the report has it)",
            "code_location": "string — file:line or function name if known (always when the report has it)"
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
  `scan_date` is when the scan STARTED: use `YYYY-MM-DD`, or
  `YYYY-MM-DD HH:MM` (24-hour) when the report states a start time.
- Also extract scan-run metadata when the report states it: total cost in
  USD (`cost`), total tokens used by the scanner (`tokens`), and wall-clock
  duration in seconds (`duration_seconds`). These describe the scan run
  itself, NOT this extraction step. Use null for any the report omits.
- If the report states which AI model or engine PERFORMED the scan (e.g. an
  LLM identifier like `claude-sonnet-4-6`, `claude-opus-4-7`, or `gpt-5`),
  return it as `scan_model` — a short, label-friendly string, distinct from
  `scanner_name` (the tool/methodology). Use null when not stated.
- For vuln_type, use a short canonical type (e.g., "XSS", "SQLi", "IDOR",
  "Missing Security Headers", "CSRF").
- severity must be one of: "critical", "high", "medium", "low", "info".
- description, severity, poc, remediation, and code_location are REQUIRED
  for every non-FP finding (since each one will become a documented vuln).

Respond with ONLY valid JSON (no markdown fencing) in this exact format:
{
    "scanner_name": "string",
    "scan_date": "YYYY-MM-DD or YYYY-MM-DD HH:MM",
    "scan_model": "claude-sonnet-4-6" or null,
    "cost": 4.56 or null,
    "tokens": 1234567 or null,
    "duration_seconds": 754 or null,
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
        """Return the app matching name+version exactly, or None.

        Raises ``AmbiguousAppError`` when more than one app matches. Migration
        010 rebuilt the `apps` table without the original UNIQUE(name, version),
        so duplicates are possible and at least one pair exists — taking the
        first row would silently attach a scan to whichever duplicate the query
        happened to return first, and the scan would then be measured against
        that app's ground truth. Refusing is the only safe answer: which app is
        meant is a decision the operator has to make with --app-id.
        """
        resp = self.client.get("/api/apps", params={"q": name})
        resp.raise_for_status()
        matches = [
            a for a in resp.json().get("apps", [])
            if a.get("name") == name and (a.get("version") or "") == (version or "")
        ]
        if len(matches) > 1:
            raise AmbiguousAppError(name, version, matches)
        return matches[0] if matches else None

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

    def mark_fp(self, scan_id: int, finding_id: int, fp_group: str | None = None) -> dict:
        resp = self.client.post(
            f"/api/scans/{scan_id}/findings/{finding_id}/mark-fp",
            json={"fp_group": fp_group} if fp_group else None,
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

    # Stream the response. A non-streaming create() holds one socket open with
    # no bytes flowing until the whole answer is ready; on a detail-rich report
    # the server-side generation outlasts the 600s read timeout and the request
    # dies with APITimeoutError. Streaming keeps SSE events flowing so the
    # connection never idles. See https://docs.anthropic.com/en/api/errors#long-requests
    with Spinner(spinner_msg or "Analyzing scan with Claude..."):
        with client.messages.stream(
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user_message}],
        ) as stream:
            text = stream.get_final_text()
            response = stream.get_final_message()

    text = text.strip()
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


def format_duration(seconds: float) -> str:
    """Human-friendly elapsed time, e.g. '47s' or '2m 7s'."""
    secs = int(round(seconds))
    if secs < 60:
        return f"{secs}s"
    return f"{secs // 60}m {secs % 60}s"


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


# ── Match validation ─────────────────────────────────────────
#
# Cheap, deterministic sanity checks applied to the LLM's own proposed
# matches before they're sent to the API. Added after an incident where
# several unrelated findings (a pass-the-hash login bug, a 2FA-enrollment-
# without-reauth bug, a TOTP-replay bug) all auto-matched to an unrelated
# "JWT none-algorithm accepted" vuln. Investigation traced that specific
# incident to the server-side heuristic matcher, not the LLM (see
# tasks/scanimport-resilience.md) — but a title-level relevance check here
# is still worthwhile defense-in-depth against the LLM independently making
# the same kind of category-level-only match, since vuln_type alone was
# shown to be too coarse a signal (the finding's own vuln_type is often
# identical to the wrongly-matched vuln's vuln_type by construction).

_TITLE_STOPWORDS = {
    "a", "an", "the", "and", "or", "on", "in", "of", "to", "for", "with",
    "via", "no", "not", "is", "are", "be", "by", "at", "as", "this", "that",
    "any", "all", "endpoint", "vulnerability", "issue", "finding",
}


def _title_keywords(text: str) -> set[str]:
    """Meaningful lowercase words from a title/type string."""
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {w for w in words if w not in _TITLE_STOPWORDS and len(w) > 2}


def _titles_share_a_keyword(a: str, b: str) -> bool:
    """True if two titles share at least one meaningful word, or either is
    too short/empty to judge at all. False is the actionable signal: the
    finding and the vuln it's about to be matched to don't appear to
    describe the same thing by name, even loosely."""
    wa, wb = _title_keywords(a), _title_keywords(b)
    if not wa or not wb:
        return True
    return bool(wa & wb)


def validate_llm_matches(mapping: dict, vulns: list) -> list[str]:
    """Sanity-check the LLM's proposed matches in place; return warnings.

    Two checks, both defensive rather than blocking (the operator sees the
    warning and can still let the match through — this never silently drops
    a match on its own):
    - Hallucination guard: matched_vuln_db_id must be a real id from the
      `vulns` list that was actually shown to the model. A hallucinated id
      would otherwise be POSTed to the API as-is.
    - Title relevance: the finding's own title and the matched vuln's title
      should share at least one meaningful keyword. Zero overlap doesn't
      prove the match is wrong, but it's exactly the pattern behind every
      real mismatch found so far, so it's worth a human's attention.
    """
    vuln_lookup = {v["id"]: v for v in vulns}
    warnings = []
    for f in mapping.get("findings", []):
        matched = f.get("matched_vuln_db_id")
        if matched is None:
            continue
        vuln = vuln_lookup.get(matched)
        if vuln is None:
            warnings.append(
                f"'{f.get('title', f.get('vuln_type', '?'))}' was matched to "
                f"DB id {matched}, which isn't in the known-vulns list shown "
                f"to the model — dropping the match (possible hallucination)."
            )
            f["matched_vuln_db_id"] = None
            continue
        finding_title = f.get("title") or f.get("vuln_type") or ""
        vuln_title = vuln.get("title") or vuln.get("vuln_type") or ""
        if not _titles_share_a_keyword(finding_title, vuln_title):
            warnings.append(
                f"'{finding_title}' matched to '{vuln_title}' ({vuln.get('vuln_id', '?')}) "
                f"share no common keyword — please double-check this one."
            )
    return warnings


def submit_to_vulnapps(client: VulnappsClient, app_id: int, mapping: dict, is_public: bool, notes: str, cost: float | None = None, tokens: int | None = None, duration: int | None = None, scanner_version: str | None = None, config: dict | None = None):
    """Submit the scan and apply LLM-corrected matches. `duration` is in SECONDS.

    *config* holds the configuration fingerprint fields (model, reasoning
    effort, harness version, token budget, seed, run group, trial index) plus
    the matcher identity. Without them a run cannot later be attributed to what
    produced it, so the importer always sends whatever it knows.
    """
    findings_payload = []
    for f in mapping.get("findings", []):
        item = {
            "vuln_type": f.get("vuln_type", ""),
            "http_method": f.get("http_method", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "filename": f.get("filename", ""),
        }
        for k in ("title", "severity", "description", "poc", "remediation",
                  "code_location", "fp_group", "reasoning"):
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
    for key, value in (config or {}).items():
        if value not in (None, ""):
            scan_data[key] = value
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
    unmatches = 0
    fp_marks = 0

    with Spinner("Applying LLM match corrections..."):
        for i, sf in enumerate(server_findings):
            if i >= len(llm_findings):
                break
            lf = llm_findings[i]

            if lf.get("is_false_positive"):
                client.mark_fp(scan_id, sf["id"], lf.get("fp_group"))
                fp_marks += 1
                continue

            # Compare against whatever the server's own heuristic matcher
            # already applied at submission time (sf["matched_vuln_id"]).
            # `!=` (not `matched is not None and ...`) covers all three
            # directions: the LLM found a match the heuristic missed, the
            # LLM disagrees with the heuristic's match, and — previously
            # unhandled — the LLM concludes this finding doesn't belong
            # anywhere even though the heuristic auto-matched it to
            # something. That last case used to silently keep a wrong
            # heuristic match forever, since only a *different* non-null
            # match ever triggered a correction call.
            matched = lf.get("matched_vuln_db_id")
            current = sf.get("matched_vuln_id")
            if matched != current:
                client.match_finding(scan_id, sf["id"], matched)
                if matched is None:
                    unmatches += 1
                else:
                    corrections += 1

    if corrections or unmatches or fp_marks:
        print(f"  {colored('✓', 'GREEN')} Applied {colored(str(corrections), 'CYAN')} match corrections, "
              f"{colored(str(unmatches), 'CYAN')} unmatches, {colored(str(fp_marks), 'CYAN')} FP marks")
    else:
        print(f"  {colored('✓', 'GREEN')} Heuristic matching was already correct")

    # Severity coverage on MATCHED findings, reported at import time. Severity
    # band error can only be computed where the tool's own severity was captured,
    # and a silent gap here reads downstream as a well-calibrated scanner.
    matched = [lf for lf in llm_findings
               if lf.get("matched_vuln_db_id") is not None and not lf.get("is_false_positive")]
    with_sev = [lf for lf in matched if lf.get("severity")]
    if matched:
        pct = 100 * len(with_sev) / len(matched)
        mark, colour = ("✓", "GREEN") if pct == 100 else ("⚠", "YELLOW")
        print(f"  {colored(mark, colour)} Severity reported on "
              f"{colored(f'{len(with_sev)}/{len(matched)}', 'CYAN')} matched findings "
              f"({pct:.0f}%)")
        if pct < 100:
            print(f"    {C.DIM}Findings without a reported severity are excluded from "
                  f"severity band error.{C.RESET}")

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


def _as_float(v) -> float | None:
    """Coerce an LLM-supplied value to float, tolerating '$4.56' / '4,560'. None on failure."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(str(v).strip().lstrip("$").replace(",", ""))
    except (ValueError, TypeError):
        return None


def _as_int(v) -> int | None:
    """Coerce an LLM-supplied value to int, tolerating '1,234,567' / '1234.0'. None on failure."""
    f = _as_float(v)
    return int(f) if f is not None else None


def _matcher_identity(args) -> tuple:
    """(matcher_version, matcher_prompt_sha256) for this import run.

    The importer IS the matcher: the LLM decides the final finding→vuln mapping
    and the server-side heuristic is only its first pass. Recording the mapping
    model and a hash of the mapping prompt is what keeps a metric change
    attributable — otherwise a shift could come from the model under test, the
    corpus revision, or the mapper, with no way to tell which.
    """
    engine = "cli" if args.use_cli else "api"
    version = f"llm-{engine}:{args.model}" if args.model else f"llm-{engine}"
    sha = hashlib.sha256(SYSTEM_PROMPT_MAP.encode("utf-8")).hexdigest()
    return version, sha


def _scan_config(args, scan_model: str | None) -> dict:
    """Configuration fingerprint fields to send with the scan."""
    matcher_version, matcher_sha = _matcher_identity(args)
    return {
        "model": scan_model,
        "model_version": args.model_version,
        "reasoning_effort": args.reasoning_effort,
        "harness_version": args.harness_version,
        "token_budget": args.token_budget,
        "seed": args.seed,
        "run_group": args.run_group,
        "trial_index": args.trial_index,
        "matcher_version": matcher_version,
        "matcher_prompt_sha256": matcher_sha,
    }


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

  {b}Configuration fingerprint{r} {d}(what produced the run — record these or the run{r}
  {d}cannot be attributed later){r}{b}:{r}
    {c}--scan-model{r} {d}<m>{r}           Model that RAN the scan, e.g. {c}claude-opus-5{r}
                              {d}(overrides the model read from the report){r}
    {c}--model-version{r} {d}<v>{r}        Model snapshot/version, e.g. {c}20260415{r}
    {c}--reasoning-effort{r} {d}<e>{r}     Effort the scanner ran with, e.g. {c}low{r}, {c}high{r}, {c}max{r}
    {c}--harness-version{r} {d}<v>{r}      Harness/agent version or git commit
    {c}--token-budget{r} {d}<n>{r}         Token budget the scanner was given
    {c}--seed{r} {d}<s>{r}                 Run seed {d}(excluded from the fingerprint){r}
    {c}--run-group{r} {d}<g>{r}            Ties k trials of one configuration together
    {c}--trial-index{r} {d}<i>{r}          0-based trial index within the run group
                              {d}Scanner+version+model+version+effort+harness+budget form{r}
                              {d}the fingerprint; seed and trial index are excluded, so{r}
                              {d}k trials aggregate into a mean and a min–max band.{r}
                              {d}Reporting needs ≥5 trials per configuration.{r}

  {b}LLM mapping{r} {d}(used by the importer to map findings to known vulns){r}{b}:{r}
    {c}--model{r} {d}<model>{r}            Claude model used by the importer for mapping/extraction
                              {d}(default: claude-haiku-4-5 for extract-only, claude-{r}
                              {d}sonnet-4-6 for mapping). This is NOT the model that ran{r}
                              {d}the scan — use {r}{c}--scan-model{r}{d} for that.{r}
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
    ./scanimport.sh --app-id 1 --dir ./scans/ --scanner {o}"Snyk COS"{r} --scanner-version 101 --scan-start {o}"2026-08-04"{r} --labels {o}"claude-opus-4-7,greybox,used-sast"{r}
    ./scanimport.sh --app-id 1 --probely abc123,def456
    {d}# one trial of a configuration sweep (repeat with --trial-index 1..4){r}
    ./scanimport.sh --app-id 1 --dir ./trial-0/ --scanner {o}"Snyk COS"{r} --scan-model {o}claude-opus-5{r} \\
      --reasoning-effort high --harness-version 7d37b87 --token-budget 500000 \\
      --run-group {o}sweep-2026-08-01{r} --trial-index 0 --seed 0
""")


# ── Main ─────────────────────────────────────────────────────

def main():
    C.init()

    # Intercept no-args and --help/-h so we can show a colored grouped help
    # (argparse's default formatter is plain and ungrouped).
    if len(sys.argv) == 1 or any(a in ("-h", "--help") for a in sys.argv[1:]):
        show_pretty_help()
        return

    started_at = time.monotonic()

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
    # ── Configuration fingerprint ────────────────────────────
    # These describe the run under test. Together with scanner name/version they
    # form the config_fingerprint the server computes; --seed and --trial-index
    # are deliberately excluded from it, so k trials of one configuration
    # aggregate into a mean and a min–max band instead of k separate results.
    parser.add_argument("--scan-model", default=None,
                        help="Model that PERFORMED the scan, e.g. 'claude-opus-5' (overrides the value read from the report). Distinct from --model, which is the model used for this mapping step.")
    parser.add_argument("--model-version", default=None,
                        help="Version/snapshot of the scanning model, e.g. '20260415'")
    parser.add_argument("--reasoning-effort", default=None,
                        help="Reasoning effort the scanner ran with, e.g. 'low', 'high', 'max'")
    parser.add_argument("--harness-version", default=None,
                        help="Harness/agent version or git commit that produced the scan")
    parser.add_argument("--token-budget", type=int, default=None,
                        help="Token budget the scanner was given (part of the configuration)")
    parser.add_argument("--seed", default=None,
                        help="Run seed. Excluded from the fingerprint so trials group together.")
    parser.add_argument("--run-group", default=None,
                        help="Label tying k trials of one configuration together, e.g. 'sweep-2026-08-01'")
    parser.add_argument("--trial-index", type=int, default=None,
                        help="0-based index of this trial within its run group")
    parser.add_argument("--scan-start", default=None,
                        help="Scan start time in 'YYYY-MM-DD HH:MM' (overrides LLM-detected date). "
                             "Plain 'YYYY-MM-DD' also accepted.")
    parser.add_argument("--public", action="store_true", help="Make scan public (default: private)")
    parser.add_argument("--labels", default="",
                        help="Comma-separated labels (auto-created if missing). "
                             "The model that ran the scan is auto-added as a label "
                             "when the report states it (no need to pass it here). "
                             "Suggested conventions: "
                             "methodology — blackbox, greybox; "
                             "model — claude-opus-4-6, claude-opus-4-7, "
                             "gpt-5.5-cyber-preview, gpt-5.4-cyber; "
                             "judge — judge-claude-opus-4-7; "
                             "thinking budget — thinking-medium, thinking-high; "
                             "tools — used-dast, used-sast.")
    parser.add_argument("--confirm", action="store_true", help="Ask for confirmation before submitting each scan")
    parser.add_argument("--cost", type=float, default=None, help="Scan cost in USD (optional, private). Overrides any cost the LLM reads from the report.")
    parser.add_argument("--tokens", type=int, default=None, help="Scan token count (optional, private). Overrides the report's value; falls back to the importer's own mapping tokens if neither is available.")
    parser.add_argument("--duration", type=float, default=None, help="Scan duration in minutes (optional, private). Overrides the report's duration.")
    parser.add_argument("--notes", default="", help="Notes to attach to the scan")
    parser.add_argument("--model", default=None,
                        help="Claude model used by the importer (default: auto — "
                             "claude-haiku-4-5 for extract-only mode, "
                             "claude-sonnet-4-6 for mapping mode). NOT the "
                             "model used to run the scan itself — that is "
                             "auto-detected from the report and added as a label "
                             "when stated.")
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
        except AmbiguousAppError as e:
            # Refuse rather than pick. Attaching a scan to the wrong duplicate
            # measures it against ground truth the operator never chose, and
            # nothing downstream would reveal the mistake.
            print(f"  {colored('✗', 'RED')} {e}", file=sys.stderr)
            print(f"    {C.DIM}Duplicate name+version rows exist. Pass --app-id to say "
                  f"which one you mean:{C.RESET}", file=sys.stderr)
            for a in e.matches:
                print(f"      {colored('id ' + str(a['id']), 'CYAN')}  "
                      f"visibility={a.get('visibility')}  "
                      f"vulns={a.get('vuln_count', '?')}  "
                      f"created={a.get('created_at', '?')}", file=sys.stderr)
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
        args.model = "claude-haiku-4-5" if not vulns else "claude-sonnet-4-6"
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
        # Cost/tokens aren't in Probely's API; fall back to anything the LLM
        # parsed, then to the importer's own mapping tokens.
        cost = args.cost if args.cost is not None else _as_float(llm_out.get("cost"))
        tokens = args.tokens or _as_int(llm_out.get("tokens")) or llm_out.get("_llm_tokens")

        match_warnings = validate_llm_matches(mapping, vulns)

        print_header(f"Probely Import — {len(merged['findings'])} findings")
        print_mapping_table(mapping, vulns)
        if match_warnings:
            print(f"\n  {colored('⚠ MATCH WARNINGS', 'YELLOW')} {C.DIM}({len(match_warnings)}){C.RESET}")
            for w in match_warnings:
                print(f"    {colored('!', 'YELLOW')} {w}")

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
            scan_model = llm_out.get("scan_model")
            if scan_model and scan_model not in label_names:
                label_names.append(scan_model)
            scan_id = submit_to_vulnapps(client, args.app_id, mapping, is_public, args.notes, cost, tokens, duration, args.scanner_version)
            for label_name in label_names:
                client.add_label(scan_id, label_name)
            if label_names:
                print(f"  {colored('✓', 'GREEN')} Labels: {colored(', '.join(label_names), 'CYAN')}")
            print(f"  {colored('🔗', 'BLUE')} {args.url}/scans/{scan_id}")
        except httpx.HTTPStatusError as e:
            print(f"  {colored('✗', 'RED')} Submit failed: {e.response.status_code} {e.response.text}", file=sys.stderr)
            sys.exit(1)

        print(f"  {colored('⏱', 'CYAN')} Import time: {colored(format_duration(time.monotonic() - started_at), 'BOLD')}")
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
                    # Scan-run metrics usually appear once (in a summary file);
                    # keep the first non-null value seen across chunks.
                    for k in ("cost", "tokens", "duration_seconds", "scan_model"):
                        if mapping.get(k) is None and partial.get(k) is not None:
                            mapping[k] = partial[k]
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

    match_warnings = validate_llm_matches(mapping, vulns)

    print_mapping_table(mapping, vulns)
    if match_warnings:
        print(f"\n  {colored('⚠ MATCH WARNINGS', 'YELLOW')} {C.DIM}({len(match_warnings)}){C.RESET}")
        for w in match_warnings:
            print(f"    {colored('!', 'YELLOW')} {w}")

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
        # Precedence: explicit CLI flag > value the LLM read from the report.
        # Tokens additionally fall back to the importer's own mapping tokens.
        cost = args.cost if args.cost is not None else _as_float(mapping.get("cost"))
        tokens = args.tokens or _as_int(mapping.get("tokens")) or mapping.get("_llm_tokens")
        # --duration is minutes; backend expects seconds. The report's
        # duration_seconds is already in seconds.
        duration_s = int(args.duration * 60) if args.duration is not None else _as_int(mapping.get("duration_seconds"))
        # Auto-add the model that ran the scan as a label. Precedence: explicit
        # --scan-model > the value the LLM read from the report.
        scan_model = args.scan_model or mapping.get("scan_model")
        if scan_model and scan_model not in label_names:
            label_names.append(scan_model)
        config = _scan_config(args, scan_model)
        scan_id = submit_to_vulnapps(client, args.app_id, mapping, is_public, args.notes, cost, tokens, duration_s, args.scanner_version, config)
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

    print(f"  {colored('⏱', 'CYAN')} Import time: {colored(format_duration(time.monotonic() - started_at), 'BOLD')}")
    print(f"\n  {colored('Done.', 'GREEN')}\n")


if __name__ == "__main__":
    main()
