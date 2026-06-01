from __future__ import annotations

import hashlib
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

from app.config import STATE_DIR, MAX_STATE_SIZE
from app.matching import match_finding as match_finding_algo
from app.visibility import scan_visibility_filter
from app.dependencies import get_team_role


# ---------------------------------------------------------------------------
# Permission helpers (no HTTP dependencies)
# ---------------------------------------------------------------------------

async def _check_scan_write(db, user, scan, app) -> None:
    """Raise PermissionError if user cannot write to this scan."""
    if not user:
        raise PermissionError("Not authenticated")
    if user["role"] == "admin":
        return
    if scan["submitted_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return
    raise PermissionError("You don't have write access to this scan")


async def _check_app_write(db, user, app) -> None:
    """Raise PermissionError if user lacks app-write access (mirrors vulns._require_app_write)."""
    if not user:
        raise PermissionError("Authentication required")
    if user["role"] == "admin":
        return
    if app["visibility"] == "public":
        raise PermissionError("Only admins can edit public apps")
    if app["created_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return
    raise PermissionError("You don't have write access to this app")


async def _check_scan_submit(db, user, app) -> None:
    """Raise PermissionError if user cannot submit scans on this app."""
    if not user:
        raise PermissionError("Not authenticated")
    if user["role"] == "admin":
        return
    if app["visibility"] == "public":
        raise PermissionError("Only admins can submit scans on public apps")
    if app["visibility"] == "private" and app["created_by"] != user["sub"]:
        raise PermissionError("Only the app creator can submit scans on private apps")
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role not in ("admin", "contributor"):
            raise PermissionError("Team contributor access required to submit scans")


async def _get_scan_and_app(db, scan_id):
    """Fetch scan and its app. Raises ValueError if not found."""
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = await cursor.fetchone()
    if not scan:
        raise ValueError("Scan not found")
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
    app = await cursor.fetchone()
    return scan, app


async def _check_scan_view(db, user, scan, app) -> None:
    """Raise PermissionError if user cannot view this scan.

    Mirrors the inline check in get_scan(): admins always; otherwise public
    scans on public apps, the submitter, or any member of the app's team.
    """
    if not user:
        if not (scan["is_public"] and app["visibility"] == "public"):
            raise PermissionError("Not authenticated")
        return
    if user["role"] == "admin":
        return
    if scan["is_public"]:
        return
    if scan["submitted_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role is not None:
            return
    raise PermissionError("Access denied")


def _compute_metrics(findings, all_vulns):
    """Compute TP/FP/pending/FN/precision/recall/F1 from findings and known vulns."""
    matched_vuln_ids = {
        f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None
    }
    tp = len(matched_vuln_ids)
    fp = sum(1 for f in findings if f["is_false_positive"] == 1)
    pending = sum(
        1 for f in findings
        if f["matched_vuln_id"] is None and f["is_false_positive"] == 0
    )
    missed_vulns = [v for v in all_vulns if v["id"] not in matched_vuln_ids]
    fn = len(missed_vulns)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "tp": tp,
        "fp": fp,
        "pending": pending,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }, matched_vuln_ids, missed_vulns


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

async def list_scans(
    db, user,
    app_id=None, scanner="", latest="", q="",
    label="", filter="",
) -> dict:
    """List scans with filters. Returns dict with scans, metadata, and filter options."""
    extra_filters = ""
    extra_params = []
    app = None

    if app_id:
        extra_filters += " AND scans.app_id = ?"
        extra_params.append(app_id)
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()

    if filter == "public":
        extra_filters += " AND apps.visibility = 'public'"
    elif filter == "private":
        extra_filters += " AND apps.visibility = 'private'"
    elif filter == "teams":
        extra_filters += " AND apps.visibility = 'team'"
    elif filter and filter.startswith("team:") and user:
        try:
            tid = int(filter[5:])
            extra_filters += " AND apps.team_id = ?"
            extra_params.append(tid)
        except ValueError:
            pass

    if scanner:
        extra_filters += " AND scans.scanner_name = ?"
        extra_params.append(scanner)


    if label:
        extra_filters += (
            " AND scans.id IN ("
            "SELECT scan_id FROM scan_labels JOIN labels ON scan_labels.label_id = labels.id "
            "WHERE labels.name = ?)"
        )
        extra_params.append(label)

    if q:
        extra_filters += " AND (apps.name LIKE ? OR scans.scanner_name LIKE ? OR users.name LIKE ?)"
        q_like = f"%{q}%"
        extra_params.extend([q_like, q_like, q_like])

    vis_clause, vis_params = scan_visibility_filter(user)

    # Severity counts use COALESCE(finding.severity, vuln.severity) so a TP
    # finding (whose severity is usually empty by design — the LLM was told
    # to leave it blank for matched findings) still contributes through the
    # severity carried on the matched vulnerability. FP findings are
    # excluded — the user explicitly marked them as not-real.
    sev_subquery = (
        "(SELECT COUNT(*) FROM scan_findings sf "
        "LEFT JOIN vulnerabilities v ON v.id = sf.matched_vuln_id "
        "WHERE sf.scan_id = scans.id AND sf.is_false_positive = 0 "
        "AND lower(COALESCE(NULLIF(sf.severity, ''), v.severity)) = ?)"
    )

    base_query = f"""SELECT scans.*, apps.name as app_name, apps.version as app_version,
                  users.name as submitter_name,
                  (SELECT COUNT(DISTINCT matched_vuln_id) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                  (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count,
                  (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NULL AND is_false_positive=0) as pending_count,
                  ((SELECT COUNT(*) FROM vulnerabilities WHERE app_id = scans.app_id)
                   - (SELECT COUNT(DISTINCT matched_vuln_id) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL)) as fn_count,
                  {sev_subquery} as sev_critical,
                  {sev_subquery} as sev_high,
                  {sev_subquery} as sev_medium,
                  {sev_subquery} as sev_low,
                  {sev_subquery} as sev_info
           FROM scans
           LEFT JOIN apps ON scans.app_id=apps.id
           LEFT JOIN users ON scans.submitted_by=users.id
           WHERE {vis_clause}{extra_filters}"""

    # Severity subqueries each take one bound parameter, prepended to the
    # existing visibility + filter params.
    sev_params = ["critical", "high", "medium", "low", "info"]

    if latest:
        sql = f"""WITH base AS ({base_query}),
                  ranked AS (
                      SELECT *, ROW_NUMBER() OVER (
                          PARTITION BY scanner_name, app_id
                          ORDER BY scan_date DESC, created_at DESC
                      ) as rn FROM base
                  )
                  SELECT * FROM ranked WHERE rn = 1
                  ORDER BY created_at DESC"""
    else:
        sql = base_query + " ORDER BY scans.created_at DESC"

    # The base query's SELECT contains the severity subqueries (which use
    # placeholders), then the WHERE clause's visibility + extra-filter params.
    cursor = await db.execute(sql, sev_params + vis_params + extra_params)
    scans = await cursor.fetchall()

    # Batch-fetch labels for all returned scans
    scan_labels_map: dict[int, list[dict]] = {}
    scan_ids = [s["id"] for s in scans]
    if scan_ids:
        placeholders = ",".join("?" * len(scan_ids))
        cursor = await db.execute(
            f"""SELECT sl.scan_id, l.id, l.name, l.color
                FROM scan_labels sl JOIN labels l ON sl.label_id = l.id
                WHERE sl.scan_id IN ({placeholders})
                ORDER BY l.name""",
            scan_ids,
        )
        for row in await cursor.fetchall():
            scan_labels_map.setdefault(row["scan_id"], []).append(
                {"id": row["id"], "name": row["name"], "color": row["color"]}
            )

    # All label names for filter dropdown
    cursor = await db.execute("SELECT DISTINCT name FROM labels ORDER BY name")
    all_labels = [row["name"] for row in await cursor.fetchall()]

    # Distinct scanner names (scoped to app if filtered)
    scanner_filter = " AND scans.app_id = ?" if app_id else ""
    scanner_params = vis_params + ([app_id] if app_id else [])
    cursor = await db.execute(
        f"""SELECT DISTINCT scans.scanner_name
           FROM scans LEFT JOIN apps ON scans.app_id=apps.id
           WHERE {vis_clause}{scanner_filter}
           ORDER BY scans.scanner_name""",
        scanner_params,
    )
    scanners = [row["scanner_name"] for row in await cursor.fetchall()]

    # Distinct apps for filter dropdown
    cursor = await db.execute(
        f"""SELECT DISTINCT apps.id, apps.name, apps.version
           FROM scans JOIN apps ON scans.app_id=apps.id
           WHERE apps.name IS NOT NULL AND {vis_clause}
           ORDER BY apps.name, apps.version""",
        vis_params,
    )
    apps_list = await cursor.fetchall()

    # User's teams for filter dropdown
    user_teams = []
    if user:
        cursor = await db.execute(
            """SELECT teams.id, teams.name FROM teams
               JOIN team_members ON team_members.team_id = teams.id
               WHERE team_members.user_id = ?
               ORDER BY teams.name""",
            (user["sub"],),
        )
        user_teams = await cursor.fetchall()

    return {
        "scans": scans,
        "app": app,
        "scan_labels_map": scan_labels_map,
        "scanners": scanners,
        "apps_list": apps_list,
        "all_labels": all_labels,
        "user_teams": user_teams,
    }


async def get_scan(db, user, scan_id: int) -> dict:
    """Get full scan detail with metrics, findings, labels, permissions."""
    cursor = await db.execute(
        "SELECT scans.*, users.name as submitter_name "
        "FROM scans LEFT JOIN users ON scans.submitted_by=users.id "
        "WHERE scans.id = ?",
        (scan_id,),
    )
    scan = await cursor.fetchone()
    if not scan:
        raise ValueError("Scan not found")

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
    app = await cursor.fetchone()

    # Visibility check — collapse "not authorized" into "not found" so the
    # response cannot be used to enumerate the existence of private scans
    # (vuln-0005, vuln-0008).
    if not user:
        if not (scan["is_public"] and app and app["visibility"] == "public"):
            raise ValueError("Scan not found")
    elif user["role"] != "admin":
        can_see = (
            (scan["is_public"] and app and app["visibility"] == "public")
            or scan["submitted_by"] == user["sub"]
            or (app and app["visibility"] == "team" and app["team_id"]
                and await get_team_role(db, user["sub"], app["team_id"]) is not None)
        )
        if not can_see:
            raise ValueError("Scan not found")

    cursor = await db.execute(
        "SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,)
    )
    findings = await cursor.fetchall()

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY vuln_id",
        (scan["app_id"],),
    )
    known_vulns = await cursor.fetchall()

    metrics, matched_vuln_ids, missed_vulns = _compute_metrics(findings, known_vulns)

    # Finding counts per matched vuln (for duplicate indicator)
    vuln_finding_counts = dict(
        Counter(f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None)
    )

    # Finding descriptions per matched vuln (for tooltips)
    vuln_finding_details: dict[int, list[str]] = {}
    for f in findings:
        vid = f["matched_vuln_id"]
        if vid is not None:
            lbl = f["vuln_type"] or ""
            loc = f["url"] or f["filename"] or ""
            if loc:
                lbl = f"{lbl}: {loc}"
            vuln_finding_details.setdefault(vid, []).append(lbl)

    # Edit / cost permissions
    can_edit = False
    can_view_cost = False
    if user:
        if user["role"] == "admin":
            can_edit = True
            can_view_cost = True
        elif scan["submitted_by"] == user["sub"]:
            can_edit = True
            can_view_cost = True
        elif app["visibility"] == "team" and app["team_id"]:
            team_role = await get_team_role(db, user["sub"], app["team_id"])
            if team_role in ("admin", "contributor"):
                can_edit = True
            if team_role is not None:
                can_view_cost = True

    # Labels for this scan
    cursor = await db.execute(
        """SELECT l.id, l.name, l.color FROM labels l
           JOIN scan_labels sl ON sl.label_id = l.id
           WHERE sl.scan_id = ? ORDER BY l.name""",
        (scan_id,),
    )
    labels = [dict(row) for row in await cursor.fetchall()]

    # All labels for autocomplete
    cursor = await db.execute("SELECT id, name, color FROM labels ORDER BY name")
    all_labels = [dict(row) for row in await cursor.fetchall()]

    # Redact cost/tokens/duration/notes when the caller may not view them.
    # The `can_view_cost` flag was previously just a UI hint and the raw
    # fields shipped to the client anyway (vuln-0015).
    scan_out = dict(scan)
    if not can_view_cost:
        for k in ("cost", "tokens", "duration", "notes"):
            scan_out[k] = None

    return {
        "scan": scan_out,
        "app": app,
        "metrics": metrics,
        "findings": findings,
        "missed_vulns": missed_vulns,
        "known_vulns": known_vulns,
        "labels": labels,
        "all_labels": all_labels,
        "can_edit": can_edit,
        "can_view_cost": can_view_cost,
        "vuln_finding_counts": vuln_finding_counts,
        "vuln_finding_details": vuln_finding_details,
    }


async def submit_scan(
    db, user,
    app_id: int,
    scanner_name: str,
    scan_date: str,
    is_public: int,
    notes: str | None,
    cost: float | None,
    tokens: int | None,
    duration: int | None,
    findings_data: list[dict],
    labels: list[str] | None = None,
    scanner_version: str | None = None,
) -> int:
    """Create a scan, auto-match findings, apply labels. Returns scan_id."""
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    await _check_scan_submit(db, user, app)

    # A scan can only be public when its parent app is public; otherwise the
    # is_public flag would expose a scan on a private/team app to anonymous
    # readers (vuln-0018).
    if is_public and app["visibility"] != "public":
        is_public = 0

    cursor = await db.execute(
        """INSERT INTO scans (app_id, scanner_name, scanner_version, scan_date, is_public, notes, cost, tokens, duration, submitted_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (app_id, scanner_name, scanner_version, scan_date, is_public, notes, cost, tokens, duration, user["sub"]),
    )
    scan_id = cursor.lastrowid

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ?", (app_id,)
    )
    known_vulns = await cursor.fetchall()

    for f in findings_data:
        matched_vuln_id, is_false_positive = match_finding_algo(f, known_vulns)
        await db.execute(
            """INSERT INTO scan_findings
               (scan_id, vuln_type, http_method, url, parameter, filename,
                matched_vuln_id, is_false_positive,
                title, severity, description, poc, remediation, code_location)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.get("vuln_type", ""),
                f.get("http_method", ""),
                f.get("url", ""),
                f.get("parameter", ""),
                f.get("filename", ""),
                matched_vuln_id,
                is_false_positive,
                f.get("title"),
                f.get("severity"),
                f.get("description"),
                f.get("poc"),
                f.get("remediation"),
                f.get("code_location"),
            ),
        )

    # Apply labels. Non-admin callers can only attach labels that already
    # exist — creating a brand-new global label is an admin-only operation
    # (vuln-0021). Unknown names are silently skipped so well-behaved CI
    # integrations don't blow up.
    if labels:
        is_admin = user["role"] == "admin"
        for label_name in labels:
            label_name = label_name.strip()
            if not label_name:
                continue
            cursor = await db.execute(
                "SELECT id FROM labels WHERE name = ?", (label_name,)
            )
            label_row = await cursor.fetchone()
            if not label_row:
                if not is_admin:
                    continue
                await db.execute(
                    "INSERT INTO labels (name, color) VALUES (?, ?)",
                    (label_name, "#f97316"),
                )
                cursor = await db.execute(
                    "SELECT id FROM labels WHERE name = ?", (label_name,)
                )
                label_row = await cursor.fetchone()
            await db.execute(
                "INSERT OR IGNORE INTO scan_labels (scan_id, label_id) VALUES (?, ?)",
                (scan_id, label_row["id"]),
            )

    await db.commit()
    return scan_id


async def delete_scan(db, user, scan_id: int) -> None:
    """Delete a scan and its findings, label associations, and state blob."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    state_file = _state_path(scan_id)
    if state_file.exists():
        try:
            state_file.unlink()
        except OSError:
            pass

    await db.execute("DELETE FROM scan_labels WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    await db.commit()


async def update_scan(db, user, scan_id: int, updates: dict) -> dict:
    """Update scan metadata (scanner_name, scan_date, notes, is_public, ...)."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    allowed = {
        "scanner_name", "scanner_version", "scan_date", "notes",
        "cost", "tokens", "duration", "is_public",
    }
    clean = {k: v for k, v in updates.items() if k in allowed and v is not None}

    # is_public must respect the parent app's visibility (vuln-0018).
    if "is_public" in clean:
        new_pub = 1 if clean["is_public"] in (True, 1, "1", "true") else 0
        if new_pub and app["visibility"] != "public":
            raise ValueError("Cannot publish a scan on a non-public app")
        clean["is_public"] = new_pub

    if not clean:
        return dict(scan)

    set_clause = ", ".join(f"{k}=?" for k in clean)
    values = list(clean.values()) + [scan_id]
    await db.execute(f"UPDATE scans SET {set_clause} WHERE id=?", values)
    await db.commit()

    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    return dict(await cursor.fetchone())


async def match_finding(db, user, scan_id: int, finding_id: int, vuln_id) -> dict:
    """Manually match a finding to a vuln (or clear the match).

    The supplied vuln must belong to the same app as the scan — otherwise the
    finding row would reference a vulnerability the caller may not be allowed
    to read, leaking cross-tenant data (vuln-0004).

    Returns {ok, matched_vuln_id, is_false_positive}.
    """
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    cursor = await db.execute(
        "SELECT id FROM scan_findings WHERE id = ? AND scan_id = ?",
        (finding_id, scan_id),
    )
    if not await cursor.fetchone():
        raise ValueError("Finding not found")

    if vuln_id is not None:
        try:
            matched_vuln_id = int(vuln_id)
        except (TypeError, ValueError):
            raise ValueError("vuln_id must be an integer")
        cursor = await db.execute(
            "SELECT app_id FROM vulnerabilities WHERE id = ?", (matched_vuln_id,)
        )
        row = await cursor.fetchone()
        if not row or row["app_id"] != scan["app_id"]:
            raise ValueError("Vulnerability not found")
        is_false_positive = 0
    else:
        matched_vuln_id = None
        is_false_positive = 0

    await db.execute(
        "UPDATE scan_findings SET matched_vuln_id = ?, is_false_positive = ? WHERE id = ? AND scan_id = ?",
        (matched_vuln_id, is_false_positive, finding_id, scan_id),
    )
    await db.commit()

    return {"ok": True, "matched_vuln_id": matched_vuln_id, "is_false_positive": is_false_positive}


async def mark_finding_fp(db, user, scan_id: int, finding_id: int) -> None:
    """Mark a finding as false positive."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    await db.execute(
        "UPDATE scan_findings SET matched_vuln_id = NULL, is_false_positive = 1 WHERE id = ? AND scan_id = ?",
        (finding_id, scan_id),
    )
    await db.commit()


_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


async def _next_disc_slug(db, app_id: int) -> str:
    """Return the next DISC-NNN slug for the app (zero-padded, starts at 001)."""
    cursor = await db.execute(
        "SELECT vuln_id FROM vulnerabilities WHERE app_id = ? AND vuln_id LIKE 'DISC-%'",
        (app_id,),
    )
    max_n = 0
    for row in await cursor.fetchall():
        suffix = row["vuln_id"][5:]
        if suffix.isdigit():
            n = int(suffix)
            if n > max_n:
                max_n = n
    return f"DISC-{max_n + 1:03d}"


async def promote_finding(
    db, user, scan_id: int, finding_id: int, overrides: dict | None = None,
) -> dict:
    """Create a vuln on the scan's app from a pending finding's details, then
    link the finding to the new vuln.

    *overrides* may supply or replace any of: vuln_id, title, severity, vuln_type,
    description, poc, remediation, code_location, http_method, url, parameter,
    filename. Anything missing falls back to the finding's stored values; severity
    defaults to "medium" and vuln_id auto-generates as the next DISC-NNN.

    Requires app-write (creating a vuln is an app-level action).

    Returns {ok, vuln, finding_id}.
    """
    overrides = overrides or {}
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT * FROM scan_findings WHERE id = ? AND scan_id = ?",
        (finding_id, scan_id),
    )
    finding = await cursor.fetchone()
    if not finding:
        raise ValueError("Finding not found")

    def _pick(key: str, default=None):
        if key in overrides and overrides[key] not in (None, ""):
            return overrides[key]
        val = finding[key] if key in finding.keys() else None
        return val if val not in (None, "") else default

    title = _pick("title") or _pick("vuln_type") or "Untitled finding"
    severity = (_pick("severity") or "medium").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"

    vuln_id_slug = overrides.get("vuln_id") or await _next_disc_slug(db, app["id"])

    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, http_method, url,
            parameter, filename, description, code_location, poc, remediation,
            created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            app["id"],
            vuln_id_slug,
            title,
            severity,
            _pick("vuln_type"),
            _pick("http_method"),
            _pick("url"),
            _pick("parameter"),
            _pick("filename"),
            _pick("description"),
            _pick("code_location"),
            _pick("poc"),
            _pick("remediation"),
            user["sub"],
        ),
    )
    new_vuln_id = cursor.lastrowid

    await db.execute(
        "UPDATE scan_findings SET matched_vuln_id = ?, is_false_positive = 0 WHERE id = ?",
        (new_vuln_id, finding_id),
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (new_vuln_id,))
    vuln_row = await cursor.fetchone()

    return {"ok": True, "vuln": dict(vuln_row), "finding_id": finding_id}


async def rematch_scan(db, user, scan_id: int) -> dict:
    """Re-run auto-matching on all findings in a scan. Returns {updated}."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ?", (scan["app_id"],)
    )
    known_vulns = await cursor.fetchall()

    cursor = await db.execute(
        "SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,)
    )
    findings = await cursor.fetchall()

    updated = 0
    for f in findings:
        finding_dict = {
            "vuln_type": f["vuln_type"],
            "http_method": f["http_method"],
            "url": f["url"],
            "parameter": f["parameter"],
            "filename": f["filename"],
        }
        matched_vuln_id, is_false_positive = match_finding_algo(finding_dict, known_vulns)

        if matched_vuln_id != f["matched_vuln_id"] or is_false_positive != f["is_false_positive"]:
            await db.execute(
                "UPDATE scan_findings SET matched_vuln_id = ?, is_false_positive = ? WHERE id = ?",
                (matched_vuln_id, is_false_positive, f["id"]),
            )
            updated += 1

    await db.commit()
    return {"updated": updated}


async def compare_scans(db, user, app_id: int, scan_ids: list[int]) -> dict:
    """Build comparison data for multiple scans on an app.

    Returns {app, available_scans, scanners, matrix, fp_matrix, known_vuln_count, can_edit}.
    """
    from app.visibility import app_visibility_filter
    vis_clause, vis_params = app_visibility_filter(user)
    cursor = await db.execute(
        f"SELECT * FROM apps WHERE id = ? AND {vis_clause}",
        [app_id] + vis_params,
    )
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    # Edit permissions
    can_edit = False
    if user:
        if user["role"] == "admin":
            can_edit = True
        elif app["visibility"] != "public" and app["created_by"] == user["sub"]:
            can_edit = True
        elif app["visibility"] == "team" and app["team_id"]:
            team_role = await get_team_role(db, user["sub"], app["team_id"])
            if team_role in ("admin", "contributor"):
                can_edit = True

    # Available scans for selector
    vis_clause, vis_params = scan_visibility_filter(user)
    cursor = await db.execute(
        f"""SELECT scans.*, users.name as submitter_name
           FROM scans LEFT JOIN apps ON scans.app_id=apps.id
           LEFT JOIN users ON scans.submitted_by=users.id
           WHERE scans.app_id=? AND {vis_clause}
           ORDER BY scans.created_at DESC""",
        [app_id] + vis_params,
    )
    available_scans = await cursor.fetchall()

    # If no scan IDs, return just the selector data
    if not scan_ids:
        return {
            "app": app,
            "available_scans": available_scans,
            "scanners": [],
            "matrix": [],
            "fp_matrix": [],
            "known_vuln_count": 0,
            "can_edit": can_edit,
        }

    # Known vulns
    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, vuln_id",
        (app_id,),
    )
    known_vulns = await cursor.fetchall()

    # Build per-scanner comparison data
    scanners = []
    for sid in scan_ids:
        cursor = await db.execute(
            "SELECT * FROM scans WHERE id = ? AND app_id = ?", (sid, app_id)
        )
        scan = await cursor.fetchone()
        if not scan:
            continue

        cursor = await db.execute(
            "SELECT * FROM scan_findings WHERE scan_id = ?", (sid,)
        )
        findings = await cursor.fetchall()

        cursor = await db.execute(
            """SELECT l.id, l.name, l.color FROM labels l
               JOIN scan_labels sl ON sl.label_id = l.id
               WHERE sl.scan_id = ? ORDER BY l.name""",
            (sid,),
        )
        scan_labels = [dict(row) for row in await cursor.fetchall()]

        matched_ids = {
            f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None
        }
        tp = len(matched_ids)
        fp = sum(1 for f in findings if f["is_false_positive"] == 1)
        pending = sum(
            1 for f in findings
            if f["matched_vuln_id"] is None and f["is_false_positive"] == 0
        )
        fn = sum(1 for v in known_vulns if v["id"] not in matched_ids)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        fp_findings = [dict(f) for f in findings if f["is_false_positive"] == 1]

        # Short date: omit year if current year
        scan_date = scan["scan_date"]
        try:
            dt = datetime.strptime(scan_date, "%Y-%m-%d")
        except (ValueError, TypeError):
            try:
                dt = datetime.strptime(scan_date[:19], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                dt = None
        if dt:
            has_time = dt.hour or dt.minute
            if dt.year == datetime.now().year:
                short_date = dt.strftime("%b %d %H:%M") if has_time else dt.strftime("%b %d")
            else:
                short_date = dt.strftime("%b %d, %Y %H:%M") if has_time else dt.strftime("%b %d, %Y")
        else:
            short_date = scan_date

        scanners.append({
            "scan": scan,
            "short_date": short_date,
            "labels": scan_labels,
            "metrics": {
                "tp": tp, "fp": fp, "pending": pending, "fn": fn,
                "precision": precision, "recall": recall, "f1": f1,
            },
            "matched_vuln_ids": matched_ids,
            "fp_findings": fp_findings,
        })

    # Sort by scan date ascending (oldest first)
    scanners.sort(key=lambda s: (s["scan"]["scan_date"] or "", s["scan"]["id"]))

    # Detection matrix
    matrix = []
    for v in known_vulns:
        row = {
            "vuln": v,
            "detections": [v["id"] in s["matched_vuln_ids"] for s in scanners],
        }
        row["found_by"] = sum(row["detections"])
        matrix.append(row)

    # FP matrix
    fp_keys: dict[tuple, dict] = {}
    for i, s in enumerate(scanners):
        for fp in s["fp_findings"]:
            url_val = (fp.get("url") or "").strip()
            filename_val = (fp.get("filename") or "").strip()
            key = (
                (fp.get("vuln_type") or "").lower(),
                (fp.get("http_method") or "").lower(),
                url_val.lower(),
                (fp.get("parameter") or "").lower(),
                filename_val.lower(),
            )
            if key not in fp_keys:
                location = url_val or filename_val or "-"
                fp_keys[key] = {
                    "vuln_type": fp.get("vuln_type", ""),
                    "http_method": fp.get("http_method", ""),
                    "url": url_val,
                    "parameter": fp.get("parameter", ""),
                    "filename": filename_val,
                    "location": location,
                    "flagged_by": [False] * len(scanners),
                }
            fp_keys[key]["flagged_by"][i] = True

    fp_matrix = list(fp_keys.values())
    for fp in fp_matrix:
        fp["flagged_count"] = sum(fp["flagged_by"])
    fp_matrix.sort(key=lambda x: -x["flagged_count"])

    return {
        "app": app,
        "available_scans": available_scans,
        "scanners": scanners,
        "matrix": matrix,
        "fp_matrix": fp_matrix,
        "known_vuln_count": len(known_vulns),
        "can_edit": can_edit,
    }


async def get_available_scans(db, user, app_id: int) -> list:
    """Get all visible scans for an app (for the scan selector)."""
    from app.visibility import app_visibility_filter
    app_vis, app_params = app_visibility_filter(user)
    cursor = await db.execute(
        f"SELECT id FROM apps WHERE id = ? AND {app_vis}", [app_id] + app_params
    )
    if not await cursor.fetchone():
        raise ValueError("App not found")

    vis_clause, vis_params = scan_visibility_filter(user)
    cursor = await db.execute(
        f"""SELECT scans.*, users.name as submitter_name
           FROM scans LEFT JOIN apps ON scans.app_id=apps.id
           LEFT JOIN users ON scans.submitted_by=users.id
           WHERE scans.app_id=? AND {vis_clause}
           ORDER BY scans.created_at DESC""",
        [app_id] + vis_params,
    )
    return await cursor.fetchall()


# ---------------------------------------------------------------------------
# Scan state (zip blob of the source directory used to produce the scan)
# ---------------------------------------------------------------------------

def _state_path(scan_id: int) -> Path:
    return Path(STATE_DIR) / f"{scan_id}.zip"


async def set_scan_state(db, user, scan_id: int, content: bytes, filename: str) -> dict:
    """Persist a zip of the source-of-truth directory used to produce this
    scan. Overwrites any existing state. Returns the new metadata."""
    if len(content) > MAX_STATE_SIZE:
        raise ValueError(f"State file too large ({len(content)} > {MAX_STATE_SIZE} bytes)")
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256(content).hexdigest()
    path = _state_path(scan_id)
    # Write to a sibling tmp first, then rename — atomic enough for our needs.
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)

    safe_name = (filename or f"scan-{scan_id}.zip").strip() or f"scan-{scan_id}.zip"
    await db.execute(
        "UPDATE scans SET state_filename=?, state_size=?, state_sha256=? WHERE id=?",
        (safe_name, len(content), sha, scan_id),
    )
    await db.commit()
    return {"filename": safe_name, "size": len(content), "sha256": sha}


async def get_scan_state(db, user, scan_id: int) -> tuple[Path, str, int, str]:
    """Return (on-disk path, filename, size, sha256). Raises ValueError if
    no state attached, PermissionError if user cannot view this scan."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_view(db, user, scan, app)
    if not scan["state_filename"]:
        raise ValueError("No state attached to this scan")
    path = _state_path(scan_id)
    if not path.exists():
        raise ValueError("State file is missing on disk")
    return path, scan["state_filename"], scan["state_size"], scan["state_sha256"]


async def delete_scan_state(db, user, scan_id: int) -> None:
    """Remove the state blob (used when deleting a scan or by an explicit
    delete request)."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)
    path = _state_path(scan_id)
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass
    await db.execute(
        "UPDATE scans SET state_filename=NULL, state_size=NULL, state_sha256=NULL WHERE id=?",
        (scan_id,),
    )
    await db.commit()
