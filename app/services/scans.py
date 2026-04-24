from __future__ import annotations

from collections import Counter
from datetime import datetime

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
    authenticated="", label="", filter="",
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

    if authenticated == "1":
        extra_filters += " AND scans.authenticated = 1"
    elif authenticated == "0":
        extra_filters += " AND scans.authenticated = 0"

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

    base_query = f"""SELECT scans.*, apps.name as app_name, apps.version as app_version,
                  users.name as submitter_name,
                  (SELECT COUNT(DISTINCT matched_vuln_id) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                  (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count
           FROM scans
           LEFT JOIN apps ON scans.app_id=apps.id
           LEFT JOIN users ON scans.submitted_by=users.id
           WHERE {vis_clause}{extra_filters}"""

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

    cursor = await db.execute(sql, vis_params + extra_params)
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

    # Visibility check
    if not user:
        if not (scan["is_public"] and app["visibility"] == "public"):
            raise PermissionError("Not authenticated")
    elif user["role"] != "admin":
        can_see = (
            scan["is_public"]
            or scan["submitted_by"] == user["sub"]
            or (app["visibility"] == "team" and app["team_id"]
                and await get_team_role(db, user["sub"], app["team_id"]) is not None)
        )
        if not can_see:
            raise PermissionError("Access denied")

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

    return {
        "scan": scan,
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
    authenticated: int,
    is_public: int,
    notes: str | None,
    cost: float | None,
    findings_data: list[dict],
    labels: list[str] | None = None,
) -> int:
    """Create a scan, auto-match findings, apply labels. Returns scan_id."""
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    await _check_scan_submit(db, user, app)

    cursor = await db.execute(
        """INSERT INTO scans (app_id, scanner_name, scan_date, authenticated, is_public, notes, cost, submitted_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (app_id, scanner_name, scan_date, authenticated, is_public, notes, cost, user["sub"]),
    )
    scan_id = cursor.lastrowid

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ?", (app_id,)
    )
    known_vulns = await cursor.fetchall()

    for f in findings_data:
        matched_vuln_id, is_false_positive = match_finding_algo(f, known_vulns)
        await db.execute(
            """INSERT INTO scan_findings (scan_id, vuln_type, http_method, url, parameter, filename, matched_vuln_id, is_false_positive)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.get("vuln_type", ""),
                f.get("http_method", ""),
                f.get("url", ""),
                f.get("parameter", ""),
                f.get("filename", ""),
                matched_vuln_id,
                is_false_positive,
            ),
        )

    # Apply labels
    if labels:
        for label_name in labels:
            label_name = label_name.strip()
            if not label_name:
                continue
            await db.execute(
                "INSERT OR IGNORE INTO labels (name, color) VALUES (?, ?)",
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
    """Delete a scan and its findings and label associations."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    await db.execute("DELETE FROM scan_labels WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    await db.commit()


async def match_finding(db, user, scan_id: int, finding_id: int, vuln_id) -> dict:
    """Manually match a finding to a vuln (or clear the match).

    Returns {ok, matched_vuln_id, is_false_positive}.
    """
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    if vuln_id is not None:
        matched_vuln_id = int(vuln_id)
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
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
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
            if dt.year == datetime.now().year:
                short_date = dt.strftime("%b %d")
            else:
                short_date = dt.strftime("%b %d, %Y")
        except (ValueError, TypeError):
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
