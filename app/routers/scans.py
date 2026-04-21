from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, Response, JSONResponse
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_user, require_scan_write, get_team_role
from app.matching import match_finding
from app.visibility import app_visibility_filter, scan_visibility_filter

router = APIRouter(prefix="")


EXAMPLE_JSON = json.dumps({
    "findings": [
        {"vuln_type": "XSS", "http_method": "GET", "url": "/search", "parameter": "q"},
        {"vuln_type": "SQLi", "http_method": "POST", "url": "/login", "parameter": "email"},
        {"vuln_type": "Hardcoded Secret", "filename": "src/config/database.py"},
        {"vuln_type": "SQL Injection", "filename": "src/db/queries.php"}
    ]
}, indent=2)

EXAMPLE_CSV = """vuln_type,http_method,url,parameter,filename
XSS,GET,/search,q,
SQLi,POST,/login,email,
Hardcoded Secret,,,,src/config/database.py
SQL Injection,,,,src/db/queries.php
"""


@router.get("/scans/example/json")
async def example_json():
    return Response(
        content=EXAMPLE_JSON,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=example_findings.json"},
    )


@router.get("/scans/example/csv")
async def example_csv():
    return Response(
        content=EXAMPLE_CSV,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=example_findings.csv"},
    )


@router.get("/scans", response_class=HTMLResponse)
async def list_scans(request: Request, app_id: str = "", filter: str = "",
                     scanner: str = "", latest: str = "", q: str = "",
                     authenticated: str = "", label: str = ""):
    user = request.state.user
    # Convert app_id from string to int (form submits empty string when unselected)
    app_id = int(app_id) if app_id and app_id.isdigit() else None

    db = await get_connection()
    try:
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
            extra_filters += " AND scans.id IN (SELECT scan_id FROM scan_labels JOIN labels ON scan_labels.label_id = labels.id WHERE labels.name = ?)"
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
        scan_labels_map = {}
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

        # Get all label names for filter dropdown
        cursor = await db.execute("SELECT DISTINCT name FROM labels ORDER BY name")
        all_labels = [row["name"] for row in await cursor.fetchall()]

        # Get distinct scanner names for filter dropdown (scoped to app if filtered)
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

        # Get distinct apps for filter dropdown
        cursor = await db.execute(
            f"""SELECT DISTINCT apps.id, apps.name, apps.version
               FROM scans JOIN apps ON scans.app_id=apps.id
               WHERE apps.name IS NOT NULL AND {vis_clause}
               ORDER BY apps.name, apps.version""",
            vis_params,
        )
        apps_list = await cursor.fetchall()

        # Get user's teams for filter dropdown
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
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "scans/list.html", {
            "user": request.state.user,
            "scans": scans,
            "app": app,
            "filter": filter,
            "user_teams": user_teams,
            "scanners": scanners,
            "apps_list": apps_list,
            "latest": latest,
            "scanner": scanner,
            "q": q,
            "app_id": app_id,
            "authenticated": authenticated,
            "label": label,
            "all_labels": all_labels,
            "scan_labels_map": scan_labels_map,
        }
    )


@router.get("/apps/{app_id}/scans", response_class=HTMLResponse)
async def submit_scan_form(request: Request, app_id: int):
    user = await require_user(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

        # Check scan submission permission
        if user["role"] != "admin":
            if app["visibility"] == "public":
                raise HTTPException(status_code=403, detail="Clone this app to submit scans. Only admins can submit scans on public apps.")
            elif app["visibility"] == "private" and app["created_by"] != user["sub"]:
                raise HTTPException(status_code=403, detail="Only the app creator can submit scans on private apps")
            elif app["visibility"] == "team" and app["team_id"]:
                team_role = await get_team_role(db, user["sub"], app["team_id"])
                if team_role not in ("admin", "contributor"):
                    raise HTTPException(status_code=403, detail="Team contributor access required to submit scans")
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "scans/submit.html", {"user": user, "app": app}
    )


@router.post("/apps/{app_id}/scans")
async def submit_scan(request: Request, app_id: int):
    user = await require_user(request)
    form = await request.form()

    scanner_name = form.get("scanner_name")
    scan_date = form.get("scan_date")
    authenticated = 1 if form.get("authenticated") else 0
    is_public = 1 if form.get("is_public") else 0
    notes = form.get("notes")
    cost_raw = (form.get("cost") or "").strip()
    try:
        cost = float(cost_raw) if cost_raw else None
    except ValueError:
        cost = None

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

        # Check scan submission permission
        if user["role"] != "admin":
            if app["visibility"] == "public":
                raise HTTPException(status_code=403, detail="Only admins can submit scans on public apps")
            elif app["visibility"] == "private" and app["created_by"] != user["sub"]:
                raise HTTPException(status_code=403, detail="Only the app creator can submit scans on private apps")
            elif app["visibility"] == "team" and app["team_id"]:
                team_role = await get_team_role(db, user["sub"], app["team_id"])
                if team_role not in ("admin", "contributor"):
                    raise HTTPException(status_code=403, detail="Team contributor access required")

        # Try file upload first
        findings_data = []
        scan_file = form.get("scan_file")
        if scan_file and hasattr(scan_file, "read") and scan_file.filename:
            content = (await scan_file.read()).decode("utf-8")
            filename_lower = scan_file.filename.lower()

            if filename_lower.endswith(".json"):
                parsed = json.loads(content)
                for f in parsed.get("findings", []):
                    if f.get("vuln_type"):
                        findings_data.append({
                            "vuln_type": f.get("vuln_type", ""),
                            "http_method": f.get("http_method", ""),
                            "url": f.get("url", ""),
                            "parameter": f.get("parameter", ""),
                            "filename": f.get("filename", ""),
                        })
            elif filename_lower.endswith(".csv"):
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    if row.get("vuln_type"):
                        findings_data.append({
                            "vuln_type": row.get("vuln_type", ""),
                            "http_method": row.get("http_method", ""),
                            "url": row.get("url", ""),
                            "parameter": row.get("parameter", ""),
                            "filename": row.get("filename", ""),
                        })

        # Fall back to manual form findings if no file
        if not findings_data:
            i = 0
            while True:
                vt = form.get(f"findings[{i}][vuln_type]")
                if vt is None:
                    break
                findings_data.append({
                    "vuln_type": vt,
                    "url": form.get(f"findings[{i}][url]", ""),
                    "http_method": form.get(f"findings[{i}][http_method]", ""),
                    "parameter": form.get(f"findings[{i}][parameter]", ""),
                    "filename": form.get(f"findings[{i}][filename]", ""),
                })
                i += 1

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
            matched_vuln_id, is_false_positive = match_finding(f, known_vulns)

            await db.execute(
                """INSERT INTO scan_findings (scan_id, vuln_type, http_method, url, parameter, filename, matched_vuln_id, is_false_positive)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, f["vuln_type"], f.get("http_method", ""), f.get("url", ""),
                 f.get("parameter", ""), f.get("filename", ""), matched_vuln_id, is_false_positive),
            )

        # Process labels (comma-separated)
        labels_str = form.get("labels", "")
        if labels_str:
            for label_name in [l.strip() for l in labels_str.split(",") if l.strip()]:
                await db.execute(
                    "INSERT OR IGNORE INTO labels (name, color) VALUES (?, ?)",
                    (label_name, "#f97316"),
                )
                cursor = await db.execute("SELECT id FROM labels WHERE name = ?", (label_name,))
                label_row = await cursor.fetchone()
                await db.execute(
                    "INSERT OR IGNORE INTO scan_labels (scan_id, label_id) VALUES (?, ?)",
                    (scan_id, label_row["id"]),
                )

        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@router.post("/scans/{scan_id}/delete")
async def delete_scan(request: Request, scan_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        await require_scan_write(request, db, scan, app)

        await db.execute("DELETE FROM scan_labels WHERE scan_id = ?", (scan_id,))
        await db.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
        await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url="/scans", status_code=303)


@router.get("/apps/{app_id}/compare", response_class=HTMLResponse)
async def compare_scans(request: Request, app_id: int, scans: str = ""):
    user = request.state.user

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()

        # Determine edit permissions for the app
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

        # Get all visible scans for this app
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

        # If no scan IDs provided, show selector
        if not scans:
            return templates.TemplateResponse(
                request, "scans/compare.html",
                {
                    "user": user,
                    "app": app,
                    "available_scans": available_scans,
                    "comparison": None,
                    "can_edit": can_edit,
                },
            )

        # Parse selected scan IDs (max 7)
        scan_ids = [int(s) for s in scans.split(",") if s.strip().isdigit()][:7]
        if not scan_ids:
            return templates.TemplateResponse(
                request, "scans/compare.html",
                {
                    "user": user,
                    "app": app,
                    "available_scans": available_scans,
                    "comparison": None,
                    "error": "No valid scans selected.",
                    "can_edit": can_edit,
                },
            )

        # Get known vulns for this app
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, vuln_id",
            (app_id,),
        )
        known_vulns = await cursor.fetchall()

        # Build comparison data for each selected scan
        scanners = []
        for sid in scan_ids:
            cursor = await db.execute("SELECT * FROM scans WHERE id = ? AND app_id = ?", (sid, app_id))
            scan = await cursor.fetchone()
            if not scan:
                continue

            cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (sid,))
            findings = await cursor.fetchall()

            cursor = await db.execute(
                """SELECT l.id, l.name, l.color FROM labels l
                   JOIN scan_labels sl ON sl.label_id = l.id
                   WHERE sl.scan_id = ? ORDER BY l.name""",
                (sid,),
            )
            scan_labels = [dict(row) for row in await cursor.fetchall()]

            matched_ids = {f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None}
            tp = len(matched_ids)
            fp = sum(1 for f in findings if f["is_false_positive"] == 1)
            pending = sum(1 for f in findings if f["matched_vuln_id"] is None and f["is_false_positive"] == 0)
            fn = sum(1 for v in known_vulns if v["id"] not in matched_ids)

            # Pending findings excluded from precision/recall
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

            # Only explicitly marked FP findings go into the FP matrix
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
                "metrics": {"tp": tp, "fp": fp, "pending": pending, "fn": fn, "precision": precision, "recall": recall, "f1": f1},
                "matched_vuln_ids": matched_ids,
                "fp_findings": fp_findings,
            })

        # Order scanners by scan date ascending (oldest first) so the matrix
        # columns read as a timeline. Fall back to scan id for stable sort.
        scanners.sort(key=lambda s: (s["scan"]["scan_date"] or "", s["scan"]["id"]))

        # Build detection matrix: for each vuln, which scanners found it
        matrix = []
        for v in known_vulns:
            row = {
                "vuln": v,
                "detections": [v["id"] in s["matched_vuln_ids"] for s in scanners],
            }
            row["found_by"] = sum(row["detections"])
            matrix.append(row)

        # Build FP matrix: unique FPs across all scanners
        fp_keys = {}  # key -> {vuln_type, http_method, url, parameter, filename, location, flagged_by: [bool]}
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

    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "scans/compare.html",
        {
            "user": user,
            "app": app,
            "available_scans": available_scans,
            "comparison": {
                "scanners": scanners,
                "matrix": matrix,
                "fp_matrix": fp_matrix,
                "known_vuln_count": len(known_vulns),
            },
            "selected_ids": scan_ids,
            "can_edit": can_edit,
        },
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int):
    user = request.state.user

    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT scans.*, users.name as submitter_name FROM scans LEFT JOIN users ON scans.submitted_by=users.id WHERE scans.id = ?",
            (scan_id,),
        )
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        # Visibility check: public scans on public apps for anonymous,
        # otherwise check scan visibility
        if not user:
            if not (scan["is_public"] and app["visibility"] == "public"):
                raise HTTPException(status_code=401, detail="Not authenticated")
        elif user["role"] != "admin":
            can_see = (
                scan["is_public"]
                or scan["submitted_by"] == user["sub"]
                or (app["visibility"] == "team" and app["team_id"] and
                    await get_team_role(db, user["sub"], app["team_id"]) is not None)
            )
            if not can_see:
                raise HTTPException(status_code=403, detail="Access denied")

        cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,))
        findings = await cursor.fetchall()

        # Get all known vulns for this app (for matching dropdown + metrics)
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY vuln_id", (scan["app_id"],)
        )
        all_vulns = await cursor.fetchall()

        # Compute metrics
        matched_vuln_ids = {f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None}
        tp = len(matched_vuln_ids)
        fp = sum(1 for f in findings if f["is_false_positive"] == 1)
        pending = sum(1 for f in findings if f["matched_vuln_id"] is None and f["is_false_positive"] == 0)

        missed_vulns = [v for v in all_vulns if v["id"] not in matched_vuln_ids]
        fn = len(missed_vulns)

        # Count findings per matched vuln for duplicate indicator
        vuln_finding_counts = Counter(f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None)

        # Build list of finding descriptions per matched vuln (for tooltips)
        vuln_finding_details: dict[int, list[str]] = {}
        for f in findings:
            vid = f["matched_vuln_id"]
            if vid is not None:
                label = f["vuln_type"] or ""
                loc = f["url"] or f["filename"] or ""
                if loc:
                    label = f"{label}: {loc}"
                vuln_finding_details.setdefault(vid, []).append(label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metrics = {
            "tp": tp,
            "fp": fp,
            "pending": pending,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

        # Determine scan edit permissions
        can_edit_scan = False
        can_view_cost = False
        if user:
            if user["role"] == "admin":
                can_edit_scan = True
                can_view_cost = True
            elif scan["submitted_by"] == user["sub"]:
                can_edit_scan = True
                can_view_cost = True
            elif app["visibility"] == "team" and app["team_id"]:
                team_role = await get_team_role(db, user["sub"], app["team_id"])
                if team_role in ("admin", "contributor"):
                    can_edit_scan = True
                if team_role is not None:
                    can_view_cost = True

        # Fetch labels for this scan
        cursor = await db.execute(
            """SELECT l.id, l.name, l.color FROM labels l
               JOIN scan_labels sl ON sl.label_id = l.id
               WHERE sl.scan_id = ? ORDER BY l.name""",
            (scan_id,),
        )
        scan_label_list = [dict(row) for row in await cursor.fetchall()]

        # All labels for autocomplete
        cursor = await db.execute("SELECT id, name, color FROM labels ORDER BY name")
        all_labels = [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "scans/detail.html",
        {
            "user": user,
            "scan": scan,
            "app": app,
            "metrics": metrics,
            "findings": findings,
            "missed_vulns": missed_vulns,
            "known_vulns": all_vulns,
            "vuln_finding_counts": dict(vuln_finding_counts),
            "vuln_finding_details": vuln_finding_details,
            "can_edit_scan": can_edit_scan,
            "can_view_cost": can_view_cost,
            "scan_labels": scan_label_list,
            "all_labels_json": json.dumps(all_labels),
        },
    )


@router.post("/scans/{scan_id}/findings/{finding_id}/match")
async def match_finding_to_vuln(request: Request, scan_id: int, finding_id: int):
    body = await request.json()
    vuln_id = body.get("vuln_id")  # None or int

    if vuln_id is not None:
        matched_vuln_id = int(vuln_id)
        is_false_positive = 0
    else:
        matched_vuln_id = None
        is_false_positive = 0

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        await require_scan_write(request, db, scan, app)

        await db.execute(
            "UPDATE scan_findings SET matched_vuln_id = ?, is_false_positive = ? WHERE id = ? AND scan_id = ?",
            (matched_vuln_id, is_false_positive, finding_id, scan_id),
        )
        await db.commit()
    finally:
        await db.close()

    return {"ok": True, "matched_vuln_id": matched_vuln_id, "is_false_positive": is_false_positive}


@router.post("/scans/{scan_id}/rematch")
async def rematch_scan(request: Request, scan_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        await require_scan_write(request, db, scan, app)

        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ?", (scan["app_id"],)
        )
        known_vulns = await cursor.fetchall()

        cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,))
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
            matched_vuln_id, is_false_positive = match_finding(finding_dict, known_vulns)

            if matched_vuln_id != f["matched_vuln_id"] or is_false_positive != f["is_false_positive"]:
                await db.execute(
                    "UPDATE scan_findings SET matched_vuln_id = ?, is_false_positive = ? WHERE id = ?",
                    (matched_vuln_id, is_false_positive, f["id"]),
                )
                updated += 1

        await db.commit()
    finally:
        await db.close()

    return {"ok": True, "updated": updated}


@router.post("/scans/{scan_id}/findings/{finding_id}/mark-fp")
async def mark_finding_fp(request: Request, scan_id: int, finding_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        await require_scan_write(request, db, scan, app)

        await db.execute(
            "UPDATE scan_findings SET matched_vuln_id = NULL, is_false_positive = 1 WHERE id = ? AND scan_id = ?",
            (finding_id, scan_id),
        )
        await db.commit()
    finally:
        await db.close()

    return {"ok": True}


# ── Label management ─────────────────────────────────────────


@router.get("/labels/autocomplete")
async def labels_autocomplete():
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT id, name, color FROM labels ORDER BY name")
        labels = [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()
    return {"labels": labels}


@router.post("/scans/{scan_id}/labels")
async def add_label_to_scan(request: Request, scan_id: int):
    body = await request.json()
    name = (body.get("name") or "").strip()
    color = body.get("color", "#f97316").strip()
    if not name:
        return JSONResponse({"detail": "Label name required"}, status_code=400)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()
        await require_scan_write(request, db, scan, app)

        # Upsert label
        await db.execute(
            "INSERT OR IGNORE INTO labels (name, color) VALUES (?, ?)",
            (name, color),
        )
        cursor = await db.execute("SELECT id, name, color FROM labels WHERE name = ?", (name,))
        label = dict(await cursor.fetchone())

        # Link to scan
        await db.execute(
            "INSERT OR IGNORE INTO scan_labels (scan_id, label_id) VALUES (?, ?)",
            (scan_id, label["id"]),
        )
        await db.commit()
    finally:
        await db.close()

    return {"ok": True, "label": label}


@router.delete("/scans/{scan_id}/labels/{label_id}")
async def remove_label_from_scan(request: Request, scan_id: int, label_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()
        await require_scan_write(request, db, scan, app)

        await db.execute(
            "DELETE FROM scan_labels WHERE scan_id = ? AND label_id = ?",
            (scan_id, label_id),
        )
        await db.commit()
    finally:
        await db.close()

    return {"ok": True}
