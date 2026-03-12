import csv
import io
import json
from collections import Counter
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_user, require_active_user
from app.matching import match_finding

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
async def list_scans(request: Request, app_id: int = None):
    user = request.state.user

    db = await get_connection()
    try:
        app_filter = ""
        params = []
        app = None

        if app_id:
            app_filter = "AND scans.app_id = ?"
            params.append(app_id)
            cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
            app = await cursor.fetchone()

        if user:
            cursor = await db.execute(
                f"""SELECT scans.*, apps.name as app_name, users.name as submitter_name,
                          (SELECT COUNT(DISTINCT matched_vuln_id) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count
                   FROM scans
                   LEFT JOIN apps ON scans.app_id=apps.id
                   LEFT JOIN users ON scans.submitted_by=users.id
                   WHERE (scans.is_public=1 OR scans.submitted_by=?) {app_filter}
                   ORDER BY scans.created_at DESC""",
                [user["sub"]] + params,
            )
        else:
            cursor = await db.execute(
                f"""SELECT scans.*, apps.name as app_name, users.name as submitter_name,
                          (SELECT COUNT(DISTINCT matched_vuln_id) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count
                   FROM scans
                   LEFT JOIN apps ON scans.app_id=apps.id
                   LEFT JOIN users ON scans.submitted_by=users.id
                   WHERE scans.is_public=1 {app_filter}
                   ORDER BY scans.created_at DESC""",
                params,
            )
        scans = await cursor.fetchall()
    finally:
        await db.close()

    return templates.TemplateResponse(
        "scans/list.html", {"request": request, "user": request.state.user, "scans": scans, "app": app}
    )


@router.get("/apps/{app_id}/scans", response_class=HTMLResponse)
async def submit_scan_form(request: Request, app_id: int):
    await require_active_user(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
    finally:
        await db.close()

    return templates.TemplateResponse(
        "scans/submit.html", {"request": request, "user": request.state.user, "app": app}
    )


@router.post("/apps/{app_id}/scans")
async def submit_scan(request: Request, app_id: int):
    user = await require_active_user(request)
    form = await request.form()

    scanner_name = form.get("scanner_name")
    scan_date = form.get("scan_date")
    authenticated = 1 if form.get("authenticated") else 0
    is_public = 1 if form.get("is_public") else 0
    notes = form.get("notes")

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

    db = await get_connection()
    try:
        cursor = await db.execute(
            """INSERT INTO scans (app_id, scanner_name, scan_date, authenticated, is_public, notes, submitted_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (app_id, scanner_name, scan_date, authenticated, is_public, notes, user["sub"]),
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

        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@router.post("/scans/{scan_id}/delete")
async def delete_scan(request: Request, scan_id: int):
    await require_active_user(request)

    db = await get_connection()
    try:
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

        # Get all visible scans for this app
        if user:
            cursor = await db.execute(
                """SELECT scans.*, users.name as submitter_name
                   FROM scans LEFT JOIN users ON scans.submitted_by=users.id
                   WHERE scans.app_id=? AND (scans.is_public=1 OR scans.submitted_by=?)
                   ORDER BY scans.created_at DESC""",
                (app_id, user["sub"]),
            )
        else:
            cursor = await db.execute(
                """SELECT scans.*, users.name as submitter_name
                   FROM scans LEFT JOIN users ON scans.submitted_by=users.id
                   WHERE scans.app_id=? AND scans.is_public=1
                   ORDER BY scans.created_at DESC""",
                (app_id,),
            )
        available_scans = await cursor.fetchall()

        # If no scan IDs provided, show selector
        if not scans:
            return templates.TemplateResponse(
                "scans/compare.html",
                {
                    "request": request,
                    "user": user,
                    "app": app,
                    "available_scans": available_scans,
                    "comparison": None,
                },
            )

        # Parse selected scan IDs (max 7)
        scan_ids = [int(s) for s in scans.split(",") if s.strip().isdigit()][:7]
        if not scan_ids:
            return templates.TemplateResponse(
                "scans/compare.html",
                {
                    "request": request,
                    "user": user,
                    "app": app,
                    "available_scans": available_scans,
                    "comparison": None,
                    "error": "No valid scans selected.",
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
                "metrics": {"tp": tp, "fp": fp, "pending": pending, "fn": fn, "precision": precision, "recall": recall, "f1": f1},
                "matched_vuln_ids": matched_ids,
                "fp_findings": fp_findings,
            })

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
        "scans/compare.html",
        {
            "request": request,
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
        },
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int):
    await require_user(request)

    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT scans.*, users.name as submitter_name FROM scans LEFT JOIN users ON scans.submitted_by=users.id WHERE scans.id = ?",
            (scan_id,),
        )
        scan = await cursor.fetchone()

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,))
        findings = await cursor.fetchall()

        # Get all known vulns for this app (for matching dropdown + metrics)
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY vuln_id", (scan["app_id"],)
        )
        all_vulns = await cursor.fetchall()

        # Compute metrics (pending findings excluded from precision/recall)
        # TP counts unique matched vulns, not finding count
        matched_vuln_ids = {f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None}
        tp = len(matched_vuln_ids)
        fp = sum(1 for f in findings if f["is_false_positive"] == 1)
        pending = sum(1 for f in findings if f["matched_vuln_id"] is None and f["is_false_positive"] == 0)

        missed_vulns = [v for v in all_vulns if v["id"] not in matched_vuln_ids]
        fn = len(missed_vulns)

        # Count findings per matched vuln for duplicate indicator
        vuln_finding_counts = Counter(f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None)

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
    finally:
        await db.close()

    return templates.TemplateResponse(
        "scans/detail.html",
        {
            "request": request,
            "user": request.state.user,
            "scan": scan,
            "app": app,
            "metrics": metrics,
            "findings": findings,
            "missed_vulns": missed_vulns,
            "known_vulns": all_vulns,
            "vuln_finding_counts": dict(vuln_finding_counts),
        },
    )


@router.post("/scans/{scan_id}/findings/{finding_id}/match")
async def match_finding_to_vuln(request: Request, scan_id: int, finding_id: int):
    await require_active_user(request)
    body = await request.json()
    vuln_id = body.get("vuln_id")  # None or int

    if vuln_id is not None:
        matched_vuln_id = int(vuln_id)
        is_false_positive = 0
    else:
        # Unmapping sets to pending (not FP) — user must explicitly mark FP
        matched_vuln_id = None
        is_false_positive = 0

    db = await get_connection()
    try:
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
    await require_active_user(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()

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
    await require_active_user(request)

    db = await get_connection()
    try:
        await db.execute(
            "UPDATE scan_findings SET matched_vuln_id = NULL, is_false_positive = 1 WHERE id = ? AND scan_id = ?",
            (finding_id, scan_id),
        )
        await db.commit()
    finally:
        await db.close()

    return {"ok": True}
