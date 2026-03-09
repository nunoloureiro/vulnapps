from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_user

router = APIRouter(prefix="")


@router.get("/scans", response_class=HTMLResponse)
async def list_scans(request: Request):
    user = request.state.user

    db = await get_connection()
    try:
        if user:
            cursor = await db.execute(
                """SELECT scans.*, apps.name as app_name,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count
                   FROM scans
                   LEFT JOIN apps ON scans.app_id=apps.id
                   WHERE scans.is_public=1 OR scans.submitted_by=?
                   ORDER BY scans.created_at DESC""",
                (user["sub"],),
            )
        else:
            cursor = await db.execute(
                """SELECT scans.*, apps.name as app_name,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count
                   FROM scans
                   LEFT JOIN apps ON scans.app_id=apps.id
                   WHERE scans.is_public=1
                   ORDER BY scans.created_at DESC"""
            )
        scans = await cursor.fetchall()
    finally:
        await db.close()

    return templates.TemplateResponse(
        "scans/list.html", {"request": request, "user": request.state.user, "scans": scans}
    )


@router.get("/apps/{app_id}/scans", response_class=HTMLResponse)
async def submit_scan_form(request: Request, app_id: int):
    await require_user(request)

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
    user = await require_user(request)
    form = await request.form()

    scanner_name = form.get("scanner_name")
    scan_date = form.get("scan_date")
    authenticated = 1 if form.get("authenticated") else 0
    is_public = 1 if form.get("is_public") else 0
    notes = form.get("notes")

    # Parse findings from form: findings[0][vuln_type], findings[0][url], etc.
    findings_data = []
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
            f_vuln_type = f["vuln_type"]
            f_url = f["url"]
            f_http_method = f["http_method"]
            f_parameter = f["parameter"]

            matched_vuln_id = None
            is_false_positive = 1

            for v in known_vulns:
                if (
                    (v["vuln_type"] or "").lower() == (f_vuln_type or "").lower()
                    and (v["http_method"] or "").lower() == (f_http_method or "").lower()
                    and (v["url"] or "").lower() == (f_url or "").lower()
                    and (v["parameter"] or "").lower() == (f_parameter or "").lower()
                ):
                    matched_vuln_id = v["id"]
                    is_false_positive = 0
                    break

            await db.execute(
                """INSERT INTO scan_findings (scan_id, vuln_type, http_method, url, parameter, matched_vuln_id, is_false_positive)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, f_vuln_type, f_http_method, f_url, f_parameter, matched_vuln_id, is_false_positive),
            )

        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


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
                """SELECT scans.*, users.username as submitter_name
                   FROM scans LEFT JOIN users ON scans.submitted_by=users.id
                   WHERE scans.app_id=? AND (scans.is_public=1 OR scans.submitted_by=?)
                   ORDER BY scans.created_at DESC""",
                (app_id, user["sub"]),
            )
        else:
            cursor = await db.execute(
                """SELECT scans.*, users.username as submitter_name
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

            tp = sum(1 for f in findings if f["matched_vuln_id"] is not None)
            fp = sum(1 for f in findings if f["is_false_positive"] == 1)
            matched_ids = {f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None}
            fn = sum(1 for v in known_vulns if v["id"] not in matched_ids)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

            fp_findings = [dict(f) for f in findings if f["is_false_positive"] == 1]

            scanners.append({
                "scan": scan,
                "metrics": {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1},
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
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,))
        findings = await cursor.fetchall()

        # Compute metrics
        tp = sum(1 for f in findings if f["matched_vuln_id"] is not None)
        fp = sum(1 for f in findings if f["is_false_positive"] == 1)

        # Find missed vulns (FN): known vulns with no matching finding in this scan
        matched_vuln_ids = {f["matched_vuln_id"] for f in findings if f["matched_vuln_id"] is not None}
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ?", (scan["app_id"],)
        )
        all_vulns = await cursor.fetchall()
        missed_vulns = [v for v in all_vulns if v["id"] not in matched_vuln_ids]
        fn = len(missed_vulns)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metrics = {
            "tp": tp,
            "fp": fp,
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
        },
    )
