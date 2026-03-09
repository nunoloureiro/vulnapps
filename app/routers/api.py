from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.dependencies import require_user, require_contributor

router = APIRouter(prefix="/api/v1")


@router.get("/apps")
async def list_apps(request: Request):
    db = await get_connection()
    try:
        cursor = await db.execute(
            """SELECT apps.*, users.username as creator_name,
                      (SELECT COUNT(*) FROM vulnerabilities WHERE app_id=apps.id) as vuln_count
               FROM apps LEFT JOIN users ON apps.created_by=users.id
               ORDER BY apps.created_at DESC"""
        )
        apps = [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()

    return {"apps": apps}


@router.get("/apps/{app_id}")
async def app_detail(request: Request, app_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute(
            """SELECT apps.*, users.username as creator_name
               FROM apps LEFT JOIN users ON apps.created_by=users.id
               WHERE apps.id = ?""",
            (app_id,),
        )
        app = await cursor.fetchone()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title",
            (app_id,),
        )
        vulns = [dict(row) for row in await cursor.fetchall()]

        cursor = await db.execute(
            "SELECT name FROM app_technologies WHERE app_id = ? ORDER BY name", (app_id,)
        )
        tech_stack = [row["name"] for row in await cursor.fetchall()]
    finally:
        await db.close()

    result = dict(app)
    result["tech_stack"] = tech_stack
    return {"app": result, "vulnerabilities": vulns}


@router.get("/apps/{app_id}/vulns")
async def list_vulns(request: Request, app_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title",
            (app_id,),
        )
        vulns = [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()

    return {"vulnerabilities": vulns}


@router.post("/apps")
async def create_app(request: Request):
    user = await require_contributor(request)
    body = await request.json()

    db = await get_connection()
    try:
        cursor = await db.execute(
            "INSERT INTO apps (name, version, description, url, created_by) VALUES (?, ?, ?, ?, ?)",
            (
                body["name"],
                body["version"],
                body.get("description"),
                body.get("url"),
                user["sub"],
            ),
        )
        app_id = cursor.lastrowid

        for tech in body.get("tech_stack", []):
            await db.execute(
                "INSERT OR IGNORE INTO app_technologies (app_id, name) VALUES (?, ?)",
                (app_id, tech.strip()),
            )
        await db.commit()

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
        cursor = await db.execute(
            "SELECT name FROM app_technologies WHERE app_id = ? ORDER BY name", (app_id,)
        )
        tech_stack = [row["name"] for row in await cursor.fetchall()]
    finally:
        await db.close()

    result = dict(app)
    result["tech_stack"] = tech_stack
    return {"app": result}


@router.post("/apps/{app_id}/vulns")
async def create_vuln(request: Request, app_id: int):
    user = await require_contributor(request)
    body = await request.json()

    db = await get_connection()
    try:
        cursor = await db.execute(
            """INSERT INTO vulnerabilities
               (app_id, vuln_id, title, severity, vuln_type, http_method, url, parameter,
                description, code_location, poc, remediation, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                app_id,
                body["vuln_id"],
                body["title"],
                body["severity"],
                body.get("vuln_type"),
                body.get("http_method"),
                body.get("url"),
                body.get("parameter"),
                body.get("description"),
                body.get("code_location"),
                body.get("poc"),
                body.get("remediation"),
                user["sub"],
            ),
        )
        await db.commit()
        vuln_id = cursor.lastrowid

        cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
        vuln = await cursor.fetchone()
    finally:
        await db.close()

    return {"vulnerability": dict(vuln)}


@router.get("/scans")
async def list_scans(request: Request):
    user = request.state.user

    db = await get_connection()
    try:
        if user:
            cursor = await db.execute(
                """SELECT scans.*, apps.name as app_name,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count
                   FROM scans LEFT JOIN apps ON scans.app_id=apps.id
                   WHERE scans.is_public=1 OR scans.submitted_by=?
                   ORDER BY scans.created_at DESC""",
                (user["sub"],),
            )
        else:
            cursor = await db.execute(
                """SELECT scans.*, apps.name as app_name,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND matched_vuln_id IS NOT NULL) as tp_count,
                          (SELECT COUNT(*) FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1) as fp_count
                   FROM scans LEFT JOIN apps ON scans.app_id=apps.id
                   WHERE scans.is_public=1
                   ORDER BY scans.created_at DESC"""
            )
        scans = [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()

    return {"scans": scans}


@router.get("/scans/{scan_id}")
async def scan_detail(request: Request, scan_id: int):
    await require_user(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
        app = await cursor.fetchone()

        cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,))
        findings = await cursor.fetchall()

        tp = sum(1 for f in findings if f["matched_vuln_id"] is not None)
        fp = sum(1 for f in findings if f["is_false_positive"] == 1)

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

    return {
        "scan": dict(scan),
        "app": dict(app),
        "metrics": metrics,
        "findings": [dict(f) for f in findings],
        "missed_vulns": [dict(v) for v in missed_vulns],
    }


@router.post("/apps/{app_id}/scans")
async def submit_scan(request: Request, app_id: int):
    user = await require_user(request)
    body = await request.json()

    scanner_name = body["scanner_name"]
    scan_date = body["scan_date"]
    authenticated = 1 if body.get("authenticated") else 0
    is_public = 1 if body.get("is_public", True) else 0
    notes = body.get("notes")
    findings_data = body.get("findings", [])

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
            f_vuln_type = f.get("vuln_type", "")
            f_url = f.get("url", "")
            f_http_method = f.get("http_method", "")
            f_parameter = f.get("parameter", "")

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

        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
    finally:
        await db.close()

    return {"scan": dict(scan), "scan_id": scan_id}


@router.get("/apps/{app_id}/compare")
async def compare_scans(request: Request, app_id: int, scans: str = ""):
    if not scans:
        raise HTTPException(status_code=400, detail="Provide scan IDs as ?scans=1,2,3")

    scan_ids = [int(s) for s in scans.split(",") if s.strip().isdigit()][:7]
    if len(scan_ids) < 2:
        raise HTTPException(status_code=400, detail="At least 2 scan IDs required")

    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, vuln_id",
            (app_id,),
        )
        known_vulns = await cursor.fetchall()

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
                "scan": dict(scan),
                "metrics": {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1},
                "matched_vuln_ids": list(matched_ids),
                "false_positives": fp_findings,
            })

        matrix = []
        for v in known_vulns:
            vid = v["id"]
            detections = [vid in s["matched_vuln_ids"] for s in scanners]
            matrix.append({
                "vuln_id": v["vuln_id"],
                "title": v["title"],
                "severity": v["severity"],
                "detections": detections,
                "found_by": sum(detections),
            })
    finally:
        await db.close()

    return {
        "scanners": scanners,
        "matrix": matrix,
        "known_vuln_count": len(known_vulns),
    }
