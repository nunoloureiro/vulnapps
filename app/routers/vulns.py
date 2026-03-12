import csv
import io
import json

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_contributor

router = APIRouter(prefix="/apps")


EXAMPLE_VULNS_JSON = json.dumps({
    "vulnerabilities": [
        {"vuln_id": "V-001", "title": "SQL Injection - Login", "severity": "high", "vuln_type": "SQLi",
         "http_method": "POST", "url": "/login", "parameter": "email", "description": "SQL injection via email field"},
        {"vuln_id": "V-002", "title": "Hardcoded Secret", "severity": "medium", "vuln_type": "Hardcoded Secret",
         "filename": "src/config/db.py", "line_number": 12, "description": "Database password in source code"},
    ]
}, indent=2)

EXAMPLE_VULNS_CSV = """vuln_id,title,severity,vuln_type,http_method,url,parameter,filename,line_number,description
V-001,SQL Injection - Login,high,SQLi,POST,/login,email,,,SQL injection via email field
V-002,Hardcoded Secret,medium,Hardcoded Secret,,,,,src/config/db.py,12,Database password in source code
"""


@router.get("/vulns/example/json")
async def example_vulns_json():
    return Response(
        content=EXAMPLE_VULNS_JSON,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=example_vulns.json"},
    )


@router.get("/vulns/example/csv")
async def example_vulns_csv():
    return Response(
        content=EXAMPLE_VULNS_CSV,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=example_vulns.csv"},
    )


@router.post("/{app_id}/vulns/import")
async def import_vulns(request: Request, app_id: int):
    user = await require_contributor(request)
    form = await request.form()

    vuln_file = form.get("vuln_file")
    if not vuln_file or not hasattr(vuln_file, "read") or not vuln_file.filename:
        return RedirectResponse(url=f"/apps/{app_id}", status_code=303)

    content = (await vuln_file.read()).decode("utf-8")
    filename_lower = vuln_file.filename.lower()
    vulns_data = []

    if filename_lower.endswith(".json"):
        parsed = json.loads(content)
        for v in parsed.get("vulnerabilities", []):
            if v.get("title"):
                vulns_data.append(v)
    elif filename_lower.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            if row.get("title"):
                vulns_data.append(row)

    if not vulns_data:
        return RedirectResponse(url=f"/apps/{app_id}", status_code=303)

    db = await get_connection()
    try:
        # Get existing vuln count for auto-generating vuln_ids
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM vulnerabilities WHERE app_id = ?", (app_id,)
        )
        existing_count = (await cursor.fetchone())["count"]

        for i, v in enumerate(vulns_data):
            vuln_id = v.get("vuln_id") or f"V-{existing_count + i + 1:03d}"
            severity = v.get("severity", "medium").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"
            line_number = v.get("line_number")
            if line_number:
                try:
                    line_number = int(line_number)
                except (ValueError, TypeError):
                    line_number = None

            await db.execute(
                """INSERT INTO vulnerabilities
                   (app_id, vuln_id, title, severity, vuln_type, http_method, url, parameter,
                    filename, line_number, description, code_location, poc, remediation, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    app_id,
                    vuln_id,
                    v.get("title", ""),
                    severity,
                    v.get("vuln_type", ""),
                    v.get("http_method", ""),
                    v.get("url", ""),
                    v.get("parameter", ""),
                    v.get("filename", ""),
                    line_number,
                    v.get("description", ""),
                    v.get("code_location", ""),
                    v.get("poc", ""),
                    v.get("remediation", ""),
                    user["sub"],
                ),
            )
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}", status_code=303)


@router.get("/{app_id}/vulns/new-from-fp", response_class=HTMLResponse)
async def new_vuln_from_fp(request: Request, app_id: int,
                           vuln_type: str = "", http_method: str = "",
                           url: str = "", parameter: str = "", filename: str = ""):
    """Pre-fill the vuln form from a false positive finding."""
    await require_contributor(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
    finally:
        await db.close()

    prefill = {
        "vuln_id": "",
        "title": vuln_type,
        "severity": "medium",
        "vuln_type": vuln_type,
        "http_method": http_method,
        "url": url,
        "parameter": parameter,
        "filename": filename,
        "description": "",
        "code_location": "",
        "poc": "",
        "remediation": "",
        "line_number": None,
    }

    return templates.TemplateResponse(
        "vulns/form.html",
        {"request": request, "user": request.state.user, "app": app, "vuln": None, "prefill": prefill},
    )


@router.get("/{app_id}/vulns/new", response_class=HTMLResponse)
async def new_vuln_form(request: Request, app_id: int):
    await require_contributor(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
    finally:
        await db.close()

    return templates.TemplateResponse(
        "vulns/form.html",
        {"request": request, "user": request.state.user, "app": app, "vuln": None},
    )


@router.post("/{app_id}/vulns")
async def create_vuln(request: Request, app_id: int):
    user = await require_contributor(request)
    form = await request.form()

    db = await get_connection()
    try:
        await db.execute(
            """INSERT INTO vulnerabilities
               (app_id, vuln_id, title, severity, vuln_type, http_method, url, parameter,
                filename, line_number, description, code_location, poc, remediation, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                app_id,
                form.get("vuln_id"),
                form.get("title"),
                form.get("severity"),
                form.get("vuln_type"),
                form.get("http_method"),
                form.get("url"),
                form.get("parameter"),
                form.get("filename"),
                int(form.get("line_number")) if form.get("line_number") else None,
                form.get("description"),
                form.get("code_location"),
                form.get("poc"),
                form.get("remediation"),
                user["sub"],
            ),
        )
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}", status_code=303)


@router.get("/{app_id}/vulns/{vuln_id}", response_class=HTMLResponse)
async def vuln_detail(request: Request, app_id: int, vuln_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()

        cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
        vuln = await cursor.fetchone()
    finally:
        await db.close()

    return templates.TemplateResponse(
        "vulns/detail.html",
        {"request": request, "user": request.state.user, "app": app, "vuln": vuln},
    )


@router.get("/{app_id}/vulns/{vuln_id}/edit", response_class=HTMLResponse)
async def edit_vuln_form(request: Request, app_id: int, vuln_id: int):
    await require_contributor(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()

        cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
        vuln = await cursor.fetchone()
    finally:
        await db.close()

    return templates.TemplateResponse(
        "vulns/form.html",
        {"request": request, "user": request.state.user, "app": app, "vuln": vuln},
    )


@router.post("/{app_id}/vulns/{vuln_id}/edit")
async def update_vuln(request: Request, app_id: int, vuln_id: int):
    await require_contributor(request)
    form = await request.form()

    db = await get_connection()
    try:
        await db.execute(
            """UPDATE vulnerabilities SET vuln_id=?, title=?, severity=?, vuln_type=?,
               http_method=?, url=?, parameter=?, filename=?, line_number=?, description=?,
               code_location=?, poc=?, remediation=? WHERE id=?""",
            (
                form.get("vuln_id"),
                form.get("title"),
                form.get("severity"),
                form.get("vuln_type"),
                form.get("http_method"),
                form.get("url"),
                form.get("parameter"),
                form.get("filename"),
                int(form.get("line_number")) if form.get("line_number") else None,
                form.get("description"),
                form.get("code_location"),
                form.get("poc"),
                form.get("remediation"),
                vuln_id,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}/vulns/{vuln_id}", status_code=303)


@router.post("/{app_id}/vulns/{vuln_id}/delete")
async def delete_vuln(request: Request, app_id: int, vuln_id: int):
    await require_contributor(request)

    db = await get_connection()
    try:
        await db.execute("DELETE FROM vulnerabilities WHERE id = ? AND app_id = ?", (vuln_id, app_id))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}", status_code=303)


@router.post("/{app_id}/vulns/{vuln_id}/inline")
async def inline_update_vuln(request: Request, app_id: int, vuln_id: int):
    await require_contributor(request)
    body = await request.json()

    allowed = {"vuln_id", "title", "severity", "vuln_type", "http_method", "url", "parameter", "filename", "line_number"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return {"ok": False}

    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [vuln_id, app_id]

    db = await get_connection()
    try:
        await db.execute(
            f"UPDATE vulnerabilities SET {set_clause} WHERE id=? AND app_id=?",
            values,
        )
        await db.commit()
    finally:
        await db.close()

    return {"ok": True}


