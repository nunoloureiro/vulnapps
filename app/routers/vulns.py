from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_contributor

router = APIRouter(prefix="/apps")


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
                description, code_location, poc, remediation, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                app_id,
                form.get("vuln_id"),
                form.get("title"),
                form.get("severity"),
                form.get("vuln_type"),
                form.get("http_method"),
                form.get("url"),
                form.get("parameter"),
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
               http_method=?, url=?, parameter=?, description=?, code_location=?,
               poc=?, remediation=? WHERE id=?""",
            (
                form.get("vuln_id"),
                form.get("title"),
                form.get("severity"),
                form.get("vuln_type"),
                form.get("http_method"),
                form.get("url"),
                form.get("parameter"),
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
