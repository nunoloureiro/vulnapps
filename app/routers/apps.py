from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_contributor

router = APIRouter(prefix="/apps")


async def _get_tech_stack(db, app_id: int) -> list:
    cursor = await db.execute(
        "SELECT name FROM app_technologies WHERE app_id = ? ORDER BY name", (app_id,)
    )
    return [row["name"] for row in await cursor.fetchall()]


async def _save_tech_stack(db, app_id: int, tech_string: str):
    await db.execute("DELETE FROM app_technologies WHERE app_id = ?", (app_id,))
    for name in (t.strip() for t in tech_string.split(",") if t.strip()):
        await db.execute(
            "INSERT OR IGNORE INTO app_technologies (app_id, name) VALUES (?, ?)",
            (app_id, name),
        )


@router.get("", response_class=HTMLResponse)
async def list_apps(request: Request, q: str = ""):
    db = await get_connection()
    try:
        base_query = """
            SELECT apps.*, users.username as creator_name,
                   (SELECT COUNT(*) FROM vulnerabilities WHERE app_id=apps.id) as vuln_count
            FROM apps
            LEFT JOIN users ON apps.created_by=users.id
        """
        if q:
            cursor = await db.execute(
                base_query + " WHERE apps.name LIKE ? ORDER BY apps.created_at DESC",
                (f"%{q}%",),
            )
        else:
            cursor = await db.execute(base_query + " ORDER BY apps.created_at DESC")
        apps = await cursor.fetchall()

        # Get tech stack for each app
        apps_with_tech = []
        for app in apps:
            tech = await _get_tech_stack(db, app["id"])
            apps_with_tech.append({"app": app, "tech": tech})
    finally:
        await db.close()

    return templates.TemplateResponse(
        "apps/list.html", {"request": request, "user": request.state.user, "apps": apps_with_tech, "q": q}
    )


@router.get("/new", response_class=HTMLResponse)
async def new_app_form(request: Request):
    await require_contributor(request)
    return templates.TemplateResponse(
        "apps/form.html", {"request": request, "user": request.state.user, "app": None, "tech_stack": ""}
    )


@router.post("/new")
async def create_app(request: Request):
    user = await require_contributor(request)
    form = await request.form()

    db = await get_connection()
    try:
        cursor = await db.execute(
            "INSERT INTO apps (name, version, description, url, created_by) VALUES (?, ?, ?, ?, ?)",
            (
                form.get("name"),
                form.get("version"),
                form.get("description"),
                form.get("url"),
                user["sub"],
            ),
        )
        app_id = cursor.lastrowid
        await _save_tech_stack(db, app_id, form.get("tech_stack", ""))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}", status_code=303)


@router.get("/{app_id}", response_class=HTMLResponse)
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

        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title", (app_id,)
        )
        vulns = await cursor.fetchall()

        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM scans WHERE app_id = ?", (app_id,)
        )
        scan_count = (await cursor.fetchone())["count"]

        tech_stack = await _get_tech_stack(db, app_id)

        # Severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1
    finally:
        await db.close()

    return templates.TemplateResponse(
        "apps/detail.html",
        {
            "request": request,
            "user": request.state.user,
            "app": app,
            "vulns": vulns,
            "scan_count": scan_count,
            "tech_stack": tech_stack,
            "vuln_count": len(vulns),
            "severity_counts": severity_counts,
        },
    )


@router.get("/{app_id}/edit", response_class=HTMLResponse)
async def edit_app_form(request: Request, app_id: int):
    await require_contributor(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
        tech_stack = await _get_tech_stack(db, app_id)
    finally:
        await db.close()

    return templates.TemplateResponse(
        "apps/form.html", {
            "request": request,
            "user": request.state.user,
            "app": app,
            "tech_stack": ", ".join(tech_stack),
        }
    )


@router.post("/{app_id}/edit")
async def update_app(request: Request, app_id: int):
    await require_contributor(request)
    form = await request.form()

    db = await get_connection()
    try:
        await db.execute(
            """UPDATE apps SET name=?, version=?, description=?, url=?,
               updated_at=datetime('now') WHERE id=?""",
            (
                form.get("name"),
                form.get("version"),
                form.get("description"),
                form.get("url"),
                app_id,
            ),
        )
        await _save_tech_stack(db, app_id, form.get("tech_stack", ""))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}", status_code=303)
