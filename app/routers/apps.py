from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_user, require_app_write, get_team_role
from app.visibility import app_visibility_filter

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


def _can_edit_app(user, app) -> bool:
    """Check if user can edit this app (for template use)."""
    if not user:
        return False
    if user["role"] == "admin":
        return True
    if app["visibility"] == "public":
        return False
    if app["created_by"] == user["sub"]:
        return True
    # Team check is done in routes where db is available; this is a simple check
    return False


@router.get("", response_class=HTMLResponse)
async def list_apps(request: Request, q: str = "", filter: str = ""):
    user = request.state.user
    db = await get_connection()
    try:
        vis_clause, vis_params = app_visibility_filter(user)
        extra_filters = ""
        extra_params = []

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

        if q:
            extra_filters += " AND apps.name LIKE ?"
            extra_params.append(f"%{q}%")

        base_query = f"""
            SELECT apps.*, users.name as creator_name,
                   (SELECT COUNT(*) FROM vulnerabilities WHERE app_id=apps.id) as vuln_count,
                   (SELECT COUNT(*) FROM scans WHERE app_id=apps.id) as scan_count
            FROM apps
            LEFT JOIN users ON apps.created_by=users.id
            WHERE {vis_clause}{extra_filters}
            ORDER BY apps.created_at DESC
        """
        cursor = await db.execute(base_query, vis_params + extra_params)
        apps = await cursor.fetchall()

        # Get tech stack for each app
        apps_with_tech = []
        for app in apps:
            tech = await _get_tech_stack(db, app["id"])
            apps_with_tech.append({"app": app, "tech": tech})

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
        request, "apps/list.html", {
            "user": request.state.user,
            "apps": apps_with_tech,
            "q": q,
            "filter": filter,
            "user_teams": user_teams,
        }
    )


@router.get("/new", response_class=HTMLResponse)
async def new_app_form(request: Request, clone_from: int = None):
    user = await require_user(request)

    db = await get_connection()
    try:
        cursor = await db.execute(
            """SELECT teams.* FROM teams
               JOIN team_members ON team_members.team_id = teams.id
               WHERE team_members.user_id = ?
               ORDER BY teams.name""",
            (user["sub"],),
        )
        user_teams = await cursor.fetchall()

        # Pre-fill from clone source
        source_app = None
        source_tech = ""
        if clone_from:
            vis_clause, vis_params = app_visibility_filter(user)
            cursor = await db.execute(
                f"SELECT * FROM apps WHERE id = ? AND {vis_clause}",
                [clone_from] + vis_params,
            )
            source_app = await cursor.fetchone()
            if source_app:
                source_tech = ", ".join(await _get_tech_stack(db, source_app["id"]))
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "apps/form.html", {
            "user": user,
            "app": None,
            "tech_stack": source_tech,
            "teams": user_teams,
            "clone_from": source_app,
        }
    )


@router.post("/new")
async def create_app(request: Request):
    user = await require_user(request)
    form = await request.form()

    db = await get_connection()
    try:
        visibility = form.get("visibility", "private")
        if visibility not in ("public", "team", "private"):
            visibility = "private"
        team_id = form.get("team_id") or None
        if team_id:
            team_id = int(team_id)

        # Validate visibility permissions
        if visibility == "public" and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Only admins can create public apps")
        if visibility == "team":
            if not team_id:
                raise HTTPException(status_code=400, detail="Team required for team visibility")
            team_role = await get_team_role(db, user["sub"], team_id)
            if user["role"] != "admin" and team_role not in ("admin", "contributor"):
                raise HTTPException(status_code=403, detail="Team contributor access required")

        cursor = await db.execute(
            "INSERT INTO apps (name, version, description, url, created_by, visibility, team_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                form.get("name"),
                form.get("version"),
                form.get("description"),
                form.get("url"),
                user["sub"],
                visibility,
                team_id,
            ),
        )
        app_id = cursor.lastrowid
        await _save_tech_stack(db, app_id, form.get("tech_stack", ""))

        # Clone vulns from source app if specified
        clone_from = form.get("clone_from")
        if clone_from:
            clone_from = int(clone_from)
            # Verify read access to source app
            vis_clause, vis_params = app_visibility_filter(user)
            cursor = await db.execute(
                f"SELECT id FROM apps WHERE id = ? AND {vis_clause}",
                [clone_from] + vis_params,
            )
            if await cursor.fetchone():
                cursor = await db.execute(
                    "SELECT * FROM vulnerabilities WHERE app_id = ?", (clone_from,)
                )
                source_vulns = await cursor.fetchall()
                for v in source_vulns:
                    await db.execute(
                        """INSERT INTO vulnerabilities
                           (app_id, vuln_id, title, severity, vuln_type, http_method, url, parameter,
                            filename, line_number, description, code_location, poc, remediation, created_by)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            app_id,
                            v["vuln_id"],
                            v["title"],
                            v["severity"],
                            v["vuln_type"],
                            v["http_method"],
                            v["url"],
                            v["parameter"],
                            v["filename"],
                            v["line_number"],
                            v["description"],
                            v["code_location"],
                            v["poc"],
                            v["remediation"],
                            user["sub"],
                        ),
                    )

        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}", status_code=303)


@router.get("/{app_id}", response_class=HTMLResponse)
async def app_detail(request: Request, app_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        vis_clause, vis_params = app_visibility_filter(user)
        cursor = await db.execute(
            f"""SELECT apps.*, users.name as creator_name
               FROM apps LEFT JOIN users ON apps.created_by=users.id
               WHERE apps.id = ? AND {vis_clause}""",
            [app_id] + vis_params,
        )
        app = await cursor.fetchone()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

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

        # Determine edit permissions
        can_edit = False
        can_submit_scan = False
        if user:
            if user["role"] == "admin":
                can_edit = True
                can_submit_scan = True
            elif app["visibility"] == "public":
                can_edit = False
                can_submit_scan = False
            elif app["created_by"] == user["sub"]:
                can_edit = True
                can_submit_scan = True
            elif app["visibility"] == "team" and app["team_id"]:
                team_role = await get_team_role(db, user["sub"], app["team_id"])
                if team_role in ("admin", "contributor"):
                    can_edit = True
                    can_submit_scan = True
                elif team_role == "view":
                    can_submit_scan = False
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "apps/detail.html",
        {
            "user": request.state.user,
            "app": app,
            "vulns": vulns,
            "scan_count": scan_count,
            "tech_stack": tech_stack,
            "vuln_count": len(vulns),
            "severity_counts": severity_counts,
            "can_edit": can_edit,
            "can_submit_scan": can_submit_scan,
        },
    )


@router.get("/{app_id}/edit", response_class=HTMLResponse)
async def edit_app_form(request: Request, app_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

        await require_app_write(request, db, app)

        tech_stack = await _get_tech_stack(db, app_id)

        user = request.state.user
        cursor = await db.execute(
            """SELECT teams.* FROM teams
               JOIN team_members ON team_members.team_id = teams.id
               WHERE team_members.user_id = ?
               ORDER BY teams.name""",
            (user["sub"],),
        )
        user_teams = await cursor.fetchall()
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "apps/form.html", {
            "user": user,
            "app": app,
            "tech_stack": ", ".join(tech_stack),
            "teams": user_teams,
        }
    )


@router.post("/{app_id}/edit")
async def update_app(request: Request, app_id: int):
    form = await request.form()

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

        user = await require_app_write(request, db, app)

        visibility = form.get("visibility", "private")
        if visibility not in ("public", "team", "private"):
            visibility = "private"
        team_id = form.get("team_id") or None
        if team_id:
            team_id = int(team_id)

        # Validate visibility permissions
        if visibility == "public" and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Only admins can set public visibility")
        if visibility == "team":
            if not team_id:
                raise HTTPException(status_code=400, detail="Team required for team visibility")
            team_role = await get_team_role(db, user["sub"], team_id)
            if user["role"] != "admin" and team_role not in ("admin", "contributor"):
                raise HTTPException(status_code=403, detail="Team contributor access required")

        await db.execute(
            """UPDATE apps SET name=?, version=?, description=?, url=?,
               visibility=?, team_id=?, updated_at=datetime('now') WHERE id=?""",
            (
                form.get("name"),
                form.get("version"),
                form.get("description"),
                form.get("url"),
                visibility,
                team_id,
                app_id,
            ),
        )
        await _save_tech_stack(db, app_id, form.get("tech_stack", ""))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/apps/{app_id}", status_code=303)
