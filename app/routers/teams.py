from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_user, require_active_user

router = APIRouter(prefix="/teams")


async def _require_team_admin(user: dict, team_id: int, db) -> None:
    """Check that user is a team admin or app admin."""
    if user["role"] == "admin":
        return
    cursor = await db.execute(
        "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
        (team_id, user["sub"]),
    )
    row = await cursor.fetchone()
    if not row or row["role"] != "admin":
        raise HTTPException(status_code=403, detail="Team admin access required")


@router.get("", response_class=HTMLResponse)
async def list_teams(request: Request):
    user = await require_user(request)

    db = await get_connection()
    try:
        if user["role"] == "admin":
            cursor = await db.execute(
                """SELECT teams.*, COUNT(tm.id) as member_count,
                          (SELECT role FROM team_members WHERE team_id=teams.id AND user_id=?) as my_role
                   FROM teams
                   LEFT JOIN team_members tm ON tm.team_id = teams.id
                   GROUP BY teams.id
                   ORDER BY teams.name""",
                (user["sub"],),
            )
        else:
            cursor = await db.execute(
                """SELECT teams.*, COUNT(tm2.id) as member_count, tm.role as my_role
                   FROM teams
                   JOIN team_members tm ON tm.team_id = teams.id AND tm.user_id = ?
                   LEFT JOIN team_members tm2 ON tm2.team_id = teams.id
                   GROUP BY teams.id
                   ORDER BY teams.name""",
                (user["sub"],),
            )
        teams_list = await cursor.fetchall()
    finally:
        await db.close()

    return templates.TemplateResponse(
        "teams/list.html", {"request": request, "user": user, "teams": teams_list}
    )


@router.get("/new", response_class=HTMLResponse)
async def new_team_form(request: Request):
    await require_active_user(request)

    return templates.TemplateResponse(
        "teams/form.html", {"request": request, "user": request.state.user, "team": None}
    )


@router.post("/new")
async def create_team(request: Request):
    user = await require_active_user(request)
    form = await request.form()
    name = form.get("name", "").strip()

    if not name:
        return RedirectResponse(url="/teams/new", status_code=303)

    db = await get_connection()
    try:
        cursor = await db.execute(
            "INSERT INTO teams (name, created_by) VALUES (?, ?)",
            (name, user["sub"]),
        )
        team_id = cursor.lastrowid

        # Creator becomes team admin
        await db.execute(
            "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, 'admin')",
            (team_id, user["sub"]),
        )
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/teams/{team_id}", status_code=303)


@router.get("/{team_id}", response_class=HTMLResponse)
async def team_detail(request: Request, team_id: int):
    user = await require_user(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM teams WHERE id = ?", (team_id,))
        team = await cursor.fetchone()
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")

        # Check access: must be member or app admin
        if user["role"] != "admin":
            cursor = await db.execute(
                "SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?",
                (team_id, user["sub"]),
            )
            if not await cursor.fetchone():
                raise HTTPException(status_code=403, detail="Not a team member")

        cursor = await db.execute(
            """SELECT users.id, users.name, users.email, tm.role as team_role
               FROM team_members tm
               JOIN users ON users.id = tm.user_id
               WHERE tm.team_id = ?
               ORDER BY tm.role DESC, users.name""",
            (team_id,),
        )
        members = await cursor.fetchall()

        # Check if current user is team admin
        cursor = await db.execute(
            "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, user["sub"]),
        )
        my_membership = await cursor.fetchone()
        is_team_admin = user["role"] == "admin" or (my_membership and my_membership["role"] == "admin")
    finally:
        await db.close()

    return templates.TemplateResponse(
        "teams/detail.html",
        {
            "request": request,
            "user": user,
            "team": team,
            "members": members,
            "is_team_admin": is_team_admin,
        },
    )


@router.post("/{team_id}/members")
async def add_member(request: Request, team_id: int):
    user = await require_user(request)

    db = await get_connection()
    try:
        await _require_team_admin(user, team_id, db)

        form = await request.form()
        email = form.get("email", "").strip()

        cursor = await db.execute("SELECT id FROM users WHERE email = ?", (email,))
        target = await cursor.fetchone()
        if target:
            await db.execute(
                "INSERT OR IGNORE INTO team_members (team_id, user_id, role) VALUES (?, ?, 'member')",
                (team_id, target["id"]),
            )
            await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/teams/{team_id}", status_code=303)


@router.post("/{team_id}/members/{uid}/remove")
async def remove_member(request: Request, team_id: int, uid: int):
    user = await require_user(request)

    db = await get_connection()
    try:
        await _require_team_admin(user, team_id, db)

        await db.execute(
            "DELETE FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, uid),
        )
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/teams/{team_id}", status_code=303)


@router.post("/{team_id}/members/{uid}/role")
async def change_member_role(request: Request, team_id: int, uid: int):
    user = await require_user(request)

    db = await get_connection()
    try:
        await _require_team_admin(user, team_id, db)

        form = await request.form()
        role = form.get("role")
        if role not in ("member", "admin"):
            return RedirectResponse(url=f"/teams/{team_id}", status_code=303)

        await db.execute(
            "UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?",
            (role, team_id, uid),
        )
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url=f"/teams/{team_id}", status_code=303)


@router.post("/{team_id}/delete")
async def delete_team(request: Request, team_id: int):
    user = await require_user(request)

    db = await get_connection()
    try:
        await _require_team_admin(user, team_id, db)

        await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url="/teams", status_code=303)
