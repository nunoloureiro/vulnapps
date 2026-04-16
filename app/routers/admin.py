from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from app.templating import templates
from app.database import get_connection
from app.dependencies import require_admin

router = APIRouter(prefix="/admin")


@router.get("/users", response_class=HTMLResponse)
async def list_users(request: Request):
    await require_admin(request)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM users ORDER BY created_at DESC")
        users = await cursor.fetchall()
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "admin/users.html", {"user": request.state.user, "users": users}
    )


@router.post("/users/{user_id}/role")
async def update_user_role(request: Request, user_id: int):
    await require_admin(request)
    form = await request.form()
    role = form.get("role")

    if role not in ("user", "admin"):
        return RedirectResponse(url="/admin/users", status_code=303)

    db = await get_connection()
    try:
        # Don't allow changing own role
        admin = request.state.user
        if user_id == admin["sub"]:
            return RedirectResponse(url="/admin/users", status_code=303)

        await db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url="/admin/users", status_code=303)


@router.post("/users/{user_id}/inline")
async def inline_update_user(request: Request, user_id: int):
    admin = await require_admin(request)
    body = await request.json()

    allowed = {"name", "email", "role"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return {"ok": False}

    # Validate role if being changed
    if "role" in updates and updates["role"] not in ("user",):
        return {"ok": False, "error": "Invalid role"}

    # Don't allow editing admin users (except self name/email)
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        target = await cursor.fetchone()
        if not target:
            return {"ok": False, "error": "User not found"}

        if target["role"] == "admin" and user_id != admin["sub"]:
            return {"ok": False, "error": "Cannot edit other admins"}

        if target["role"] == "admin" and "role" in updates:
            return {"ok": False, "error": "Cannot change admin role"}

        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [user_id]

        await db.execute(f"UPDATE users SET {set_clause} WHERE id=?", values)
        await db.commit()
    finally:
        await db.close()

    return {"ok": True}


@router.post("/users/{user_id}/delete")
async def delete_user(request: Request, user_id: int):
    admin = await require_admin(request)

    if user_id == admin["sub"]:
        return RedirectResponse(url="/admin/users", status_code=303)

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        target = await cursor.fetchone()
        if not target or target["role"] == "admin":
            return RedirectResponse(url="/admin/users", status_code=303)

        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url="/admin/users", status_code=303)


# ── Label Management ─────────────────────────────────────────


@router.get("/labels", response_class=HTMLResponse)
async def list_labels(request: Request):
    await require_admin(request)

    db = await get_connection()
    try:
        cursor = await db.execute(
            """SELECT l.*, (SELECT COUNT(*) FROM scan_labels WHERE label_id = l.id) as scan_count
               FROM labels l ORDER BY l.name"""
        )
        labels = await cursor.fetchall()
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "admin/labels.html", {"user": request.state.user, "labels": labels}
    )


@router.post("/labels")
async def create_label(request: Request):
    await require_admin(request)
    form = await request.form()
    name = (form.get("name") or "").strip()
    color = (form.get("color") or "#f97316").strip()

    if not name:
        return RedirectResponse(url="/admin/labels", status_code=303)

    db = await get_connection()
    try:
        await db.execute(
            "INSERT OR IGNORE INTO labels (name, color) VALUES (?, ?)",
            (name, color),
        )
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url="/admin/labels", status_code=303)


@router.post("/labels/{label_id}/update")
async def update_label(request: Request, label_id: int):
    await require_admin(request)
    body = await request.json()

    db = await get_connection()
    try:
        updates = {}
        if "name" in body and body["name"].strip():
            updates["name"] = body["name"].strip()
        if "color" in body and body["color"].strip():
            updates["color"] = body["color"].strip()

        if not updates:
            return {"ok": False}

        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [label_id]
        await db.execute(f"UPDATE labels SET {set_clause} WHERE id=?", values)
        await db.commit()
    finally:
        await db.close()

    return {"ok": True}


@router.post("/labels/{label_id}/delete")
async def delete_label(request: Request, label_id: int):
    await require_admin(request)

    db = await get_connection()
    try:
        await db.execute("DELETE FROM scan_labels WHERE label_id = ?", (label_id,))
        await db.execute("DELETE FROM labels WHERE id = ?", (label_id,))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url="/admin/labels", status_code=303)
