from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse
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
        "admin/users.html", {"request": request, "user": request.state.user, "users": users}
    )


@router.post("/users/{user_id}/role")
async def update_user_role(request: Request, user_id: int):
    await require_admin(request)
    form = await request.form()
    role = form.get("role")

    if role not in ("viewer", "user", "contributor"):
        return RedirectResponse(url="/admin/users", status_code=303)

    db = await get_connection()
    try:
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
    if "role" in updates and updates["role"] not in ("viewer", "user", "contributor"):
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
