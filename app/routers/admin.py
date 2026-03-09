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

    if role not in ("user", "contributor"):
        return RedirectResponse(url="/admin/users", status_code=303)

    db = await get_connection()
    try:
        await db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        await db.commit()
    finally:
        await db.close()

    return RedirectResponse(url="/admin/users", status_code=303)
