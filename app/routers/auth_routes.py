import secrets
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from app.templating import templates
from app.database import get_connection
from app.auth import hash_password, verify_password, create_token, hash_api_key
from app.seed import seed_taintedport

router = APIRouter(prefix="/auth")
account_router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(request, "auth/login.html", {"user": request.state.user})


@router.post("/login")
async def login(request: Request):
    form = await request.form()
    email = form.get("email")
    password = form.get("password")

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = await cursor.fetchone()

        if not user or not verify_password(password, user["password_hash"]):
            return templates.TemplateResponse(
                request, "auth/login.html",
                {"user": request.state.user, "error": "Invalid credentials"},
                status_code=400,
            )

        await db.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?", (user["id"],)
        )
        await db.commit()
    finally:
        await db.close()

    token = create_token(user["id"], user["name"], user["role"])
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie("token", token, httponly=True, samesite="lax")
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse(request, "auth/register.html", {"user": request.state.user})


@router.post("/register")
async def register(request: Request):
    form = await request.form()
    name = form.get("name")
    email = form.get("email")
    password = form.get("password")

    hashed = hash_password(password)

    db = await get_connection()
    try:
        # First user becomes admin automatically
        cursor = await db.execute("SELECT COUNT(*) as count FROM users")
        count = (await cursor.fetchone())["count"]
        role = "admin" if count == 0 else "user"

        await db.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (name, email, hashed, role),
        )
        await db.commit()
        cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = await cursor.fetchone()

        # Seed TaintedPort app when first user (admin) registers
        if role == "admin":
            await seed_taintedport(db, user["id"])
    finally:
        await db.close()

    token = create_token(user["id"], user["name"], user["role"])
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie("token", token, httponly=True, samesite="lax")
    return response


@router.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("token")
    return response


@account_router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request):
    if not request.state.user:
        return RedirectResponse(url="/auth/login", status_code=303)
    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT id, name, email, role, created_at FROM users WHERE id = ?",
            (request.state.user["sub"],),
        )
        account = await cursor.fetchone()
        cursor = await db.execute(
            "SELECT id, key_prefix, name, scope, created_at, last_used FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
            (request.state.user["sub"],),
        )
        api_keys = [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()
    return templates.TemplateResponse(
        request, "account.html", {"user": request.state.user, "account": account, "api_keys": api_keys}
    )


@account_router.post("/account/name")
async def update_name(request: Request):
    if not request.state.user:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        return JSONResponse({"detail": "Name is required"}, status_code=400)
    db = await get_connection()
    try:
        await db.execute(
            "UPDATE users SET name = ? WHERE id = ?",
            (name, request.state.user["sub"]),
        )
        await db.commit()
    finally:
        await db.close()
    token = create_token(request.state.user["sub"], name, request.state.user["role"])
    response = JSONResponse({"ok": True, "name": name})
    response.set_cookie("token", token, httponly=True, samesite="lax")
    return response


@account_router.post("/account/password")
async def update_password(request: Request):
    if not request.state.user:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    body = await request.json()
    current_password = body.get("current_password", "")
    new_password = body.get("new_password", "")
    if len(new_password) < 4:
        return JSONResponse({"detail": "Password must be at least 4 characters"}, status_code=400)
    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            (request.state.user["sub"],),
        )
        user = await cursor.fetchone()
        if not user or not verify_password(current_password, user["password_hash"]):
            return JSONResponse({"detail": "Current password is incorrect"}, status_code=400)
        await db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), request.state.user["sub"]),
        )
        await db.commit()
    finally:
        await db.close()
    return JSONResponse({"ok": True})


@account_router.post("/account/api-keys")
async def create_api_key(request: Request):
    if not request.state.user:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    body = await request.json()
    name = (body.get("name") or "default").strip()[:50]
    scope = body.get("scope", "read")
    if scope not in ("read", "vuln-mapper", "full"):
        return JSONResponse({"detail": "Invalid scope"}, status_code=400)

    raw_key = "va_" + secrets.token_hex(32)
    prefix = raw_key[:11]  # "va_" + 8 hex chars
    hashed = hash_api_key(raw_key)

    db = await get_connection()
    try:
        await db.execute(
            "INSERT INTO api_keys (user_id, key_prefix, key_hash, name, scope) VALUES (?, ?, ?, ?, ?)",
            (request.state.user["sub"], prefix, hashed, name, scope),
        )
        await db.commit()
    finally:
        await db.close()

    return JSONResponse({"ok": True, "key": raw_key, "prefix": prefix, "name": name, "scope": scope})


@account_router.delete("/account/api-keys/{key_id}")
async def revoke_api_key(request: Request, key_id: int):
    if not request.state.user:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT * FROM api_keys WHERE id = ? AND user_id = ?",
            (key_id, request.state.user["sub"]),
        )
        key = await cursor.fetchone()
        if not key:
            return JSONResponse({"detail": "API key not found"}, status_code=404)
        await db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        await db.commit()
    finally:
        await db.close()
    return JSONResponse({"ok": True})
