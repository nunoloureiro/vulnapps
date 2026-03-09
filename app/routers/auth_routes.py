from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from app.templating import templates
from app.database import get_connection
from app.auth import hash_password, verify_password, create_token
from app.seed import seed_taintedport

router = APIRouter(prefix="/auth")


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse("auth/login.html", {"request": request, "user": request.state.user})


@router.post("/login")
async def login(request: Request):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")

    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = await cursor.fetchone()
    finally:
        await db.close()

    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "user": request.state.user, "error": "Invalid credentials"},
            status_code=400,
        )

    token = create_token(user["id"], user["username"], user["role"])
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie("token", token, httponly=True)
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse("auth/register.html", {"request": request, "user": request.state.user})


@router.post("/register")
async def register(request: Request):
    form = await request.form()
    username = form.get("username")
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
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, hashed, role),
        )
        await db.commit()
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = await cursor.fetchone()

        # Seed TaintedPort app when first user (admin) registers
        if role == "admin":
            await seed_taintedport(db, user["id"])
    finally:
        await db.close()

    token = create_token(user["id"], user["username"], user["role"])
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie("token", token, httponly=True)
    return response


@router.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("token")
    return response
