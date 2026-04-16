from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pathlib import Path
from app.database import get_connection, run_migrations
from app.dependencies import get_current_user
from app.templating import templates

BASE_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = await get_connection()
    await run_migrations(db)
    await db.close()
    yield


app = FastAPI(title="Vulnapps", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def inject_user(request: Request, call_next):
    request.state.user = await get_current_user(request)
    response = await call_next(request)
    return response


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "home.html", {"user": request.state.user})


@app.get("/users/{user_id}", response_class=HTMLResponse)
async def user_profile(request: Request, user_id: int):
    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT id, name, role, created_at FROM users WHERE id = ?", (user_id,)
        )
        profile = await cursor.fetchone()
        if not profile:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="User not found")

        cursor = await db.execute(
            """SELECT apps.id, apps.name, apps.version,
                      (SELECT COUNT(*) FROM vulnerabilities WHERE app_id=apps.id) as vuln_count
               FROM apps WHERE apps.created_by = ? ORDER BY apps.created_at DESC""",
            (user_id,),
        )
        user_apps = await cursor.fetchall()
    finally:
        await db.close()

    return templates.TemplateResponse(
        request, "profile.html",
        {"user": request.state.user, "profile": profile, "user_apps": user_apps},
    )


from app.routers import auth_routes, apps, vulns, scans, admin, api, teams  # noqa: E402

app.include_router(auth_routes.router)
app.include_router(auth_routes.account_router)
app.include_router(apps.router)
app.include_router(vulns.router)
app.include_router(scans.router)
app.include_router(admin.router)
app.include_router(teams.router)
app.include_router(api.router)
