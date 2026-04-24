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


app = FastAPI(
    title="Vulnapps",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    redirect_slashes=False,
)
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


# ── New API routes under /api ──
from app.routers.api import auth as api_auth, account as api_account, admin as api_admin  # noqa: E402
from app.routers.api import apps as api_apps, vulns as api_vulns, scans as api_scans  # noqa: E402
from app.routers.api import teams as api_teams  # noqa: E402

app.include_router(api_auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(api_account.router, prefix="/api/account", tags=["account"])
app.include_router(api_apps.router, prefix="/api/apps", tags=["apps"])
app.include_router(api_vulns.router, prefix="/api/apps", tags=["vulnerabilities"])
app.include_router(api_scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(api_scans.submit_router, prefix="/api/apps", tags=["scans"])
app.include_router(api_scans.labels_router, prefix="/api/labels", tags=["labels"])
app.include_router(api_teams.router, prefix="/api/teams", tags=["teams"])
app.include_router(api_admin.router, prefix="/api/admin", tags=["admin"])

# ── Legacy web routes (kept during transition) ──
from app.routers import auth_routes, apps, vulns, scans, admin, api_legacy, teams  # noqa: E402

app.include_router(auth_routes.router)
app.include_router(auth_routes.account_router)
app.include_router(apps.router)
app.include_router(vulns.router)
app.include_router(scans.router)
app.include_router(admin.router)
app.include_router(teams.router)
app.include_router(api_legacy.router)
