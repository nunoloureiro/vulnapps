from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
from app.database import get_connection, run_migrations
from app.dependencies import get_current_user

BASE_DIR = Path(__file__).parent
PROJECT_DIR = BASE_DIR.parent
SPA_DIR = PROJECT_DIR / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = await get_connection()
    await run_migrations(db)
    await db.close()
    yield


app = FastAPI(
    title="Vulnapps",
    description="Vulnerability registry for benchmarking security scanners",
    version="1.0.0",
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


# ── API routes under /api ──
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


# ── SPA serving ──
# Serve Vite build assets if the dist directory exists
if SPA_DIR.exists():
    app.mount("/assets", StaticFiles(directory=SPA_DIR / "assets"), name="spa-assets")


# SPA catch-all: any non-API, non-static path serves the React app
@app.middleware("http")
async def spa_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    # If a real route handled it (not 404/405), return as-is
    if response.status_code not in (404, 405):
        return response
    # Don't serve SPA for API or static paths
    if path.startswith("/api") or path.startswith("/static"):
        return response
    # Serve the SPA index.html for client-side routing
    spa_index = SPA_DIR / "index.html"
    if spa_index.exists():
        return FileResponse(spa_index)
    return response
