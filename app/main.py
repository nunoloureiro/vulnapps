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
    return templates.TemplateResponse("home.html", {"request": request, "user": request.state.user})


from app.routers import auth_routes, apps, vulns, scans, admin, api  # noqa: E402

app.include_router(auth_routes.router)
app.include_router(apps.router)
app.include_router(vulns.router)
app.include_router(scans.router)
app.include_router(admin.router)
app.include_router(api.router)
