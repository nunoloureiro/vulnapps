"""API router — authentication (login, register, me)."""

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.services import auth as auth_service

router = APIRouter()


@router.post("/login")
async def login(request: Request):
    body = await request.json()
    db = await get_connection()
    try:
        result = await auth_service.login(db, body.get("email"), body.get("password"))
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    finally:
        await db.close()
    return result


@router.post("/register")
async def register(request: Request):
    body = await request.json()
    db = await get_connection()
    try:
        result = await auth_service.register(
            db, body.get("name"), body.get("email"), body.get("password")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return result


@router.get("/me")
async def me(request: Request):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = await get_connection()
    try:
        profile = await auth_service.get_me(db, user["sub"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"user": profile}


@router.get("/debug")
async def auth_debug(request: Request):
    """Diagnostic endpoint — shows what the server sees for auth."""
    cookie_token = request.cookies.get("token")
    auth_header = request.headers.get("authorization", "")
    bearer_token = auth_header[7:] if auth_header.startswith("Bearer ") else None

    from app.auth import decode_token
    token = cookie_token or bearer_token
    decoded = None
    token_source = None
    error = None

    if cookie_token:
        token_source = "cookie"
    elif bearer_token:
        token_source = "bearer"

    if token:
        if token.startswith("va_"):
            decoded = {"type": "api_key", "prefix": token[:11]}
        else:
            try:
                decoded = decode_token(token)
                if decoded is None:
                    error = "decode_token returned None (invalid/expired JWT)"
            except Exception as e:
                error = str(e)

    return {
        "has_cookie_token": bool(cookie_token),
        "has_bearer_token": bool(bearer_token),
        "token_source": token_source,
        "token_prefix": token[:20] + "..." if token else None,
        "decoded": decoded,
        "error": error,
        "user_from_middleware": dict(request.state.user) if request.state.user else None,
    }
