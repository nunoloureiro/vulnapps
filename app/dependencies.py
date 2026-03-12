from __future__ import annotations
from fastapi import Request, HTTPException
from app.database import get_connection
from app.auth import decode_token


async def get_db():
    db = await get_connection()
    try:
        yield db
    finally:
        await db.close()


async def get_current_user(request: Request) -> dict | None:
    token = request.cookies.get("token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        return None
    return decode_token(token)


async def require_user(request: Request) -> dict:
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


async def require_active_user(request: Request) -> dict:
    """Rejects viewers — requires user, contributor, or admin."""
    user = await require_user(request)
    if user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="Viewers have read-only access")
    return user


async def require_contributor(request: Request) -> dict:
    user = await require_user(request)
    if user["role"] not in ("contributor", "admin"):
        raise HTTPException(status_code=403, detail="Contributor access required")
    return user


async def require_admin(request: Request) -> dict:
    user = await require_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
