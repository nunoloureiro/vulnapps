"""API router — authentication (login, register, me)."""

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.services import auth as auth_service
from app import throttle

router = APIRouter()


@router.post("/login")
async def login(request: Request):
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    # Per-IP burst limit and per-account lockout (vuln-0007). Identical
    # behaviour regardless of whether the email is registered, so the
    # endpoint does not double as an account-existence oracle (vuln-0017).
    await throttle.rate_limit(request, "login", max_hits=10, window_s=60)
    await throttle.check_lockout("login", email)
    db = await get_connection()
    try:
        result = await auth_service.login(db, email, body.get("password"))
    except ValueError as e:
        await throttle.record_failure("login", email, threshold=10, lockout_s=900)
        raise HTTPException(status_code=401, detail=str(e))
    finally:
        await db.close()
    await throttle.record_success("login", email)
    return result


@router.post("/register")
async def register(request: Request):
    # Rate limit registration to slow account-creation abuse and to limit any
    # remaining timing signal on the duplicate-email path.
    await throttle.rate_limit(request, "register", max_hits=5, window_s=60)
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


@router.post("/logout")
async def logout(request: Request):
    """Server-side logout — bumps the user's password_version so every
    outstanding JWT for this account is rejected on the next request
    (vuln-0019). API-key callers are not affected; revoke the key instead."""
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if user.get("api_key_scope") is not None:
        raise HTTPException(
            status_code=400,
            detail="Logout is a JWT-session operation; revoke the API key instead",
        )
    db = await get_connection()
    try:
        await db.execute(
            "UPDATE users SET password_version = password_version + 1 WHERE id = ?",
            (user["sub"],),
        )
        await db.commit()
    finally:
        await db.close()
    return {"ok": True}


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


