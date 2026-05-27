"""API router — account management (profile, name, password, API keys)."""

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.services import auth as auth_service
from app import throttle

router = APIRouter()


def _require_auth(request: Request) -> dict:
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def _require_jwt(request: Request) -> dict:
    """Require a primary-session JWT — reject API-key callers.

    Account-level mutations (rename, password change, mint/revoke keys) are
    not in scope for any API key, regardless of its scope (vuln-0003).
    """
    user = _require_auth(request)
    if user.get("api_key_scope") is not None:
        raise HTTPException(
            status_code=403,
            detail="API keys cannot perform account operations; use a session login",
        )
    return user


@router.get("")
async def get_account(request: Request):
    user = _require_auth(request)
    db = await get_connection()
    try:
        account = await auth_service.get_me(db, user["sub"])
        api_keys = await auth_service.list_api_keys(db, user["sub"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"account": account, "api_keys": api_keys}


@router.put("/name")
async def update_name(request: Request):
    user = _require_jwt(request)
    body = await request.json()
    db = await get_connection()
    try:
        name = await auth_service.update_name(db, user["sub"], body.get("name"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    # No fresh token: name changes do not affect authentication and minting
    # a new JWT here is what previously gave API-key callers a session
    # JWT shortcut (vuln-0003).
    return {"ok": True, "name": name}


@router.put("/password")
async def update_password(request: Request):
    user = _require_jwt(request)
    # Treat wrong-current-password as a brute-force attempt against the
    # account password (vuln-0007).
    await throttle.rate_limit(request, "password", max_hits=5, window_s=60)
    identifier = f"user:{user['sub']}"
    await throttle.check_lockout("password", identifier)
    body = await request.json()
    db = await get_connection()
    try:
        result = await auth_service.update_password(
            db, user["sub"], body.get("current_password"), body.get("new_password")
        )
    except ValueError as e:
        await throttle.record_failure(
            "password", identifier, threshold=5, lockout_s=900
        )
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    await throttle.record_success("password", identifier)
    return {"ok": True, **result}


@router.post("/api-keys")
async def create_api_key(request: Request):
    user = _require_auth(request)
    body = await request.json()
    db = await get_connection()
    try:
        result = await auth_service.create_api_key(
            db,
            user["sub"],
            body.get("name"),
            body.get("scope"),
            caller_scope=user.get("api_key_scope"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True, **result}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(request: Request, key_id: int):
    user = _require_jwt(request)
    db = await get_connection()
    try:
        await auth_service.revoke_api_key(db, user["sub"], key_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}
