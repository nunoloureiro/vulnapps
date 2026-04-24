"""API router — account management (profile, name, password, API keys)."""

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.auth import create_token
from app.services import auth as auth_service

router = APIRouter()


def _require_auth(request: Request) -> dict:
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
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
    user = _require_auth(request)
    body = await request.json()
    db = await get_connection()
    try:
        name = await auth_service.update_name(db, user["sub"], body.get("name"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    token = create_token(user["sub"], name, user["role"])
    return {"ok": True, "name": name, "token": token}


@router.put("/password")
async def update_password(request: Request):
    user = _require_auth(request)
    body = await request.json()
    db = await get_connection()
    try:
        await auth_service.update_password(
            db, user["sub"], body.get("current_password"), body.get("new_password")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


@router.post("/api-keys")
async def create_api_key(request: Request):
    user = _require_auth(request)
    body = await request.json()
    db = await get_connection()
    try:
        result = await auth_service.create_api_key(
            db, user["sub"], body.get("name"), body.get("scope")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True, **result}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(request: Request, key_id: int):
    user = _require_auth(request)
    db = await get_connection()
    try:
        await auth_service.revoke_api_key(db, user["sub"], key_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}
