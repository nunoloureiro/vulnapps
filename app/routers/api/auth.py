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
