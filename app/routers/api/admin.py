"""API router — admin operations (users, labels)."""

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.services import users as users_service
from app.services import labels as labels_service

router = APIRouter()


def _require_admin(request: Request) -> dict:
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# -- Users ------------------------------------------------------------------


@router.get("/users")
async def list_users(request: Request):
    _require_admin(request)
    db = await get_connection()
    try:
        users = await users_service.list_users(db)
    finally:
        await db.close()
    return {"users": users}


@router.put("/users/{user_id}")
async def update_user(request: Request, user_id: int):
    user = _require_admin(request)
    body = await request.json()
    db = await get_connection()
    try:
        await users_service.update_user(db, user, user_id, body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


@router.delete("/users/{user_id}")
async def delete_user(request: Request, user_id: int):
    user = _require_admin(request)
    db = await get_connection()
    try:
        await users_service.delete_user(db, user, user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


# -- Labels -----------------------------------------------------------------


@router.get("/labels")
async def list_labels(request: Request):
    _require_admin(request)
    db = await get_connection()
    try:
        labels = await labels_service.admin_list_labels(db)
    finally:
        await db.close()
    return {"labels": labels}


@router.post("/labels")
async def create_label(request: Request):
    _require_admin(request)
    body = await request.json()
    db = await get_connection()
    try:
        label = await labels_service.admin_create_label(
            db, body.get("name"), body.get("color")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"label": label}


@router.put("/labels/{label_id}")
async def update_label(request: Request, label_id: int):
    _require_admin(request)
    body = await request.json()
    db = await get_connection()
    try:
        await labels_service.admin_update_label(db, label_id, body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


@router.delete("/labels/{label_id}")
async def delete_label(request: Request, label_id: int):
    _require_admin(request)
    db = await get_connection()
    try:
        await labels_service.admin_delete_label(db, label_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}
