from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.dependencies import require_scope
from app.services import known_fps as known_fps_service

router = APIRouter()

_BAD_REQUEST = ("required", "must be", "already exists")


def _status(msg: str) -> int:
    return 400 if any(part in msg for part in _BAD_REQUEST) else 404


@router.get("/{app_id}/known-fps")
async def list_known_fps(request: Request, app_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        result = await known_fps_service.list_known_fps(db, user, app_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await db.close()
    return {"known_fps": result}


@router.post("/{app_id}/known-fps")
async def create_known_fp(request: Request, app_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    db = await get_connection()
    try:
        known_fp = await known_fps_service.create_known_fp(db, user, app_id, body)
    except ValueError as e:
        raise HTTPException(status_code=_status(str(e)), detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"known_fp": known_fp}


@router.put("/{app_id}/known-fps/{known_fp_pk}")
async def update_known_fp(request: Request, app_id: int, known_fp_pk: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    db = await get_connection()
    try:
        known_fp = await known_fps_service.update_known_fp(db, user, app_id, known_fp_pk, body)
    except ValueError as e:
        raise HTTPException(status_code=_status(str(e)), detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"known_fp": known_fp}


@router.delete("/{app_id}/known-fps/{known_fp_pk}")
async def delete_known_fp(request: Request, app_id: int, known_fp_pk: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    db = await get_connection()
    try:
        await known_fps_service.delete_known_fp(db, user, app_id, known_fp_pk)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}
