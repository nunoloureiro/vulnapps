from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.services import scanners as scanners_service

router = APIRouter()


@router.get("")
async def list_scanners(request: Request):
    user = request.state.user
    db = await get_connection()
    try:
        scanners = await scanners_service.list_scanners(db, user)
    finally:
        await db.close()
    return {"scanners": scanners}


@router.get("/{name}")
async def get_scanner(request: Request, name: str):
    user = request.state.user
    db = await get_connection()
    try:
        result = await scanners_service.get_scanner_detail(db, user, name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await db.close()
    return result
