from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.dependencies import require_scope
from app.services import chains as chains_service

router = APIRouter()


@router.get("/{app_id}/chains")
async def list_chains(request: Request, app_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        result = await chains_service.list_chains(db, user, app_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await db.close()
    return {"chains": result}


@router.post("/{app_id}/chains")
async def create_chain(request: Request, app_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    db = await get_connection()
    try:
        chain = await chains_service.create_chain(db, user, app_id, body)
    except ValueError as e:
        msg = str(e)
        status = 400 if ("required" in msg or "must be one of" in msg or "Invalid" in msg
                          or "already exists" in msg or "not found on this app" in msg
                          or "at least two" in msg or "same vulnerability" in msg) else 404
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"chain": chain}


@router.put("/{app_id}/chains/{chain_pk}")
async def update_chain(request: Request, app_id: int, chain_pk: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    db = await get_connection()
    try:
        chain = await chains_service.update_chain(db, user, app_id, chain_pk, body)
    except ValueError as e:
        msg = str(e)
        status = 400 if ("must be one of" in msg or "Invalid" in msg
                          or "not found on this app" in msg or "at least two" in msg
                          or "same vulnerability" in msg) else 404
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"chain": chain}


@router.delete("/{app_id}/chains/{chain_pk}")
async def delete_chain(request: Request, app_id: int, chain_pk: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    db = await get_connection()
    try:
        await chains_service.delete_chain(db, user, app_id, chain_pk)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}
