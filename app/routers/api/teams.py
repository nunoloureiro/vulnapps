from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.dependencies import require_scope
from app.services import teams as teams_service

router = APIRouter()


def _require_user(request: Request) -> dict:
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def _require_team_write(request: Request) -> dict:
    """Auth + scope guard for team-mutation routes (vuln-0003)."""
    user = _require_user(request)
    require_scope(user, "full")
    return user


@router.get("")
async def list_teams(request: Request):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = await get_connection()
    try:
        result = await teams_service.list_teams(db, user)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"teams": result}


@router.get("/{team_id}")
async def get_team(request: Request, team_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = await get_connection()
    try:
        result = await teams_service.get_team(db, user, team_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return result


@router.post("")
async def create_team(request: Request):
    user = _require_team_write(request)

    body = await request.json()
    db = await get_connection()
    try:
        team = await teams_service.create_team(db, user, name=body.get("name", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"team": team}


@router.put("/{team_id}")
async def rename_team(request: Request, team_id: int):
    user = _require_team_write(request)
    body = await request.json()
    db = await get_connection()
    try:
        team = await teams_service.rename_team(db, user, team_id, body.get("name", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True, "team": team}


@router.delete("/{team_id}")
async def delete_team(request: Request, team_id: int):
    user = _require_team_write(request)

    db = await get_connection()
    try:
        await teams_service.delete_team(db, user, team_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


@router.post("/{team_id}/members")
async def add_member(request: Request, team_id: int):
    user = _require_team_write(request)

    body = await request.json()
    db = await get_connection()
    try:
        await teams_service.add_member(
            db, user, team_id,
            email=body.get("email", ""),
            role=body.get("role", "view"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


@router.put("/{team_id}/members/{user_id}")
async def change_member_role(request: Request, team_id: int, user_id: int):
    user = _require_team_write(request)

    body = await request.json()
    db = await get_connection()
    try:
        await teams_service.change_member_role(
            db, user, team_id, user_id, role=body.get("role", "view"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


@router.delete("/{team_id}/members/{user_id}")
async def remove_member(request: Request, team_id: int, user_id: int):
    user = _require_team_write(request)

    db = await get_connection()
    try:
        await teams_service.remove_member(db, user, team_id, user_id)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}
