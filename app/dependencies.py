from __future__ import annotations
from typing import Optional
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


async def require_admin(request: Request) -> dict:
    user = await require_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def get_team_role(db, user_id: int, team_id: int) -> Optional[str]:
    """Get user's role in a team, or None if not a member."""
    cursor = await db.execute(
        "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
        (team_id, user_id),
    )
    row = await cursor.fetchone()
    return row["role"] if row else None


async def require_app_write(request: Request, db, app: dict) -> dict:
    """Check write access to an app. Returns user dict.

    Rules:
    - Admin: always
    - Public apps: admin only
    - Private apps: creator only
    - Team apps: creator, or team admin/contributor
    """
    user = await require_user(request)

    if user["role"] == "admin":
        return user

    if app["visibility"] == "public":
        raise HTTPException(status_code=403, detail="Only admins can edit public apps")

    if app["created_by"] == user["sub"]:
        return user

    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return user

    raise HTTPException(status_code=403, detail="You don't have write access to this app")


async def require_scan_write(request: Request, db, scan: dict, app: dict) -> dict:
    """Check write access to a scan. Returns user dict.

    Rules:
    - Admin: always
    - Scan submitter: always
    - Team admin/contributor: for scans on team apps
    """
    user = await require_user(request)

    if user["role"] == "admin":
        return user

    if scan["submitted_by"] == user["sub"]:
        return user

    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return user

    raise HTTPException(status_code=403, detail="You don't have write access to this scan")
