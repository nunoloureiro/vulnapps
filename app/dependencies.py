from __future__ import annotations
from typing import Optional
from fastapi import Request, HTTPException
from app.database import get_connection
from app.auth import decode_token, verify_api_key


async def get_db():
    db = await get_connection()
    try:
        yield db
    finally:
        await db.close()


# Scope hierarchy: read < vuln-mapper < full
SCOPE_LEVELS = {"read": 0, "vuln-mapper": 1, "full": 2}


async def get_current_user(request: Request) -> dict | None:
    token = request.cookies.get("token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        return None

    # API key auth (va_ prefix)
    if token.startswith("va_"):
        return await _resolve_api_key(token)

    # JWT auth
    return decode_token(token)


async def _resolve_api_key(key: str) -> dict | None:
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM api_keys")
        rows = await cursor.fetchall()
        for row in rows:
            if verify_api_key(key, row["key_hash"]):
                # Update last_used
                await db.execute(
                    "UPDATE api_keys SET last_used = datetime('now') WHERE id = ?",
                    (row["id"],),
                )
                await db.commit()
                # Load user
                cursor = await db.execute(
                    "SELECT * FROM users WHERE id = ?", (row["user_id"],)
                )
                user = await cursor.fetchone()
                if not user:
                    return None
                return {
                    "sub": user["id"],
                    "name": user["name"],
                    "role": user["role"],
                    "api_key_scope": row["scope"],
                }
        return None
    finally:
        await db.close()


def require_scope(user: dict, min_scope: str):
    """Raise 403 if API key scope is insufficient. JWT/cookie users always pass."""
    scope = user.get("api_key_scope")
    if scope is None:
        return  # JWT/cookie auth — full access
    if SCOPE_LEVELS.get(scope, 0) < SCOPE_LEVELS.get(min_scope, 0):
        raise HTTPException(
            status_code=403,
            detail=f"API key scope '{scope}' insufficient, requires '{min_scope}'",
        )


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
