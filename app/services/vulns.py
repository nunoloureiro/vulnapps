from __future__ import annotations

from app.dependencies import get_team_role
from app.visibility import app_visibility_filter


# ---------------------------------------------------------------------------
# Helpers (private)
# ---------------------------------------------------------------------------

async def _get_visible_app(db, user, app_id: int):
    """Fetch an app after checking visibility. Raises ValueError if not found."""
    vis_clause, vis_params = app_visibility_filter(user)
    cursor = await db.execute(
        f"SELECT * FROM apps WHERE id = ? AND {vis_clause}",
        [app_id] + vis_params,
    )
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")
    return app


async def _require_app_write(db, user, app) -> None:
    """Raise PermissionError when user lacks write access to *app*."""
    if not user:
        raise PermissionError("Authentication required")
    if user["role"] == "admin":
        return
    if app["visibility"] == "public":
        raise PermissionError("Only admins can edit public apps")
    if app["created_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return
    raise PermissionError("You don't have write access to this app")


def _can_edit(user, app) -> bool:
    """Synchronous best-effort edit check (no team lookup)."""
    if not user:
        return False
    if user["role"] == "admin":
        return True
    if app["visibility"] == "public":
        return False
    if app["created_by"] == user["sub"]:
        return True
    return False


async def _can_edit_full(db, user, app) -> bool:
    """Full edit-permission check including async team role lookup."""
    if _can_edit(user, app):
        return True
    if user and app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return True
    return False


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

async def list_vulns(db, user, app_id: int) -> list:
    """Return vulnerabilities for an app visible to *user*.

    Raises ``ValueError`` if the app is not found / not visible.
    """
    await _get_visible_app(db, user, app_id)

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title",
        (app_id,),
    )
    return [dict(row) for row in await cursor.fetchall()]


async def get_vuln(db, user, app_id: int, vuln_id: int) -> dict:
    """Return a single vulnerability with a ``can_edit`` flag.

    Raises ``ValueError`` if app or vuln is not found / not visible.
    """
    app = await _get_visible_app(db, user, app_id)

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE id = ? AND app_id = ?",
        (vuln_id, app_id),
    )
    vuln = await cursor.fetchone()
    if not vuln:
        raise ValueError("Vulnerability not found")

    can_edit = await _can_edit_full(db, user, app)

    return {"vuln": dict(vuln), "app": dict(app), "can_edit": can_edit}


async def create_vuln(db, user, app_id: int, vuln_data: dict) -> dict:
    """Create a vulnerability on the given app. Returns the new row as a dict.

    *vuln_data* keys: vuln_id, title, severity, vuln_type, http_method, url,
    parameter, filename, line_number, description, code_location, poc, remediation.

    Raises ``ValueError`` if app not found.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    line_number = vuln_data.get("line_number")
    if line_number:
        try:
            line_number = int(line_number)
        except (ValueError, TypeError):
            line_number = None

    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, http_method, url,
            parameter, filename, line_number, description, code_location,
            poc, remediation, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            app_id,
            vuln_data.get("vuln_id"),
            vuln_data.get("title"),
            vuln_data.get("severity"),
            vuln_data.get("vuln_type"),
            vuln_data.get("http_method"),
            vuln_data.get("url"),
            vuln_data.get("parameter"),
            vuln_data.get("filename"),
            line_number,
            vuln_data.get("description"),
            vuln_data.get("code_location"),
            vuln_data.get("poc"),
            vuln_data.get("remediation"),
            user["sub"],
        ),
    )
    await db.commit()

    new_id = cursor.lastrowid
    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (new_id,))
    return dict(await cursor.fetchone())


async def update_vuln(db, user, app_id: int, vuln_id: int, vuln_data: dict) -> dict:
    """Full update of a vulnerability. Returns the updated row as a dict.

    Raises ``ValueError`` if app or vuln not found.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE id = ? AND app_id = ?",
        (vuln_id, app_id),
    )
    if not await cursor.fetchone():
        raise ValueError("Vulnerability not found")

    line_number = vuln_data.get("line_number")
    if line_number:
        try:
            line_number = int(line_number)
        except (ValueError, TypeError):
            line_number = None

    await db.execute(
        """UPDATE vulnerabilities SET vuln_id=?, title=?, severity=?, vuln_type=?,
           http_method=?, url=?, parameter=?, filename=?, line_number=?,
           description=?, code_location=?, poc=?, remediation=?
           WHERE id=?""",
        (
            vuln_data.get("vuln_id"),
            vuln_data.get("title"),
            vuln_data.get("severity"),
            vuln_data.get("vuln_type"),
            vuln_data.get("http_method"),
            vuln_data.get("url"),
            vuln_data.get("parameter"),
            vuln_data.get("filename"),
            line_number,
            vuln_data.get("description"),
            vuln_data.get("code_location"),
            vuln_data.get("poc"),
            vuln_data.get("remediation"),
            vuln_id,
        ),
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    return dict(await cursor.fetchone())


async def delete_vuln(db, user, app_id: int, vuln_id: int) -> None:
    """Delete a vulnerability.

    Raises ``ValueError`` if app not found.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    await db.execute(
        "DELETE FROM vulnerabilities WHERE id = ? AND app_id = ?",
        (vuln_id, app_id),
    )
    await db.commit()


async def inline_update_vuln(
    db, user, app_id: int, vuln_id: int, updates: dict
) -> None:
    """Partial update of whitelisted vuln fields.

    Allowed fields: vuln_id, title, severity, vuln_type, http_method, url,
    parameter, filename, line_number.

    Raises ``ValueError`` if app not found or no valid fields supplied.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    allowed = {
        "vuln_id", "title", "severity", "vuln_type", "http_method",
        "url", "parameter", "filename", "line_number",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed}
    if not filtered:
        raise ValueError("No valid fields to update")

    set_clause = ", ".join(f"{k}=?" for k in filtered)
    values = list(filtered.values()) + [vuln_id, app_id]

    await db.execute(
        f"UPDATE vulnerabilities SET {set_clause} WHERE id=? AND app_id=?",
        values,
    )
    await db.commit()


async def import_vulns(db, user, app_id: int, vulns_data: list) -> int:
    """Bulk-import vulnerabilities from a list of dicts (parsed JSON/CSV).

    Returns the number of vulnerabilities imported.

    Raises ``ValueError`` if app not found.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    if not vulns_data:
        return 0

    # Get existing vuln count for auto-generating vuln_ids
    cursor = await db.execute(
        "SELECT COUNT(*) as count FROM vulnerabilities WHERE app_id = ?",
        (app_id,),
    )
    existing_count = (await cursor.fetchone())["count"]

    imported = 0
    for i, v in enumerate(vulns_data):
        if not v.get("title"):
            continue

        vuln_id = v.get("vuln_id") or f"V-{existing_count + i + 1:03d}"
        severity = v.get("severity", "medium").lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        line_number = v.get("line_number")
        if line_number:
            try:
                line_number = int(line_number)
            except (ValueError, TypeError):
                line_number = None

        await db.execute(
            """INSERT INTO vulnerabilities
               (app_id, vuln_id, title, severity, vuln_type, http_method, url,
                parameter, filename, line_number, description, code_location,
                poc, remediation, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                app_id,
                vuln_id,
                v.get("title", ""),
                severity,
                v.get("vuln_type", ""),
                v.get("http_method", ""),
                v.get("url", ""),
                v.get("parameter", ""),
                v.get("filename", ""),
                line_number,
                v.get("description", ""),
                v.get("code_location", ""),
                v.get("poc", ""),
                v.get("remediation", ""),
                user["sub"],
            ),
        )
        imported += 1

    await db.commit()
    return imported
