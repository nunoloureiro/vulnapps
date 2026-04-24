from __future__ import annotations

from app.dependencies import get_team_role
from app.visibility import app_visibility_filter


# ---------------------------------------------------------------------------
# Helpers (private)
# ---------------------------------------------------------------------------

async def _get_tech_stack(db, app_id: int) -> list[str]:
    cursor = await db.execute(
        "SELECT name FROM app_technologies WHERE app_id = ? ORDER BY name",
        (app_id,),
    )
    return [row["name"] for row in await cursor.fetchall()]


async def _save_tech_stack(db, app_id: int, tech_string: str) -> None:
    await db.execute("DELETE FROM app_technologies WHERE app_id = ?", (app_id,))
    for name in (t.strip() for t in tech_string.split(",") if t.strip()):
        await db.execute(
            "INSERT OR IGNORE INTO app_technologies (app_id, name) VALUES (?, ?)",
            (app_id, name),
        )


def _check_app_write(user, app) -> bool:
    """Return True if *user* has write access to *app*.

    Rules (mirrored from ``require_app_write``):
    - Admin: always allowed
    - Public apps: admin only
    - Private apps: creator only
    - Team apps: creator (team role checked separately where db is available)
    """
    if not user:
        return False
    if user["role"] == "admin":
        return True
    if app["visibility"] == "public":
        return False
    if app["created_by"] == user["sub"]:
        return True
    return False


async def _check_app_write_full(db, user, app) -> bool:
    """Full write-permission check including async team role lookup."""
    if _check_app_write(user, app):
        return True
    if (
        user
        and app["visibility"] == "team"
        and app["team_id"]
    ):
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return True
    return False


async def _require_app_write(db, user, app) -> None:
    """Raise ``PermissionError`` when user lacks write access."""
    if not user:
        raise PermissionError("Authentication required")
    if not await _check_app_write_full(db, user, app):
        raise PermissionError("You don't have write access to this app")


def _validate_visibility(user, visibility, team_id):
    """Validate visibility/team_id combination. Raises PermissionError or ValueError."""
    if visibility not in ("public", "team", "private"):
        visibility = "private"
    if visibility == "public" and user["role"] != "admin":
        raise PermissionError("Only admins can create public apps")
    if visibility == "team" and not team_id:
        raise ValueError("Team required for team visibility")
    return visibility


async def _validate_team_access(db, user, team_id):
    """Raise PermissionError if user lacks contributor+ access to the team."""
    team_role = await get_team_role(db, user["sub"], team_id)
    if user["role"] != "admin" and team_role not in ("admin", "contributor"):
        raise PermissionError("Team contributor access required")


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

async def list_apps(db, user, q: str = "", filter: str = "") -> list:
    """Return apps visible to *user*, optionally filtered by *q* and *filter*.

    Each item is a dict with keys: app (row), tech (list[str]).
    The app row includes ``vuln_count``, ``scan_count``, and ``creator_name``.
    """
    vis_clause, vis_params = app_visibility_filter(user)
    extra_filters = ""
    extra_params: list = []

    if filter == "public":
        extra_filters += " AND apps.visibility = 'public'"
    elif filter == "private":
        extra_filters += " AND apps.visibility = 'private'"
    elif filter == "teams":
        extra_filters += " AND apps.visibility = 'team'"
    elif filter and filter.startswith("team:") and user:
        try:
            tid = int(filter[5:])
            extra_filters += " AND apps.team_id = ?"
            extra_params.append(tid)
        except ValueError:
            pass

    if q:
        extra_filters += " AND apps.name LIKE ?"
        extra_params.append(f"%{q}%")

    query = f"""
        SELECT apps.*, users.name as creator_name,
               (SELECT COUNT(*) FROM vulnerabilities WHERE app_id=apps.id) as vuln_count,
               (SELECT COUNT(*) FROM scans WHERE app_id=apps.id) as scan_count
        FROM apps
        LEFT JOIN users ON apps.created_by=users.id
        WHERE {vis_clause}{extra_filters}
        ORDER BY apps.created_at DESC
    """
    cursor = await db.execute(query, vis_params + extra_params)
    apps = await cursor.fetchall()

    result = []
    for app in apps:
        tech = await _get_tech_stack(db, app["id"])
        result.append({"app": app, "tech": tech})
    return result


async def get_app(db, user, app_id: int) -> dict:
    """Return full app detail visible to *user*.

    Returns a dict with keys:
        app, vulns, tech_stack, scan_count,
        severity_counts, can_edit, can_submit_scan
    Raises ``ValueError`` if not found / not visible.
    """
    vis_clause, vis_params = app_visibility_filter(user)
    cursor = await db.execute(
        f"""SELECT apps.*, users.name as creator_name
            FROM apps LEFT JOIN users ON apps.created_by=users.id
            WHERE apps.id = ? AND {vis_clause}""",
        [app_id] + vis_params,
    )
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title",
        (app_id,),
    )
    vulns = await cursor.fetchall()

    cursor = await db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE app_id = ?", (app_id,)
    )
    scan_count = (await cursor.fetchone())["count"]

    tech_stack = await _get_tech_stack(db, app_id)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = v["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Permissions
    can_edit = False
    can_submit_scan = False
    if user:
        if user["role"] == "admin":
            can_edit = True
            can_submit_scan = True
        elif app["visibility"] == "public":
            can_edit = False
            can_submit_scan = False
        elif app["created_by"] == user["sub"]:
            can_edit = True
            can_submit_scan = True
        elif app["visibility"] == "team" and app["team_id"]:
            team_role = await get_team_role(db, user["sub"], app["team_id"])
            if team_role in ("admin", "contributor"):
                can_edit = True
                can_submit_scan = True

    return {
        "app": app,
        "vulns": vulns,
        "tech_stack": tech_stack,
        "scan_count": scan_count,
        "severity_counts": severity_counts,
        "can_edit": can_edit,
        "can_submit_scan": can_submit_scan,
    }


async def create_app(
    db,
    user,
    name: str,
    version: str,
    description: str | None,
    url: str | None,
    visibility: str,
    team_id: int | None,
    tech_stack: str,
    clone_from: int | None = None,
) -> dict:
    """Create a new app and return its row as a dict.

    *tech_stack* is a comma-separated string.
    If *clone_from* is given, vulnerabilities are copied from that app
    (provided the user has read access to it).

    Raises ``PermissionError`` for visibility violations.
    Raises ``ValueError`` for invalid inputs (e.g. team visibility without team).
    """
    if not user:
        raise PermissionError("Authentication required")

    visibility = _validate_visibility(user, visibility, team_id)
    if visibility == "team":
        await _validate_team_access(db, user, team_id)

    cursor = await db.execute(
        """INSERT INTO apps (name, version, description, url, created_by,
           visibility, team_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (name, version, description, url, user["sub"], visibility, team_id),
    )
    app_id = cursor.lastrowid
    await _save_tech_stack(db, app_id, tech_stack)

    # Clone vulnerabilities from source app
    if clone_from:
        vis_clause, vis_params = app_visibility_filter(user)
        cursor = await db.execute(
            f"SELECT id FROM apps WHERE id = ? AND {vis_clause}",
            [clone_from] + vis_params,
        )
        if await cursor.fetchone():
            cursor = await db.execute(
                "SELECT * FROM vulnerabilities WHERE app_id = ?", (clone_from,)
            )
            source_vulns = await cursor.fetchall()
            for v in source_vulns:
                await db.execute(
                    """INSERT INTO vulnerabilities
                       (app_id, vuln_id, title, severity, vuln_type, http_method,
                        url, parameter, filename, line_number, description,
                        code_location, poc, remediation, created_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        app_id,
                        v["vuln_id"],
                        v["title"],
                        v["severity"],
                        v["vuln_type"],
                        v["http_method"],
                        v["url"],
                        v["parameter"],
                        v["filename"],
                        v["line_number"],
                        v["description"],
                        v["code_location"],
                        v["poc"],
                        v["remediation"],
                        user["sub"],
                    ),
                )

    await db.commit()

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    result = dict(app)
    result["tech_stack"] = await _get_tech_stack(db, app_id)
    return result


async def update_app(
    db,
    user,
    app_id: int,
    name: str,
    version: str,
    description: str | None,
    url: str | None,
    visibility: str,
    team_id: int | None,
    tech_stack: str,
) -> dict:
    """Update an existing app. Returns the updated row as a dict.

    Raises ``ValueError`` if app not found.
    Raises ``PermissionError`` if access denied or visibility invalid.
    """
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    await _require_app_write(db, user, app)

    visibility = _validate_visibility(user, visibility, team_id)
    if visibility == "team":
        await _validate_team_access(db, user, team_id)

    await db.execute(
        """UPDATE apps SET name=?, version=?, description=?, url=?,
           visibility=?, team_id=?, updated_at=datetime('now') WHERE id=?""",
        (name, version, description, url, visibility, team_id, app_id),
    )
    await _save_tech_stack(db, app_id, tech_stack)
    await db.commit()

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    result = dict(app)
    result["tech_stack"] = await _get_tech_stack(db, app_id)
    return result


async def delete_app(db, user, app_id: int) -> None:
    """Delete an app. Cascade handles vulns/scans.

    Raises ``ValueError`` if not found, ``PermissionError`` if access denied.
    """
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    await _require_app_write(db, user, app)

    await db.execute("DELETE FROM apps WHERE id = ?", (app_id,))
    await db.commit()


async def get_user_teams(db, user_id) -> list:
    """Return teams the user belongs to (for form dropdowns)."""
    cursor = await db.execute(
        """SELECT teams.id, teams.name FROM teams
           JOIN team_members ON team_members.team_id = teams.id
           WHERE team_members.user_id = ?
           ORDER BY teams.name""",
        (user_id,),
    )
    return await cursor.fetchall()
