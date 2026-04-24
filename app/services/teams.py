from __future__ import annotations


# ---------------------------------------------------------------------------
# Permission helper
# ---------------------------------------------------------------------------

async def _require_team_admin(db, user, team_id: int) -> None:
    """Raise PermissionError if user is not a team admin or app admin."""
    if not user:
        raise PermissionError("Not authenticated")
    if user["role"] == "admin":
        return
    cursor = await db.execute(
        "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
        (team_id, user["sub"]),
    )
    row = await cursor.fetchone()
    if not row or row["role"] != "admin":
        raise PermissionError("Team admin access required")


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

async def list_teams(db, user) -> list:
    """List teams visible to the user. Admins see all teams.

    Each team includes member_count and my_role.
    """
    if not user:
        raise PermissionError("Not authenticated")

    if user["role"] == "admin":
        cursor = await db.execute(
            """SELECT teams.*, COUNT(tm.id) as member_count,
                      (SELECT role FROM team_members WHERE team_id=teams.id AND user_id=?) as my_role
               FROM teams
               LEFT JOIN team_members tm ON tm.team_id = teams.id
               GROUP BY teams.id
               ORDER BY teams.name""",
            (user["sub"],),
        )
    else:
        cursor = await db.execute(
            """SELECT teams.*, COUNT(tm2.id) as member_count, tm.role as my_role
               FROM teams
               JOIN team_members tm ON tm.team_id = teams.id AND tm.user_id = ?
               LEFT JOIN team_members tm2 ON tm2.team_id = teams.id
               GROUP BY teams.id
               ORDER BY teams.name""",
            (user["sub"],),
        )

    return [dict(row) for row in await cursor.fetchall()]


async def get_team(db, user, team_id: int) -> dict:
    """Get team details with members.

    Returns {team, members, is_team_admin}.
    """
    if not user:
        raise PermissionError("Not authenticated")

    cursor = await db.execute("SELECT * FROM teams WHERE id = ?", (team_id,))
    team = await cursor.fetchone()
    if not team:
        raise ValueError("Team not found")

    # Access check: must be member or app admin
    if user["role"] != "admin":
        cursor = await db.execute(
            "SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, user["sub"]),
        )
        if not await cursor.fetchone():
            raise PermissionError("Not a team member")

    cursor = await db.execute(
        """SELECT users.id, users.name, users.email, tm.role as team_role
           FROM team_members tm
           JOIN users ON users.id = tm.user_id
           WHERE tm.team_id = ?
           ORDER BY tm.role DESC, users.name""",
        (team_id,),
    )
    members = [dict(row) for row in await cursor.fetchall()]

    # Check if current user is team admin
    cursor = await db.execute(
        "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
        (team_id, user["sub"]),
    )
    my_membership = await cursor.fetchone()
    is_team_admin = (
        user["role"] == "admin"
        or (my_membership and my_membership["role"] == "admin")
    )

    return {
        "team": team,
        "members": members,
        "is_team_admin": is_team_admin,
    }


async def create_team(db, user, name: str) -> dict:
    """Create a team. Creator becomes admin. Returns the team dict."""
    if not user:
        raise PermissionError("Not authenticated")

    name = (name or "").strip()
    if not name:
        raise ValueError("Team name required")

    cursor = await db.execute(
        "INSERT INTO teams (name, created_by) VALUES (?, ?)",
        (name, user["sub"]),
    )
    team_id = cursor.lastrowid

    # Creator becomes team admin
    await db.execute(
        "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, 'admin')",
        (team_id, user["sub"]),
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM teams WHERE id = ?", (team_id,))
    team = await cursor.fetchone()
    return dict(team)


async def delete_team(db, user, team_id: int) -> None:
    """Delete a team. Requires team admin permission."""
    await _require_team_admin(db, user, team_id)

    await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    await db.commit()


async def add_member(db, user, team_id: int, email: str, role: str) -> None:
    """Add a member to a team by email. Requires team admin permission."""
    await _require_team_admin(db, user, team_id)

    email = (email or "").strip()
    if not email:
        raise ValueError("Email required")

    if role not in ("admin", "contributor", "view"):
        role = "view"

    cursor = await db.execute("SELECT id FROM users WHERE email = ?", (email,))
    target = await cursor.fetchone()
    if not target:
        raise ValueError("User not found")

    await db.execute(
        "INSERT OR IGNORE INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)",
        (team_id, target["id"], role),
    )
    await db.commit()


async def remove_member(db, user, team_id: int, member_user_id: int) -> None:
    """Remove a member from a team. Requires team admin permission."""
    await _require_team_admin(db, user, team_id)

    await db.execute(
        "DELETE FROM team_members WHERE team_id = ? AND user_id = ?",
        (team_id, member_user_id),
    )
    await db.commit()


async def change_member_role(db, user, team_id: int, member_user_id: int, role: str) -> None:
    """Change a member's role in a team. Requires team admin permission."""
    await _require_team_admin(db, user, team_id)

    if role not in ("admin", "contributor", "view"):
        raise ValueError("Invalid role. Must be admin, contributor, or view.")

    await db.execute(
        "UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?",
        (role, team_id, member_user_id),
    )
    await db.commit()
