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


async def _team_owner_id(db, team_id: int) -> int | None:
    cursor = await db.execute(
        "SELECT created_by FROM teams WHERE id = ?", (team_id,)
    )
    row = await cursor.fetchone()
    return row["created_by"] if row else None


def _is_owner(user, owner_id: int | None) -> bool:
    return bool(owner_id) and user and user["sub"] == owner_id


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

    Returns 404 ("Team not found") in both the "team does not exist" and the
    "caller is not a member" cases so the response cannot be used to
    enumerate the existence of teams the caller cannot see (vuln-0008).
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
            raise ValueError("Team not found")

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


async def rename_team(db, user, team_id: int, name: str) -> dict:
    """Rename a team. Requires team admin permission."""
    await _require_team_admin(db, user, team_id)
    name = (name or "").strip()
    if not name:
        raise ValueError("Team name is required")
    await db.execute("UPDATE teams SET name = ? WHERE id = ?", (name, team_id))
    await db.commit()
    cursor = await db.execute("SELECT * FROM teams WHERE id = ?", (team_id,))
    return dict(await cursor.fetchone())


async def delete_team(db, user, team_id: int) -> None:
    """Delete a team. Only the team owner (or app admin) may delete (vuln-0006)."""
    await _require_team_admin(db, user, team_id)
    owner_id = await _team_owner_id(db, team_id)
    if owner_id is None:
        raise ValueError("Team not found")
    if user["role"] != "admin" and not _is_owner(user, owner_id):
        raise PermissionError("Only the team owner can delete the team")

    await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    await db.commit()


async def add_member(db, user, team_id: int, email: str, role: str) -> None:
    """Add a member to a team by email. Requires team admin permission.

    Returns identical success regardless of whether the email is registered
    so the endpoint cannot be used to enumerate user accounts (vuln-0020).
    """
    await _require_team_admin(db, user, team_id)

    email = (email or "").strip().lower()
    if not email:
        raise ValueError("Email required")

    if role not in ("admin", "contributor", "view"):
        role = "view"

    cursor = await db.execute("SELECT id FROM users WHERE email = ?", (email,))
    target = await cursor.fetchone()
    if target:
        await db.execute(
            "INSERT OR IGNORE INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)",
            (team_id, target["id"], role),
        )
        await db.commit()
    # No-op for unknown email — do not leak account existence.


async def remove_member(db, user, team_id: int, member_user_id: int) -> None:
    """Remove a member from a team. Requires team admin permission.

    The team owner (``teams.created_by``) is protected: only the owner may
    remove themselves; other admins cannot evict the owner (vuln-0006).
    """
    await _require_team_admin(db, user, team_id)

    owner_id = await _team_owner_id(db, team_id)
    if owner_id is not None and member_user_id == owner_id and not _is_owner(user, owner_id):
        raise PermissionError("Cannot remove the team owner")

    await db.execute(
        "DELETE FROM team_members WHERE team_id = ? AND user_id = ?",
        (team_id, member_user_id),
    )
    await db.commit()


async def change_member_role(db, user, team_id: int, member_user_id: int, role: str) -> None:
    """Change a member's role in a team. Requires team admin permission.

    The team owner cannot be demoted by anyone other than themselves (vuln-0006).
    """
    await _require_team_admin(db, user, team_id)

    if role not in ("admin", "contributor", "view"):
        raise ValueError("Invalid role. Must be admin, contributor, or view.")

    owner_id = await _team_owner_id(db, team_id)
    if (
        owner_id is not None
        and member_user_id == owner_id
        and role != "admin"
        and not _is_owner(user, owner_id)
    ):
        raise PermissionError("Cannot demote the team owner")

    await db.execute(
        "UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?",
        (role, team_id, member_user_id),
    )
    await db.commit()
