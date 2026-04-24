"""User management service — admin operations and user profiles."""


async def list_users(db) -> list:
    """Return all users ordered by created_at DESC."""
    cursor = await db.execute("SELECT * FROM users ORDER BY created_at DESC")
    return [dict(row) for row in await cursor.fetchall()]


async def update_user(db, admin_user: dict, target_user_id: int, updates: dict) -> None:
    """Inline update a user's name, email, or role.

    Raises ValueError on validation failures or permission issues.
    """
    allowed = {"name", "email", "role"}
    updates = {k: v for k, v in updates.items() if k in allowed}
    if not updates:
        raise ValueError("No valid fields to update")

    # Validate role if being changed
    if "role" in updates and updates["role"] not in ("user",):
        raise ValueError("Invalid role")

    # Look up target user
    cursor = await db.execute("SELECT * FROM users WHERE id = ?", (target_user_id,))
    target = await cursor.fetchone()
    if not target:
        raise ValueError("User not found")

    # Don't allow editing other admin users
    if target["role"] == "admin" and target_user_id != admin_user["sub"]:
        raise ValueError("Cannot edit other admins")

    # Don't allow changing an admin's role
    if target["role"] == "admin" and "role" in updates:
        raise ValueError("Cannot change admin role")

    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [target_user_id]

    await db.execute(f"UPDATE users SET {set_clause} WHERE id=?", values)
    await db.commit()


async def update_user_role(db, admin_user: dict, target_user_id: int, role: str) -> None:
    """Change a user's role.

    Raises ValueError if role is invalid, or admin tries to change own role.
    """
    if role not in ("user", "admin"):
        raise ValueError("Invalid role")

    if target_user_id == admin_user["sub"]:
        raise ValueError("Cannot change own role")

    await db.execute("UPDATE users SET role = ? WHERE id = ?", (role, target_user_id))
    await db.commit()


async def delete_user(db, admin_user: dict, target_user_id: int) -> None:
    """Delete a user account.

    Raises ValueError if trying to delete self or an admin.
    """
    if target_user_id == admin_user["sub"]:
        raise ValueError("Cannot delete yourself")

    cursor = await db.execute("SELECT * FROM users WHERE id = ?", (target_user_id,))
    target = await cursor.fetchone()
    if not target:
        raise ValueError("User not found")

    if target["role"] == "admin":
        raise ValueError("Cannot delete admin users")

    await db.execute("DELETE FROM users WHERE id = ?", (target_user_id,))
    await db.commit()


async def get_profile(db, user_id: int) -> dict:
    """Return user profile with their apps and vulnerability counts."""
    cursor = await db.execute(
        "SELECT id, name, email, role, created_at FROM users WHERE id = ?",
        (user_id,),
    )
    user = await cursor.fetchone()
    if not user:
        raise ValueError("User not found")

    cursor = await db.execute(
        """SELECT apps.*,
                  (SELECT COUNT(*) FROM vulnerabilities WHERE app_id = apps.id) as vuln_count
           FROM apps
           WHERE apps.created_by = ?
           ORDER BY apps.created_at DESC""",
        (user_id,),
    )
    apps = [dict(row) for row in await cursor.fetchall()]

    result = dict(user)
    result["apps"] = apps
    return result
