"""Auth service — login, registration, account management, API keys."""

import secrets
from app.auth import hash_password, verify_password, create_token, hash_api_key


async def login(db, email: str, password: str) -> dict:
    """Authenticate user and return token + user info.

    Raises ValueError on invalid credentials.
    """
    cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = await cursor.fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        raise ValueError("Invalid credentials")

    await db.execute(
        "UPDATE users SET last_login = datetime('now') WHERE id = ?", (user["id"],)
    )
    await db.commit()

    token = create_token(user["id"], user["name"], user["role"])
    return {
        "token": token,
        "user": {"id": user["id"], "name": user["name"], "role": user["role"]},
    }


async def register(db, name: str, email: str, password: str) -> dict:
    """Register a new user. First user gets admin role.

    Returns {token, user, is_first_user}.
    Raises sqlite3 IntegrityError on duplicate email (let caller handle).
    """
    from app.seed import seed_taintedport

    hashed = hash_password(password)

    # First user becomes admin automatically
    cursor = await db.execute("SELECT COUNT(*) as count FROM users")
    count = (await cursor.fetchone())["count"]
    role = "admin" if count == 0 else "user"

    await db.execute(
        "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
        (name, email, hashed, role),
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = await cursor.fetchone()

    is_first_user = role == "admin"

    # Seed TaintedPort app when first user (admin) registers
    if is_first_user:
        await seed_taintedport(db, user["id"])

    token = create_token(user["id"], user["name"], user["role"])
    return {
        "token": token,
        "user": {"id": user["id"], "name": user["name"], "role": user["role"]},
        "is_first_user": is_first_user,
    }


async def get_me(db, user_id: int) -> dict:
    """Return user profile (id, name, email, role, created_at)."""
    cursor = await db.execute(
        "SELECT id, name, email, role, created_at FROM users WHERE id = ?",
        (user_id,),
    )
    user = await cursor.fetchone()
    if not user:
        raise ValueError("User not found")
    return dict(user)


async def update_name(db, user_id: int, new_name: str) -> str:
    """Update user's display name. Returns the new name."""
    name = (new_name or "").strip()
    if not name:
        raise ValueError("Name is required")

    await db.execute(
        "UPDATE users SET name = ? WHERE id = ?",
        (name, user_id),
    )
    await db.commit()
    return name


async def update_password(
    db, user_id: int, current_password: str, new_password: str
) -> None:
    """Change user's password.

    Raises ValueError if current password is wrong or new password too short.
    """
    if len(new_password) < 4:
        raise ValueError("Password must be at least 4 characters")

    cursor = await db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (user_id,)
    )
    user = await cursor.fetchone()
    if not user or not verify_password(current_password, user["password_hash"]):
        raise ValueError("Current password is incorrect")

    await db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password(new_password), user_id),
    )
    await db.commit()


async def create_api_key(db, user_id: int, name: str, scope: str) -> dict:
    """Create a new API key for the user.

    Returns {key (raw), prefix, name, scope}.
    Raises ValueError on invalid scope.
    """
    name = (name or "default").strip()[:50]
    if scope not in ("read", "vuln-mapper", "full"):
        raise ValueError("Invalid scope")

    raw_key = "va_" + secrets.token_hex(32)
    prefix = raw_key[:11]  # "va_" + 8 hex chars
    hashed = hash_api_key(raw_key)

    await db.execute(
        "INSERT INTO api_keys (user_id, key_prefix, key_hash, name, scope) VALUES (?, ?, ?, ?, ?)",
        (user_id, prefix, hashed, name, scope),
    )
    await db.commit()

    return {"key": raw_key, "prefix": prefix, "name": name, "scope": scope}


async def revoke_api_key(db, user_id: int, key_id: int) -> None:
    """Delete an API key owned by the user.

    Raises ValueError if key not found or not owned by user.
    """
    cursor = await db.execute(
        "SELECT id FROM api_keys WHERE id = ? AND user_id = ?",
        (key_id, user_id),
    )
    key = await cursor.fetchone()
    if not key:
        raise ValueError("API key not found")

    await db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    await db.commit()


async def list_api_keys(db, user_id: int) -> list:
    """Return all API keys for the user (without raw key values)."""
    cursor = await db.execute(
        "SELECT id, key_prefix, name, scope, created_at, last_used "
        "FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    )
    return [dict(row) for row in await cursor.fetchall()]
