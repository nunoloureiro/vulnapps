"""Auth service — login, registration, account management, API keys."""
from __future__ import annotations

import secrets
import sqlite3
from app.auth import hash_password, verify_password, create_token, hash_api_key


# Pre-computed bcrypt hash of a high-entropy value. Used to make the wrong-email
# code path run bcrypt too, so the response time of login does not leak whether
# an email is registered (vuln-0017).
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


def _password_meets_policy(password: str) -> str | None:
    """Return None if OK, else an error message. Mirrored on register + change."""
    if password is None:
        return "Password is required"
    if not isinstance(password, str):
        return "Password must be a string"
    # bcrypt only sees the first 72 bytes; reject longer to avoid confusion
    if len(password.encode("utf-8")) > 72:
        return "Password must be at most 72 bytes"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if password.strip() == "":
        return "Password cannot be empty or whitespace"
    return None


async def login(db, email: str, password: str) -> dict:
    """Authenticate user and return token + user info.

    Raises ValueError on invalid credentials.

    Always runs bcrypt (against a dummy hash when the user does not exist) so
    the timing of a wrong-password response is the same regardless of whether
    the email is registered (vuln-0017).
    """
    cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email or "",))
    user = await cursor.fetchone()

    candidate_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
    pw_ok = verify_password(password or "", candidate_hash)

    if not user or not pw_ok:
        raise ValueError("Invalid credentials")

    await db.execute(
        "UPDATE users SET last_login = datetime('now') WHERE id = ?", (user["id"],)
    )
    await db.commit()

    token = create_token(
        user["id"], user["name"], user["role"], user["password_version"]
    )
    return {
        "token": token,
        "user": {"id": user["id"], "name": user["name"], "role": user["role"]},
    }


async def register(db, name: str, email: str, password: str) -> dict:
    """Register a new user. First user gets admin role.

    Returns {token, user, is_first_user}.
    Raises ValueError for input validation errors (including duplicate email).
    """
    from app.seed import seed_taintedport

    name = (name or "").strip()
    email = (email or "").strip().lower()
    if not name:
        raise ValueError("Name is required")
    if not email:
        raise ValueError("Email is required")

    err = _password_meets_policy(password)
    if err:
        raise ValueError(err)

    hashed = hash_password(password)

    # First user becomes admin automatically
    cursor = await db.execute("SELECT COUNT(*) as count FROM users")
    count = (await cursor.fetchone())["count"]
    role = "admin" if count == 0 else "user"

    try:
        await db.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (name, email, hashed, role),
        )
        await db.commit()
    except sqlite3.IntegrityError:
        # Generic message — same body as other validation failures so the
        # response does not act as an account-existence oracle (vuln-0017).
        raise ValueError("Registration could not be completed")

    cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = await cursor.fetchone()

    is_first_user = role == "admin"

    # Seed TaintedPort app when first user (admin) registers
    if is_first_user:
        await seed_taintedport(db, user["id"])

    token = create_token(
        user["id"], user["name"], user["role"], user["password_version"]
    )
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
) -> dict:
    """Change user's password and invalidate existing JWTs.

    Returns {token, user, password_version} — the changing client uses the
    fresh token; all previously-issued JWTs for this user now fail because
    their `pv` claim no longer matches `users.password_version` (vuln-0019).

    Raises ValueError if current password is wrong or the new password does
    not meet the password policy.
    """
    err = _password_meets_policy(new_password)
    if err:
        raise ValueError(err)

    cursor = await db.execute(
        "SELECT id, name, role, password_hash, password_version FROM users WHERE id = ?",
        (user_id,),
    )
    user = await cursor.fetchone()
    # Always run bcrypt — even if user disappeared between auth and now — to
    # keep timing uniform.
    candidate_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
    if not user or not verify_password(current_password or "", candidate_hash):
        raise ValueError("Current password is incorrect")

    await db.execute(
        "UPDATE users SET password_hash = ?, "
        "password_version = password_version + 1 WHERE id = ?",
        (hash_password(new_password), user_id),
    )
    await db.commit()

    cursor = await db.execute(
        "SELECT id, name, role, password_version FROM users WHERE id = ?", (user_id,)
    )
    refreshed = await cursor.fetchone()
    token = create_token(
        refreshed["id"], refreshed["name"], refreshed["role"], refreshed["password_version"]
    )
    return {
        "token": token,
        "user": {"id": refreshed["id"], "name": refreshed["name"], "role": refreshed["role"]},
        "password_version": refreshed["password_version"],
    }


async def create_api_key(
    db, user_id: int, name: str, scope: str, *, caller_scope: str | None = None
) -> dict:
    """Create a new API key for the user.

    *caller_scope* is the scope of the API key used to make this call, or None
    when called with primary-session (JWT) auth. An API-key caller may only
    mint keys with a scope ≤ its own scope (vuln-0003).

    Returns {key (raw), prefix, name, scope}.
    Raises ValueError on invalid scope or PermissionError on scope escalation.
    """
    from app.dependencies import SCOPE_LEVELS

    name = (name or "default").strip()[:50]
    if scope not in ("read", "vuln-mapper", "full"):
        raise ValueError("Invalid scope")

    if caller_scope is not None:
        # API-key callers can only mint keys with scope <= their own.
        if SCOPE_LEVELS.get(scope, 99) > SCOPE_LEVELS.get(caller_scope, 0):
            raise PermissionError(
                f"API key scope '{caller_scope}' cannot mint scope '{scope}'"
            )

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
