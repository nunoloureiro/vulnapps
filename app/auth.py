from __future__ import annotations
import bcrypt
import hashlib
import jwt
from datetime import datetime, timedelta, timezone
from app.config import SECRET_KEY, TOKEN_EXPIRY_HOURS


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def hash_api_key(key: str) -> str:
    """Hash an API key using SHA-256 (fast lookup, key is high-entropy)."""
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(key: str, stored_hash: str) -> bool:
    """Verify an API key against its stored SHA-256 hash."""
    return hashlib.sha256(key.encode()).hexdigest() == stored_hash


def create_token(user_id: int, name: str, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "name": name,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        payload["sub"] = int(payload["sub"])
        # Normalize stale roles from old tokens
        if payload.get("role") in ("viewer", "contributor"):
            payload["role"] = "user"
        return payload
    except (jwt.PyJWTError, ValueError, KeyError):
        return None
