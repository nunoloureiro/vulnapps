"""In-memory rate limiter / per-account lockout for auth endpoints.

Process-local (does not survive restart, does not coordinate across replicas).
Enough to make brute-forcing visibly slow and to fail open if memory is lost.
For multi-replica deployments, replace the backing dicts with Redis."""
from __future__ import annotations
import asyncio
import time
from collections import deque

# IP -> deque[timestamp]
_ip_hits: dict[str, deque[float]] = {}
# (action, key) -> [fail_count, locked_until]
_failures: dict[tuple[str, str], list[float]] = {}
_lock = asyncio.Lock()


def _client_ip(request) -> str:
    # Honor CF-Connecting-IP / X-Forwarded-For when behind a trusted proxy
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


async def rate_limit(request, action: str, *, max_hits: int, window_s: float) -> None:
    """Raise HTTPException(429) if the caller exceeds max_hits per window_s."""
    from fastapi import HTTPException
    ip = _client_ip(request)
    key = f"{action}:{ip}"
    now = time.monotonic()
    async with _lock:
        dq = _ip_hits.setdefault(key, deque())
        while dq and now - dq[0] > window_s:
            dq.popleft()
        if len(dq) >= max_hits:
            retry = max(1, int(window_s - (now - dq[0])))
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={"Retry-After": str(retry)},
            )
        dq.append(now)


async def check_lockout(action: str, identifier: str) -> None:
    """Raise HTTPException(429) if (action, identifier) is in a lockout window."""
    from fastapi import HTTPException
    key = (action, (identifier or "").lower())
    now = time.monotonic()
    async with _lock:
        state = _failures.get(key)
        if state and state[1] > now:
            retry = max(1, int(state[1] - now))
            raise HTTPException(
                status_code=429,
                detail="Account temporarily locked due to repeated failures",
                headers={"Retry-After": str(retry)},
            )


async def record_failure(
    action: str,
    identifier: str,
    *,
    threshold: int = 10,
    lockout_s: float = 900.0,
    reset_after_s: float = 900.0,
) -> None:
    """Increment failure counter; trigger a lockout once threshold is reached."""
    key = (action, (identifier or "").lower())
    now = time.monotonic()
    async with _lock:
        state = _failures.get(key)
        # Reset the counter if there's been no recent activity
        if not state or (state[0] >= 1 and now - state[1] > reset_after_s and state[1] <= now):
            state = [0, now]
        state[0] += 1
        if state[0] >= threshold:
            state[1] = now + lockout_s
        else:
            state[1] = now  # last failure time
        _failures[key] = state


async def record_success(action: str, identifier: str) -> None:
    """Clear failure counter on successful auth."""
    key = (action, (identifier or "").lower())
    async with _lock:
        _failures.pop(key, None)
