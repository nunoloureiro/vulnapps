"""Human-readable, append-only history of operations on scan findings and
app vulnerabilities. See tasks/audit-log-plan.md for the full design.

The message is rendered once, at write time, by the caller — this module
just persists and reads it back. Rendering here (rather than structured
fields templated by the frontend) means a later rename of the actor, the
matched vuln's title, or its vuln_id slug can never make a historical log
entry describe something that didn't happen.
"""

from __future__ import annotations

import json


async def record_audit_event(
    db, *, entity_type: str, action: str, actor: dict, message: str,
    entity_id: int | None = None, scan_id: int | None = None,
    app_id: int | None = None, details: dict | None = None,
) -> None:
    """Append one audit_log row.

    Does not commit — call this in the same transaction as the write it
    documents, then commit once, so the two can never drift apart.
    """
    await db.execute(
        """INSERT INTO audit_log
           (entity_type, entity_id, scan_id, app_id, action, actor_id, message, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            entity_type, entity_id, scan_id, app_id, action,
            actor["sub"], message,
            json.dumps(details) if details is not None else None,
        ),
    )


async def list_audit_events(
    db, *, scan_id: int | None = None, app_id: int | None = None, limit: int = 200,
) -> list[dict]:
    """Most-recent-first audit rows for a scan or an app.

    Exactly one of scan_id/app_id must be given — the two scopes are never
    combined into one query.
    """
    if (scan_id is None) == (app_id is None):
        raise ValueError("exactly one of scan_id or app_id is required")

    if scan_id is not None:
        cursor = await db.execute(
            "SELECT * FROM audit_log WHERE scan_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            (scan_id, limit),
        )
    else:
        cursor = await db.execute(
            "SELECT * FROM audit_log WHERE app_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            (app_id, limit),
        )
    return [dict(row) for row in await cursor.fetchall()]
