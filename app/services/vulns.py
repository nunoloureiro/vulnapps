from __future__ import annotations

from app.dependencies import get_team_role
from app.visibility import app_visibility_filter


# ---------------------------------------------------------------------------
# Input bounds (root-cause guard for the 2026-07 recon flood)
# ---------------------------------------------------------------------------
# A scan agent created 48k vulns on a single app — one with a 1 MB title —
# turning ``GET /api/apps/{id}`` into a 14 MB response that OOM-killed the
# 512 MB host. These caps bound both flood vectors at the write path so no
# single app can ever produce a multi-MB payload again. Legit vulns are tiny
# (observed maxima: title 85, description 350, poc 128), so real data is never
# touched — the caps only bite pathological/abusive input.

MAX_VULNS_PER_APP = 1000

_FIELD_CAPS = {
    "vuln_id": 100,
    "title": 500,
    "vuln_type": 100,
    "http_method": 16,
    "url": 2048,
    "parameter": 512,
    "filename": 1024,
    "description": 10000,
    "code_location": 4096,
    "poc": 10000,
    "remediation": 10000,
}


def _cap(value, field):
    """Truncate a string *field* to its cap. Non-strings pass through unchanged.

    Truncation (rather than rejection) keeps bulk imports flowing on a single
    oversized row while still bounding stored size; the caps sit far above any
    legitimate value, so this only ever trims abusive input.
    """
    cap = _FIELD_CAPS.get(field)
    if cap is not None and isinstance(value, str) and len(value) > cap:
        return value[:cap]
    return value


def _cap_field(value, field, stats):
    """Like :func:`_cap`, but bump ``stats['truncated']`` when it actually trims.

    Lets the bulk importer report how many field values it silently shortened,
    so a caller can surface it instead of the truncation going unnoticed.
    """
    capped = _cap(value, field)
    if isinstance(value, str) and len(capped) < len(value):
        stats["truncated"] += 1
    return capped


async def _vuln_count(db, app_id: int) -> int:
    cursor = await db.execute(
        "SELECT COUNT(*) AS c FROM vulnerabilities WHERE app_id = ?", (app_id,)
    )
    return (await cursor.fetchone())["c"]


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

    # Bounded read: mirrors the per-app cap so a flooded app can never return
    # a multi-MB list (the endpoint that once served 48k vulns / 14 MB).
    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title LIMIT ?",
        (app_id, MAX_VULNS_PER_APP),
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

    if await _vuln_count(db, app_id) >= MAX_VULNS_PER_APP:
        raise ValueError(
            f"This app has reached the maximum of {MAX_VULNS_PER_APP} vulnerabilities"
        )

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
            _cap(vuln_data.get("vuln_id"), "vuln_id"),
            _cap(vuln_data.get("title"), "title"),
            vuln_data.get("severity"),
            _cap(vuln_data.get("vuln_type"), "vuln_type"),
            _cap(vuln_data.get("http_method"), "http_method"),
            _cap(vuln_data.get("url"), "url"),
            _cap(vuln_data.get("parameter"), "parameter"),
            _cap(vuln_data.get("filename"), "filename"),
            line_number,
            _cap(vuln_data.get("description"), "description"),
            _cap(vuln_data.get("code_location"), "code_location"),
            _cap(vuln_data.get("poc"), "poc"),
            _cap(vuln_data.get("remediation"), "remediation"),
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
            _cap(vuln_data.get("vuln_id"), "vuln_id"),
            _cap(vuln_data.get("title"), "title"),
            vuln_data.get("severity"),
            _cap(vuln_data.get("vuln_type"), "vuln_type"),
            _cap(vuln_data.get("http_method"), "http_method"),
            _cap(vuln_data.get("url"), "url"),
            _cap(vuln_data.get("parameter"), "parameter"),
            _cap(vuln_data.get("filename"), "filename"),
            line_number,
            _cap(vuln_data.get("description"), "description"),
            _cap(vuln_data.get("code_location"), "code_location"),
            _cap(vuln_data.get("poc"), "poc"),
            _cap(vuln_data.get("remediation"), "remediation"),
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


def _valid_vuln_rows(vulns_data: list) -> int:
    """Count rows that would import (a dict with a non-empty title)."""
    return sum(1 for v in vulns_data if isinstance(v, dict) and v.get("title"))


async def import_vulns(db, user, app_id: int, vulns_data: list) -> dict:
    """Bulk-import vulnerabilities from a list of dicts (parsed JSON/CSV).

    Returns an audit dict ``{imported, skipped_over_cap, truncated_fields}``:
    - ``imported``        — rows written
    - ``skipped_over_cap``— valid rows dropped because the per-app cap
                            (``MAX_VULNS_PER_APP``) was reached
    - ``truncated_fields``— field values shortened to their length cap
    The last two make the otherwise-silent caps auditable so a caller can warn
    the user when data was dropped or trimmed.

    Raises ``ValueError`` if app not found.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    if not vulns_data:
        return {"imported": 0, "skipped_over_cap": 0, "truncated_fields": 0}

    # Get existing vuln count for auto-generating vuln_ids and for enforcing
    # the per-app cap. Bulk import is the primary flood vector, so we stop at
    # the cap rather than reject the whole batch — a partial import with a
    # clear count beats failing an otherwise-valid upload.
    cursor = await db.execute(
        "SELECT COUNT(*) as count FROM vulnerabilities WHERE app_id = ?",
        (app_id,),
    )
    existing_count = (await cursor.fetchone())["count"]
    budget = MAX_VULNS_PER_APP - existing_count
    if budget <= 0:
        # Already full: every valid row is dropped over the cap.
        return {
            "imported": 0,
            "skipped_over_cap": _valid_vuln_rows(vulns_data),
            "truncated_fields": 0,
        }

    def _safe_str(value) -> str:
        """Coerce to a str that SQLite can bind. Lone surrogates (which can
        appear in attacker-controlled JSON/CSV) make the sqlite3 binder raise
        UnicodeEncodeError mid-loop; replacing them keeps the import going
        and prevents the raw codec message from reaching the response
        (vuln-0022)."""
        if value is None:
            return ""
        s = value if isinstance(value, str) else str(value)
        return s.encode("utf-8", errors="replace").decode("utf-8")

    imported = 0
    skipped_over_cap = 0
    truncated_fields = 0
    for i, v in enumerate(vulns_data):
        if not isinstance(v, dict):
            continue
        if not v.get("title"):
            continue
        if imported >= budget:
            # per-app cap reached — keep counting valid rows we had to drop
            # so the caller can tell the user how much didn't fit.
            skipped_over_cap += 1
            continue

        vuln_id = v.get("vuln_id") or f"V-{existing_count + i + 1:03d}"
        severity = (v.get("severity") or "medium")
        severity = severity.lower() if isinstance(severity, str) else "medium"
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        line_number = v.get("line_number")
        if line_number:
            try:
                line_number = int(line_number)
            except (ValueError, TypeError):
                line_number = None

        stats = {"truncated": 0}
        await db.execute(
            """INSERT INTO vulnerabilities
               (app_id, vuln_id, title, severity, vuln_type, http_method, url,
                parameter, filename, line_number, description, code_location,
                poc, remediation, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                app_id,
                _cap_field(_safe_str(vuln_id), "vuln_id", stats),
                _cap_field(_safe_str(v.get("title")), "title", stats),
                severity,
                _cap_field(_safe_str(v.get("vuln_type")), "vuln_type", stats),
                _cap_field(_safe_str(v.get("http_method")), "http_method", stats),
                _cap_field(_safe_str(v.get("url")), "url", stats),
                _cap_field(_safe_str(v.get("parameter")), "parameter", stats),
                _cap_field(_safe_str(v.get("filename")), "filename", stats),
                line_number,
                _cap_field(_safe_str(v.get("description")), "description", stats),
                _cap_field(_safe_str(v.get("code_location")), "code_location", stats),
                _cap_field(_safe_str(v.get("poc")), "poc", stats),
                _cap_field(_safe_str(v.get("remediation")), "remediation", stats),
                user["sub"],
            ),
        )
        truncated_fields += stats["truncated"]
        imported += 1

    await db.commit()
    return {
        "imported": imported,
        "skipped_over_cap": skipped_over_cap,
        "truncated_fields": truncated_fields,
    }
