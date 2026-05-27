from __future__ import annotations

from app.dependencies import get_team_role


# ---------------------------------------------------------------------------
# Permission helper
# ---------------------------------------------------------------------------

async def _check_scan_write(db, user, scan, app) -> None:
    """Raise PermissionError if user cannot write to this scan."""
    if not user:
        raise PermissionError("Not authenticated")
    if user["role"] == "admin":
        return
    if scan["submitted_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return
    raise PermissionError("You don't have write access to this scan")


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

async def list_labels(db) -> list:
    """All labels ordered by name."""
    cursor = await db.execute("SELECT id, name, color FROM labels ORDER BY name")
    return [dict(row) for row in await cursor.fetchall()]


import re

_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$")


def _validate_color(color: str) -> str:
    """Reject anything other than a hex color so the value cannot be used
    as a CSS-injection vehicle when rendered into a style attribute
    (vuln-0021)."""
    color = (color or "").strip()
    if not color:
        return "#f97316"
    if not _COLOR_RE.match(color):
        raise ValueError("color must be a #hex value")
    return color


async def add_label_to_scan(db, user, scan_id: int, name: str, color: str = "#f97316") -> dict:
    """Attach an existing label to a scan. Returns the label dict.

    Non-admin callers can only attach labels that already exist; creating
    a new label name is an admin-only operation that must go through
    ``POST /api/admin/labels`` (vuln-0021).
    """
    if not name or not name.strip():
        raise ValueError("Label name required")
    name = name.strip()
    color = _validate_color(color)

    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = await cursor.fetchone()
    if not scan:
        raise ValueError("Scan not found")

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
    app = await cursor.fetchone()
    await _check_scan_write(db, user, scan, app)

    cursor = await db.execute(
        "SELECT id, name, color FROM labels WHERE name = ?", (name,)
    )
    existing = await cursor.fetchone()
    if existing:
        label = dict(existing)
    else:
        if user.get("role") != "admin":
            raise PermissionError(
                "Only admins can create new labels; pick an existing label name"
            )
        await db.execute(
            "INSERT INTO labels (name, color) VALUES (?, ?)",
            (name, color),
        )
        cursor = await db.execute(
            "SELECT id, name, color FROM labels WHERE name = ?", (name,)
        )
        label = dict(await cursor.fetchone())

    # Link to scan
    await db.execute(
        "INSERT OR IGNORE INTO scan_labels (scan_id, label_id) VALUES (?, ?)",
        (scan_id, label["id"]),
    )
    await db.commit()

    return label


async def remove_label_from_scan(db, user, scan_id: int, label_id: int) -> None:
    """Remove a label association from a scan."""
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = await cursor.fetchone()
    if not scan:
        raise ValueError("Scan not found")

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
    app = await cursor.fetchone()
    await _check_scan_write(db, user, scan, app)

    await db.execute(
        "DELETE FROM scan_labels WHERE scan_id = ? AND label_id = ?",
        (scan_id, label_id),
    )
    await db.commit()


async def admin_list_labels(db) -> list:
    """All labels with scan_count, ordered by name."""
    cursor = await db.execute(
        """SELECT l.*, (SELECT COUNT(*) FROM scan_labels WHERE label_id = l.id) as scan_count
           FROM labels l ORDER BY l.name"""
    )
    return [dict(row) for row in await cursor.fetchall()]


async def admin_create_label(db, name: str, color: str) -> dict:
    """Create a new label. Returns the label dict."""
    name = (name or "").strip()
    color = _validate_color(color)
    if not name:
        raise ValueError("Label name required")

    await db.execute(
        "INSERT OR IGNORE INTO labels (name, color) VALUES (?, ?)",
        (name, color),
    )
    await db.commit()

    cursor = await db.execute(
        "SELECT id, name, color FROM labels WHERE name = ?", (name,)
    )
    return dict(await cursor.fetchone())


async def admin_update_label(db, label_id: int, updates: dict) -> None:
    """Update a label's name and/or color."""
    clean = {}
    if "name" in updates and updates["name"] and updates["name"].strip():
        clean["name"] = updates["name"].strip()
    if "color" in updates and updates["color"]:
        clean["color"] = _validate_color(updates["color"])

    if not clean:
        raise ValueError("No valid updates provided")

    set_clause = ", ".join(f"{k}=?" for k in clean)
    values = list(clean.values()) + [label_id]
    await db.execute(f"UPDATE labels SET {set_clause} WHERE id=?", values)
    await db.commit()


async def admin_delete_label(db, label_id: int) -> None:
    """Delete a label and all its scan associations."""
    await db.execute("DELETE FROM scan_labels WHERE label_id = ?", (label_id,))
    await db.execute("DELETE FROM labels WHERE id = ?", (label_id,))
    await db.commit()
