"""CRUD for an app's known false positives (see migrations/044_known_false_positives.sql).

A known FP is a non-issue scanners keep flagging on this app: a planted decoy
(``source='decoy'``, D-n ids from the app's catalog) or an FP a reviewer chose
to remember (``source='reviewed'``, FP-NNN ids). Linking a finding to one
copies the entry's ``fp_id`` into the finding's ``fp_group`` and its
``penalty_weight`` into ``fp_impact_weight``, so the scorer treats it as an
ordinary clustered FP. This module keeps those copies in sync when the entry
changes.

Known FPs are not revisioned: like a reviewer's own FP decisions, they change
review state, not the ground truth recall is measured against.
"""

from __future__ import annotations

import re

from app import scoring
from app.services import audit as audit_service
from app.services.vulns import _get_visible_app, _require_app_write

SOURCES = ("decoy", "reviewed")
_TEXT_FIELDS = ("title", "vuln_type", "http_method", "url", "parameter", "filename", "description")


async def list_known_fps(db, user, app_id: int) -> list[dict]:
    """Known FPs for an app, each with ``finding_count`` (linked findings).

    Raises ``ValueError`` if the app is not found / not visible.
    """
    await _get_visible_app(db, user, app_id)
    return await _rows(db, app_id)


async def _rows(db, app_id: int) -> list[dict]:
    cursor = await db.execute(
        """SELECT k.*, (SELECT COUNT(*) FROM scan_findings sf WHERE sf.known_fp_id = k.id)
                  AS finding_count
           FROM known_false_positives k WHERE k.app_id = ?""",
        (app_id,),
    )
    rows = [dict(row) for row in await cursor.fetchall()]
    # D2 before D10, decoys before reviewed ones.
    rows.sort(key=lambda r: (r["source"] != "decoy", _natural_key(r["fp_id"])))
    return rows


def _natural_key(fp_id: str):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", fp_id)]


async def get_known_fp(db, app_id: int, known_fp_pk: int):
    cursor = await db.execute(
        "SELECT * FROM known_false_positives WHERE id = ? AND app_id = ?", (known_fp_pk, app_id)
    )
    return await cursor.fetchone()


async def _next_reviewed_id(db, app_id: int) -> str:
    cursor = await db.execute(
        "SELECT fp_id FROM known_false_positives WHERE app_id = ? AND fp_id LIKE 'FP-%'", (app_id,)
    )
    numbers = [int(m.group(1)) for row in await cursor.fetchall()
               if (m := re.fullmatch(r"FP-(\d+)", row["fp_id"]))]
    return f"FP-{max(numbers, default=0) + 1:03d}"


def _clean(data: dict, existing=None) -> dict:
    """Validated column values for an insert/update. *existing* fills gaps."""
    out = {}
    for key in _TEXT_FIELDS:
        if key in data:
            value = data[key]
            out[key] = str(value).strip() or None if value is not None else None
        else:
            out[key] = existing[key] if existing is not None else None
    if not out["title"]:
        raise ValueError("title is required for a known false positive")

    if "penalty_weight" in data:
        penalty = data["penalty_weight"]
        if penalty is not None and (type(penalty) is not int or penalty not in scoring.WEIGHT_SCALE):
            raise ValueError("penalty_weight must be null or one of 1, 3, 9, 27")
        out["penalty_weight"] = penalty
    else:
        out["penalty_weight"] = existing["penalty_weight"] if existing is not None else None

    source = data.get("source") or (existing["source"] if existing is not None else "reviewed")
    if source not in SOURCES:
        raise ValueError(f"source must be one of {list(SOURCES)}")
    out["source"] = source
    return out


async def insert_known_fp(db, user, app_id: int, data: dict, created_from_finding_id=None) -> int:
    """Insert without committing or checking access. Returns the new PK.

    Shared by ``create_known_fp`` and marking a finding FP with "remember",
    which runs inside the finding's own transaction.
    """
    values = _clean(data)
    fp_id = (data.get("fp_id") or "").strip().upper()
    if not fp_id:
        if values["source"] == "decoy":
            raise ValueError("fp_id is required for a decoy (its catalog id, e.g. D1)")
        fp_id = await _next_reviewed_id(db, app_id)
    try:
        cursor = await db.execute(
            """INSERT INTO known_false_positives
               (app_id, fp_id, title, vuln_type, http_method, url, parameter, filename,
                description, penalty_weight, source, created_from_finding_id, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (app_id, fp_id, values["title"], values["vuln_type"], values["http_method"],
             values["url"], values["parameter"], values["filename"], values["description"],
             values["penalty_weight"], values["source"], created_from_finding_id, user["sub"]),
        )
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ValueError(f"Known false positive id '{fp_id}' already exists on this app")
        raise
    known_fp_pk = cursor.lastrowid
    await audit_service.record_audit_event(
        db, entity_type="known_fp", action="known_fp_created", actor=user,
        message=f"{user['name']} added known false positive {fp_id}: \"{values['title']}\"",
        entity_id=known_fp_pk, app_id=app_id,
    )
    return known_fp_pk


async def create_known_fp(db, user, app_id: int, data: dict) -> dict:
    """Register a known FP. Returns the created row.

    Raises ``ValueError`` on invalid data / unknown app, ``PermissionError``
    if access is denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)
    known_fp_pk = await insert_known_fp(db, user, app_id, data)
    await db.commit()
    return next(r for r in await _rows(db, app_id) if r["id"] == known_fp_pk)


async def update_known_fp(db, user, app_id: int, known_fp_pk: int, data: dict) -> dict:
    """Update a known FP, renaming it if ``fp_id`` is given (FP-007 -> D8).

    The linked findings' fp_group/fp_impact_weight follow the entry, so a
    rename or penalty change rescoring every scan that hit it is deliberate.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)
    existing = await get_known_fp(db, app_id, known_fp_pk)
    if not existing:
        raise ValueError("Known false positive not found")

    values = _clean(data, existing)
    fp_id = (data.get("fp_id") or existing["fp_id"]).strip().upper()
    try:
        await db.execute(
            """UPDATE known_false_positives SET fp_id = ?, title = ?, vuln_type = ?,
                   http_method = ?, url = ?, parameter = ?, filename = ?, description = ?,
                   penalty_weight = ?, source = ?, updated_at = datetime('now')
               WHERE id = ?""",
            (fp_id, values["title"], values["vuln_type"], values["http_method"], values["url"],
             values["parameter"], values["filename"], values["description"],
             values["penalty_weight"], values["source"], known_fp_pk),
        )
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ValueError(f"Known false positive id '{fp_id}' already exists on this app")
        raise
    await db.execute(
        "UPDATE scan_findings SET fp_group = ?, fp_impact_weight = ? WHERE known_fp_id = ?",
        (fp_id, values["penalty_weight"], known_fp_pk),
    )

    changes = []
    if fp_id != existing["fp_id"]:
        changes.append(f"renamed {existing['fp_id']} → {fp_id}")
    if values["penalty_weight"] != existing["penalty_weight"]:
        changes.append(f"penalty {existing['penalty_weight'] or 'unreviewed'} → "
                       f"{values['penalty_weight'] or 'unreviewed'}")
    if values["source"] != existing["source"]:
        changes.append(f"source {existing['source']} → {values['source']}")
    await audit_service.record_audit_event(
        db, entity_type="known_fp", action="known_fp_updated", actor=user,
        message=f"{user['name']} updated known false positive {fp_id}: \"{values['title']}\""
                + (f" ({'; '.join(changes)})" if changes else ""),
        entity_id=known_fp_pk, app_id=app_id,
    )
    await db.commit()
    return next(r for r in await _rows(db, app_id) if r["id"] == known_fp_pk)


async def delete_known_fp(db, user, app_id: int, known_fp_pk: int) -> None:
    """Delete a known FP. Its findings stay FP, keeping the group and penalty
    they were copied, so no past score moves; they are only unlinked."""
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)
    existing = await get_known_fp(db, app_id, known_fp_pk)
    if not existing:
        raise ValueError("Known false positive not found")

    await db.execute("UPDATE scan_findings SET known_fp_id = NULL WHERE known_fp_id = ?", (known_fp_pk,))
    await db.execute("DELETE FROM known_false_positives WHERE id = ?", (known_fp_pk,))
    await audit_service.record_audit_event(
        db, entity_type="known_fp", action="known_fp_deleted", actor=user,
        message=f"{user['name']} deleted known false positive {existing['fp_id']}: \"{existing['title']}\"",
        entity_id=known_fp_pk, app_id=app_id,
    )
    await db.commit()
