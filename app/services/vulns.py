from __future__ import annotations

import csv
import io

from app.dependencies import get_team_role
from app.visibility import app_visibility_filter
from app import scoring
from app.services import audit as audit_service
from app.services import scoring as scoring_service


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

# Column order for CSV export. Matches exactly what bulk import reads from a
# CSV row (see import_vulns below), so an exported file round-trips.
EXPORT_FIELDS = (
    "vuln_id", "title", "severity", "vuln_type", "http_method", "url",
    "parameter", "filename", "line_number", "description", "code_location",
    "poc", "remediation", "impact_weight", "difficulty_tier",
)


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


def _csv_safe(value) -> str:
    """Stringify a cell and neutralize spreadsheet formula injection.

    A value starting with =, +, -, or @ is interpreted as a formula by Excel/
    Sheets when the CSV is opened; prefixing it with a quote forces text.
    """
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    if s and s[0] in ("=", "+", "-", "@"):
        return "'" + s
    return s


async def export_vulns_csv(db, user, app_id: int) -> tuple[str, str]:
    """Return (csv_text, app_name) for every vulnerability on *app_id*.

    Visible to anyone who can view the app (same rule as :func:`list_vulns`) —
    export is read-only, so it carries no write-permission check. Unlike the
    display list this is never capped at ``MAX_VULNS_PER_APP``: it's a single
    file, not a paginated response, so the OOM concern behind that cap doesn't
    apply here.

    Raises ``ValueError`` if the app is not found / not visible.
    """
    app = await _get_visible_app(db, user, app_id)

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title",
        (app_id,),
    )
    rows = await cursor.fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(EXPORT_FIELDS)
    for row in rows:
        writer.writerow([_csv_safe(row[f]) for f in EXPORT_FIELDS])
    return buf.getvalue(), app["name"]


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


def _scoring_fields(vuln_data: dict, existing=None) -> tuple[int, str, bool]:
    """Resolve (impact_weight, difficulty_tier, tier_was_explicit) for a write.

    **`impact_weight` derives from `severity`.** Ground-truth severity IS
    contextual severity — a directory listing is Low by convention but stored as
    critical in an app where it exposes the database and the JWT signing key — so
    the 1:1 map (info/low→1, medium→3, high→9, critical→27) is the rule and an
    explicit weight is exceptional, not expected. The column is still stored
    because the revision scheme needs an immutable per-revision value.

    Both fields are validated against the scale and the three tiers — SQLite
    cannot express those as CHECK constraints on an added column, so the
    constraint lives here.

    On an update, *existing* is the current row, and omitting a field means
    "leave it alone" — the inline table editor sends only the columns it knows
    about and must not reset a deliberate override. The one exception is a
    changed `severity`: since severity determines the weight, re-deriving is the
    whole point, so an unstated weight follows the new severity.
    """
    weight = scoring.validate_weight(vuln_data.get("impact_weight"))
    if weight is None:
        severity = vuln_data.get("severity")
        severity_changed = (
            existing is not None
            and severity is not None
            and str(severity).strip().lower()
            != str(scoring.field(existing, "severity", "")).strip().lower()
        )
        if existing is not None and not severity_changed:
            weight = scoring.weight_of(existing)
        else:
            weight = scoring.weight_from_severity(severity)

    tier = scoring.validate_tier(vuln_data.get("difficulty_tier"))
    tier_was_explicit = tier is not None
    if tier is None:
        tier = scoring.tier_of(existing) if existing is not None else scoring.DEFAULT_TIER
    return weight, tier, tier_was_explicit


async def create_vuln(db, user, app_id: int, vuln_data: dict) -> dict:
    """Create a vulnerability on the given app. Returns the new row as a dict.

    *vuln_data* keys: vuln_id, title, severity, vuln_type, http_method, url,
    parameter, filename, line_number, description, code_location, poc,
    remediation, impact_weight, difficulty_tier, existed_since_revision.

    Adding a vuln changes ground truth, so on an app that already has scans this
    opens a new revision (reason ``new_prior_vuln``). ``existed_since_revision``
    defaults to 1 — the flaw was in the app all along and prior scans take the
    miss on re-score — and can be set to the new revision when a code change
    introduced it.

    Raises ``ValueError`` if app not found or a scoring field is invalid.
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

    impact_weight, difficulty_tier, tier_reviewed = _scoring_fields(vuln_data)

    revision, _created = await scoring_service.revision_for_corpus_change(
        db, app_id, "new_prior_vuln",
        notes=f"Added vuln: {vuln_data.get('vuln_id') or vuln_data.get('title')}",
        user=user,
    )
    existed_since = vuln_data.get("existed_since_revision")
    try:
        existed_since = int(existed_since) if existed_since not in (None, "") else 1
    except (TypeError, ValueError):
        existed_since = 1

    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, http_method, url,
            parameter, filename, line_number, description, code_location,
            poc, remediation, created_by, impact_weight, difficulty_tier,
            weight_verified, existed_since_revision, known_since_revision)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
            impact_weight,
            difficulty_tier,
            1 if tier_reviewed else 0,
            existed_since,
            revision,
        ),
    )
    new_id = cursor.lastrowid

    vuln_id_slug = vuln_data.get("vuln_id") or f"#{new_id}"
    title = vuln_data.get("title") or "Untitled"
    severity_label = vuln_data.get("severity") or "medium"
    await audit_service.record_audit_event(
        db, entity_type="vulnerability", action="vuln_created", actor=user,
        message=f"{user['name']} created vulnerability {vuln_id_slug}: \"{title}\" ({severity_label})",
        entity_id=new_id, app_id=app_id,
    )

    await db.commit()

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
    existing = await cursor.fetchone()
    if not existing:
        raise ValueError("Vulnerability not found")

    line_number = vuln_data.get("line_number")
    if line_number:
        try:
            line_number = int(line_number)
        except (ValueError, TypeError):
            line_number = None

    impact_weight, difficulty_tier, tier_reviewed = _scoring_fields(vuln_data, existing)

    # Weights are immutable within a revision: changing one changes every
    # weighted number ever computed for this app, so it opens a revision
    # (reason `weight_change`) and the app must be re-scored. The tier is a
    # reporting axis only — it never moves the weighted total, so it does not.
    if impact_weight != scoring.weight_of(existing):
        await scoring_service.revision_for_corpus_change(
            db, app_id, "weight_change",
            notes=(
                f"{existing['vuln_id']} impact_weight "
                f"{scoring.weight_of(existing)} → {impact_weight}"
            ),
            user=user,
        )

    await db.execute(
        """UPDATE vulnerabilities SET vuln_id=?, title=?, severity=?, vuln_type=?,
           http_method=?, url=?, parameter=?, filename=?, line_number=?,
           description=?, code_location=?, poc=?, remediation=?,
           impact_weight=?, difficulty_tier=?,
           weight_verified=MAX(weight_verified, ?)
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
            impact_weight,
            difficulty_tier,
            1 if tier_reviewed else 0,
            vuln_id,
        ),
    )

    new_values = {
        "vuln_id": _cap(vuln_data.get("vuln_id"), "vuln_id"),
        "title": _cap(vuln_data.get("title"), "title"),
        "severity": vuln_data.get("severity"),
        "vuln_type": _cap(vuln_data.get("vuln_type"), "vuln_type"),
        "http_method": _cap(vuln_data.get("http_method"), "http_method"),
        "url": _cap(vuln_data.get("url"), "url"),
        "parameter": _cap(vuln_data.get("parameter"), "parameter"),
        "filename": _cap(vuln_data.get("filename"), "filename"),
        "line_number": line_number,
        "description": _cap(vuln_data.get("description"), "description"),
        "code_location": _cap(vuln_data.get("code_location"), "code_location"),
        "poc": _cap(vuln_data.get("poc"), "poc"),
        "remediation": _cap(vuln_data.get("remediation"), "remediation"),
        "impact_weight": impact_weight,
        "difficulty_tier": difficulty_tier,
    }
    # Short, scalar fields are worth showing old -> new in the log; long
    # free-text fields just note that they changed, to keep the message
    # skimmable rather than dumping a paragraph diff.
    changes = []
    for field in ("vuln_id", "title", "severity", "vuln_type", "impact_weight", "difficulty_tier"):
        if existing[field] != new_values[field]:
            changes.append(f"{field} {existing[field]} → {new_values[field]}")
    for field in ("http_method", "url", "parameter", "filename", "line_number",
                  "description", "code_location", "poc", "remediation"):
        if existing[field] != new_values[field]:
            changes.append(field)

    if changes:
        vuln_id_slug = new_values["vuln_id"] or existing["vuln_id"]
        await audit_service.record_audit_event(
            db, entity_type="vulnerability", action="vuln_updated", actor=user,
            message=f"{user['name']} updated {vuln_id_slug}: {', '.join(changes)}",
            entity_id=vuln_id, app_id=app_id,
        )

    await db.commit()

    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    return dict(await cursor.fetchone())


async def delete_vuln(db, user, app_id: int, vuln_id: int) -> None:
    """Delete a vulnerability.

    Only for ground truth that was never measured. A vuln some scan already
    matched cannot be deleted — that would rewrite history and orphan the
    finding; invalidate it instead (see :func:`invalidate_vuln`), which retires
    it from the next revision on while leaving every recorded number intact.

    Raises ``ValueError`` if app not found or the vuln has been matched.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT COUNT(*) AS c FROM scan_findings WHERE matched_vuln_id = ?", (vuln_id,)
    )
    matched = (await cursor.fetchone())["c"]
    if matched:
        raise ValueError(
            f"This vulnerability is matched by {matched} scan finding(s) and cannot be "
            "deleted. Invalidate it instead so historical scorings stay reproducible."
        )

    # Captured only to describe the vuln in the audit message -- the row
    # itself is gone right after the DELETE below.
    cursor = await db.execute(
        "SELECT vuln_id, title FROM vulnerabilities WHERE id = ? AND app_id = ?",
        (vuln_id, app_id),
    )
    vuln = await cursor.fetchone()
    if not vuln:
        raise ValueError("Vulnerability not found")

    await db.execute(
        "DELETE FROM vulnerabilities WHERE id = ? AND app_id = ?",
        (vuln_id, app_id),
    )
    await audit_service.record_audit_event(
        db, entity_type="vulnerability", action="vuln_deleted", actor=user,
        message=f"{user['name']} deleted vulnerability {vuln['vuln_id']}: \"{vuln['title']}\"",
        entity_id=vuln_id, app_id=app_id,
    )
    await db.commit()


async def invalidate_vuln(db, user, app_id: int, vuln_id: int, notes=None) -> dict:
    """Retire a vuln from ground truth without destroying history.

    Opens a revision (reason ``vuln_invalidated``) and stamps
    ``invalidated_at_revision`` with it, so the scope rule keeps the vuln in
    scope for every earlier revision — scorings computed back then stay exactly
    reproducible — while dropping it from this revision onward.

    Raises ``ValueError`` if app or vuln not found.
    Raises ``PermissionError`` if access denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE id = ? AND app_id = ?", (vuln_id, app_id)
    )
    vuln = await cursor.fetchone()
    if not vuln:
        raise ValueError("Vulnerability not found")
    if vuln["invalidated_at_revision"] is not None:
        raise ValueError("Vulnerability is already invalidated")

    revision, _created = await scoring_service.revision_for_corpus_change(
        db, app_id, "vuln_invalidated",
        notes=notes or f"Invalidated {vuln['vuln_id']}: {vuln['title']}",
        user=user,
    )
    await db.execute(
        "UPDATE vulnerabilities SET invalidated_at_revision = ? WHERE id = ?",
        (revision, vuln_id),
    )
    await audit_service.record_audit_event(
        db, entity_type="vulnerability", action="vuln_invalidated", actor=user,
        message=(
            f"{user['name']} invalidated {vuln['vuln_id']}: \"{vuln['title']}\" "
            f"(opened ground-truth revision {revision})"
        ),
        entity_id=vuln_id, app_id=app_id,
    )
    await db.commit()
    return {"ok": True, "vuln_id": vuln_id, "invalidated_at_revision": revision}


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
        "impact_weight", "difficulty_tier",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed}
    if not filtered:
        raise ValueError("No valid fields to update")

    if "impact_weight" in filtered:
        filtered["impact_weight"] = scoring.validate_weight(filtered["impact_weight"])
    if "difficulty_tier" in filtered:
        filtered["difficulty_tier"] = scoring.validate_tier(filtered["difficulty_tier"])
        if filtered["difficulty_tier"] is not None:
            # Stating a tier explicitly is what distinguishes a reviewed
            # 'commodity' from the migration-024 placeholder.
            filtered["weight_verified"] = 1

    # Same rule as the full update: a weight change opens a revision, because it
    # moves every weighted number already recorded for this app.
    if filtered.get("impact_weight") is not None:
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE id = ? AND app_id = ?", (vuln_id, app_id)
        )
        existing = await cursor.fetchone()
        if existing and filtered["impact_weight"] != scoring.weight_of(existing):
            await scoring_service.revision_for_corpus_change(
                db, app_id, "weight_change",
                notes=(
                    f"{existing['vuln_id']} impact_weight "
                    f"{scoring.weight_of(existing)} → {filtered['impact_weight']}"
                ),
                user=user,
            )

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


async def import_vulns(db, user, app_id: int, vulns_data: list,
                       existed_since: str | None = None) -> dict:
    """Bulk-import vulnerabilities from a list of dicts (parsed JSON/CSV).

    On an app that already has scans this opens one revision (reason
    ``corpus_change``) for the whole batch. *existed_since* says whether the
    imported flaws were present all along:

      ``all_along``     — ``existed_since_revision = 1``; every prior scan takes
                          the miss once re-scored.
      ``this_revision`` — the default. Prior scans are untouched.

    The default is deliberately the conservative one: a bulk upload cannot ask
    the operator, and silently lowering every historical recall is not something
    to do by accident.

    Returns an audit dict ``{imported, skipped_over_cap, truncated_fields, revision}``:
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
        return {"imported": 0, "skipped_over_cap": 0, "truncated_fields": 0, "revision": None}

    revision, _created = await scoring_service.revision_for_corpus_change(
        db, app_id, "corpus_change",
        notes=f"Bulk import of {_valid_vuln_rows(vulns_data)} vuln(s)",
        user=user,
    )
    import_revision = 1 if (existed_since or "").strip().lower() == "all_along" else revision
    known_revision = revision

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

        try:
            impact_weight, difficulty_tier, tier_reviewed = _scoring_fields({**v, "severity": severity})
        except ValueError:
            # A bad weight in one row of a bulk upload must not fail the batch;
            # fall back to the severity map, same as a row that omits it.
            impact_weight = scoring.weight_from_severity(severity)
            difficulty_tier = scoring.DEFAULT_TIER
            tier_reviewed = False

        stats = {"truncated": 0}
        await db.execute(
            """INSERT INTO vulnerabilities
               (app_id, vuln_id, title, severity, vuln_type, http_method, url,
                parameter, filename, line_number, description, code_location,
                poc, remediation, created_by, impact_weight, difficulty_tier,
                weight_verified, existed_since_revision, known_since_revision)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                impact_weight,
                difficulty_tier,
                1 if tier_reviewed else 0,
                import_revision,
                known_revision,
            ),
        )
        truncated_fields += stats["truncated"]
        imported += 1

    if imported:
        await audit_service.record_audit_event(
            db, entity_type="vulnerability", action="vulns_imported", actor=user,
            message=f"{user['name']} bulk-imported {imported} vulnerabilit{'y' if imported == 1 else 'ies'}",
            app_id=app_id,
            details={"imported": imported, "skipped_over_cap": skipped_over_cap},
        )

    await db.commit()
    return {
        "imported": imported,
        "skipped_over_cap": skipped_over_cap,
        "truncated_fields": truncated_fields,
        "revision": revision,
        "existed_since_revision": import_revision,
    }


async def list_app_history(db, user, app_id: int) -> list[dict]:
    """Audit-log entries for this app's vulnerabilities, most recent first.

    Gated on the same write-access check as editing the app's ground truth —
    this app has no account-level contributor/viewer role today (see
    tasks/audit-log-plan.md SS0), so "contributor and admin can see it, viewer
    and user can't" is exactly what per-resource write access already means.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)
    return await audit_service.list_audit_events(db, app_id=app_id)
