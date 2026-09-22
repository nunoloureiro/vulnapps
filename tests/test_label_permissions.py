"""Who can create a brand-new label — service-level tests against a freshly
migrated throwaway database, following the convention in
tests/test_audit_log.py.

Creating a label used to require a *global* admin, full stop — even a team
admin/contributor with full scan-write access to the app in question, or the
creator of their own private app, couldn't coin a new label name; they could
only attach ones that already existed. These tests lock in the fix: team
admins/contributors can now create new labels on their own team's apps. A
private app's own creator (the one case where someone can submit a scan
without being a global admin or any team's admin/contributor — see
_check_scan_submit) still cannot, unchanged from before.

Team role "view" has no scan-write access at all (can't even attach an
existing label to someone else's scan), so it isn't a useful case for
isolating the label-creation restriction specifically — it's covered by
tests/test_api_endpoints.py's broader write-access checks instead.
"""

import os
import tempfile

import aiosqlite
import pytest_asyncio

from app.database import run_migrations
from app.services import labels as labels_service
from app.services import scans as scans_service

ADMIN = {"sub": 1, "name": "Admin", "role": "admin", "scope": "full"}
CONTRIBUTOR = {"sub": 2, "name": "Contributor", "role": "user", "scope": "full"}
OUTSIDER = {"sub": 3, "name": "Outsider", "role": "user", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "labels.db")
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    for u in (ADMIN, CONTRIBUTOR, OUTSIDER):
        await conn.execute(
            "INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, 'x', ?)",
            (u["sub"], u["name"], f"user{u['sub']}@example.com", u["role"]),
        )
    await conn.commit()
    yield conn
    await conn.close()


async def make_team_app(db, member_role="contributor"):
    """A team-visibility app with CONTRIBUTOR as a team member at the given
    team role (OUTSIDER is deliberately not on this team at all)."""
    cursor = await db.execute(
        "INSERT INTO teams (name, created_by) VALUES ('Team', ?)", (ADMIN["sub"],)
    )
    team_id = cursor.lastrowid
    await db.execute(
        "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)",
        (team_id, CONTRIBUTOR["sub"], member_role),
    )
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility, team_id) "
        "VALUES ('Target', '1.0', ?, 'team', ?)",
        (ADMIN["sub"], team_id),
    )
    await db.commit()
    return cursor.lastrowid


async def make_private_app(db, owner):
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility) VALUES ('Solo', '1.0', ?, 'private')",
        (owner["sub"],),
    )
    await db.commit()
    return cursor.lastrowid


async def make_scan(db, app_id, submitted_by=ADMIN):
    return await scans_service.submit_scan(
        db, submitted_by, app_id,
        scanner_name="COS", scan_date="2026-09-17", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[],
    )


async def scan_label_names(db, scan_id):
    cursor = await db.execute(
        "SELECT l.name FROM labels l JOIN scan_labels sl ON sl.label_id = l.id WHERE sl.scan_id = ?",
        (scan_id,),
    )
    return {row["name"] for row in await cursor.fetchall()}


# ---------------------------------------------------------------------------
# labels_service.add_label_to_scan
# ---------------------------------------------------------------------------

async def test_team_contributor_can_create_a_new_label(db):
    app_id = await make_team_app(db, member_role="contributor")
    scan_id = await make_scan(db, app_id)
    label = await labels_service.add_label_to_scan(db, CONTRIBUTOR, scan_id, "brand-new-label")
    assert label["name"] == "brand-new-label"


async def test_team_admin_can_create_a_new_label(db):
    """Team-level admin, distinct from the global 'admin' account role —
    this also used to be rejected pre-fix."""
    app_id = await make_team_app(db, member_role="admin")
    scan_id = await make_scan(db, app_id)
    label = await labels_service.add_label_to_scan(db, CONTRIBUTOR, scan_id, "brand-new-label")
    assert label["name"] == "brand-new-label"


async def test_private_apps_own_creator_still_cannot_create_a_new_label(db):
    """Unchanged from before the fix: submitting your own private app's scan
    grants write access to it, but not the (separate, still-gated) ability
    to coin a brand-new label name."""
    app_id = await make_private_app(db, OUTSIDER)
    scan_id = await make_scan(db, app_id, submitted_by=OUTSIDER)
    try:
        await labels_service.add_label_to_scan(db, OUTSIDER, scan_id, "brand-new-label")
        assert False, "expected PermissionError"
    except PermissionError:
        pass


async def test_private_apps_own_creator_can_still_attach_an_existing_label(db):
    """The fix only touches *creating* a label; attaching one that already
    exists was never restricted and must stay that way."""
    app_id = await make_private_app(db, OUTSIDER)
    scan_id = await make_scan(db, app_id, submitted_by=OUTSIDER)
    await labels_service.add_label_to_scan(db, ADMIN, scan_id, "already-exists")
    label = await labels_service.add_label_to_scan(db, OUTSIDER, scan_id, "already-exists")
    assert label["name"] == "already-exists"


async def test_non_team_member_cannot_touch_labels_at_all(db):
    """A stranger with no relationship to the app has no scan-write access
    in the first place -- this predates the fix and is unrelated to it, but
    confirms the fix didn't accidentally widen write access itself."""
    app_id = await make_team_app(db)
    scan_id = await make_scan(db, app_id)
    try:
        await labels_service.add_label_to_scan(db, OUTSIDER, scan_id, "already-exists")
        assert False, "expected PermissionError"
    except PermissionError:
        pass


# ---------------------------------------------------------------------------
# scans_service.submit_scan's inline `labels=[...]` path
# ---------------------------------------------------------------------------

async def test_submit_scan_lets_a_contributor_create_a_label_inline(db):
    app_id = await make_team_app(db, member_role="contributor")
    scan_id = await scans_service.submit_scan(
        db, CONTRIBUTOR, app_id,
        scanner_name="COS", scan_date="2026-09-17", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[], labels=["fresh-from-import"],
    )
    assert "fresh-from-import" in await scan_label_names(db, scan_id)


async def test_submit_scan_silently_skips_a_new_label_for_a_private_apps_own_creator(db):
    """Unknown label names are silently skipped (not an error) so a
    well-behaved CI integration with a low-privilege key doesn't blow up —
    predates the contributor fix and must keep working. A private app's own
    creator is the one case where submit_scan succeeds without the caller
    being a global admin or any team's admin/contributor, so new-label
    creation should still be skipped for them specifically."""
    app_id = await make_private_app(db, OUTSIDER)
    scan_id = await scans_service.submit_scan(
        db, OUTSIDER, app_id,
        scanner_name="COS", scan_date="2026-09-17", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[], labels=["should-be-skipped"],
    )
    assert "should-be-skipped" not in await scan_label_names(db, scan_id)
