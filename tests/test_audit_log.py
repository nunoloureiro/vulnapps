"""Audit/history log — service-level tests against a freshly migrated
throwaway database, following the convention in tests/test_scoring_revisions.py.
"""

import os
import tempfile

import aiosqlite
import pytest
import pytest_asyncio

from app.database import run_migrations
from app.services import audit as audit_service
from app.services import scans as scans_service
from app.services import vulns as vulns_service

ADMIN = {"sub": 1, "name": "Nuno", "role": "admin", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "audit.db")
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    await conn.execute(
        "INSERT INTO users (id, name, email, password_hash, role) "
        "VALUES (1, 'Nuno', 't@example.com', 'x', 'admin')"
    )
    await conn.commit()
    yield conn
    await conn.close()


async def make_app(db, name="Target"):
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility) VALUES (?, '1.0', 1, 'private')",
        (name,),
    )
    await db.commit()
    return cursor.lastrowid


async def add_vuln(db, app_id, slug, severity="high", weight=9, tier="commodity",
                    vuln_type="SQLi", url="/a", title=None):
    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, url, created_by,
            impact_weight, difficulty_tier, weight_verified,
            existed_since_revision, known_since_revision)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, 1, 1, 1)""",
        (app_id, slug, title or f"Vuln {slug}", severity, vuln_type, url, weight, tier),
    )
    await db.commit()
    return cursor.lastrowid


async def submit(db, app_id, findings, scanner_name="COS"):
    return await scans_service.submit_scan(
        db, ADMIN, app_id,
        scanner_name=scanner_name, scan_date="2026-09-06", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=findings,
    )


async def first_finding_id(db, scan_id):
    cursor = await db.execute(
        "SELECT id FROM scan_findings WHERE scan_id = ? ORDER BY id LIMIT 1", (scan_id,)
    )
    return (await cursor.fetchone())["id"]


# ---------------------------------------------------------------------------
# Core record/list round-trip
# ---------------------------------------------------------------------------

async def test_record_and_list_round_trip(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "title": "X"}])

    await audit_service.record_audit_event(
        db, entity_type="scan_finding", action="finding_marked_fp", actor=ADMIN,
        message="Nuno marked \"X\" as a false positive", scan_id=scan_id,
    )
    await db.commit()

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert len(entries) == 1
    assert entries[0]["message"] == "Nuno marked \"X\" as a false positive"


async def test_list_requires_exactly_one_scope(db):
    with pytest.raises(ValueError):
        await audit_service.list_audit_events(db)
    with pytest.raises(ValueError):
        await audit_service.list_audit_events(db, scan_id=1, app_id=1)


async def test_scan_scoped_and_app_scoped_entries_never_cross(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "title": "X"}])
    await audit_service.record_audit_event(
        db, entity_type="scan_finding", action="finding_marked_fp", actor=ADMIN,
        message="scan-scoped", scan_id=scan_id,
    )
    await audit_service.record_audit_event(
        db, entity_type="vulnerability", action="vuln_created", actor=ADMIN,
        message="app-scoped", app_id=app_id,
    )
    await db.commit()

    scan_entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    app_entries = await audit_service.list_audit_events(db, app_id=app_id)
    assert [e["message"] for e in scan_entries] == ["scan-scoped"]
    assert [e["message"] for e in app_entries] == ["app-scoped"]


async def test_most_recent_first(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "title": "X"}])
    for msg in ("first", "second", "third"):
        await audit_service.record_audit_event(
            db, entity_type="scan_finding", action="finding_marked_fp", actor=ADMIN,
            message=msg, scan_id=scan_id,
        )
        await db.commit()

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert [e["message"] for e in entries] == ["third", "second", "first"]


# ---------------------------------------------------------------------------
# scans.py hooks
# ---------------------------------------------------------------------------

async def test_match_finding_new_match(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "TP-014", title="Path Traversal")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "Path Traversal in Export"}])
    finding_id = await first_finding_id(db, scan_id)

    await scans_service.match_finding(db, ADMIN, scan_id, finding_id, vuln_id)

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert len(entries) == 1
    assert entries[0]["action"] == "finding_matched"
    assert "Path Traversal in Export" in entries[0]["message"]
    assert "TP-014" in entries[0]["message"]


async def test_match_finding_changed_match(db):
    app_id = await make_app(db)
    vuln_a = await add_vuln(db, app_id, "TP-001", title="A")
    vuln_b = await add_vuln(db, app_id, "TP-002", title="B")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    finding_id = await first_finding_id(db, scan_id)

    await scans_service.match_finding(db, ADMIN, scan_id, finding_id, vuln_a)
    await scans_service.match_finding(db, ADMIN, scan_id, finding_id, vuln_b)

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert len(entries) == 2
    assert entries[0]["action"] == "finding_matched"
    assert "changed the mapping" in entries[0]["message"]
    assert "TP-002" in entries[0]["message"]


async def test_match_finding_unmatch(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "TP-001", title="A")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    finding_id = await first_finding_id(db, scan_id)

    await scans_service.match_finding(db, ADMIN, scan_id, finding_id, vuln_id)
    await scans_service.match_finding(db, ADMIN, scan_id, finding_id, None)

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert len(entries) == 2
    assert entries[0]["action"] == "finding_unmatched"
    assert "removed the mapping" in entries[0]["message"]
    assert "TP-001" in entries[0]["message"]


async def test_mark_finding_fp(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    finding_id = await first_finding_id(db, scan_id)

    await scans_service.mark_finding_fp(db, ADMIN, scan_id, finding_id)

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert len(entries) == 1
    assert entries[0]["action"] == "finding_marked_fp"
    assert "false positive" in entries[0]["message"]


async def test_set_finding_ignored_both_directions(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    finding_id = await first_finding_id(db, scan_id)

    await scans_service.set_finding_ignored(db, ADMIN, scan_id, finding_id, True)
    await scans_service.set_finding_ignored(db, ADMIN, scan_id, finding_id, False)

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert len(entries) == 2
    assert entries[0]["action"] == "finding_unignored"
    assert "un-ignored" in entries[0]["message"]
    assert entries[1]["action"] == "finding_marked_ignored"
    assert "ignored" in entries[1]["message"]


async def test_promote_finding_produces_two_rows(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "XSS", "title": "Stored XSS"}])
    finding_id = await first_finding_id(db, scan_id)

    result = await scans_service.promote_finding(
        db, ADMIN, scan_id, finding_id, overrides={"existed_since": "all_along"},
    )
    new_vuln_id = result["vuln"]["id"]

    scan_entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    app_entries = await audit_service.list_audit_events(db, app_id=app_id)
    assert len(scan_entries) == 1
    assert scan_entries[0]["action"] == "finding_promoted"
    assert scan_entries[0]["entity_id"] == finding_id
    assert len(app_entries) == 1
    assert app_entries[0]["action"] == "vuln_created"
    assert app_entries[0]["entity_id"] == new_vuln_id


async def test_rematch_scan_zero_rows_when_nothing_changed(db):
    app_id = await make_app(db)
    await add_vuln(db, app_id, "TP-001", vuln_type="SQLi", url="/login")
    scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/login", "title": "SQLi"}])

    result = await scans_service.rematch_scan(db, ADMIN, scan_id)
    assert result["updated"] == 0
    assert await audit_service.list_audit_events(db, scan_id=scan_id) == []


async def test_rematch_scan_one_aggregate_row_when_updated(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "url": "/login", "title": "A"},
        {"vuln_type": "XSS", "url": "/search", "title": "B"},
    ])
    # Add matching vulns AFTER submission, so both findings start unmatched.
    await add_vuln(db, app_id, "TP-001", vuln_type="SQLi", url="/login")
    await add_vuln(db, app_id, "TP-002", vuln_type="XSS", url="/search")

    result = await scans_service.rematch_scan(db, ADMIN, scan_id)
    assert result["updated"] == 2

    entries = await audit_service.list_audit_events(db, scan_id=scan_id)
    assert len(entries) == 1  # one aggregate row, not one per finding
    assert entries[0]["action"] == "scan_rematched"
    assert "2 finding(s) changed" in entries[0]["message"]


# ---------------------------------------------------------------------------
# vulns.py hooks
# ---------------------------------------------------------------------------

async def test_create_vuln(db):
    app_id = await make_app(db)
    await vulns_service.create_vuln(db, ADMIN, app_id, {
        "vuln_id": "TP-001", "title": "SQL Injection", "severity": "critical",
    })

    entries = await audit_service.list_audit_events(db, app_id=app_id)
    assert len(entries) == 1
    assert entries[0]["action"] == "vuln_created"
    assert "TP-001" in entries[0]["message"]
    assert "critical" in entries[0]["message"]


async def test_update_vuln_lists_changed_fields(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "TP-001", severity="high", weight=9, title="Old Title")

    await vulns_service.update_vuln(db, ADMIN, app_id, vuln_id, {
        "vuln_id": "TP-001", "title": "Old Title", "severity": "critical",
        "vuln_type": "SQLi", "url": "/a",
    })

    entries = await audit_service.list_audit_events(db, app_id=app_id)
    assert len(entries) == 1
    assert entries[0]["action"] == "vuln_updated"
    assert "severity high → critical" in entries[0]["message"]
    assert "title" not in entries[0]["message"].split(":", 1)[1]  # title unchanged, not listed


async def test_update_vuln_no_changes_produces_no_row(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "TP-001", severity="high", weight=9,
                              vuln_type="SQLi", url="/a", title="Same")

    await vulns_service.update_vuln(db, ADMIN, app_id, vuln_id, {
        "vuln_id": "TP-001", "title": "Same", "severity": "high",
        "vuln_type": "SQLi", "url": "/a", "impact_weight": 9, "difficulty_tier": "commodity",
    })

    assert await audit_service.list_audit_events(db, app_id=app_id) == []


async def test_delete_vuln_row_persists_after_deletion(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "TP-001", title="Gone Soon")

    await vulns_service.delete_vuln(db, ADMIN, app_id, vuln_id)

    entries = await audit_service.list_audit_events(db, app_id=app_id)
    assert len(entries) == 1
    assert entries[0]["action"] == "vuln_deleted"
    assert "Gone Soon" in entries[0]["message"]
    assert "TP-001" in entries[0]["message"]


async def test_invalidate_vuln(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "TP-001", title="Stale Finding")

    await vulns_service.invalidate_vuln(db, ADMIN, app_id, vuln_id)

    entries = await audit_service.list_audit_events(db, app_id=app_id)
    assert len(entries) == 1
    assert entries[0]["action"] == "vuln_invalidated"
    assert "Stale Finding" in entries[0]["message"]
    assert "revision" in entries[0]["message"]


async def test_import_vulns_one_aggregate_row(db):
    app_id = await make_app(db)
    result = await vulns_service.import_vulns(db, ADMIN, app_id, [
        {"title": "V1", "severity": "high"},
        {"title": "V2", "severity": "low"},
    ])
    assert result["imported"] == 2

    entries = await audit_service.list_audit_events(db, app_id=app_id)
    assert len(entries) == 1  # one row, not one per imported vuln
    assert entries[0]["action"] == "vulns_imported"
    assert "2 vulnerabilities" in entries[0]["message"]


async def test_import_vulns_zero_rows_when_nothing_valid(db):
    app_id = await make_app(db)
    result = await vulns_service.import_vulns(db, ADMIN, app_id, [{"no_title": "x"}])
    assert result["imported"] == 0
    assert await audit_service.list_audit_events(db, app_id=app_id) == []


# ---------------------------------------------------------------------------
# Cascade deletes
# ---------------------------------------------------------------------------

async def test_deleting_a_scan_cascades_its_audit_rows(db):
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    finding_id = await first_finding_id(db, scan_id)
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, finding_id)
    assert len(await audit_service.list_audit_events(db, scan_id=scan_id)) == 1

    await scans_service.delete_scan(db, ADMIN, scan_id)

    cursor = await db.execute("SELECT COUNT(*) AS c FROM audit_log WHERE scan_id = ?", (scan_id,))
    assert (await cursor.fetchone())["c"] == 0


async def test_deleting_an_app_cascades_its_audit_rows(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "TP-001", title="Gone With The App")
    await vulns_service.invalidate_vuln(db, ADMIN, app_id, vuln_id)
    assert len(await audit_service.list_audit_events(db, app_id=app_id)) == 1

    import app.services.apps as apps_service
    await apps_service.delete_app(db, ADMIN, app_id)

    cursor = await db.execute("SELECT COUNT(*) AS c FROM audit_log WHERE app_id = ?", (app_id,))
    assert (await cursor.fetchone())["c"] == 0
