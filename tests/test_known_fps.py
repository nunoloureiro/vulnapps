"""Known false positives: a per-app corpus findings link to when marked FP.

Same throwaway-DB convention as tests/test_finding_matches.py.
"""

import os
import tempfile

import aiosqlite
import pytest
import pytest_asyncio

from app.database import run_migrations
from app.services import apps as apps_service
from app.services import known_fps as known_fps_service
from app.services import scans as scans_service

ADMIN = {"sub": 1, "name": "Nuno", "role": "admin", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "knownfp.db")
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


async def make_app(db):
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility) VALUES ('T', '1.0', 1, 'private')"
    )
    await db.commit()
    return cursor.lastrowid


async def submit(db, app_id, titles):
    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="S", scan_date="2026-10-29", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[{"vuln_type": "IDOR", "title": t, "url": "/orders/1/receipt",
                        "http_method": "GET"} for t in titles],
    )
    cursor = await db.execute("SELECT id FROM scan_findings WHERE scan_id = ? ORDER BY id", (scan_id,))
    return scan_id, [r["id"] for r in await cursor.fetchall()]


async def finding(db, finding_id):
    cursor = await db.execute("SELECT * FROM scan_findings WHERE id = ?", (finding_id,))
    return await cursor.fetchone()


async def decoy(db, app_id, **extra):
    return await known_fps_service.create_known_fp(db, ADMIN, app_id, {
        "fp_id": "d4", "title": "IDOR on receipt (ownership enforced)", "source": "decoy",
        "vuln_type": "IDOR", "url": "/orders/:id/receipt", "penalty_weight": 9, **extra,
    })


async def test_linking_copies_the_known_fp_group_and_penalty(db):
    app_id = await make_app(db)
    d4 = await decoy(db, app_id)
    assert d4["fp_id"] == "D4", "ids are normalised to upper case"
    scan_id, (a, b) = await submit(db, app_id, ["IDOR receipt", "BOLA receipt"])

    # The request's own group/penalty lose to the known FP's.
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, a, "other", fp_impact_weight=27,
                                        known_fp_id=d4["id"])
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, b, known_fp_id=d4["id"])

    for fid in (a, b):
        row = await finding(db, fid)
        assert (row["is_false_positive"], row["known_fp_id"], row["fp_group"], row["fp_impact_weight"]) \
            == (1, d4["id"], "D4", 9)

    detail = await scans_service.get_scan(db, ADMIN, scan_id)
    assert detail["metrics"]["fp_groups"] == 1, "one decoy is one FP, however many findings hit it"
    assert detail["metrics"]["weighted_fp_penalty"] == 9
    assert [k["fp_id"] for k in detail["known_fps"]] == ["D4"]


async def test_remember_adds_the_finding_as_a_reviewed_known_fp(db):
    app_id = await make_app(db)
    scan_id, (a, b) = await submit(db, app_id, ["IDOR receipt", "Another"])

    await scans_service.mark_finding_fp(db, ADMIN, scan_id, a, fp_impact_weight=3, remember=True)
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, b, remember=True)

    known = await known_fps_service.list_known_fps(db, ADMIN, app_id)
    assert [(k["fp_id"], k["source"], k["penalty_weight"], k["finding_count"]) for k in known] \
        == [("FP-001", "reviewed", 3, 1), ("FP-002", "reviewed", None, 1)]
    first = known[0]
    assert (first["title"], first["vuln_type"], first["url"], first["created_from_finding_id"]) \
        == ("IDOR receipt", "IDOR", "/orders/1/receipt", a)
    assert (await finding(db, a))["fp_group"] == "FP-001"


async def test_a_plain_fp_stays_unlinked(db):
    app_id = await make_app(db)
    scan_id, (a,) = await submit(db, app_id, ["x"])
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, a, "headers")
    row = await finding(db, a)
    assert (row["known_fp_id"], row["fp_group"]) == (None, "headers")
    assert await known_fps_service.list_known_fps(db, ADMIN, app_id) == []


async def test_editing_a_known_fp_follows_through_to_its_findings(db):
    """Renaming FP-007 -> D8 (promotion into the catalog) or re-weighting it
    must move every scan that hit it, not leave stale copies."""
    app_id = await make_app(db)
    scan_id, (a,) = await submit(db, app_id, ["x"])
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, a, remember=True)
    known_pk = (await finding(db, a))["known_fp_id"]

    updated = await known_fps_service.update_known_fp(db, ADMIN, app_id, known_pk, {
        "fp_id": "D8", "source": "decoy", "penalty_weight": 1,
    })
    assert (updated["fp_id"], updated["source"], updated["title"]) == ("D8", "decoy", "x")
    row = await finding(db, a)
    assert (row["fp_group"], row["fp_impact_weight"]) == ("D8", 1)


async def test_deleting_a_known_fp_unlinks_without_moving_scores(db):
    app_id = await make_app(db)
    d4 = await decoy(db, app_id)
    scan_id, (a,) = await submit(db, app_id, ["x"])
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, a, known_fp_id=d4["id"])

    await known_fps_service.delete_known_fp(db, ADMIN, app_id, d4["id"])
    row = await finding(db, a)
    assert (row["is_false_positive"], row["known_fp_id"], row["fp_group"], row["fp_impact_weight"]) \
        == (1, None, "D4", 9)


async def test_clearing_the_fp_drops_the_link(db):
    app_id = await make_app(db)
    d4 = await decoy(db, app_id)
    scan_id, (a, b) = await submit(db, app_id, ["x", "y"])
    for fid in (a, b):
        await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, known_fp_id=d4["id"])

    await scans_service.match_finding(db, ADMIN, scan_id, a, [], [])
    await scans_service.set_finding_ignored(db, ADMIN, scan_id, b, True)
    for fid in (a, b):
        assert (await finding(db, fid))["known_fp_id"] is None


async def test_validation(db):
    app_id = await make_app(db)
    other_app = await make_app(db)
    other = await decoy(db, other_app)
    scan_id, (a,) = await submit(db, app_id, ["x"])

    with pytest.raises(ValueError, match="not found on this app"):
        await scans_service.mark_finding_fp(db, ADMIN, scan_id, a, known_fp_id=other["id"])
    with pytest.raises(ValueError, match="fp_id is required for a decoy"):
        await known_fps_service.create_known_fp(db, ADMIN, app_id, {"title": "t", "source": "decoy"})
    with pytest.raises(ValueError, match="penalty_weight"):
        await known_fps_service.create_known_fp(db, ADMIN, app_id, {"title": "t", "penalty_weight": 5})
    await decoy(db, app_id)
    with pytest.raises(ValueError, match="already exists"):
        await decoy(db, app_id)


async def test_clone_carries_the_known_fps(db):
    app_id = await make_app(db)
    await decoy(db, app_id)
    clone = await apps_service.create_app(db, ADMIN, "T", "1.1", None, None, "private", None, "",
                                          clone_from=app_id)
    known = await known_fps_service.list_known_fps(db, ADMIN, clone["id"])
    assert [(k["fp_id"], k["source"], k["penalty_weight"]) for k in known] == [("D4", "decoy", 9)]
