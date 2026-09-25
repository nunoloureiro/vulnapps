"""TP split by ground-truth severity, and Ignore reaching every state.

Two separate complaints from the same session, both about the scan views:

1. The scan list and the comparison table showed a bare TP count with no sense
   of what it was made of — 45 true positives reads very differently if they
   are 8 criticals versus 8 lows. The split has to come from the CATALOG's
   severity, not the scanner's reported one: `tp` counts distinct matched
   vulns, so the vuln row is what carries the authoritative label, and it is
   the same side the impact weights come from.

2. Ignore was offered only on a Pending finding, so moving an FP to Ignored
   meant mapping it to some vuln, unmapping it to get back to Pending, then
   ignoring. The service already handled every transition; only the button was
   conditional. These tests pin the service behaviour the UI now relies on.

Same throwaway-DB convention as tests/test_finding_matches.py.
"""

import os
import tempfile

import aiosqlite
import pytest_asyncio

from app.database import run_migrations
from app.services import finding_matches
from app.services import scans as scans_service
from app.services import scoring as scoring_service

ADMIN = {"sub": 1, "name": "Nuno", "role": "admin", "scope": "full"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "tpsev.db")
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


async def add_vuln(db, app_id, slug, severity="high", url="/a"):
    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, url, created_by,
            impact_weight, difficulty_tier, weight_verified,
            existed_since_revision, known_since_revision)
           VALUES (?, ?, ?, ?, 'SQLi', ?, 1, 9, 'commodity', 1, 1, 1)""",
        (app_id, slug, f"Vuln {slug}", severity, url),
    )
    await db.commit()
    return cursor.lastrowid


async def submit(db, app_id, findings):
    return await scans_service.submit_scan(
        db, ADMIN, app_id,
        scanner_name="COS", scan_date="2026-09-25", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=findings,
    )


async def findings_of(db, scan_id):
    cursor = await db.execute(
        "SELECT id FROM scan_findings WHERE scan_id = ? ORDER BY id", (scan_id,)
    )
    return [r["id"] for r in await cursor.fetchall()]


async def list_row(db, scan_id):
    result = await scans_service.list_scans(db, ADMIN)
    return next(s for s in result["scans"] if s["id"] == scan_id)


# --- the TP split -----------------------------------------------------------

async def test_split_counts_catalog_severity_not_the_scanner_s(db):
    """The whole point of the decision: a scanner calling a medium bug critical
    must not move it into the critical bucket."""
    app_id = await make_app(db)
    vuln = await add_vuln(db, app_id, "TP-001", severity="medium")
    scan_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "title": "found it", "severity": "critical"},
    ])
    fid = (await findings_of(db, scan_id))[0]
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [vuln], [])

    row = await list_row(db, scan_id)
    assert row["tp_medium"] == 1, "should follow the catalog's medium"
    assert row["tp_critical"] == 0, "must not follow the scanner's critical"


async def test_split_sums_to_tp_count(db):
    """The invariant the UI depends on — a breakdown that disagreed with the
    number beside it would be worse than showing none."""
    app_id = await make_app(db)
    vulns = [
        await add_vuln(db, app_id, "TP-001", severity="critical", url="/1"),
        await add_vuln(db, app_id, "TP-002", severity="critical", url="/2"),
        await add_vuln(db, app_id, "TP-003", severity="high", url="/3"),
        await add_vuln(db, app_id, "TP-004", severity="low", url="/4"),
        await add_vuln(db, app_id, "TP-005", severity="medium", url="/5"),
    ]
    scan_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "title": f"f{i}"} for i in range(len(vulns))
    ])
    for fid, vid in zip(await findings_of(db, scan_id), vulns):
        await scans_service.match_finding(db, ADMIN, scan_id, fid, [vid], [])

    row = await list_row(db, scan_id)
    assert row["tp_count"] == 5
    assert sum(row[f"tp_{sev}"] for sev in SEVERITIES) == row["tp_count"]
    assert (row["tp_critical"], row["tp_high"], row["tp_medium"], row["tp_low"]) == (2, 1, 1, 1)


async def test_split_counts_distinct_vulns_not_findings(db):
    """`tp` is distinct matched vulns, so two findings hitting the same vuln
    are one TP — the split has to agree or it stops summing."""
    app_id = await make_app(db)
    vuln = await add_vuln(db, app_id, "TP-001", severity="critical")
    scan_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "title": "first report"},
        {"vuln_type": "SQLi", "title": "same bug again"},
    ])
    for fid in await findings_of(db, scan_id):
        await scans_service.match_finding(db, ADMIN, scan_id, fid, [vuln], [])

    row = await list_row(db, scan_id)
    assert row["tp_count"] == 1
    assert row["tp_critical"] == 1
    assert sum(row[f"tp_{sev}"] for sev in SEVERITIES) == row["tp_count"]


async def test_split_matches_the_scorer(db):
    """The list builds the split in SQL, the scorer builds it in Python, and
    the grouped view swaps one for the other. They have to agree."""
    app_id = await make_app(db)
    crit = await add_vuln(db, app_id, "TP-001", severity="critical", url="/1")
    low = await add_vuln(db, app_id, "TP-002", severity="low", url="/2")
    await add_vuln(db, app_id, "TP-003", severity="high", url="/3")  # missed
    scan_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "title": "a"}, {"vuln_type": "SQLi", "title": "b"},
    ])
    for fid, vid in zip(await findings_of(db, scan_id), [crit, low]):
        await scans_service.match_finding(db, ADMIN, scan_id, fid, [vid], [])

    # Plain list view: the split comes from SQL.
    plain = await list_row(db, scan_id)
    from_sql = {sev: plain[f"tp_{sev}"] for sev in SEVERITIES}

    # Scorer, computed independently in Python.
    revision = await scoring_service.latest_revision(db, plain["app_id"])
    from_scorer = (await scoring_service.score(db, plain, revision))["metrics"]["tp_by_severity"]

    assert from_sql == from_scorer == {"critical": 1, "high": 0, "medium": 0, "low": 1, "info": 0}

    # With metrics requested the service swaps the SQL columns for the
    # scorer's, and the result still sums to the tp shown beside it.
    result = await scans_service.list_scans(db, ADMIN, include_metrics=True)
    row = next(s for s in result["scans"] if s["id"] == scan_id)
    assert {sev: row[f"tp_{sev}"] for sev in SEVERITIES} == from_scorer
    assert sum(row[f"tp_{sev}"] for sev in SEVERITIES) == row["metrics"]["tp"]
    assert "tp_by_severity" not in row["metrics"], "nested values break grouped averaging"


# --- Ignore from any state --------------------------------------------------

async def test_ignoring_a_matched_finding_drops_its_matches(db):
    """Previously unreachable in the UI: you had to unmap first."""
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-001", url="/1")
    b = await add_vuln(db, app_id, "TP-002", url="/2")
    scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "title": "noise"}])
    fid = (await findings_of(db, scan_id))[0]
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a, b], [])

    await scans_service.set_finding_ignored(db, ADMIN, scan_id, fid, True)

    matches = (await finding_matches.load(db, [fid]))[fid]
    assert matches["vuln_ids"] == [] and matches["chain_ids"] == []
    row = await list_row(db, scan_id)
    assert row["tp_count"] == 0
    assert sum(row[f"tp_{sev}"] for sev in SEVERITIES) == 0


async def test_ignoring_an_fp_clears_the_flag_and_group(db):
    """The exact trip the user was forced into: FP -> Ignored, no detour."""
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "XSS", "title": "bogus"}])
    fid = (await findings_of(db, scan_id))[0]
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, "missing-headers")

    await scans_service.set_finding_ignored(db, ADMIN, scan_id, fid, True)

    cursor = await db.execute(
        "SELECT is_false_positive, is_ignored, fp_group FROM scan_findings WHERE id = ?", (fid,)
    )
    row = await cursor.fetchone()
    assert (row["is_false_positive"], row["is_ignored"], row["fp_group"]) == (0, 1, None)
    assert (await list_row(db, scan_id))["fp_count"] == 0


async def test_un_ignoring_returns_to_pending(db):
    """Nothing called this before — an ignored finding could only leave that
    state sideways, by being marked FP."""
    app_id = await make_app(db)
    scan_id = await submit(db, app_id, [{"vuln_type": "XSS", "title": "maybe"}])
    fid = (await findings_of(db, scan_id))[0]
    await scans_service.set_finding_ignored(db, ADMIN, scan_id, fid, True)

    await scans_service.set_finding_ignored(db, ADMIN, scan_id, fid, False)

    cursor = await db.execute(
        "SELECT is_false_positive, is_ignored FROM scan_findings WHERE id = ?", (fid,)
    )
    row = await cursor.fetchone()
    assert (row["is_false_positive"], row["is_ignored"]) == (0, 0)
    assert (await list_row(db, scan_id))["pending_count"] == 1


async def test_ignore_audit_names_what_it_discarded(db):
    """Ignoring is now reachable from states that hold something, so the log
    has to say what went away — 'marked as ignored' alone loses the matches."""
    app_id = await make_app(db)
    vuln = await add_vuln(db, app_id, "TP-001")
    scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "title": "thing"}])
    fid = (await findings_of(db, scan_id))[0]
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [vuln], [])

    await scans_service.set_finding_ignored(db, ADMIN, scan_id, fid, True)

    cursor = await db.execute(
        "SELECT message FROM audit_log WHERE action = 'finding_marked_ignored' "
        "ORDER BY id DESC LIMIT 1"
    )
    message = (await cursor.fetchone())["message"]
    assert "dropped 1 existing match" in message
