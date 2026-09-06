"""The scan importer's LLM mapper already asked for a `reasoning` field per
finding and printed it to the terminal, but never sent it to the API -- the
one artifact that could explain *why* a match was made was generated and
then discarded. This confirms it now survives submit_scan -> get_scan
end to end (migration 035_finding_reasoning.sql).
"""

import os
import tempfile

import aiosqlite
import pytest_asyncio

from app.database import run_migrations
from app.services import scans as scans_service

ADMIN = {"sub": 1, "name": "tester", "role": "admin", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "reasoning.db")
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    await conn.execute(
        "INSERT INTO users (id, name, email, password_hash, role) "
        "VALUES (1, 'tester', 't@example.com', 'x', 'admin')"
    )
    await conn.commit()
    yield conn
    await conn.close()


async def test_reasoning_round_trips_through_submit_and_get(db):
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility) VALUES ('T', '1.0', 1, 'private')"
    )
    await db.commit()
    app_id = cursor.lastrowid

    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id,
        scanner_name="Test Scanner", scan_date="2026-09-06",
        is_public=0, notes=None, cost=None, tokens=None, duration=None,
        findings_data=[{
            "vuln_type": "SQLi",
            "title": "SQL Injection - Login Email",
            "reasoning": "Both exploit the same unparameterized query in authenticateDirect().",
        }],
    )

    result = await scans_service.get_scan(db, ADMIN, scan_id)
    findings = result["findings"]
    assert len(findings) == 1
    assert findings[0]["reasoning"] == (
        "Both exploit the same unparameterized query in authenticateDirect()."
    )


async def test_reasoning_is_optional(db):
    """A finding with no reasoning (e.g. from a non-LLM ingestion path)
    must not break submission."""
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility) VALUES ('T2', '1.0', 1, 'private')"
    )
    await db.commit()
    app_id = cursor.lastrowid

    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id,
        scanner_name="Test Scanner", scan_date="2026-09-06",
        is_public=0, notes=None, cost=None, tokens=None, duration=None,
        findings_data=[{"vuln_type": "SQLi"}],
    )
    result = await scans_service.get_scan(db, ADMIN, scan_id)
    assert result["findings"][0]["reasoning"] is None
