"""App detail names the team a team-visible app belongs to, like the list does.

Same throwaway-DB convention as tests/test_finding_matches.py.
"""

import os
import tempfile

import aiosqlite
import pytest_asyncio

from app.database import run_migrations
from app.services import apps as apps_service

ADMIN = {"sub": 1, "name": "Nuno", "role": "admin", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "teamname.db")
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    await conn.execute(
        "INSERT INTO users (id, name, email, password_hash, role) "
        "VALUES (1, 'Nuno', 't@example.com', 'x', 'admin')"
    )
    await conn.execute("INSERT INTO teams (id, name, created_by) VALUES (7, 'Red Team', 1)")
    await conn.commit()
    yield conn
    await conn.close()


async def test_app_detail_carries_the_team_name(db):
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility, team_id) "
        "VALUES ('T', '1.0', 1, 'team', 7)"
    )
    await db.commit()
    detail = await apps_service.get_app(db, ADMIN, cursor.lastrowid)
    assert detail["app"]["team_name"] == "Red Team"
