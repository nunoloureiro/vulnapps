"""The migration runner must not silently skip statements.

executescript stops at the first failing statement. The runner used to treat
"duplicate column name" as "already applied" and record the file, so every
statement after a column that already existed never ran. That mattered for
migration 042: the live database already had some of its columns (leftovers
of a removed migration) and not the new ones.
"""

import aiosqlite
import pytest

from app import database


async def _cols(db, table):
    cur = await db.execute(f"PRAGMA table_info({table})")
    return [r[1] for r in await cur.fetchall()]


@pytest.fixture
async def db(tmp_path):
    conn = await aiosqlite.connect(tmp_path / "m.db")
    await conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT)")
    await conn.execute("CREATE TABLE log (n INTEGER)")
    await conn.commit()
    yield conn
    await conn.close()


async def test_statements_after_an_existing_column_still_run(db):
    await database._run_migration_script(db, """
ALTER TABLE t ADD COLUMN a TEXT;
ALTER TABLE t ADD COLUMN b TEXT;
ALTER TABLE t ADD COLUMN c TEXT;
""")
    assert await _cols(db, "t") == ["id", "a", "b", "c"]


async def test_nothing_before_the_failure_runs_twice(db):
    """Replaying the whole file would re-run the INSERT."""
    await database._run_migration_script(db, """
INSERT INTO log (n) VALUES (1);
ALTER TABLE t ADD COLUMN a TEXT;
INSERT INTO log (n) VALUES (2);
""")
    cur = await db.execute("SELECT n FROM log ORDER BY n")
    assert [r[0] for r in await cur.fetchall()] == [1, 2]


async def test_several_existing_columns_in_one_file(db):
    await db.execute("ALTER TABLE t ADD COLUMN c TEXT")
    await db.commit()
    await database._run_migration_script(db, """
ALTER TABLE t ADD COLUMN a TEXT;
ALTER TABLE t ADD COLUMN b TEXT;
ALTER TABLE t ADD COLUMN c TEXT;
ALTER TABLE t ADD COLUMN d TEXT;
""")
    assert await _cols(db, "t") == ["id", "a", "c", "b", "d"]


async def test_other_errors_still_raise(db):
    with pytest.raises(Exception, match="no such table"):
        await database._run_migration_script(db, "ALTER TABLE missing ADD COLUMN x TEXT;")


def test_splitter_keeps_semicolons_inside_strings_and_triggers():
    sql = """INSERT INTO log VALUES (';');
CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES (1); END;
ALTER TABLE t ADD COLUMN z TEXT;
"""
    assert len(database.split_sql_statements(sql)) == 3


async def test_prod_like_db_gets_every_provenance_column(tmp_path):
    """The real case: a scans table that already has some of 042's columns."""
    conn = await aiosqlite.connect(tmp_path / "p.db")
    try:
        await database.run_migrations(conn)
        cols = await _cols(conn, "scans")
        for c in ("imported_by", "importer_version", "matcher_version", "seed", "trial_index"):
            assert c in cols, c
    finally:
        await conn.close()
