import re
import sqlite3

import aiosqlite
from pathlib import Path
from app.config import DATABASE_PATH

MIGRATIONS_DIR = Path(__file__).parent.parent / "migrations"


async def get_connection() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys=ON")
    return db


def split_sql_statements(sql: str) -> list[str]:
    """Split a migration script into complete statements.

    Uses sqlite3.complete_statement rather than splitting on ';', so a trigger
    body or a string literal containing ';' stays in one piece.
    """
    statements, current = [], ""
    for line in sql.splitlines(keepends=True):
        current += line
        if sqlite3.complete_statement(current):
            if current.strip().strip(";").strip():
                statements.append(current)
            current = ""
    if current.strip():
        statements.append(current)
    return statements


_DUPLICATE_COLUMN = re.compile(r"duplicate column name: (\w+)", re.I)


async def _run_migration_script(db: aiosqlite.Connection, sql: str):
    """executescript the migration; on "duplicate column", resume AFTER it.

    executescript stops at the first failing statement. The old handling then
    recorded the file as applied, so every statement after a column that
    already existed silently never ran. It is not replaced by executing
    statement by statement: the table-rebuild migrations bracket their work in
    PRAGMA foreign_keys=OFF/ON, which only takes effect between transactions --
    executescript guarantees that, per-statement execution does not, and a
    rebuild with foreign keys still on cascades deletes. Nor is the whole file
    replayed, which would re-run the statements before the failure. The error
    names the column, so the failing statement is known exactly; everything
    before it has run, everything after it runs now.
    """
    while True:
        try:
            await db.executescript(sql)
            return
        except sqlite3.OperationalError as e:
            m = _DUPLICATE_COLUMN.search(str(e))
            if not m:
                raise
            statements = split_sql_statements(sql)
            column = re.compile(rf"\bADD\s+(?:COLUMN\s+)?{re.escape(m.group(1))}\b", re.I)
            failed_at = next((i for i, s in enumerate(statements) if column.search(s)), None)
            if failed_at is None:
                raise  # cannot tell where it stopped; never guess
            sql = "".join(statements[failed_at + 1:])
            if not sql.strip():
                return


async def run_migrations(db: aiosqlite.Connection):
    # Create migrations tracking table
    await db.execute(
        "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))"
    )
    await db.commit()

    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    for migration_file in migration_files:
        name = migration_file.name
        cursor = await db.execute("SELECT 1 FROM _migrations WHERE name = ?", (name,))
        if await cursor.fetchone():
            continue
        # A column that already exists skips only itself -- see _run_migration_script.
        await _run_migration_script(db, migration_file.read_text())
        await db.execute("INSERT INTO _migrations (name) VALUES (?)", (name,))
        await db.commit()
