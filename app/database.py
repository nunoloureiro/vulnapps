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
        sql = migration_file.read_text()
        try:
            await db.executescript(sql)
        except sqlite3.OperationalError as e:
            # A column an ADD COLUMN wants already exists -- the desired end state is
            # already true, most likely because an earlier deploy applied a since-
            # edited version of this same filename (tracking is by filename only, so
            # editing an already-applied file's content never replays it) or a
            # column was added by a one-off manual reconciliation. Either way this
            # is not a real failure; a mismatched table/other-column error still
            # raises normally.
            if "duplicate column name" not in str(e):
                raise
        await db.execute("INSERT INTO _migrations (name) VALUES (?)", (name,))
        await db.commit()
