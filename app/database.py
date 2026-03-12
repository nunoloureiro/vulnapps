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
        await db.executescript(sql)
        await db.execute("INSERT INTO _migrations (name) VALUES (?)", (name,))
        await db.commit()
