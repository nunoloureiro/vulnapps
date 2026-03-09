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
    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    for migration_file in migration_files:
        sql = migration_file.read_text()
        await db.executescript(sql)
    await db.commit()
