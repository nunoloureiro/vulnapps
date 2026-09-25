"""Exercise label intersections/unions through the API against synthetic data."""

import aiosqlite
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.database import run_migrations
from app.routers.api import scans as scans_api
from app.services import scans as scans_service


async def test_label_filters_support_all_any_and_single_label_urls(tmp_path, monkeypatch):
    path = tmp_path / "scan-filters.db"

    async def connect():
        db = await aiosqlite.connect(path)
        db.row_factory = aiosqlite.Row
        return db

    db = await connect()
    try:
        await run_migrations(db)
        await db.execute("INSERT INTO users (id, name, email, password_hash, role) VALUES (1, 'Demo', 'demo@example.invalid', 'x', 'admin')")
        await db.execute("INSERT INTO apps (id, name, version, created_by, visibility) VALUES (1, 'Demo', '1', 1, 'public')")
        for scan_id in range(1, 5):
            await db.execute(
                "INSERT INTO scans (id, app_id, scanner_name, scan_date, submitted_by) VALUES (?, 1, 'Demo scanner', ?, 1)",
                (scan_id, f"2026-09-{scan_id:02}"),
            )
        await db.executemany("INSERT OR IGNORE INTO labels (name, color) VALUES (?, '#f97316')", [("blackbox",), ("candidate",)])
        await db.executemany(
            "INSERT INTO scan_labels (scan_id, label_id) SELECT ?, id FROM labels WHERE name = ?",
            [(1, "blackbox"), (1, "candidate"), (2, "blackbox"), (3, "candidate")],
        )
        await db.commit()

        admin = {"sub": 1, "role": "admin"}
        # Existing service callers may still pass one string.
        result = await scans_service.list_scans(db, admin, label="blackbox")
        assert {scan["id"] for scan in result["scans"]} == {1, 2}
    finally:
        await db.close()

    app = FastAPI()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        request.state.user = admin
        return await call_next(request)

    app.include_router(scans_api.router, prefix="/api/scans")
    monkeypatch.setattr(scans_api, "get_connection", connect)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        cases = [
            ("", {1, 2, 3, 4}),
            ("label=blackbox", {1, 2}),
            ("label=blackbox&label=candidate", {1}),
            ("label=blackbox&label=candidate&label_match=all", {1}),
            ("label=blackbox&label=candidate&label_match=any", {1, 2, 3}),
            ("label=blackbox&label=blackbox&label=", {1, 2}),
            ("label=blackbox&label=missing", set()),
            ("label=blackbox&label=missing&label_match=any", {1, 2}),
            ("label=blackbox&label=candidate&latest=1", {1}),
        ]
        for query, expected in cases:
            response = await client.get(f"/api/scans?{query}")
            assert response.status_code == 200, response.text
            assert {scan["id"] for scan in response.json()["scans"]} == expected, query
        assert (await client.get('/api/scans?label_match=invalid')).status_code == 422
