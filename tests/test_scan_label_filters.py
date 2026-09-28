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
        ordinary = (await client.get('/api/scans')).json()["scans"]
        assert all("metrics" not in scan for scan in ordinary)
        scored = (await client.get('/api/scans?include_metrics=true&label=blackbox')).json()["scans"]
        assert {scan["id"] for scan in scored} == {1, 2}
        assert all(scan["metrics"]["weighted_total"] == 0 for scan in scored)


async def test_coverage_reaches_the_http_response(tmp_path, monkeypatch):
    """The list route copies an explicit set of keys from the service result.
    Coverage was computed but not on that list, so the page never showed it —
    service-level tests could not see that; this one goes through the route."""
    path = tmp_path / "coverage.db"

    async def connect():
        db = await aiosqlite.connect(path)
        db.row_factory = aiosqlite.Row
        return db

    db = await connect()
    try:
        await run_migrations(db)
        await db.execute("INSERT INTO users (id, name, email, password_hash, role) VALUES (1, 'Demo', 'demo@example.invalid', 'x', 'admin')")
        await db.execute("INSERT INTO apps (id, name, version, created_by, visibility) VALUES (1, 'Demo', '1', 1, 'public')")
        await db.execute("INSERT INTO apps (id, name, version, created_by, visibility) VALUES (2, 'Demo', '2', 1, 'public')")
        for scan_id, app_id in ((1, 1), (2, 2)):
            await db.execute(
                "INSERT INTO scans (id, app_id, scanner_name, scan_date, submitted_by) VALUES (?, ?, 'S', '2026-09-28', 1)",
                (scan_id, app_id),
            )
        await db.commit()
    finally:
        await db.close()

    app = FastAPI()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        request.state.user = {"sub": 1, "role": "admin"}
        return await call_next(request)

    app.include_router(scans_api.router, prefix="/api/scans")
    monkeypatch.setattr(scans_api, "get_connection", connect)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        one = (await client.get("/api/scans?app_id=1")).json()
        assert one["coverage"] is not None and one["coverage"]["scan_count"] == 1
        both = (await client.get("/api/scans")).json()
        assert "coverage" in both and both["coverage"] is None, "two app versions = two apps = no row"


async def test_submission_stores_provenance_and_run_details(tmp_path, monkeypatch):
    """Through the real submit route: the importer's provenance and run
    details land in the scan row. Before migration 042 the route read eight
    named fields and silently dropped every one of these."""
    path = tmp_path / "prov.db"

    async def connect():
        db = await aiosqlite.connect(path)
        db.row_factory = aiosqlite.Row
        return db

    db = await connect()
    try:
        await run_migrations(db)
        await db.execute("INSERT INTO users (id, name, email, password_hash, role) VALUES (1, 'Demo', 'demo@example.invalid', 'x', 'admin')")
        await db.execute("INSERT INTO apps (id, name, version, created_by, visibility) VALUES (1, 'Demo', '1', 1, 'public')")
        await db.commit()
    finally:
        await db.close()

    app = FastAPI()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        request.state.user = {"sub": 1, "role": "admin"}
        return await call_next(request)

    app.include_router(scans_api.submit_router, prefix="/api/apps")
    monkeypatch.setattr(scans_api, "get_connection", connect)

    # The submit route authenticates from the Authorization header, not
    # request.state.user; stand in for it with the same admin.
    async def _admin(request):
        return {"sub": 1, "role": "admin"}
    monkeypatch.setattr(scans_api, "require_user", _admin)
    body = {
        "scanner_name": "S", "scan_date": "2026-09-28", "findings": [],
        "imported_by": "vulnapps import_scan", "importer_version": "v1.198", "importer_commit": "abc123-dirty",
        "extractor_version": "llm-api:claude-sonnet-5", "matcher_version": "llm-api:claude-opus-5",
        "seed": "42", "trial_index": 3, "token_budget": "not-a-number", "run_group": "g1",
        "submitted_by": 999,  # not a run-detail field: must be ignored, never written
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/api/apps/1/scans", json=body)
        assert r.status_code == 200, r.text
        scan_id = r.json()["scan_id"]

    db = await connect()
    try:
        cur = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = dict(await cur.fetchone())
    finally:
        await db.close()
    assert (row["imported_by"], row["importer_version"], row["importer_commit"]) == \
        ("vulnapps import_scan", "v1.198", "abc123-dirty")
    assert (row["extractor_version"], row["matcher_version"]) == ("llm-api:claude-sonnet-5", "llm-api:claude-opus-5")
    assert (row["seed"], row["trial_index"], row["run_group"]) == (42, 3, "g1")
    assert row["token_budget"] is None, "an unparseable integer is dropped, not stored as text"
    assert row["submitted_by"] == 1, "only whitelisted fields are taken from the body"
