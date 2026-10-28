"""Pagination must preserve filtering, scoring scope, and full-result coverage."""

import aiosqlite
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.database import run_migrations
from app.routers.api import scans as scans_api
from app.services import scans as scans_service


ADMIN = {"sub": 1, "role": "admin"}


@pytest_asyncio.fixture
async def scan_db(tmp_path):
    path = tmp_path / "pagination.db"
    db = await aiosqlite.connect(path)
    db.row_factory = aiosqlite.Row
    await run_migrations(db)
    await db.execute("INSERT INTO users (id, name, email, password_hash, role) VALUES (1, 'Owner', 'owner@example.invalid', 'x', 'admin')")
    await db.executemany(
        "INSERT INTO apps (id, name, version, visibility, created_by) VALUES (?, ?, '1', ?, 1)",
        [(1, "Public target", "public"), (2, "Private target", "private")],
    )
    await db.executemany(
        """INSERT INTO scans (id, app_id, scanner_name, scan_date, created_at,
                              submitted_by, is_public, corpus_revision, cost)
           VALUES (?, ?, ?, ?, ?, 1, ?, 1, ?)""",
        [(1, 1, "S1", "2026-10-27 09:00", "2026-10-28", 1, 2),
         (2, 1, "S1", "2026-10-27 09:00", "2026-10-28", 1, None),
         (3, 1, "S2", "2026-10-27T10:00:00+01:00", "2026-10-29", 1, None),
         (4, 1, "S3", "2026-10-26", "2026-10-30", 1, 1),
         (5, 1, "S4", "", "2026-10-27 09:30", 1, None),
         (6, 2, "S1", "2026-10-31", "2026-10-31", 1, None),
         (7, 1, "S1", "2026-11-01", "2026-11-01", 0, None)],
    )
    await db.execute("INSERT INTO labels (name, color) VALUES ('candidate', '#fff')")
    await db.executemany("INSERT INTO scan_labels (scan_id, label_id) SELECT ?, id FROM labels WHERE name = 'candidate'", [(1,), (3,)])
    await db.commit()
    try:
        yield db, path
    finally:
        await db.close()


async def test_pages_are_authorized_stable_and_score_only_the_requested_page(scan_db, monkeypatch):
    db, _ = scan_db
    scored_ids = []
    real_score = scans_service.scoring_service.score_many

    async def record_score(db, scans):
        scored_ids.extend(scan["id"] for scan in scans)
        return await real_score(db, scans)

    monkeypatch.setattr(scans_service.scoring_service, "score_many", record_score)
    first = await scans_service.list_scans(db, None, page=1, page_size=2)
    second = await scans_service.list_scans(db, None, page=2, page_size=2, include_metrics=True)
    third = await scans_service.list_scans(db, None, page=3, page_size=2)
    assert [s["id"] for r in (first, second, third) for s in r["scans"]] == [5, 3, 2, 1, 4]
    assert scored_ids == [2, 1]
    assert second["pagination"] == {"total": 5, "page": 2, "page_size": 2, "pages": 3}
    assert second["coverage"]["scan_count"] == 5
    assert set(second["scan_labels_map"]) == {1}
    assert [s["id"] for s in (await scans_service.list_scans(db, None))["scans"]] == [5, 3, 2, 1, 4]

    latest = await scans_service.list_scans(db, None, page=1, page_size=10, latest="1")
    assert [s["id"] for s in latest["scans"]] == [5, 3, 2, 4]
    assert latest["pagination"]["total"] == 4
    admin = await scans_service.list_scans(db, ADMIN, page=1, page_size=1)
    assert admin["pagination"]["total"] == 7 and admin["coverage"] is None
    scanner = await scans_service.list_scans(db, None, page=1, scanner="S1", latest="1")
    assert [s["id"] for s in scanner["scans"]] == [2]
    filtered = await scans_service.list_scans(db, None, page=2, page_size=1, label="candidate", q="Public")
    assert [s["id"] for s in filtered["scans"]] == [1]
    assert filtered["pagination"]["total"] == filtered["coverage"]["scan_count"] == 2
    empty = await scans_service.list_scans(db, None, page=8, page_size=2)
    assert empty["scans"] == [] and empty["coverage"]["scan_count"] == 5
    await db.execute("UPDATE scans SET scan_date = '2026-10-27T09:00:00.500Z' WHERE id = 1")
    await db.execute("UPDATE scans SET scan_date = '2026-10-27 09:00:00.100' WHERE id = 2")
    subsecond = await scans_service.list_scans(db, None, page=1, scanner="S1", latest="1")
    assert [s["id"] for s in subsecond["scans"]] == [1], "latest must preserve fractional seconds"
    no_results = await scans_service.list_scans(db, None, page=1, q="missing")
    assert no_results["pagination"]["pages"] == 0 and no_results["coverage"] is None


async def test_metric_sorts_use_global_canonical_scores_and_protect_hidden_cost(scan_db):
    db, _ = scan_db
    await db.executemany(
        """INSERT INTO vulnerabilities
           (id, app_id, vuln_id, title, severity, vuln_type, url, created_by,
            impact_weight, weight_verified, existed_since_revision, known_since_revision)
           VALUES (?, 1, ?, ?, ?, 'SQLi', '/', 1, ?, 1, ?, 1)""",
        [(1, "low", "Low", "low", 1, 1), (2, "high", "High", "high", 9, 1),
         (3, "future", "Future", "critical", 27, 2)],
    )
    await db.executemany(
        "INSERT INTO scan_findings (id, scan_id, vuln_type, url) VALUES (?, ?, 'SQLi', '/')",
        [(1, 1), (2, 4)],
    )
    await db.executemany(
        "INSERT INTO finding_matches (finding_id, vuln_id) VALUES (?, ?)",
        [(1, 1), (1, 3), (2, 1), (2, 2)],
    )
    await db.executemany(
        """INSERT INTO scan_findings (id, scan_id, vuln_type, url, is_false_positive, fp_group)
           VALUES (?, ?, 'SQLi', '/', 1, ?)""",
        [(3, 2, "same"), (4, 2, "SAME"), (5, 2, " same "), (6, 3, None), (7, 3, None)],
    )
    await db.commit()
    fp_sorted = await scans_service.list_scans(db, None, page=1, page_size=2, sort="fp")
    assert [(s["id"], s["fp_count"]) for s in fp_sorted["scans"]] == [(3, 2), (2, 1)]
    for sort, direction in (("weighted_found", "desc"), ("tp", "desc"), ("cost_per_point", "asc")):
        result = await scans_service.list_scans(
            db, ADMIN, app_id=1, page=1, page_size=1,
            sort=sort, direction=direction, include_metrics=True,
        )
        assert [s["id"] for s in result["scans"]] == [4], sort
        assert result["scans"][0]["metrics"]["weighted_found"] == 10
        assert result["coverage"]["scan_count"] == 6
        assert result["coverage"]["found"] == 3, "coverage spans the full filtered scan set"
    for invalid_cost in (-1, "unknown", float("inf")):
        await db.execute("UPDATE scans SET cost = ? WHERE id = 4", (invalid_cost,))
        result = await scans_service.list_scans(
            db, ADMIN, app_id=1, page=1, page_size=1, sort="cost_per_point", direction="asc",
        )
        assert [s["id"] for s in result["scans"]] == [1], "invalid cost is missing, never an efficiency winner"
    for direction in ("asc", "desc"):
        hidden = await scans_service.list_scans(db, None, page=1, page_size=2, sort="cost_per_point", direction=direction)
        assert [s["id"] for s in hidden["scans"]] == [5, 3], "hidden cost must not affect observable order"
        assert all(s["cost"] is None for s in hidden["scans"])


async def test_api_validates_pagination_and_returns_metadata(scan_db, monkeypatch):
    _, path = scan_db

    async def connect():
        db = await aiosqlite.connect(path)
        db.row_factory = aiosqlite.Row
        return db

    app = FastAPI()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        request.state.user = None
        return await call_next(request)

    app.include_router(scans_api.router, prefix="/api/scans")
    monkeypatch.setattr(scans_api, "get_connection", connect)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        result = (await client.get("/api/scans?page=1&page_size=2&sort=date&direction=desc")).json()
        assert result["pagination"] == {"total": 5, "page": 1, "page_size": 2, "pages": 3}
        assert [s["id"] for s in result["scans"]] == [5, 3]
        for query in ("page=0", "page_size=0", "page_size=201", "sort=unknown", "direction=up"):
            assert (await client.get(f"/api/scans?{query}")).status_code == 422
        assert len((await client.get("/api/scans")).json()["scans"]) == 5
        distant = await client.get("/api/scans?page=1000000000000000000000000000000")
        assert distant.status_code == 200 and distant.json()["scans"] == []
        assert distant.json()["pagination"]["total"] == 5


async def test_metric_sort_tolerates_a_scan_deleted_during_scoring(scan_db, monkeypatch):
    db, _ = scan_db
    real_score = scans_service.scoring_service.score_many

    async def delete_after_score(db, scans):
        metrics = await real_score(db, scans)
        await db.execute("DELETE FROM scans WHERE id = 5")
        await db.commit()
        return metrics

    monkeypatch.setattr(scans_service.scoring_service, "score_many", delete_after_score)
    result = await scans_service.list_scans(
        db, None, page=1, page_size=2, sort="weighted_found", include_metrics=True,
    )
    assert [scan["id"] for scan in result["scans"]] == [3]
