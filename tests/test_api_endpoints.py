"""Comprehensive API endpoint tests for Vulnapps.

Tests all 21 scenarios from the testing checklist using FastAPI's TestClient
against a temporary copy of the production database.
"""

import json
import os
import shutil
import tempfile

import pytest
from httpx import ASGITransport, AsyncClient

# Point to a temp copy of the real DB so migrations run and data exists
_REAL_DB = os.path.join(os.path.dirname(__file__), "..", "vulnapps.db")
_TMP_DIR = tempfile.mkdtemp()
_TMP_DB = os.path.join(_TMP_DIR, "test_vulnapps.db")

# Copy the database before importing the app (config reads DATABASE_PATH at import)
shutil.copy2(_REAL_DB, _TMP_DB)
# Also copy WAL/SHM if present (so we get the latest data)
for ext in ("-wal", "-shm"):
    src = _REAL_DB + ext
    if os.path.exists(src):
        shutil.copy2(src, _TMP_DB + ext)

os.environ["DATABASE_PATH"] = _TMP_DB

# Run migrations on the test DB before importing the app (since ASGITransport
# doesn't trigger FastAPI lifespan events).
import asyncio
import aiosqlite

async def _run_migrations():
    from app.database import run_migrations, get_connection
    db = await get_connection()
    await run_migrations(db)
    await db.close()

asyncio.get_event_loop().run_until_complete(_run_migrations())

from app.main import app  # noqa: E402
from app.auth import create_token  # noqa: E402


# Generate a valid admin JWT for user_id=1 (nuno, admin)
ADMIN_TOKEN = create_token(1, "nuno", "admin")
USER_TOKEN = create_token(2, "Ricardo Alves", "user")


@pytest.fixture
def auth_headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def user_headers():
    return {"Authorization": f"Bearer {USER_TOKEN}"}


@pytest.fixture
def transport():
    return ASGITransport(app=app)


@pytest.mark.asyncio
async def test_01_spa_serving(transport):
    """GET / should return HTML linking a stylesheet and the React root div.

    The CSS is bundled by Vite into a content-hashed /assets/*.css (so it
    cache-busts with the JS), so assert a stylesheet link exists rather than a
    fixed style.css URL.
    """
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert "text/html" in r.headers.get("content-type", "")
    assert 'rel="stylesheet"' in r.text and ".css" in r.text
    assert 'id="root"' in r.text
    print(f"  PASS: GET / -> {r.status_code}, HTML with stylesheet link and #root")


@pytest.mark.asyncio
async def test_02_api_root(transport):
    """GET /api should return JSON with endpoint listing."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api", headers={"Accept": "application/json"})
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert data["name"] == "Vulnapps API"
    assert "endpoints" in data
    assert "auth" in data["endpoints"]
    assert "apps" in data["endpoints"]
    assert "scans" in data["endpoints"]
    print(f"  PASS: GET /api -> {r.status_code}, JSON with endpoints")


@pytest.mark.asyncio
async def test_03_api_root_browser_redirect(transport):
    """GET /api with Accept:text/html should redirect to /api/docs."""
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
        r = await client.get("/api", headers={"Accept": "text/html"})
    assert r.status_code in (301, 302, 303, 307), f"Expected redirect, got {r.status_code}"
    assert "/api/docs" in r.headers.get("location", "")
    print(f"  PASS: GET /api (Accept:text/html) -> {r.status_code}, redirects to /api/docs")


@pytest.mark.asyncio
async def test_04_api_docs(transport):
    """GET /api/docs should return 200 (Swagger UI)."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/docs")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert "swagger" in r.text.lower() or "openapi" in r.text.lower()
    print(f"  PASS: GET /api/docs -> {r.status_code}, Swagger UI")


@pytest.mark.asyncio
async def test_05_openapi_schema(transport):
    """GET /api/openapi.json should return valid JSON schema."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/openapi.json")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "openapi" in data
    assert "paths" in data
    assert "info" in data
    print(f"  PASS: GET /api/openapi.json -> {r.status_code}, valid schema with {len(data['paths'])} paths")


@pytest.mark.asyncio
async def test_06_auth_login_wrong_creds(transport):
    """POST /api/auth/login with wrong creds should return 401."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/auth/login",
            json={"email": "bad@example.com", "password": "wrongpassword"},
        )
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    print(f"  PASS: POST /api/auth/login (bad creds) -> {r.status_code}")


@pytest.mark.asyncio
async def test_07_auth_me(transport, auth_headers):
    """GET /api/auth/me with valid token should return user."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/auth/me", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "user" in data
    assert data["user"]["id"] == 1
    assert data["user"]["name"] == "nuno"
    assert data["user"]["role"] == "admin"
    # Should NOT include password_hash
    assert "password_hash" not in data["user"]
    print(f"  PASS: GET /api/auth/me -> {r.status_code}, user={data['user']['name']}")


@pytest.mark.asyncio
async def test_08_apps_list(transport, auth_headers):
    """GET /api/apps should return apps array."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/apps", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "apps" in data
    assert isinstance(data["apps"], list)
    assert len(data["apps"]) > 0
    print(f"  PASS: GET /api/apps -> {r.status_code}, {len(data['apps'])} apps")


@pytest.mark.asyncio
async def test_09_app_detail(transport, auth_headers):
    """GET /api/apps/1 should return app with vulns."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/apps/1", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "app" in data
    assert data["app"]["id"] == 1
    assert "vulns" in data or "vulnerabilities" in data or "vuln_count" in data
    print(f"  PASS: GET /api/apps/1 -> {r.status_code}, app={data['app']['name']}")


@pytest.mark.asyncio
async def test_10_scans_list(transport, auth_headers):
    """GET /api/scans should return scans with scan_labels_map."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/scans", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "scans" in data
    assert isinstance(data["scans"], list)
    assert "scan_labels_map" in data
    assert "scanners" in data
    assert "apps_list" in data
    assert "all_labels" in data
    print(f"  PASS: GET /api/scans -> {r.status_code}, {len(data['scans'])} scans, keys: {list(data.keys())}")


@pytest.mark.asyncio
async def test_11_scan_detail(transport, auth_headers):
    """GET /api/scans/2 should return scan with metrics."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/scans/2", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "scan" in data
    assert "metrics" in data
    metrics = data["metrics"]
    for key in ("tp", "fp", "pending", "ignored", "fn", "precision", "recall", "f1"):
        assert key in metrics, f"Missing metric: {key}"
    assert "findings" in data
    assert "labels" in data
    print(f"  PASS: GET /api/scans/2 -> {r.status_code}, metrics={data['metrics']}")


@pytest.mark.asyncio
async def test_12_scan_update_and_revert(transport, auth_headers):
    """PUT /api/scans/2 with {scanner_name: 'TestUpdate'} should work, then revert."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First get original name
        r = await client.get("/api/scans/2", headers=auth_headers)
        assert r.status_code == 200
        original_name = dict(r.json()["scan"])["scanner_name"]

        # Update
        r = await client.put(
            "/api/scans/2",
            headers=auth_headers,
            json={"scanner_name": "TestUpdate"},
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        data = r.json()
        assert data.get("ok") is True
        assert data.get("scan", {}).get("scanner_name") == "TestUpdate"

        # Revert
        r = await client.put(
            "/api/scans/2",
            headers=auth_headers,
            json={"scanner_name": original_name},
        )
        assert r.status_code == 200
        assert r.json()["scan"]["scanner_name"] == original_name
    print(f"  PASS: PUT /api/scans/2 -> update and revert worked, original name: {original_name}")


@pytest.mark.asyncio
async def test_13_labels_list(transport):
    """GET /api/labels should return labels list."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/labels")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "labels" in data
    assert isinstance(data["labels"], list)
    if data["labels"]:
        label = data["labels"][0]
        assert "id" in label
        assert "name" in label
        assert "color" in label
    print(f"  PASS: GET /api/labels -> {r.status_code}, {len(data['labels'])} labels")


@pytest.mark.asyncio
async def test_14_teams(transport, auth_headers):
    """GET /api/teams (authenticated) should return teams."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/teams", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "teams" in data
    assert isinstance(data["teams"], list)
    print(f"  PASS: GET /api/teams -> {r.status_code}, {len(data['teams'])} teams")


@pytest.mark.asyncio
async def test_15_admin_users(transport, auth_headers):
    """GET /api/admin/users (authenticated as admin) should return users WITHOUT password_hash."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/admin/users", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "users" in data
    assert isinstance(data["users"], list)
    assert len(data["users"]) > 0
    for user in data["users"]:
        assert "password_hash" not in user, f"password_hash found in user: {user.get('name')}"
        assert "id" in user
        assert "name" in user
        assert "email" in user
        assert "role" in user
    print(f"  PASS: GET /api/admin/users -> {r.status_code}, {len(data['users'])} users, no password_hash")


@pytest.mark.asyncio
async def test_16_admin_labels(transport, auth_headers):
    """GET /api/admin/labels should return labels with scan_count."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/admin/labels", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "labels" in data
    assert isinstance(data["labels"], list)
    if data["labels"]:
        label = data["labels"][0]
        assert "scan_count" in label, f"Missing scan_count in label: {label}"
    print(f"  PASS: GET /api/admin/labels -> {r.status_code}, {len(data['labels'])} labels with scan_count")


@pytest.mark.asyncio
async def test_17_account(transport, auth_headers):
    """GET /api/account should return account + api_keys."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/account", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "account" in data
    assert "api_keys" in data
    assert isinstance(data["api_keys"], list)
    assert "password_hash" not in data["account"]
    print(f"  PASS: GET /api/account -> {r.status_code}, account={data['account']['name']}, {len(data['api_keys'])} api_keys")


@pytest.mark.asyncio
async def test_18_compare(transport, auth_headers):
    """GET /api/apps/1/compare?scans=2 should return comparison data with matrix."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/apps/1/compare?scans=2", headers=auth_headers)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "app" in data
    assert "scanners" in data
    assert "matrix" in data
    assert "available_scans" in data
    assert isinstance(data["matrix"], list)
    if data["matrix"]:
        row = data["matrix"][0]
        assert "vuln" in row
        assert "detections" in row
    print(f"  PASS: GET /api/apps/1/compare?scans=2 -> {r.status_code}, {len(data['matrix'])} vuln rows, {len(data['scanners'])} scanners")


@pytest.mark.asyncio
async def test_19_scope_enforcement(transport, auth_headers):
    """Create a read-scope API key, then try PUT /api/apps/1 - should get 403."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First create a read-scope API key
        r = await client.post(
            "/api/account/api-keys",
            headers=auth_headers,
            json={"name": "test-read-key", "scope": "read"},
        )
        assert r.status_code == 200, f"Failed to create API key: {r.status_code}: {r.text}"
        api_key = r.json()["key"]
        assert api_key.startswith("va_")

        # Now try to update an app with this read-scope key
        r = await client.put(
            "/api/apps/1",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"name": "TaintedPort", "version": "1.0", "visibility": "public"},
        )
        assert r.status_code == 403, f"Expected 403 for read-scope key on PUT, got {r.status_code}: {r.text}"
    print(f"  PASS: PUT /api/apps/1 with read-scope API key -> {r.status_code} (403 Forbidden)")


@pytest.mark.asyncio
async def test_20_tokens_field(transport, auth_headers):
    """Check that scan objects include the tokens field."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Check scans list
        r = await client.get("/api/scans", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        if data["scans"]:
            scan = data["scans"][0]
            # The tokens column should exist in the scan object after migration runs
            assert "tokens" in scan, f"Missing 'tokens' field in scan list item. Keys: {list(scan.keys())}"

        # Check scan detail
        r = await client.get("/api/scans/2", headers=auth_headers)
        assert r.status_code == 200
        scan = dict(r.json()["scan"])
        assert "tokens" in scan, f"Missing 'tokens' field in scan detail. Keys: {list(scan.keys())}"
    print(f"  PASS: Scan objects include 'tokens' field")


@pytest.mark.asyncio
async def test_21_client_side_routes(transport):
    """GET /scans, /apps/1, /admin/labels should all return SPA HTML."""
    routes = ["/scans", "/apps/1", "/admin/labels"]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for route in routes:
            r = await client.get(route)
            assert r.status_code == 200, f"Expected 200 for {route}, got {r.status_code}"
            assert "text/html" in r.headers.get("content-type", ""), f"{route} not HTML"
            assert 'id="root"' in r.text, f"{route} missing React root"
    print(f"  PASS: Client-side routes {routes} all return SPA HTML")


@pytest.mark.asyncio
async def test_22_ignore_finding_roundtrip(transport, auth_headers):
    """Ignoring a pending finding moves it out of Pending into Ignored without
    touching precision/recall/f1; restoring puts it back. Self-reverts."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Find a scan that has at least one pending finding.
        scans = (await client.get("/api/scans", headers=auth_headers)).json()["scans"]
        sid = next((s["id"] for s in scans if (s.get("pending_count") or 0) > 0), None)
        if sid is None:
            import pytest
            pytest.skip("no scan with a pending finding to ignore")

        before = (await client.get(f"/api/scans/{sid}", headers=auth_headers)).json()
        m0 = before["metrics"]
        fid = next(f["id"] for f in before["findings"]
                   if not f.get("matched_vuln_id") and not f.get("is_false_positive")
                   and not f.get("is_ignored"))

        # Ignore it
        r = await client.post(f"/api/scans/{sid}/findings/{fid}/ignore",
                              json={"ignored": True}, headers=auth_headers)
        assert r.status_code == 200, r.text
        m1 = (await client.get(f"/api/scans/{sid}", headers=auth_headers)).json()["metrics"]
        assert m1["pending"] == m0["pending"] - 1
        assert m1["ignored"] == m0["ignored"] + 1
        # Neutral: tp/fp/fn and precision/recall/f1 unchanged
        for k in ("tp", "fp", "fn", "precision", "recall", "f1"):
            assert m1[k] == m0[k], f"{k} changed: {m0[k]} -> {m1[k]}"

        # Restore it
        r = await client.post(f"/api/scans/{sid}/findings/{fid}/ignore",
                              json={"ignored": False}, headers=auth_headers)
        assert r.status_code == 200, r.text
        m2 = (await client.get(f"/api/scans/{sid}", headers=auth_headers)).json()["metrics"]
        assert m2["pending"] == m0["pending"]
        assert m2["ignored"] == m0["ignored"]
    print(f"  PASS: ignore round-trip on scan {sid} finding {fid} "
          f"(pending {m0['pending']}->{m1['pending']}->{m2['pending']})")


# Bonus: test that unauthenticated access to protected endpoints returns 401
@pytest.mark.asyncio
async def test_bonus_unauth_protected(transport):
    """Protected endpoints should return 401 without auth."""
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/auth/me")
        assert r.status_code == 401

        r = await client.get("/api/teams")
        assert r.status_code == 401

        r = await client.get("/api/admin/users")
        assert r.status_code == 401

        r = await client.get("/api/account")
        assert r.status_code == 401
    print(f"  PASS: Protected endpoints return 401 without auth")
