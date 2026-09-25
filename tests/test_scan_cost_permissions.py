"""Scan lists must not bypass the detail view's run-metadata permissions."""

import aiosqlite

from app.database import run_migrations
from app.services import scans as scans_service


async def test_list_and_detail_protect_cost_metadata_with_and_without_metrics(tmp_path):
    async with aiosqlite.connect(tmp_path / "cost-permissions.db") as db:
        db.row_factory = aiosqlite.Row
        await run_migrations(db)
        await db.executemany(
            "INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, 'x', ?)",
            [(i, f"User {i}", f"user{i}@example.invalid", "admin" if i == 1 else "user")
             for i in range(1, 8)],
        )
        await db.executemany(
            "INSERT INTO teams (id, name, created_by) VALUES (?, ?, 1)",
            [(1, "Scan team"), (2, "Other team")],
        )
        await db.executemany(
            "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)",
            [(1, 3, "view"), (1, 4, "contributor"), (1, 5, "admin"), (2, 7, "view")],
        )
        await db.executemany(
            "INSERT INTO apps (id, name, version, created_by, visibility, team_id) VALUES (?, ?, '1', 1, ?, ?)",
            [(1, "Public", "public", None), (2, "Team", "team", 1),
             (3, "Public with team", "public", 1), (4, "Private", "private", None)],
        )
        expected_metadata = {"cost": 12.5, "tokens": 1200, "duration": 180, "notes": "Private run notes"}
        await db.executemany(
            """INSERT INTO scans (id, app_id, scanner_name, scan_date, submitted_by,
                                  cost, tokens, duration, notes)
               VALUES (?, ?, 'Demo scanner', '2026-09-25', 2, 12.5, 1200, 180, 'Private run notes')""",
            [(i, i) for i in range(1, 5)],
        )
        await db.commit()

        cases = [
            (None, {1, 3}, set()),
            ({"sub": 1, "role": "admin"}, {1, 2, 3, 4}, {1, 2, 3, 4}),
            ({"sub": 2, "role": "user"}, {1, 2, 3, 4}, {1, 2, 3, 4}),
            *[({"sub": i, "role": "user"}, {1, 2, 3}, {2}) for i in (3, 4, 5)],
            *[({"sub": i, "role": "user"}, {1, 3}, set()) for i in (6, 7)],
        ]
        for user, visible_ids, cost_ids in cases:
            details = {scan_id: await scans_service.get_scan(db, user, scan_id) for scan_id in visible_ids}
            for include_metrics in (False, True):
                result = await scans_service.list_scans(db, user, include_metrics=include_metrics)
                assert {scan["id"] for scan in result["scans"]} == visible_ids
                for scan in result["scans"]:
                    allowed = scan["id"] in cost_ids
                    detail = details[scan["id"]]
                    assert detail["can_view_cost"] is allowed
                    assert ("metrics" in scan) is include_metrics
                    for field, value in expected_metadata.items():
                        assert scan[field] == detail["scan"][field] == (value if allowed else None)
                    assert "app_visibility" not in scan
                    assert "app_team_id" not in scan
