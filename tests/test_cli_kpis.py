"""The CLI's KPI block: a --dry-run preview must equal what vulnapps reports.

A dry run submits nothing, so the importer scores the mapping itself with the
app's own scoring code. That is only worth showing if it gives the same
numbers the scan page will once the scan is imported -- so this submits the
same mapped findings through the real service and compares the two.
"""

import os
import sys
import tempfile
from pathlib import Path

import aiosqlite
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import import_scan  # noqa: E402

from app.database import run_migrations  # noqa: E402
from app.services import chains as chains_service  # noqa: E402
from app.services import scans as scans_service  # noqa: E402

ADMIN = {"sub": 1, "name": "Nuno", "role": "admin", "scope": "full"}
KPIS = ("tp", "fp", "fp_groups", "fn", "pending", "precision_upper", "precision_lower",
        "recall", "f1", "weighted_found", "weighted_total", "weighted_rate",
        "severity_accuracy", "tp_by_severity", "tiers")


@pytest_asyncio.fixture
async def db():
    conn = await aiosqlite.connect(os.path.join(tempfile.mkdtemp(), "kpi.db"))
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    await conn.execute("INSERT INTO users (id, name, email, password_hash, role) VALUES (1, 'Nuno', 't@e.x', 'x', 'admin')")
    await conn.commit()
    yield conn
    await conn.close()


async def test_dry_run_preview_matches_what_vulnapps_reports(db):
    cur = await db.execute("INSERT INTO apps (name, version, created_by, visibility) VALUES ('T', '1', 1, 'private')")
    app_id = cur.lastrowid
    specs = [("TP-001", "critical", 27, "commodity"), ("TP-002", "high", 9, "business_logic"),
             ("TP-003", "medium", 3, "commodity"), ("TP-004", "low", 1, "business_logic")]
    ids = []
    for code, sev, w, tier in specs:
        cur = await db.execute(
            """INSERT INTO vulnerabilities (app_id, vuln_id, title, severity, vuln_type, url, created_by,
               impact_weight, difficulty_tier, weight_verified, existed_since_revision, known_since_revision)
               VALUES (?, ?, ?, ?, 'X', ?, 1, ?, ?, 1, 1, 1)""", (app_id, code, code, sev, f"/{code}", w, tier))
        ids.append(cur.lastrowid)
    await db.commit()
    chain = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "1 -> 2", "severity": "high", "member_vuln_ids": [ids[0], ids[1]]})

    # What the importer would hold after both phases.
    mapping = {"findings": [
        {"title": "a", "vuln_type": "X", "severity": "critical", "matched_vuln_db_id": ids[0]},
        {"title": "chain", "vuln_type": "X", "severity": "high", "is_chain": True,
         "matched_chain_db_id": chain["id"], "additional_vuln_db_ids": [ids[0], ids[1]]},
        {"title": "fp1", "vuln_type": "X", "is_false_positive": True, "fp_group": "g"},
        {"title": "fp2", "vuln_type": "X", "is_false_positive": True, "fp_group": "g"},
        {"title": "unmatched", "vuln_type": "X", "severity": "low"},
    ]}

    # Local preview, from exactly what the CLI fetches.
    cur = await db.execute("SELECT * FROM vulnerabilities WHERE app_id = ?", (app_id,))
    vulns = [dict(r) for r in await cur.fetchall()]
    chains = await chains_service.list_chains(db, ADMIN, app_id)
    local = import_scan.local_metrics(mapping, vulns, chains)

    # The same findings through the real service, with the importer's matches applied.
    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="S", scan_date="2026-09-28", is_public=0, notes=None,
        cost=None, tokens=None, duration=None,
        findings_data=[{k: v for k, v in f.items() if k in ("title", "vuln_type", "severity", "fp_group")}
                       for f in mapping["findings"]])
    cur = await db.execute("SELECT id FROM scan_findings WHERE scan_id = ? ORDER BY id", (scan_id,))
    fids = [r["id"] for r in await cur.fetchall()]
    for fid, f in zip(fids, mapping["findings"]):
        if f.get("is_false_positive"):
            await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, f.get("fp_group"))
            continue
        vids = ([f["matched_vuln_db_id"]] if f.get("matched_vuln_db_id") else []) + \
               [v for v in f.get("additional_vuln_db_ids", []) if v != f.get("matched_vuln_db_id")]
        cids = [f["matched_chain_db_id"]] if f.get("matched_chain_db_id") else []
        await scans_service.match_finding(db, ADMIN, scan_id, fid, vids, cids)
    server = (await scans_service.get_scan(db, ADMIN, scan_id))["metrics"]

    for key in KPIS:
        assert local[key] == server[key], key
    # And the numbers are the intended ones, not merely equal.
    assert (local["tp"], local["fp_groups"], local["fn"], local["pending"]) == (2, 1, 2, 1)
    assert local["tiers"]["chained"]["found"] == 1


def test_kpi_block_prints_everything_the_scan_page_headlines(capsys):
    metrics = {"tp": 3, "fp": 2, "fp_groups": 1, "fn": 4, "pending": 1, "precision_upper": 0.75,
               "precision_lower": 0.6, "recall": 0.43, "f1": 0.55, "adjudication_complete": False,
               "weighted_found": 45, "weighted_total": 90, "weighted_rate": 0.5,
               "severity_accuracy": 0.67, "severity_checked": 3, "severity_correct": 2,
               "tp_by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
               "tiers": {"commodity": {"count": 4, "found": 2, "weighted_rate": 0.5,
                                       "found_by_severity": {"critical": 1, "high": 1}}}}
    import_scan.print_kpis(metrics, "test")
    out = capsys.readouterr().out
    for text in ("Weighted detection", "50.0%", "45 / 90 pts", "True positives", "1C 2H 0M 0L",
                 "False positives", "(2 findings)", "Precision", "60.0%–75.0%", "Recall", "43.0%",
                 "F1", "Severity accuracy", "Commodity"):
        assert text in out, text


def test_precision_is_a_single_number_once_nothing_is_pending(capsys):
    import_scan.print_kpis({"precision_upper": 0.9, "precision_lower": 0.9, "pending": 0,
                            "adjudication_complete": True}, "t")
    assert "90.0%–" not in capsys.readouterr().out
