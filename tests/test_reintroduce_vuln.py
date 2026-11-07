"""Reintroducing a vuln counts it for scans from a new revision onward only.

TaintedPort TP-066 (#65, cashout race): not exploitable on v1.40, invalidated;
exploitable again from the release with a SQLite busy timeout. Scans already
submitted must keep their scores; scans of the new release must count it.
"""
from tests.test_chain_severity_and_promote import ADMIN, db, setup  # noqa: F401
from app.services import scans as scans_service
from app.services import scoring as scoring_service
from app.services import vulns as vulns_service


async def _metrics(db, scan_id, app_id):
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = dict(await cursor.fetchone())
    rev = await scoring_service.latest_revision(db, app_id)
    return (await scoring_service.score(db, scan, rev))["metrics"]


async def _scan(db, app_id):
    return await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="S", scan_date="2026-11-07", is_public=0,
        notes=None, cost=None, tokens=None, duration=None, findings_data=[],
    )


async def test_reintroduced_vuln_counts_only_for_later_scans(db):
    app_id, (a, b, race) = await setup(db)
    old_scan = await _scan(db, app_id)
    before = await _metrics(db, old_scan, app_id)

    await vulns_service.invalidate_vuln(db, ADMIN, app_id, race, "not exploitable on this version")
    assert (await _metrics(db, old_scan, app_id))["weighted_total"] == before["weighted_total"] - 9

    result = await vulns_service.reintroduce_vuln(db, ADMIN, app_id, race, "exploitable from the next release")
    cursor = await db.execute(
        "SELECT existed_since_revision, invalidated_at_revision FROM vulnerabilities WHERE id = ?", (race,))
    row = await cursor.fetchone()
    assert (row["existed_since_revision"], row["invalidated_at_revision"]) == (result["existed_since_revision"], None)

    after = await _metrics(db, old_scan, app_id)
    assert after["weighted_total"] == before["weighted_total"] - 9, "an earlier scan still does not count it"
    assert race not in after["missed_vuln_ids"]

    new_scan = await _scan(db, app_id)
    fresh = await _metrics(db, new_scan, app_id)
    assert race in fresh["missed_vuln_ids"], "a scan of the new release counts it"
    assert fresh["weighted_total"] == before["weighted_total"]
