"""Sink-based chain credit: paths sharing a sink are one chain, credited once.

Vuln ids below are the TaintedPort catalog numbers (#N -> id N); chain pks are
the CHAIN-### numbers. Seed mirrors KnownVulnerabilities.txt "CHAINS BY SINK".
"""
from app.scoring import compute_metrics

CRIT, HIGH = 27, 9

VULN_IDS = [1, 3, 11, 12, 13, 17, 19, 20, 21, 23, 24, 27, 28, 29, 40, 43, 44,
            45, 46, 47, 48, 49, 51, 53, 56, 60, 66]
VULNS = [{"id": i, "severity": "high", "difficulty_tier": "commodity"} for i in VULN_IDS]

# chain pk -> (members, sink, weight)
SEED = {
    1: ([1, 40], 40, CRIT), 8: ([17, 24, 40], 40, CRIT),
    9: ([49, 51, 40], 40, CRIT), 10: ([53, 24, 40], 40, CRIT),
    2: ([11, 23], 23, CRIT), 3: ([12, 23], 23, CRIT),
    6: ([13, 45], 45, CRIT), 16: ([27, 60], 60, CRIT),
    5: ([43, 44], 43, CRIT), 17: ([20, 43], 43, CRIT),
    13: ([17, 24, 20], 20, HIGH),
    14: ([53, 24, 28], 28, HIGH), 15: ([3, 28], 28, HIGH), 18: ([17, 24, 28], 28, HIGH),
    12: ([56, 29], 29, CRIT), 7: ([46, 47], 47, CRIT),
}
CHAINS = [
    {"id": pk, "chain_id": f"CHAIN-{pk:03d}", "members": m, "sink_vuln_id": s,
     "impact_weight": w}
    for pk, (m, s, w) in SEED.items()
]

_next_id = [1000]


def chain_finding(*chain_pks):
    """A finding matched directly to known path(s), plus each path's members."""
    _next_id[0] += 1
    members = sorted({v for pk in chain_pks for v in SEED[pk][0]})
    return {"id": _next_id[0], "is_chain": 1, "matched_vuln_ids": members,
            "matched_chain_ids": list(chain_pks)}


def novel(members, sink, rejected=False):
    _next_id[0] += 1
    return {"id": _next_id[0], "is_chain": 1, "matched_vuln_ids": list(members),
            "matched_chain_ids": [], "chain_sink_vuln_id": sink,
            "novel_chain_rejected": 1 if rejected else 0}


def run(findings, confirmed=()):
    m = compute_metrics(findings, VULNS, CHAINS, confirmed)
    groups = {g["sink_vuln_id"]: g for g in m["chain_groups"]}
    return m, groups


def credited_sinks(groups):
    return {s for s, g in groups.items() if g["credited"]}


def test_nine_chains_not_sixteen_rows():
    m, groups = run([])
    assert m["tiers"]["chained"]["count"] == 9
    # Denominator: one weight per sink group (7 Critical + 2 High).
    assert m["tiers"]["chained"]["weighted_total"] == 7 * CRIT + 2 * HIGH


def test_two_paths_same_sink_one_credit():
    m, groups = run([chain_finding(2), chain_finding(3)])
    assert credited_sinks(groups) == {23}
    assert m["tiers"]["chained"]["found"] == 1
    assert m["tiers"]["chained"]["weighted_found"] == CRIT


def test_coverage_two_of_four():
    m, groups = run([chain_finding(1), chain_finding(8)])
    g = groups[40]
    assert credited_sinks(groups) == {40}
    assert (g["paths_demonstrated"], g["paths_total"]) == (2, 4)
    assert {p["chain_id"] for p in g["paths"] if p["demonstrated"]} == {"CHAIN-001", "CHAIN-008"}
    assert m["tiers"]["chained"]["weighted_found"] == CRIT


def test_different_sinks_two_credits():
    m, groups = run([chain_finding(6), chain_finding(16)])
    assert credited_sinks(groups) == {45, 60}
    assert m["tiers"]["chained"]["found"] == 2


def test_new_path_alone_credits_its_sink():
    m, groups = run([chain_finding(17)])
    assert credited_sinks(groups) == {43}
    assert groups[43]["credited_weight"] == CRIT


def test_mixed_weight_group_credits_max_demonstrated():
    # Give sink #43 a High path next to its Critical one.
    chains = [dict(c) for c in CHAINS]
    next(c for c in chains if c["id"] == 5)["impact_weight"] = HIGH
    f5 = chain_finding(5)
    m = compute_metrics([f5], VULNS, chains)
    g = next(g for g in m["chain_groups"] if g["sink_vuln_id"] == 43)
    assert g["weight"] == CRIT and g["credited_weight"] == HIGH
    m = compute_metrics([f5, chain_finding(17)], VULNS, chains)
    g = next(g for g in m["chain_groups"] if g["sink_vuln_id"] == 43)
    assert g["credited_weight"] == CRIT


def test_money_bundle_is_not_a_chain():
    m, groups = run([novel([19, 21, 48, 66], 66)])
    assert credited_sinks(groups) == set()
    assert m["novel_chains"][0]["status"] == "candidate_new_chain"
    assert m["tp"] == 4  # the individual findings still count


def test_single_vuln_plus_its_impact_is_not_a_chain():
    m, groups = run([novel([29], 29)])
    assert credited_sinks(groups) == set()
    assert m["novel_chains"][0]["status"] == "not_a_chain"


def test_novel_path_to_known_sink_credited_immediately():
    f = novel([3, 40], 40)
    m, groups = run([f])
    assert credited_sinks(groups) == {40}
    assert groups[40]["credited_weight"] == CRIT
    assert groups[40]["novel_finding_ids"] == [f["id"]]
    assert m["novel_chains"][0]["status"] == "novel_path"


def test_novel_path_alongside_known_path_adds_nothing():
    f = novel([3, 40], 40)
    m, groups = run([f, chain_finding(8)])
    assert m["tiers"]["chained"]["found"] == 1
    assert m["tiers"]["chained"]["weighted_found"] == CRIT
    assert groups[40]["novel_finding_ids"] == [f["id"]]  # coverage only


def test_rejected_novel_path_loses_credit():
    m, groups = run([novel([3, 40], 40, rejected=True)])
    assert credited_sinks(groups) == set()
    assert m["novel_chains"][0]["status"] == "rejected"
    assert m["tiers"]["chained"]["weighted_found"] == 0


def test_novel_route_to_unknown_sink_is_candidate():
    m, groups = run([novel([1, 21], 21)])
    assert credited_sinks(groups) == set()
    assert m["novel_chains"][0]["status"] == "candidate_new_chain"


def test_novel_without_sink_needs_review():
    m, groups = run([novel([3, 40], None)])
    assert credited_sinks(groups) == set()
    assert m["novel_chains"][0]["status"] == "needs_sink"


def test_members_alone_still_need_confirmation():
    # Today's per-path rule is unchanged: all members matched is not enough.
    f = {"id": 1, "matched_vuln_ids": [11, 23], "matched_chain_ids": []}
    m, groups = run([f])
    assert credited_sinks(groups) == set()
    m, groups = run([f], confirmed={2})
    assert credited_sinks(groups) == {23}


def test_chain_without_sink_is_its_own_group():
    chains = [{"id": 1, "chain_id": "CHAIN-001", "members": [1, 40], "impact_weight": CRIT},
              {"id": 8, "chain_id": "CHAIN-008", "members": [17, 24, 40], "impact_weight": CRIT}]
    f = {"id": 1, "is_chain": 1, "matched_vuln_ids": [], "matched_chain_ids": [1, 8]}
    m = compute_metrics([f], VULNS, chains)
    assert m["tiers"]["chained"]["count"] == 2
    assert m["tiers"]["chained"]["found"] == 2


# ---------------------------------------------------------------------------
# Service layer: sink on chain writes, novel-path review, promotion, clone.
# ---------------------------------------------------------------------------

import pytest

from tests.test_chain_severity_and_promote import ADMIN, db, setup  # noqa: F401
from app.services import apps as apps_service
from app.services import chains as chains_service
from app.services import scans as scans_service
from app.services import scoring as scoring_service


async def test_sink_must_be_the_last_step(db):
    app_id, (a, b, c) = await setup(db)
    for wrong in (c, a):  # not a member; a member but not the last step
        with pytest.raises(ValueError, match="sink_vuln_id must be the path's last step"):
            await chains_service.create_chain(db, ADMIN, app_id, {
                "title": "A to B", "severity": "high", "member_vuln_ids": [a, b], "sink_vuln_id": wrong,
            })
    chain = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to B", "severity": "high", "member_vuln_ids": [a, b], "sink_vuln_id": b,
    })
    assert chain["sink_vuln_id"] == b


async def test_sink_change_opens_a_revision_and_regroups(db):
    app_id, (a, b, c) = await setup(db)
    p1 = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to C", "severity": "high", "member_vuln_ids": [a, c], "sink_vuln_id": c,
    })
    p2 = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "B to C", "severity": "high", "member_vuln_ids": [b, c],
    })
    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="S", scan_date="2026-11-05", is_public=0,
        notes=None, cost=None, tokens=None, duration=None, findings_data=[],
    )
    before = await scoring_service.latest_revision(db, app_id)
    await chains_service.update_chain(db, ADMIN, app_id, p2["id"], {"sink_vuln_id": c})
    assert await scoring_service.latest_revision(db, app_id) > before
    cursor = await db.execute(
        "SELECT notes FROM ground_truth_revisions WHERE app_id = ? ORDER BY revision DESC LIMIT 1", (app_id,))
    assert (await cursor.fetchone())["notes"] == "CHAIN-002 sink none → TP-020", "catalog ids, not DB ids"

    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = dict(await cursor.fetchone())
    result = await scoring_service.score(db, scan, await scoring_service.latest_revision(db, app_id))
    assert result["metrics"]["tiers"]["chained"]["count"] == 1
    # Changing a grouped path's steps moves its sink to the new last step.
    updated = await chains_service.update_chain(db, ADMIN, app_id, p1["id"], {"member_vuln_ids": [a, b]})
    assert updated["sink_vuln_id"] == b


async def test_review_reject_and_promote_novel_path(db):
    app_id, (a, b, c) = await setup(db)
    await chains_service.create_chain(db, ADMIN, app_id, {
        "chain_id": "CHAIN-001", "title": "A to C", "severity": "critical",
        "member_vuln_ids": [a, c], "sink_vuln_id": c,
    })
    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="S", scan_date="2026-11-05", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[{"vuln_type": "Chain", "title": "B then C", "is_chain": True}],
    )
    cursor = await db.execute("SELECT id FROM scan_findings WHERE scan_id = ?", (scan_id,))
    fid = (await cursor.fetchone())["id"]
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [b, c], [])

    async def chained():
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = dict(await cursor.fetchone())
        rev = await scoring_service.latest_revision(db, app_id)
        m = (await scoring_service.score(db, scan, rev))["metrics"]
        return m["tiers"]["chained"], m["novel_chains"]

    tier, novel = await chained()
    assert tier["found"] == 0 and novel[0]["status"] == "needs_sink"

    with pytest.raises(ValueError, match="matched vulnerabilities"):
        await scans_service.review_novel_chain(db, ADMIN, scan_id, fid, {"sink_vuln_id": a})
    await scans_service.review_novel_chain(db, ADMIN, scan_id, fid, {"sink_vuln_id": c})
    tier, novel = await chained()
    assert tier["found"] == 1 and tier["weighted_found"] == 27
    assert novel[0]["status"] == "novel_path"

    await scans_service.review_novel_chain(db, ADMIN, scan_id, fid, {"rejected": True})
    tier, novel = await chained()
    assert tier["found"] == 0 and novel[0]["status"] == "rejected"

    await scans_service.review_novel_chain(db, ADMIN, scan_id, fid, {"rejected": False})
    result = await scans_service.promote_finding_to_chain(db, ADMIN, scan_id, fid, {
        "severity": "critical", "member_vuln_ids": [b, c],
    })
    assert result["chain"]["chain_id"] == "CHAIN-002"
    assert result["chain"]["sink_vuln_id"] == c, "promotion keeps the sink it was credited under"
    tier, novel = await chained()
    assert tier["count"] == 1 and tier["found"] == 1 and novel == []


async def test_clone_keeps_sinks(db):
    app_id, (a, b, c) = await setup(db)
    await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to C", "severity": "high", "member_vuln_ids": [a, c], "sink_vuln_id": c,
    })
    clone = await apps_service.create_app(
        db, ADMIN, "T", "2.0", None, None, "private", None, "", clone_from=app_id,
    )
    clone_id = clone["id"]
    cursor = await db.execute(
        """SELECT v.vuln_id FROM chains c JOIN vulnerabilities v ON v.id = c.sink_vuln_id
           WHERE c.app_id = ?""", (clone_id,))
    assert [r["vuln_id"] for r in await cursor.fetchall()] == ["TP-020"]


def test_importer_keeps_sink_only_on_unmatched_chain_reports():
    from tools.import_scan import _enforce_chain_flag
    findings = [
        # kept: chain report, no known path, sink is a credited vuln
        {"is_chain": True, "matched_vuln_db_id": 3, "additional_vuln_db_ids": [40],
         "chain_sink_vuln_db_id": 40},
        # dropped: matched a known path
        {"is_chain": True, "matched_chain_db_id": 8, "additional_vuln_db_ids": [17, 40],
         "chain_sink_vuln_db_id": 40},
        # dropped: not a chain
        {"is_chain": False, "matched_vuln_db_id": 40, "chain_sink_vuln_db_id": 40},
        # dropped: sink not among the credited vulns
        {"is_chain": True, "matched_vuln_db_id": 3, "additional_vuln_db_ids": [24],
         "chain_sink_vuln_db_id": 40},
    ]
    _enforce_chain_flag({"findings": findings})
    assert [f["chain_sink_vuln_db_id"] for f in findings] == [40, None, None, None]



async def test_confirm_endpoint_is_retired():
    """Chain credit only comes from a finding that reports the chain."""
    from httpx import ASGITransport, AsyncClient
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/scans/1/chains/1/confirm", json={})
    assert resp.status_code == 410
    assert "link the finding" in resp.json()["detail"]


async def test_chain_name_is_shared_by_paths_to_the_same_sink(db):
    app_id, (a, b, c) = await setup(db)
    await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to C", "severity": "high", "member_vuln_ids": [a, c], "sink_vuln_id": c,
        "chain_name": "Takeover via C",
    })
    p2 = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "B to C", "severity": "high", "member_vuln_ids": [b, c], "sink_vuln_id": c,
    })
    lone = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to B", "severity": "high", "member_vuln_ids": [a, b],
    })
    assert p2["chain_name"] == "Takeover via C", "a path joins its sink's chain name"
    assert lone["chain_name"] == "A to B", "a path with no sink is its own chain"

    await chains_service.update_chain(db, ADMIN, app_id, p2["id"], {"chain_name": "Renamed"})
    names = {c["title"]: c["chain_name"] for c in await chains_service.list_chains(db, ADMIN, app_id)}
    assert names == {"A to C": "Renamed", "B to C": "Renamed", "A to B": "A to B"}

    clone = await apps_service.create_app(
        db, ADMIN, "T", "2.0", None, None, "private", None, "", clone_from=app_id,
    )
    names = {c["title"]: c["chain_name"] for c in await chains_service.list_chains(db, ADMIN, clone["id"])}
    assert names["B to C"] == "Renamed", "clone keeps chain names"
