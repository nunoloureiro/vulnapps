"""Finding <-> ground-truth matches (the ``finding_matches`` table).

A finding can demonstrate several things at once: a chain plus the members it
walks through, or one file read that both proves a traversal bug and quotes a
hardcoded secret. Migration 040 moved that off the old single
``matched_vuln_id``/``matched_chain_id`` columns and onto a join table; this
module is the only place that reads or writes it.

Everything downstream works on two lists attached to each finding dict,
``matched_vuln_ids`` and ``matched_chain_ids``, rather than issuing its own
SQL -- see ``attach``.
"""
from __future__ import annotations


async def load(db, finding_ids: list[int]) -> dict[int, dict[str, list[int]]]:
    """``{finding_id: {"vuln_ids": [...], "chain_ids": [...]}}`` for *finding_ids*."""
    out: dict[int, dict[str, list[int]]] = {
        fid: {"vuln_ids": [], "chain_ids": []} for fid in finding_ids
    }
    if not finding_ids:
        return out

    placeholders = ",".join("?" * len(finding_ids))
    cursor = await db.execute(
        f"SELECT finding_id, vuln_id, chain_id FROM finding_matches "
        f"WHERE finding_id IN ({placeholders}) ORDER BY rowid",
        list(finding_ids),
    )
    for row in await cursor.fetchall():
        bucket = out.setdefault(row["finding_id"], {"vuln_ids": [], "chain_ids": []})
        if row["vuln_id"] is not None:
            bucket["vuln_ids"].append(row["vuln_id"])
        else:
            bucket["chain_ids"].append(row["chain_id"])
    return out


async def attach(db, findings: list) -> list[dict]:
    """Return *findings* as dicts with their match lists attached.

    Rows come back from sqlite as ``Row`` objects, which cannot take new keys,
    so they are converted. Downstream code (scoring, the comparison matrix,
    the dashboard) then reads ``matched_vuln_ids``/``matched_chain_ids``
    instead of querying per finding.
    """
    dicts = [dict(f) for f in findings]
    matches = await load(db, [f["id"] for f in dicts])
    for f in dicts:
        m = matches.get(f["id"], {"vuln_ids": [], "chain_ids": []})
        f["matched_vuln_ids"] = m["vuln_ids"]
        f["matched_chain_ids"] = m["chain_ids"]
    return dicts


async def replace(db, finding_id: int, vuln_ids, chain_ids) -> None:
    """Make *finding_id*'s matches exactly *vuln_ids* + *chain_ids*.

    Full replacement rather than add/remove so callers are idempotent: the
    importer re-submits its whole view of a finding, and the UI sends the
    complete selection.
    """
    await db.execute("DELETE FROM finding_matches WHERE finding_id = ?", (finding_id,))
    for vid in dict.fromkeys(vuln_ids or []):
        await db.execute(
            "INSERT INTO finding_matches (finding_id, vuln_id) VALUES (?, ?)",
            (finding_id, int(vid)),
        )
    for cid in dict.fromkeys(chain_ids or []):
        await db.execute(
            "INSERT INTO finding_matches (finding_id, chain_id) VALUES (?, ?)",
            (finding_id, int(cid)),
        )


async def clear(db, finding_id: int) -> None:
    """Drop every match on *finding_id* (marking it FP or ignored does this)."""
    await db.execute("DELETE FROM finding_matches WHERE finding_id = ?", (finding_id,))


async def matched_vuln_ids_for_scan(db, scan_id: int) -> set[int]:
    """Distinct vuln ids matched by any finding in *scan_id*."""
    cursor = await db.execute(
        "SELECT DISTINCT fm.vuln_id FROM finding_matches fm "
        "JOIN scan_findings sf ON sf.id = fm.finding_id "
        "WHERE sf.scan_id = ? AND fm.vuln_id IS NOT NULL",
        (scan_id,),
    )
    return {row["vuln_id"] for row in await cursor.fetchall()}


async def count_findings_for_vuln(db, vuln_id: int) -> int:
    """How many findings are matched to *vuln_id* (the vuln-delete guard)."""
    cursor = await db.execute(
        "SELECT COUNT(*) AS c FROM finding_matches WHERE vuln_id = ?", (vuln_id,)
    )
    return (await cursor.fetchone())["c"]
