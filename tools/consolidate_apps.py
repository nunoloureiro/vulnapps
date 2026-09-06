#!/usr/bin/env python3
"""Move scans from a duplicate app onto the canonical one. Deletes nothing.

`apps` lost its UNIQUE(name, version) in migration 010, so duplicate name+version
rows exist — this database has two `TaintedPort` version `1.0` (ids 1 and 3). A
scan measured against the wrong duplicate is scored against ground truth nobody
chose, and nothing downstream reveals it.

What this does, for each moved scan:
  * re-points `scans.app_id` at the canonical app
  * re-points every finding's `matched_vuln_id` at the canonical app's vuln with
    the SAME `vuln_id` slug; a finding whose slug has no counterpart is unmatched
    and returned to Pending rather than left pointing across apps
  * stamps `corpus_revision` with the canonical app's current revision
  * appends fresh scorings (the old rows stay — they are immutable, and they
    record what was measured against the source app)

What it does NOT do: delete the source app, delete any vuln, or touch anything on
the canonical app. Run with --dry-run first; that is the default.

    python tools/consolidate_apps.py --from 1 --into 3 --dry-run
    python tools/consolidate_apps.py --from 1 --into 3 --commit
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import get_connection  # noqa: E402
from app.services import scoring as scoring_service  # noqa: E402


async def plan(db, source_id: int, target_id: int) -> dict:
    cursor = await db.execute(
        "SELECT id, name, version, visibility, team_id FROM apps WHERE id IN (?, ?)",
        (source_id, target_id),
    )
    apps = {row["id"]: dict(row) for row in await cursor.fetchall()}
    if source_id not in apps:
        raise SystemExit(f"source app {source_id} not found")
    if target_id not in apps:
        raise SystemExit(f"target app {target_id} not found")

    cursor = await db.execute(
        "SELECT vuln_id, id FROM vulnerabilities WHERE app_id = ?", (target_id,)
    )
    target_slugs = {row["vuln_id"]: row["id"] for row in await cursor.fetchall()}

    cursor = await db.execute(
        "SELECT id, scanner_name, scan_date FROM scans WHERE app_id = ? ORDER BY scan_date",
        (source_id,),
    )
    scans = [dict(r) for r in await cursor.fetchall()]

    remaps, orphans = [], []
    for scan in scans:
        cursor = await db.execute(
            """SELECT f.id, f.matched_vuln_id, v.vuln_id AS slug
               FROM scan_findings f JOIN vulnerabilities v ON v.id = f.matched_vuln_id
               WHERE f.scan_id = ?""",
            (scan["id"],),
        )
        for row in await cursor.fetchall():
            target_vuln = target_slugs.get(row["slug"])
            if target_vuln is None:
                orphans.append((scan["id"], row["id"], row["slug"]))
            else:
                remaps.append((row["id"], target_vuln, row["slug"]))

    return {
        "source": apps[source_id], "target": apps[target_id],
        "scans": scans, "remaps": remaps, "orphans": orphans,
        "target_slugs": target_slugs,
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="source", type=int, required=True,
                        help="app id to move scans OFF (left otherwise untouched)")
    parser.add_argument("--into", dest="target", type=int, required=True,
                        help="canonical app id to move scans ONTO")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", default=True,
                      help="show the plan and change nothing (default)")
    group.add_argument("--commit", action="store_true",
                      help="actually perform the move")
    args = parser.parse_args()

    db = await get_connection()
    try:
        p = await plan(db, args.source, args.target)
        src, tgt = p["source"], p["target"]
        print(f"source: app {src['id']} {src['name']} v{src['version']} "
              f"(visibility={src['visibility']})")
        print(f"target: app {tgt['id']} {tgt['name']} v{tgt['version']} "
              f"(visibility={tgt['visibility']}, {len(p['target_slugs'])} vulns)")
        print(f"\nscans to move: {len(p['scans'])}")
        for s in p["scans"]:
            print(f"  scan {s['id']}: {s['scanner_name']} {s['scan_date']}")
        print(f"\nfindings to re-point by vuln_id slug: {len(p['remaps'])}")
        if p["orphans"]:
            print(f"findings whose slug has no counterpart on the target "
                  f"(returned to Pending): {len(p['orphans'])}")
            for scan_id, finding_id, slug in p["orphans"]:
                print(f"  scan {scan_id} finding {finding_id}: {slug}")
        else:
            print("findings with no counterpart: none")

        if not args.commit:
            print("\nDry run — nothing changed. Re-run with --commit to apply.")
            return

        revision = await scoring_service.latest_revision(db, args.target)
        for finding_id, target_vuln, _slug in p["remaps"]:
            await db.execute(
                "UPDATE scan_findings SET matched_vuln_id = ? WHERE id = ?",
                (target_vuln, finding_id),
            )
        for _scan_id, finding_id, _slug in p["orphans"]:
            await db.execute(
                """UPDATE scan_findings
                   SET matched_vuln_id = NULL, is_false_positive = 0, is_ignored = 0
                   WHERE id = ?""",
                (finding_id,),
            )
            await scoring_service.clear_finding_milestones(db, finding_id)
        for s in p["scans"]:
            await db.execute(
                "UPDATE scans SET app_id = ?, corpus_revision = ? WHERE id = ?",
                (args.target, revision, s["id"]),
            )
        await db.commit()

        for s in p["scans"]:
            cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (s["id"],))
            await scoring_service.score_scan(db, await cursor.fetchone())
        await db.commit()

        print(f"\nMoved {len(p['scans'])} scan(s) onto app {args.target} at revision "
              f"{revision}. Source app {args.source} still exists with its vulns intact.")
        print("Old scoring rows are untouched; new ones were appended.")
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
