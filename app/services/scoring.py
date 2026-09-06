"""Ground-truth revisions and live scoring.

Corpus revision is what keeps a number reproducible: adding a vuln that existed
all along legitimately lowers recall on every prior scan, and that is the
desired behaviour. What matters is that the change is visible and reversible,
not that it's invisible.

Metrics are always computed live from current data — nothing is persisted.
"""

from __future__ import annotations

from app import scoring
from app.scoring import compute_metrics


VALID_REASONS = (
    "new_prior_vuln",     # a vuln was added (promoted or authored)
    "weight_change",      # an impact_weight changed — weights are immutable within a revision
    "vuln_invalidated",   # a vuln was retired from ground truth
    "corpus_change",      # anything else that changes the corpus
)


# ---------------------------------------------------------------------------
# Revisions
# ---------------------------------------------------------------------------

async def latest_revision(db, app_id: int) -> int:
    """Highest recorded revision for an app. Apps with no rows are at 1."""
    cursor = await db.execute(
        "SELECT MAX(revision) AS r FROM ground_truth_revisions WHERE app_id = ?",
        (app_id,),
    )
    row = await cursor.fetchone()
    return int(row["r"]) if row and row["r"] else 1


async def ensure_initial_revision(db, app_id: int, user=None) -> None:
    """Make sure revision 1 exists. Idempotent; does not commit."""
    cursor = await db.execute(
        "SELECT 1 FROM ground_truth_revisions WHERE app_id = ? AND revision = 1",
        (app_id,),
    )
    if await cursor.fetchone():
        return
    await db.execute(
        """INSERT INTO ground_truth_revisions (app_id, revision, reason, notes, created_by)
           VALUES (?, 1, 'corpus_change', 'Initial revision', ?)""",
        (app_id, user["sub"] if user else None),
    )


async def list_revisions(db, app_id: int) -> list[dict]:
    cursor = await db.execute(
        """SELECT r.*, u.name AS created_by_name
           FROM ground_truth_revisions r
           LEFT JOIN users u ON u.id = r.created_by
           WHERE r.app_id = ? ORDER BY r.revision""",
        (app_id,),
    )
    return [dict(row) for row in await cursor.fetchall()]


async def create_revision(db, app_id: int, reason: str, notes=None, user=None) -> int:
    """Append a new ground-truth revision. Returns the new revision number.

    Does not commit — the caller commits together with the corpus change that
    justified the revision, so the two can never drift apart.
    """
    if reason not in VALID_REASONS:
        raise ValueError(f"reason must be one of {list(VALID_REASONS)}")
    await ensure_initial_revision(db, app_id, user)
    cursor = await db.execute(
        "SELECT COALESCE(MAX(revision), 0) AS r FROM ground_truth_revisions WHERE app_id = ?",
        (app_id,),
    )
    current = int((await cursor.fetchone())["r"] or 0)
    new_revision = current + 1
    await db.execute(
        """INSERT INTO ground_truth_revisions (app_id, revision, reason, notes, created_by)
           VALUES (?, ?, ?, ?, ?)""",
        (app_id, new_revision, reason, notes, user["sub"] if user else None),
    )
    return new_revision


async def app_has_scans(db, app_id: int) -> bool:
    cursor = await db.execute(
        "SELECT 1 FROM scans WHERE app_id = ? LIMIT 1", (app_id,)
    )
    return (await cursor.fetchone()) is not None


async def revision_for_corpus_change(db, app_id: int, reason: str, notes=None,
                                     user=None) -> tuple[int, bool]:
    """Open a revision for a corpus change — but only if it can matter.

    Returns ``(revision, created)``. An app with no scans has no history to
    preserve and nothing to re-score, so authoring its ground truth stays on the
    current revision instead of spawning one revision per vuln. Once a single
    scan exists, every corpus change opens a revision, because from then on it
    moves a number somebody already recorded.
    """
    if not await app_has_scans(db, app_id):
        await ensure_initial_revision(db, app_id, user)
        return await latest_revision(db, app_id), False
    return await create_revision(db, app_id, reason, notes, user), True


# ---------------------------------------------------------------------------
# Scope queries — the revision scope rule, in SQL
# ---------------------------------------------------------------------------

# A vuln/chain is in scope at revision R when it existed by R and had not been
# invalidated at or before R. COALESCE keeps rows written before migration 025
# (NULL existed_since_revision) in scope.
_SCOPE_SQL = (
    "COALESCE(existed_since_revision, 1) <= ? "
    "AND (invalidated_at_revision IS NULL OR invalidated_at_revision > ?)"
)

# Second clause, applied when scoring one specific scan: a scan can only be
# blamed for flaws that existed in the application when it ran. Without this, a
# vuln introduced by a code change (existed_since = N) would count as a miss for
# every older scan the moment they were re-scored at revision N — a decline the
# scanner did not cause. `existed_since = 1` ("existed all along") still reaches
# every scan, which is exactly the retroactive re-scoring we want.
_RAN_BEFORE_SQL = "COALESCE(existed_since_revision, 1) <= ?"


async def fetch_vulns_in_scope(db, app_id: int, revision: int,
                               scan_corpus_revision=None) -> list:
    """Vulns in scope at *revision*, optionally narrowed to one scan's corpus."""
    sql = f"SELECT * FROM vulnerabilities WHERE app_id = ? AND {_SCOPE_SQL}"
    params = [app_id, revision, revision]
    if scan_corpus_revision is not None:
        sql += f" AND {_RAN_BEFORE_SQL}"
        params.append(int(scan_corpus_revision))
    cursor = await db.execute(sql + " ORDER BY vuln_id", params)
    return await cursor.fetchall()


async def fetch_chains_in_scope(db, app_id: int, revision: int,
                                scan_corpus_revision=None) -> list[dict]:
    """Chains in scope, each with its ordered member vuln ids."""
    sql = f"SELECT * FROM chains WHERE app_id = ? AND {_SCOPE_SQL}"
    params = [app_id, revision, revision]
    if scan_corpus_revision is not None:
        sql += f" AND {_RAN_BEFORE_SQL}"
        params.append(int(scan_corpus_revision))
    cursor = await db.execute(sql + " ORDER BY chain_id", params)
    chains = [dict(row) for row in await cursor.fetchall()]
    if not chains:
        return []
    placeholders = ",".join("?" * len(chains))
    cursor = await db.execute(
        f"""SELECT chain_pk, vuln_id FROM chain_members
            WHERE chain_pk IN ({placeholders}) ORDER BY step_order""",
        [c["id"] for c in chains],
    )
    members: dict[int, list[int]] = {}
    for row in await cursor.fetchall():
        members.setdefault(row["chain_pk"], []).append(row["vuln_id"])
    for chain in chains:
        chain["members"] = members.get(chain["id"], [])
    return chains


async def fetch_findings(db, scan_id: int) -> list:
    cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,))
    return await cursor.fetchall()


# ---------------------------------------------------------------------------
# Live scoring
# ---------------------------------------------------------------------------

async def score(db, scan, revision: int) -> dict:
    """Compute metrics for *scan* at *revision*.

    Scope is the intersection of two things: what ground truth said at
    *revision*, and what existed in the application when this scan ran. See
    ``_RAN_BEFORE_SQL`` for why the second clause is not optional.

    Returns ``{metrics, vulns, chains, findings, revision}``.
    """
    app_id = scan["app_id"]
    corpus_revision = int(scoring.field(scan, "corpus_revision", revision) or revision)
    vulns = await fetch_vulns_in_scope(db, app_id, revision, corpus_revision)
    chains = await fetch_chains_in_scope(db, app_id, revision, corpus_revision)
    findings = await fetch_findings(db, scan["id"])

    metrics = compute_metrics(findings, vulns, chains)

    return {
        "metrics": metrics,
        "vulns": vulns,
        "chains": chains,
        "findings": findings,
        "revision": revision,
    }
