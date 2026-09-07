"""CRUD for exploit chains (see migrations/028_chains.sql and app/scoring.py).

A chain is ground truth exactly like a vulnerability, except its weight is
credited only when every one of its member vulns is independently matched —
see ``scoring.compute_metrics``. This module is the only write path for the
``chains``/``chain_members`` tables; before it existed, nothing could ever
populate them, so every chain-tier credit came from individual vulns
mistagged ``difficulty_tier='chained'`` instead of a real demonstrated chain.
"""

from __future__ import annotations

from app import scoring
from app.services import audit as audit_service
from app.services import scoring as scoring_service
from app.services.vulns import _get_visible_app, _require_app_write


async def list_chains(db, user, app_id: int) -> list[dict]:
    """Return chains for an app, each with its resolved ordered ``members``.

    Raises ``ValueError`` if the app is not found / not visible.
    """
    await _get_visible_app(db, user, app_id)

    cursor = await db.execute(
        "SELECT * FROM chains WHERE app_id = ? ORDER BY chain_id", (app_id,)
    )
    chains = [dict(row) for row in await cursor.fetchall()]
    if not chains:
        return []

    placeholders = ",".join("?" * len(chains))
    cursor = await db.execute(
        f"""SELECT cm.chain_pk, cm.vuln_id, cm.step_order,
                   v.vuln_id AS vuln_code, v.title AS vuln_title
            FROM chain_members cm
            JOIN vulnerabilities v ON v.id = cm.vuln_id
            WHERE cm.chain_pk IN ({placeholders})
            ORDER BY cm.step_order""",
        [c["id"] for c in chains],
    )
    members_by_chain: dict[int, list] = {}
    for row in await cursor.fetchall():
        members_by_chain.setdefault(row["chain_pk"], []).append(
            {
                "vuln_id": row["vuln_id"],
                "vuln_code": row["vuln_code"],
                "vuln_title": row["vuln_title"],
                "step_order": row["step_order"],
            }
        )
    for c in chains:
        c["members"] = members_by_chain.get(c["id"], [])
    return chains


async def _resolve_members(db, app_id: int, member_vuln_ids: list) -> list[int]:
    """Validate that each id in *member_vuln_ids* is a vuln belonging to *app_id*.

    Returns the ids as ints, in the given (step) order. Raises ``ValueError``
    on a missing/invalid/cross-app id, or fewer than two members — a chain
    with a single member is just a vuln.
    """
    ids = []
    for v in member_vuln_ids or []:
        try:
            ids.append(int(v))
        except (TypeError, ValueError):
            raise ValueError(f"Invalid member vuln id: {v!r}")
    if len(ids) < 2:
        raise ValueError("A chain needs at least two member vulnerabilities")
    if len(set(ids)) != len(ids):
        raise ValueError("A chain cannot list the same vulnerability twice")

    placeholders = ",".join("?" * len(ids))
    cursor = await db.execute(
        f"SELECT id FROM vulnerabilities WHERE app_id = ? AND id IN ({placeholders})",
        [app_id] + ids,
    )
    found = {row["id"] for row in await cursor.fetchall()}
    missing = [i for i in ids if i not in found]
    if missing:
        raise ValueError(f"Vulnerability id(s) not found on this app: {missing}")
    return ids


async def create_chain(db, user, app_id: int, chain_data: dict) -> dict:
    """Register a new chain. Returns the created row (with ``members``).

    *chain_data* keys: chain_id, title, description, impact_weight,
    member_vuln_ids (ordered list of vuln PKs, >= 2), existed_since_revision.

    Mirrors ``vulns.create_vuln``: adding a chain changes ground truth, so on
    an app with existing scans this opens a new revision.

    Raises ``ValueError`` if the app/members are invalid or a scoring field
    fails validation. Raises ``PermissionError`` if access is denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    weight = scoring.validate_weight(chain_data.get("impact_weight"))
    if weight is None:
        raise ValueError("impact_weight is required for a chain")

    member_ids = await _resolve_members(db, app_id, chain_data.get("member_vuln_ids"))

    chain_id = (chain_data.get("chain_id") or "").strip()
    if not chain_id:
        cursor = await db.execute(
            "SELECT COUNT(*) AS c FROM chains WHERE app_id = ?", (app_id,)
        )
        chain_id = f"CHAIN-{(await cursor.fetchone())['c'] + 1:03d}"

    title = (chain_data.get("title") or "").strip()
    if not title:
        raise ValueError("title is required for a chain")

    revision, _created = await scoring_service.revision_for_corpus_change(
        db, app_id, "new_prior_vuln",
        notes=f"Added chain: {chain_id}",
        user=user,
    )
    existed_since = chain_data.get("existed_since_revision")
    try:
        existed_since = int(existed_since) if existed_since not in (None, "") else 1
    except (TypeError, ValueError):
        existed_since = 1

    try:
        cursor = await db.execute(
            """INSERT INTO chains (app_id, chain_id, title, impact_weight, description,
               existed_since_revision) VALUES (?, ?, ?, ?, ?, ?)""",
            (app_id, chain_id, title, weight, chain_data.get("description"), existed_since),
        )
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ValueError(f"Chain id '{chain_id}' already exists on this app")
        raise
    chain_pk = cursor.lastrowid

    for step_order, vuln_id in enumerate(member_ids, start=1):
        await db.execute(
            "INSERT INTO chain_members (chain_pk, vuln_id, step_order) VALUES (?, ?, ?)",
            (chain_pk, vuln_id, step_order),
        )

    await audit_service.record_audit_event(
        db, entity_type="chain", action="chain_created", actor=user,
        message=f"{user['name']} registered chain {chain_id}: \"{title}\" "
                f"({len(member_ids)} members, opened revision {revision})",
        entity_id=chain_pk, app_id=app_id,
    )
    await db.commit()

    chains = await list_chains(db, user, app_id)
    return next(c for c in chains if c["id"] == chain_pk)


async def update_chain(db, user, app_id: int, chain_pk: int, chain_data: dict) -> dict:
    """Full update of a chain's title/description/weight/members.

    Raises ``ValueError`` if the app/chain/members are invalid.
    Raises ``PermissionError`` if access is denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT * FROM chains WHERE id = ? AND app_id = ?", (chain_pk, app_id)
    )
    existing = await cursor.fetchone()
    if not existing:
        raise ValueError("Chain not found")

    weight = scoring.validate_weight(chain_data.get("impact_weight"))
    if weight is None:
        weight = existing["impact_weight"]

    if chain_data.get("member_vuln_ids") is not None:
        member_ids = await _resolve_members(db, app_id, chain_data.get("member_vuln_ids"))
    else:
        cursor = await db.execute(
            "SELECT vuln_id FROM chain_members WHERE chain_pk = ? ORDER BY step_order",
            (chain_pk,),
        )
        member_ids = [row["vuln_id"] for row in await cursor.fetchall()]

    title = (chain_data.get("title") or existing["title"]).strip()

    if weight != existing["impact_weight"]:
        await scoring_service.revision_for_corpus_change(
            db, app_id, "weight_change",
            notes=f"{existing['chain_id']} impact_weight {existing['impact_weight']} → {weight}",
            user=user,
        )

    await db.execute(
        "UPDATE chains SET title = ?, description = ?, impact_weight = ? WHERE id = ?",
        (title, chain_data.get("description", existing["description"]), weight, chain_pk),
    )
    await db.execute("DELETE FROM chain_members WHERE chain_pk = ?", (chain_pk,))
    for step_order, vuln_id in enumerate(member_ids, start=1):
        await db.execute(
            "INSERT INTO chain_members (chain_pk, vuln_id, step_order) VALUES (?, ?, ?)",
            (chain_pk, vuln_id, step_order),
        )

    await audit_service.record_audit_event(
        db, entity_type="chain", action="chain_updated", actor=user,
        message=f"{user['name']} updated chain {existing['chain_id']}: \"{title}\"",
        entity_id=chain_pk, app_id=app_id,
    )
    await db.commit()

    chains = await list_chains(db, user, app_id)
    return next(c for c in chains if c["id"] == chain_pk)


async def delete_chain(db, user, app_id: int, chain_pk: int) -> None:
    """Delete a chain and its members.

    Raises ``ValueError`` if app/chain not found.
    Raises ``PermissionError`` if access is denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT * FROM chains WHERE id = ? AND app_id = ?", (chain_pk, app_id)
    )
    chain = await cursor.fetchone()
    if not chain:
        raise ValueError("Chain not found")

    await db.execute("DELETE FROM chains WHERE id = ?", (chain_pk,))
    await audit_service.record_audit_event(
        db, entity_type="chain", action="chain_deleted", actor=user,
        message=f"{user['name']} deleted chain {chain['chain_id']}: \"{chain['title']}\"",
        entity_id=chain_pk, app_id=app_id,
    )
    await db.commit()
