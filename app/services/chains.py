"""CRUD for exploit chains (see migrations/028_chains.sql and app/scoring.py).

A chain row is one PATH: ground truth like a vulnerability, credited per the
rule in ``scoring.compute_metrics``. Paths sharing a ``sink_vuln_id`` are one
chain and are credited once per scan. This module is the only write path for the
``chains``/``chain_members`` tables; before it existed, nothing could ever
populate them, so every chain-tier credit came from individual vulns
mistagged ``difficulty_tier='chained'`` instead of a real demonstrated chain.
"""

from __future__ import annotations

from app import scoring
from app.services import audit as audit_service
from app.services import finding_matches
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
    return await scoring_service.attach_chain_defs(db, app_id, chains)


_CODE_RE = __import__("re").compile(r"^CH-(\d+)$")


async def _chain_def(db, app_id: int, sink, chain_data: dict, fallback_name: str):
    """The chain (``chain_defs`` row) an attack path ending on *sink* belongs to.

    Created on first use with the next free ``CH-NN`` code, named from
    ``chain_name`` or else the path's title. ``chain_name``/``chain_code`` in the
    write rename it. Returns None for a path with no end step (its own chain).
    Presentation and identity only: scoring groups by end step either way.
    """
    if sink is None:
        return None
    cursor = await db.execute(
        "SELECT * FROM chain_defs WHERE app_id = ? AND sink_vuln_id = ?", (app_id, sink)
    )
    row = await cursor.fetchone()
    name = (chain_data.get("chain_name") or "").strip()[:200]
    code = (chain_data.get("chain_code") or "").strip().upper()
    if code and not _CODE_RE.match(code):
        raise ValueError("Invalid chain_code: use CH-<number>, e.g. CH-03")
    if row is None:
        if not code:
            cursor = await db.execute("SELECT code FROM chain_defs WHERE app_id = ?", (app_id,))
            numbers = [int(m.group(1)) for r in await cursor.fetchall()
                       if (m := _CODE_RE.match(r["code"]))]
            code = f"CH-{max(numbers, default=0) + 1:02d}"
        try:
            await db.execute(
                "INSERT INTO chain_defs (app_id, code, name, sink_vuln_id) VALUES (?, ?, ?, ?)",
                (app_id, code, name or fallback_name, sink),
            )
        except Exception as e:
            if "UNIQUE" in str(e):
                raise ValueError(f"Chain code '{code}' already exists on this app")
            raise
    else:
        updates = {}
        if name:
            updates["name"] = name
        if code and code != row["code"]:
            updates["code"] = code
        if updates:
            try:
                await db.execute(
                    f"UPDATE chain_defs SET {', '.join(f'{k} = ?' for k in updates)} WHERE id = ?",
                    (*updates.values(), row["id"]),
                )
            except Exception as e:
                if "UNIQUE" in str(e):
                    raise ValueError(f"Chain code '{code}' already exists on this app")
                raise
    cursor = await db.execute(
        "SELECT * FROM chain_defs WHERE app_id = ? AND sink_vuln_id = ?", (app_id, sink)
    )
    return await cursor.fetchone()


async def _next_path_id(db, app_id: int, code: str) -> str:
    """Next attack-path id under chain *code*: CH-01 -> CH-01.<n+1>."""
    cursor = await db.execute(
        "SELECT chain_id FROM chains WHERE app_id = ? AND chain_id LIKE ?", (app_id, code + ".%")
    )
    numbers = [int(r["chain_id"].rsplit(".", 1)[1]) for r in await cursor.fetchall()
               if r["chain_id"].rsplit(".", 1)[1].isdigit()]
    return f"{code}.{max(numbers, default=0) + 1}"


async def _drop_empty_chain_defs(db, app_id: int) -> None:
    """A chain with no attack paths left has nothing to show or score."""
    await db.execute(
        """DELETE FROM chain_defs WHERE app_id = ? AND sink_vuln_id NOT IN
           (SELECT sink_vuln_id FROM chains WHERE app_id = ? AND sink_vuln_id IS NOT NULL)""",
        (app_id, app_id),
    )


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


def _resolve_sink(chain_data: dict, member_ids: list[int], existing=None):
    """The path's sink: the step it ENDS on, which is its LAST step.

    Paths sharing a sink are one chain for scoring (see
    ``scoring._chain_groups``). Steps are stored in execution order, so the
    sink is always the last one; it is stored explicitly so that NULL can keep
    a path out of any group (every path written before migration 045). Absent
    from the write, an update keeps a grouped path grouped, on its (possibly
    new) last step. None means the path is its own chain.
    """
    if "sink_vuln_id" in chain_data:
        raw = chain_data.get("sink_vuln_id")
        if raw in (None, ""):
            return None
        try:
            sink = int(raw)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid sink_vuln_id: {raw!r}")
    else:
        grouped = existing is not None and existing["sink_vuln_id"] is not None
        return member_ids[-1] if grouped else None
    if sink != member_ids[-1]:
        raise ValueError("sink_vuln_id must be the path's last step (steps run in order)")
    return sink


def _severity_and_weight(chain_data: dict, existing=None) -> tuple[str, int]:
    """Resolve a chain's (severity, impact_weight) from a write.

    Severity is what a curator sets; the weight derives from it 1:1, exactly as
    for vulns (see vulns.update_vuln). A caller that still sends only
    impact_weight (the pre-041 API) gets the matching severity derived back, so
    it keeps working. With neither, an update keeps what the chain had.
    """
    raw = chain_data.get("severity")
    if raw not in (None, ""):
        severity = str(raw).strip().lower()
        if severity not in scoring.CHAIN_SEVERITIES:
            raise ValueError(f"severity must be one of {list(scoring.CHAIN_SEVERITIES)}")
        return severity, scoring.weight_from_severity(severity)

    weight = scoring.validate_weight(chain_data.get("impact_weight"))
    if weight is not None:
        return scoring.severity_from_weight(weight), weight

    if existing is not None:
        weight = existing["impact_weight"]
        return (existing["severity"] or scoring.severity_from_weight(weight)), weight
    raise ValueError("severity is required for a chain")


async def create_chain(db, user, app_id: int, chain_data: dict) -> dict:
    """Register a new chain. Returns the created row (with ``members``).

    *chain_data* keys: chain_id, title, description, severity (or, pre-041,
    impact_weight — see ``_severity_and_weight``),
    member_vuln_ids (ordered list of vuln PKs, >= 2), existed_since_revision.

    Mirrors ``vulns.create_vuln``: adding a chain changes ground truth, so on
    an app with existing scans this opens a new revision.

    Raises ``ValueError`` if the app/members are invalid or a scoring field
    fails validation. Raises ``PermissionError`` if access is denied.
    """
    app = await _get_visible_app(db, user, app_id)
    await _require_app_write(db, user, app)

    severity, weight = _severity_and_weight(chain_data)

    member_ids = await _resolve_members(db, app_id, chain_data.get("member_vuln_ids"))
    sink = _resolve_sink(chain_data, member_ids)

    title = (chain_data.get("title") or "").strip()
    if not title:
        raise ValueError("title is required for a chain")

    # An attack path's id comes from its chain: CH-01.1, CH-01.2, ... A path
    # with no end step is a chain of its own and keeps a CHAIN-### id.
    chain_def = await _chain_def(db, app_id, sink, chain_data, title)
    chain_id = (chain_data.get("chain_id") or "").strip()
    if not chain_id and chain_def is not None:
        chain_id = await _next_path_id(db, app_id, chain_def["code"])
    elif not chain_id:
        # Next after the highest CHAIN-### number, not the row count: retired
        # rows leave gaps, and a count would reuse a live id.
        cursor = await db.execute("SELECT chain_id FROM chains WHERE app_id = ?", (app_id,))
        numbers = [int(r["chain_id"][6:]) for r in await cursor.fetchall()
                   if r["chain_id"].startswith("CHAIN-") and r["chain_id"][6:].isdigit()]
        chain_id = f"CHAIN-{max(numbers, default=0) + 1:03d}"

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
            """INSERT INTO chains (app_id, chain_id, title, severity, impact_weight, description,
               existed_since_revision, sink_vuln_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (app_id, chain_id, title, severity, weight, chain_data.get("description"), existed_since,
             sink),
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

    severity, weight = _severity_and_weight(chain_data, existing)

    if chain_data.get("member_vuln_ids") is not None:
        member_ids = await _resolve_members(db, app_id, chain_data.get("member_vuln_ids"))
    else:
        cursor = await db.execute(
            "SELECT vuln_id FROM chain_members WHERE chain_pk = ? ORDER BY step_order",
            (chain_pk,),
        )
        member_ids = [row["vuln_id"] for row in await cursor.fetchall()]

    sink = _resolve_sink(chain_data, member_ids, existing)

    title = (chain_data.get("title") or existing["title"]).strip()

    # The path's chain, and its id: an explicit chain_id renames it; moving to
    # another chain (a new end step) gives it the next id there. Either way the
    # first CHAIN-### id it had is kept as legacy_chain_id.
    chain_def = await _chain_def(db, app_id, sink, chain_data, title)
    chain_id = (chain_data.get("chain_id") or "").strip() or existing["chain_id"]
    if (not chain_data.get("chain_id") and chain_def is not None
            and not existing["chain_id"].startswith(chain_def["code"] + ".")):
        chain_id = await _next_path_id(db, app_id, chain_def["code"])
    legacy = existing["legacy_chain_id"]
    if chain_id != existing["chain_id"] and not legacy and existing["chain_id"].startswith("CHAIN-"):
        legacy = existing["chain_id"]

    if sink != existing["sink_vuln_id"]:
        # Regrouping paths changes what a scan's chains are worth.
        codes = {}
        ids = [v for v in (existing["sink_vuln_id"], sink) if v is not None]
        if ids:
            cursor = await db.execute(
                f"SELECT id, vuln_id FROM vulnerabilities WHERE id IN ({','.join('?' * len(ids))})", ids,
            )
            codes = {row["id"]: row["vuln_id"] for row in await cursor.fetchall()}
        label = lambda v: codes.get(v, "none") if v is not None else "none"
        await scoring_service.revision_for_corpus_change(
            db, app_id, "corpus_change",
            notes=f"{existing['chain_id']} sink {label(existing['sink_vuln_id'])} → {label(sink)}",
            user=user,
        )

    if weight != existing["impact_weight"]:
        await scoring_service.revision_for_corpus_change(
            db, app_id, "weight_change",
            notes=f"{existing['chain_id']} severity {existing['severity']} → {severity} "
                  f"(impact_weight {existing['impact_weight']} → {weight})",
            user=user,
        )

    try:
        await db.execute(
            "UPDATE chains SET title = ?, description = ?, severity = ?, impact_weight = ?, "
            "sink_vuln_id = ?, chain_id = ?, legacy_chain_id = ? WHERE id = ?",
            (title, chain_data.get("description", existing["description"]), severity, weight,
             sink, chain_id, legacy, chain_pk),
        )
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ValueError(f"Chain id '{chain_id}' already exists on this app")
        raise
    await _drop_empty_chain_defs(db, app_id)
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


async def invalidate_chain(db, user, app_id: int, chain_pk: int, notes=None) -> dict:
    """Retire an attack path from ground truth without destroying history.

    The chain twin of ``vulns.invalidate_vuln``: opens a revision (reason
    ``chain_invalidated``) and stamps ``invalidated_at_revision`` with it, so
    the scope rule keeps the path for every earlier revision -- scorings
    computed back then stay reproducible -- while every scan scored at this
    revision or later stops getting credit for it. Its findings keep their vuln
    matches. For a path ruled not to be a chain after scans were scored
    (TaintedPort CH-02, 2026-11-12), or one a code change removed.

    Raises ``ValueError`` if app/chain not found or already invalidated.
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
    if chain["invalidated_at_revision"] is not None:
        raise ValueError("Chain is already invalidated")

    revision, _created = await scoring_service.revision_for_corpus_change(
        db, app_id, "chain_invalidated",
        notes=notes or f"Invalidated {chain['chain_id']}: {chain['title']}",
        user=user,
    )
    await db.execute(
        "UPDATE chains SET invalidated_at_revision = ? WHERE id = ?", (revision, chain_pk),
    )
    await audit_service.record_audit_event(
        db, entity_type="chain", action="chain_invalidated", actor=user,
        message=(
            f"{user['name']} invalidated {chain['chain_id']}: \"{chain['title']}\" "
            f"(opened ground-truth revision {revision})"
        ),
        entity_id=chain_pk, app_id=app_id,
    )
    await db.commit()
    return {"ok": True, "chain_pk": chain_pk, "invalidated_at_revision": revision}


async def delete_chain(db, user, app_id: int, chain_pk: int) -> None:
    """Delete an attack path and its members.

    Only for ground truth that was never measured, like ``delete_vuln``: a path
    some scan finding is matched to cannot be deleted -- that would rewrite
    history and orphan the finding; invalidate it instead
    (:func:`invalidate_chain`).

    Raises ``ValueError`` if app/chain not found or the path has been matched.
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
    matched = await finding_matches.count_findings_for_chain(db, chain_pk)
    if matched:
        raise ValueError(
            f"This attack path is matched by {matched} scan finding(s) and cannot be "
            "deleted. Invalidate it instead so historical scorings stay reproducible."
        )

    await db.execute("DELETE FROM chains WHERE id = ?", (chain_pk,))
    await _drop_empty_chain_defs(db, app_id)
    await audit_service.record_audit_event(
        db, entity_type="chain", action="chain_deleted", actor=user,
        message=f"{user['name']} deleted chain {chain['chain_id']}: \"{chain['title']}\"",
        entity_id=chain_pk, app_id=app_id,
    )
    await db.commit()
