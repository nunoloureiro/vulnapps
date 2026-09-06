# Audit / History Log — Implementation Plan

Status: **PLAN ONLY — nothing implemented.** No migration, service, router, or
frontend file has been touched. This document is for review/approval.

Scope, per the request: exactly two surfaces —
1. `ScanDetail.jsx` — a "History Log" of operations on that scan's findings.
2. `AppDetail.jsx` — a "History Log" of operations on that app's vulnerabilities
   (ground truth).

No audit logging anywhere else in the app for now.

---

## 0. IMPORTANT — one open question that blocks implementation

The request says the History Log must be visible "only to `contributor` and
`admin` roles — not `viewer` or `user`."

**That role model does not exist in this codebase today.** `migrations/005_viewer_role.sql`
added `viewer`/`contributor` as account roles, but `migrations/012_permissions_redesign.sql`
(a later migration) explicitly collapsed them back out:

```
-- 012_permissions_redesign.sql
-- Account roles: user, admin (viewer/contributor merged into user)
UPDATE users SET role = 'user' WHERE role IN ('viewer', 'contributor');
...
role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin'))
```

`app/services/users.py:23` still enforces this: `updates["role"] not in ("user", "admin")`
is rejected. Today, `contributor` and `viewer` exist **only** as *team* roles
(`team_members.role IN ('admin','contributor','view')`, migration 012), scoped
to one team, not as a global account attribute. Confirmed via grep — every
`user["role"] == ...` check in `app/` compares against `'admin'` only; nothing
in the account-role code path ever checks for `'contributor'`.

So "gate to contributor/admin" cannot be implemented literally as a global
role check — if it were, only global admins (nobody has account-level
`contributor`) would ever see the log, which can't be the intent.

**Recommendation (Option B below) — reuse the existing write-access
predicate instead of inventing a new role concept:**

Every place that already needs to answer "can this person edit this
scan/app" computes it today:
- `ScanDetail`: `_check_scan_write` (`app/services/scans.py:21`) / the
  `can_edit` flag already returned by `get_scan` (`scans.py:369-384`).
- `AppDetail`: `_require_app_write` / `_can_edit_full` (`app/services/vulns.py:96-134`)
  / the `can_edit` flag already returned by `get_app` (`app/services/apps.py:213-229`).

That predicate is exactly "global admin, OR the scan submitter / app creator,
OR a team member whose **team role** is `admin` or `contributor`" — i.e. it
already is the "contributor and admin" population the request describes, just
computed per-resource instead of globally. Read-only accounts (no write
access to this particular scan/app) are exactly the "viewer/user" population
the request wants excluded.

**Plan assumes Option B**: gate the History Log (both API and UI) on the same
write-access check already used for editing that scan/app — i.e. if
`can_edit` is true, the caller may also see history for that resource. This
needs zero new role concept, matches "reuse existing patterns" from
`CLAUDE.md`, and doesn't require resurrecting the account-level
viewer/contributor roles migration 012 deliberately removed.

**This must be confirmed with the user before implementation** — if they
actually want a global `contributor` account role reinstated, that is a much
bigger change (reverts part of migration 012) and out of scope for "just add
an audit log."

---

## 1. Survey — confirmed no existing mechanism

`grep -ril "audit\|history_log\|activity_log" app/ migrations/` found only:
- `app/services/vulns.py` — the word "audit" appears once, in a docstring
  describing `import_vulns`'s *return value* (`{imported, skipped_over_cap,
  truncated_fields}`) as an "audit dict" — this is not a persisted log, just a
  descriptive comment on a response shape.
- `migrations/025_ground_truth_revisions.sql` — a comment noting
  `known_since_revision` is "Audit only" (i.e., doesn't affect scoring).

No `audit_log`/`history_log`/`activity_log` table, no generic event-recording
helper anywhere. Clean slate.

**One existing analog worth knowing about**: `ground_truth_revisions`
(migration 025) already records `{app_id, revision, reason, notes, created_by,
created_at}` for corpus-changing events, and `AppDetail.jsx`'s `GroundTruth`
component (lines 433-505) already renders it as a collapsible "N revisions"
history panel — visible to **everyone** who can view the app, not gated by
edit/write access. This is a good UI precedent (collapsible table: reason /
notes / by / when) but it is a *different, currently-ungated* feature. See
§3.4 for how the new gated History Log coexists with it without duplicating
data or accidentally exposing gated info in the ungated panel.

---

## 2. Current behavior of every function in scope

### `app/services/scans.py`

| Function | Current fetch of "before" state | Notes for audit hook |
|---|---|---|
| `match_finding(db, user, scan_id, finding_id, vuln_id)` (line 586) | Only checks finding **exists** (`SELECT id FROM scan_findings WHERE id=? AND scan_id=?`, line 598); only checks target vuln's `app_id` (`SELECT app_id FROM vulnerabilities WHERE id=?`, line 610) — does **not** currently fetch the finding's title or the vuln's `vuln_id` slug. | Needs widening: fetch full finding row (`title`, `vuln_type`, `url`/`filename`, current `matched_vuln_id`) and the target vuln's `vuln_id` text (e.g. `"TP-014"`), not just its `app_id`, to build the message. Three cases: new match, changed match, cleared match (unmatch) — distinguish via old vs. new `matched_vuln_id`. |
| `mark_finding_fp(db, user, scan_id, finding_id, fp_group)` (line 632) | No finding fetch at all before the `UPDATE`. | Add a `SELECT title, ... FROM scan_findings WHERE id=?` before the update to get the title for the message. |
| `set_finding_ignored(db, user, scan_id, finding_id, ignored)` (line 649) | Same — no finding fetch before update. | Same fix; message differs for ignore=True vs ignore=False (un-ignore → back to Pending). |
| `promote_finding(db, user, scan_id, finding_id, overrides)` (line 687) | Already fetches the full finding row (line 718) and, after insert, the new vuln row (line 797) — everything needed is already in hand. | This is a **dual-entity event** — it both resolves a finding (scan-scoped) and creates a vuln (app-scoped). Plan: write **two** audit rows from one call — one `scan_id`-scoped (shows on ScanDetail: "promoted finding X to new vuln Y"), one `app_id`-scoped (shows on AppDetail: "vuln Y created via promotion from scan Z"). See §3.2. |
| `rematch_scan(db, user, scan_id)` (line 809) | Loops all findings, applies auto-matching algorithmically; counts `updated`. | This is a **bulk/algorithmic** action, not an individual human decision per finding. Write **one aggregate row** ("re-ran auto-matching, N finding(s) changed") only if `updated > 0` — do NOT write one row per finding (would flood the log with machine decisions indistinguishable from clicks). |

### `app/services/vulns.py`

| Function | Current fetch of "before" state | Notes for audit hook |
|---|---|---|
| `create_vuln(db, user, app_id, vuln_data)` (line 259) | N/A — nothing exists yet. Has everything needed after insert (`new_id`, `vuln_id` slug, `title`, `severity`). | Straightforward one-row event. |
| `update_vuln(db, user, app_id, vuln_id, vuln_data)` (line 340) | Already fetches `existing` (full old row, line 353) before applying changes; already diffs `impact_weight` for the revision-open decision (line 370). | Reuse the same before/after pair to build a **single summary message** listing which fields changed (title/severity/impact_weight/etc.) rather than one row per field — keeps the log skimmable. |
| `delete_vuln(db, user, app_id, vuln_id)` (line 413) | Only runs a `COUNT(*)` on `scan_findings` to check it's unmatched (line 427) — never fetches the vuln's own row, so `vuln_id` slug/title are unavailable once the `DELETE` runs. | Must add a `SELECT * FROM vulnerabilities WHERE id=? AND app_id=?` **before** the delete, purely to capture text for the message (the row will be gone right after). |
| `invalidate_vuln(db, user, app_id, vuln_id, notes)` (line 444) | Already fetches the full vuln row before invalidating (line 458). | Straightforward — include the revision number it opened. |
| `import_vulns(db, user, app_id, vulns_data, existed_since)` (line 544) | Bulk; loops rows. | Same bulk-aggregation rule as `rematch_scan`: **one row per import call** ("bulk-imported N vuln(s)"), not one per row — a single CSV upload of 200 rows must not produce 200 log lines. Skip logging entirely if `imported == 0`. |
| `inline_update_vuln(db, user, app_id, vuln_id, updates)` (line 480) | **Dead code** — grepped every router file; nothing calls this service function. The frontend's inline cell editor in `AppDetail.jsx` (the `renderEditInput`/`startEdit` flow around lines 156-235) actually calls `api.put('/apps/{id}/vulns/{vuln_id}', body)`, which hits the `update_vuln` router endpoint (`app/routers/api/vulns.py:98`) → `update_vuln` service function, **not** `inline_update_vuln`. | Flag for the implementer to confirm this is genuinely unused before deciding whether to instrument it too. If confirmed dead, no hook needed here — `update_vuln` alone covers the inline-edit path. |

### `app/services/scoring.py` — `create_revision` (line 65) and friends

`create_revision`/`revision_for_corpus_change` are called from **five**
places: `create_vuln`, `update_vuln` (on weight change), `invalidate_vuln`,
`promote_finding`, and the standalone `POST /api/apps/{app_id}/revisions`
endpoint (`app/routers/api/scans.py:465-494`, which calls
`scoring_service.create_revision` directly).

**Decision: do not add an audit hook inside `create_revision` itself.** If we
did, every one of those five call sites would emit a *second*, generic
"opened revision N" row in addition to its own specific message (e.g.
`create_vuln` would log both "created vuln DISC-004" and "opened revision
6" for the same click) — duplicate noise for four of the five paths. Instead:
- The four vuln-mutation call sites each mention the revision number they
  opened directly inside their own already-specific message (e.g. "created
  vulnerability DISC-004: SQLi (opened ground-truth revision 6)").
- Only the **standalone** "open a revision" endpoint
  (`api/scans.py:465-494`, used when a human opens a revision with no other
  more-specific action) gets its own audit row, added at the router/service
  call site — not inside `create_revision` — so the four other callers are
  untouched. See §3.3.

`scoring.py` itself needs **no changes**; the hook is purely additive at the
callers.

---

## 3. Schema design

### 3.1 Migration numbering — READ THIS BEFORE PICKING A FILENAME

This session found that:
- **All migration files in this repo are currently uncommitted** (`git
  status` shows `migrations/024_vuln_weights.sql` through
  `migrations/032_benchmark_corpus.sql` as untracked, plus `034_*` new).
- **Production tracks applied migrations by filename only.** Once a filename
  has run in production, editing that file's *content* later and
  redeploying does **nothing** — the runner sees the filename already
  recorded and skips it, silently leaving production on the old schema.
- This exact mistake already happened this session:
  `migrations/034_weight_verified_deploy_fix.sql` exists *purely* to work
  around `032_benchmark_corpus.sql` having been edited in place after
  production had already applied the original `032` (under old column
  names `is_benchmark_corpus`/`scoring_reviewed`) — production was stuck
  until a fresh filename (`034`) reintroduced the same columns under their
  final names.
- The highest migration number in the repo right now is **`034`**.

**Rule for this feature: create a brand-new file, `migrations/035_audit_log.sql`,
and never edit it again once it has shipped anywhere** (including this local
dev environment, if there's any chance it's already been deployed). If a
mistake is found after the fact, ship the fix as `036_*`, not by editing `035`.

### 3.2 Table: `audit_log`

**Design choice: pre-rendered message, not structured-fields-rendered-by-frontend.**

Reasoning:
- The frontend becomes trivial either way — a scan/app id → list of
  `{message, created_at}`. No per-action-type template logic duplicated in
  JS, no risk of frontend and backend message wording drifting apart.
- The message must reflect the state **at the time of the action** — e.g.,
  "matched to TP-014" should still read that way even if TP-014 is later
  renamed or its `vuln_id` slug changes, or if the actor's display name is
  later changed via account settings, or if the finding/vuln is later
  deleted (entity may no longer exist to join against). A purely
  structured/foreign-keyed design would either need to snapshot every
  referenced value anyway (at which point you may as well render the
  string) or would render *wrong, currently-true* values for a
  *historical* event — the ground_truth_revisions/GroundTruth precedent in
  this codebase already renders live joins (`created_by_name` via `LEFT
  JOIN users`), which is fine for revisions (immutable reasons) but wrong
  for a log whose whole point is "what did X do when," where "X" and the
  entity's name can drift after the fact.
- A few structured columns are kept anyway (`entity_type`, `scan_id`/`app_id`,
  `action`) — not for rendering, but so the read endpoint can filter/index
  efficiently and so a future feature (e.g. "show only my changes," or a
  per-action icon) isn't blocked without a schema migration.

```sql
-- migrations/035_audit_log.sql

-- Human-readable, append-only history of operations on scan findings and on
-- app vulnerabilities (ground truth). Scoped to exactly two consumers today:
-- ScanDetail's "History Log" (queries by scan_id) and AppDetail's "History
-- Log" (queries by app_id). The message is rendered ONCE, at write time —
-- see tasks/audit-log-plan.md §3.2 for why (actor names, entity titles, and
-- vuln_id slugs can all change after the fact; the log must not reflect that).

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('scan_finding', 'vulnerability')),
    entity_id   INTEGER,                                   -- finding/vuln id; NULL for bulk/aggregate events (rematch, import)
    scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,   -- set for entity_type='scan_finding'
    app_id      INTEGER REFERENCES apps(id) ON DELETE CASCADE,    -- set for entity_type='vulnerability'
    action      TEXT NOT NULL,                              -- e.g. finding_matched, finding_unmatched, finding_marked_fp,
                                                              -- finding_marked_ignored, finding_unignored, finding_promoted,
                                                              -- scan_rematched, vuln_created, vuln_updated, vuln_deleted,
                                                              -- vuln_invalidated, vulns_imported, revision_opened
    actor_id    INTEGER NOT NULL REFERENCES users(id),
    message     TEXT NOT NULL,                               -- pre-rendered, human-readable, e.g.
                                                               -- "Nuno Loureiro changed the mapping of 'SQL Injection in /login'
                                                               --  to TP-014 on 2026-09-06"
    details     TEXT,                                         -- optional JSON blob, e.g. {"old_vuln_id": "TP-009", "new_vuln_id": "TP-014"}
                                                                -- kept for future filtering/tooling; not required to render the log
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_scan ON audit_log(scan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_app  ON audit_log(app_id, created_at);
```

Notes:
- `scan_id`/`app_id` are real FKs with `ON DELETE CASCADE` — deleting a scan
  or app purges its own history (mirrors how `scan_findings`/`vulnerabilities`
  already cascade-delete). `entity_id` is deliberately a plain, unconstrained
  integer (not an FK) because it can point at either a `scan_findings.id` or
  a `vulnerabilities.id` depending on `entity_type`, and because the row it
  once pointed at may legitimately no longer exist (a deleted vuln) — the
  message text is what's authoritative, `entity_id` is informational only.
- `actor_id` has no cascade; matches the existing convention for
  `created_by`/`submitted_by` columns elsewhere (no cascading user deletes
  in this schema today).
- No pagination-support columns beyond the index — see §4.3 for why a simple
  `LIMIT` is enough at this app's scale.

### 3.3 Where `revision_opened` gets used

Only from the standalone `POST /api/apps/{app_id}/revisions` handler
(`api/scans.py:465-494`) — added at the router/service call site there, not
inside `scoring_service.create_revision`. See §2's reasoning.

### 3.4 Relationship to the existing `GroundTruth` panel

Leave `ground_truth_revisions` and `AppDetail.jsx`'s existing `GroundTruth`
component (lines 433-505) exactly as they are — untouched, still visible to
anyone who can view the app (no gating change). **Do not merge revision rows
into the new gated `audit_log` timeline for display** — that panel is
intentionally ungated today, and gating it would be a behavior change nobody
asked for; conversely, copying gated audit data into that ungated panel would
leak it. The two stay visually and permission-wise separate: "Ground Truth"
(existing, ungated, revision-only) sits above the vuln table as it does now;
the new "History Log" (gated, all vuln CRUD + revision-open-standalone
events) is a distinct section at the very end of the page, per the request.

---

## 4. Backend

### 4.1 Shared helper — `app/services/audit.py` (new module)

Mirrors the shape of `app/services/scoring.py`'s `create_revision`: **does
not commit** — the caller commits together with the write it's recording, so
the two can never drift apart (same pattern already used everywhere in this
codebase for anything that must land atomically with its trigger).

```python
async def record_audit_event(
    db, *, entity_type: str, action: str, actor: dict, message: str,
    entity_id: int | None = None, scan_id: int | None = None,
    app_id: int | None = None, details: dict | None = None,
) -> None:
    """Append one audit_log row. Does not commit — call this in the same
    transaction as the write it documents, then commit once."""
    ...

async def list_audit_events(db, *, scan_id: int | None = None,
                             app_id: int | None = None, limit: int = 200) -> list[dict]:
    """Most-recent-first audit rows for a scan or an app (exactly one of the
    two must be given)."""
    ...
```

### 4.2 Call sites (additive only — no signature changes to public functions)

- `scans.py::match_finding` — widen the two existing lookups (finding: full
  row instead of just `id`; vuln: include `vuln_id` slug, not just `app_id`),
  branch the message on old vs. new `matched_vuln_id` (matched / re-matched /
  unmatched), call `record_audit_event(entity_type='scan_finding',
  action='finding_matched'|'finding_unmatched', scan_id=scan_id,
  entity_id=finding_id, ...)` before the existing `db.commit()`.
- `scans.py::mark_finding_fp` — add the missing finding-title `SELECT`, then
  the same pattern (`action='finding_marked_fp'`).
- `scans.py::set_finding_ignored` — same (`action='finding_marked_ignored'` /
  `'finding_unignored'`).
- `scans.py::promote_finding` — **two** `record_audit_event` calls: one
  `entity_type='scan_finding'` (scan-scoped), one `entity_type='vulnerability'`
  (app-scoped), both before the single `db.commit()` already there.
- `scans.py::rematch_scan` — one call, only `if updated: ...`, right before
  `db.commit()`.
- `vulns.py::create_vuln` — one call after the insert, before `db.commit()`.
- `vulns.py::update_vuln` — build the diff-summary message from `existing`
  vs. the new values, one call before `db.commit()`.
- `vulns.py::delete_vuln` — add the missing pre-delete `SELECT *`, log
  before executing the `DELETE`/`db.commit()` (message captures the
  soon-to-be-gone row).
- `vulns.py::invalidate_vuln` — one call, mentions the revision number,
  before `db.commit()`.
- `vulns.py::import_vulns` — one call, only `if imported: ...` (skip when the
  batch was empty or fully rejected), before `db.commit()`.
- `api/scans.py`'s standalone revision-open endpoint (lines 465-494) — one
  call at the router level (or a thin service wrapper), `action='revision_opened'`,
  `entity_type='vulnerability'`, `app_id=app_id`, `entity_id=None`.

### 4.3 Read endpoints

New routes, gated per §0's Option B (same predicate as `can_edit`):

- `GET /api/scans/{scan_id}/history` — mounted on the existing `router` in
  `app/routers/api/scans.py` (already handles `/{scan_id}/...` routes).
  Fetch scan+app, run the *existing* `_check_scan_write` logic from
  `scans_service` (reuse it — don't reimplement) to decide 200 vs 403, then
  `list_audit_events(db, scan_id=scan_id)`.
- `GET /api/apps/{app_id}/history` — mounted on `vulns.py`'s `router`
  (already mounted at `/api/apps`, already has `_get_visible_app`/
  `_require_app_write` available). Reuse `_can_edit_full` for the 200/403
  decision, then `list_audit_events(db, app_id=app_id)`.

Both endpoints **must** enforce this server-side regardless of what the UI
shows — a `can_edit`-gated UI element backed by an ungated API is not real
access control (the request explicitly calls this out).

Volume: given this app's scale (a benchmark-tracking tool, not
high-traffic SaaS — `MAX_VULNS_PER_APP` is already capped at 1000, and
scans/findings are comparably small), a flat `ORDER BY created_at DESC LIMIT
200` (mirroring the existing capped-read pattern in
`vulns_service.list_vulns`) is enough for v1. No offset/pagination UI is
proposed now; if a single scan/app ever produces >200 log-worthy events
(plausible only after months of heavy use), add `?before=<id>` cursor
pagination later — not needed to ship this.

---

## 5. Frontend

### 5.1 `ScanDetail.jsx`

- `get_scan` (`app/services/scans.py:312`) already returns `can_edit`; add
  nothing new there — the History Log component fetches
  `/api/scans/{id}/history` itself and the 403 the API returns for a
  non-write user is the real gate. The component only *renders* when
  `can_edit` is true (mirrors exactly how `EditableField` / the finding
  action buttons already gate on `can_edit` in this file) — this is
  UI-polish only, not the security boundary.
- Placement: new `<HistoryLog scanId={id} canView={can_edit} />` component,
  added as the **last** element inside the top-level fragment, right after
  the existing `{missed_vulns && ... && <MissedVulns .../>}` line (currently
  line 46) and before the closing `</>` / `);` / `}` (lines 47-49).
- Rendering: simple reverse-chronological list/table (mirrors the
  `GroundTruth` revisions table style already in `AppDetail.jsx`: one row per
  event, columns roughly `When | Message`). No client-side templating — just
  render `entry.message` and format `entry.created_at`.

### 5.2 `AppDetail.jsx`

- `get_app` similarly already returns `can_edit`; same pattern.
- Placement: new `<HistoryLog appId={id} canView={can_edit} />`, added right
  before the final closing `</div>` of the `container` div (currently around
  line 418, immediately after the vulns-table/empty-state block and its
  closing `)}`), i.e. as the last section on the page, distinct from and
  below the existing `GroundTruth` panel (which stays where it is, near the
  top, per §3.4).
- Reuses the same `HistoryLog` component as ScanDetail (one shared component
  in `frontend/src/components/`, parameterized by whichever of
  `scanId`/`appId` is passed) — avoids duplicating the fetch/render logic
  twice.

### 5.3 Message templates (rendered server-side; frontend just displays them verbatim)

Matching the request's own examples:

| Action | Template |
|---|---|
| Match / re-match | `{actor} changed the mapping of "{finding_title}" to {vuln_id_slug} on {date}` |
| First match (no prior match) | `{actor} matched "{finding_title}" to {vuln_id_slug} on {date}` |
| Unmatch (cleared) | `{actor} removed the mapping of "{finding_title}" (was {old_vuln_id_slug}) on {date}` |
| Mark FP | `{actor} marked "{finding_title}" as a false positive on {date}` |
| Mark ignored | `{actor} marked "{finding_title}" as ignored on {date}` |
| Un-ignore | `{actor} un-ignored "{finding_title}" (returned to Pending) on {date}` |
| Promote (scan side) | `{actor} promoted "{finding_title}" to new vulnerability {new_vuln_id_slug} on {date}` |
| Promote (app side) | `{actor} created vulnerability {new_vuln_id_slug}: "{title}" from a promoted finding on {date}` |
| Rematch (bulk) | `{actor} re-ran auto-matching on this scan — {n} finding(s) changed on {date}` |
| Vuln created | `{actor} created vulnerability {vuln_id_slug}: "{title}" ({severity}) on {date}` |
| Vuln updated | `{actor} updated {vuln_id_slug}: {comma-joined list of changed fields, e.g. "severity high → critical"} on {date}` |
| Vuln deleted | `{actor} deleted vulnerability {vuln_id_slug}: "{title}" on {date}` |
| Vuln invalidated | `{actor} invalidated {vuln_id_slug}: "{title}" (opened ground-truth revision {n}) on {date}` |
| Bulk import | `{actor} bulk-imported {n} vulnerabilit{y/ies} on {date}` |
| Revision opened (standalone) | `{actor} opened ground-truth revision {n} ({reason}) on {date}` |

`{date}` is rendered from `created_at` at write time via whatever date
formatting helper the codebase already uses elsewhere (check
`ScanCompare.jsx`'s `short_date` logic, `scans.py:932-948`, for the existing
short-date convention before inventing a new one).

---

## 6. Testing

New test file(s), following the existing service-level-against-a-throwaway-db
convention already used in `tests/test_scoring_revisions.py` (in-memory
`aiosqlite` DB, `run_migrations`, plain dict user fixtures — no HTTP layer):

- `tests/test_audit_log.py`:
  - `record_audit_event` + `list_audit_events` round-trip (write, read back,
    ordering is most-recent-first, `scan_id`-scoped query never returns
    `app_id`-scoped rows and vice versa).
  - `match_finding` (new match, re-match, and unmatch) each produce exactly
    one row with the expected `action` and a message containing the
    finding's title and the vuln's `vuln_id` slug.
  - `mark_finding_fp` / `set_finding_ignored` (both directions) each produce
    one row.
  - `promote_finding` produces **two** rows (one `scan_id`-scoped, one
    `app_id`-scoped) from a single call.
  - `rematch_scan` produces **zero** rows when nothing changed and exactly
    **one** aggregate row when `updated > 0` (not one per finding).
  - `create_vuln` / `update_vuln` / `delete_vuln` / `invalidate_vuln` each
    produce one row; `update_vuln`'s message reflects which fields actually
    changed (assert on a no-op update producing no row, or a row with an
    empty-changes message — pick one behavior and test it explicitly).
  - `import_vulns` produces one aggregate row for N>0 imported rows, zero
    rows when everything is rejected/over-cap.
  - Deleting a vuln that was never matched removes it but its audit
    row (`vuln_deleted`) persists with the captured title (proves the
    pre-delete-fetch fix in §2 actually landed).
  - Deleting a scan cascades its `audit_log` rows (FK `ON DELETE CASCADE`);
    deleting an app cascades its own.
- API-level test (extends `tests/test_api_endpoints.py`'s existing pattern,
  or a new `tests/test_history_endpoints.py`):
  - `GET /api/scans/{id}/history` returns 403 for a user without
    scan-write access and 200 with entries for one who has it (admin,
    submitter, and team-contributor cases — mirrors the three branches
    already tested for `_check_scan_write` elsewhere, if such tests exist —
    check `test_api_endpoints.py` for the existing pattern first).
  - `GET /api/apps/{id}/history` — same three-branch check against
    `_can_edit_full`.
  - Confirm the endpoint refuses even when called directly (not just
    UI-hidden) — i.e. the test must hit the route with a low-privilege
    token, not just check a frontend flag.

---

## 7. Summary of new/changed files (for the approval step — not yet created)

- **New**: `migrations/035_audit_log.sql`
- **New**: `app/services/audit.py`
- **New**: `frontend/src/components/HistoryLog.jsx`
- **New**: `tests/test_audit_log.py` (+ history-endpoint tests, new or appended)
- **Changed**: `app/services/scans.py` (`match_finding`, `mark_finding_fp`,
  `set_finding_ignored`, `promote_finding`, `rematch_scan` — each gets one or
  two additive `record_audit_event` calls plus, in two cases, a widened
  pre-existing `SELECT`)
- **Changed**: `app/services/vulns.py` (`create_vuln`, `update_vuln`,
  `delete_vuln`, `invalidate_vuln`, `import_vulns` — same additive pattern;
  `delete_vuln` gets a new pre-delete `SELECT *`)
- **Changed**: `app/routers/api/scans.py` (two new `GET .../history` routes;
  one new audit call at the standalone revision-open endpoint)
- **Changed**: `app/routers/api/vulns.py` (one new `GET .../history` route)
- **Changed**: `frontend/src/pages/ScanDetail.jsx` (one new component at the
  end of the page)
- **Changed**: `frontend/src/pages/AppDetail.jsx` (one new component at the
  end of the page)
- **Changed**: `AppBuilder.md` (spec update, per repo convention, once
  implemented)
