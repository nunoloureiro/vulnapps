# Discovery-Mode Scan Import

## Goal

Support a new workflow where the user scans popular web apps to find 0-days:
- Create the target app on import if it doesn't exist (via CLI args).
- Findings carry full details so unmapped ones can be promoted into vulns.
- Subsequent scans of the same app map to existing (now-confirmed) vulns or surface new candidates.

No new "modes" on apps/vulns — existing TP/FP/Pending finding states already model this. The deltas are:
1. CLI can create the target app (two-step, reusing `POST /api/apps` then `POST /api/apps/{id}/scans`).
2. `scan_findings` persists vuln-like details (title, severity, description, poc, remediation, code_location).
3. New "Promote finding to vuln" action on the scan page + matching API endpoint.

## Phase 1 — Schema + backend persistence
- [x] Migration `019_finding_details.sql` — add nullable columns to `scan_findings`: `title`, `severity`, `description`, `poc`, `remediation`, `code_location`.
- [x] `submit_scan` service: persist new fields when present in finding payload.
- [x] `rematch_scan` service: preserve the new fields (only writes `matched_vuln_id`/`is_false_positive` — the new columns are untouched, verified).
- [x] `get_scan` service: surface new fields in the findings list (uses `SELECT *`, so already returned).
- [ ] Pydantic models: extend the scan submission finding schema with the new optional fields. *(Skipped — `submit_scan` route reads via `body.get(...)`, no Pydantic finding schema in use; revisit only if one is introduced.)*

## Phase 2 — Promote-to-vuln endpoint
- [x] Service: `promote_finding(db, user, scan_id, finding_id, overrides)` — checks **app-write** (creating a vuln is an app-level action), creates vuln from finding details (overrides merged in), auto-generates `vuln_id` slug as next `DISC-NNN`, links finding to the new vuln.
- [x] Route: `POST /api/scans/{scan_id}/findings/{fid}/promote`. Body (all optional): `{vuln_id, title, severity, vuln_type, description, poc, remediation, code_location, http_method, url, parameter, filename}`.
- [x] API key scope: `vuln-mapper`.
- [x] Smoke-tested end-to-end against the dev DB: DISC-001 generated, overrides honored, finding linked, severity normalized, cleaned up afterward.

## Phase 3 — Frontend (ScanDetail + AppDetail)
- [x] ScanDetail: replaced the link-style "+ Vuln" with an inline-toggle button. Clicking it expands a row with a pre-filled promote form (title, severity, vuln_id auto-placeholder, description, PoC, remediation, code_location). Submit → POST `/scans/{id}/findings/{fid}/promote` → refresh.
- [x] ScanDetail: surface `finding.title` inline under the vuln_type in the Type cell when present. *(Collapsible preview of description/PoC/remediation collapses into the promote form itself — opening "+ Vuln" reveals them in editable fields, which doubles as the preview. Avoided adding a second expansion mechanism.)*
- [x] AppDetail: when `vulns.length === 0 && scan_count > 0`, the empty state now includes a hint and a "View scans" button.
- [ ] After promote, optionally trigger a per-app rematch so other pending findings auto-link. *(Deferred — promoting only links the one finding by design; rematch could be invoked separately from the existing Re-match All button. Revisit if the workflow demands it.)*
- [x] Frontend build verified clean (`npm run build`).

## Phase 4 — CLI app creation
- [x] `tools/import_scan.py`: `--app-id` now optional; added `--app-name`, `--app-version`, `--app-url`, `--app-description`, `--app-tech`, `--app-visibility` (default `private`, choices public/private/team).
- [x] If `--app-id` not given: looks up by `name+version` via new `client.find_app()` (calls `GET /api/apps?q=<name>` + exact match), reuses if found, otherwise creates via new `client.create_app()` → `POST /api/apps`. *(Note: app creation requires the `full` API-key scope; lookup-only needs `read`.)*
- [x] Extended `SYSTEM_PROMPT` to emit per-finding `title`, `severity`, `description`, `poc`, `remediation`, `code_location` for unmapped findings (mapped findings still leave them blank to avoid noise).
- [x] `submit_to_vulnapps`: forwards the new finding fields through to the API when present.
- [x] Fixed the dead `if False is not None:` block in `main()` (was an `IndentationError` — the script was actually broken before this).
- [x] Verified `python tools/import_scan.py --help` runs and shows the new flags.

## Phase 5 — Docs
- [x] `AppBuilder.md`: bumped schema header to "001-019", documented the new `scan_findings` rich-detail columns, added a row in the scans API table for the promote endpoint, and expanded the scan-submission `findings[*]` shape to call out the new optional fields.
- [x] `tools/README.md`: documented the `full`-scope requirement for app creation, added the seven new `--app-*` flags to the options table, added a "Discovery-mode" usage example, and updated "How It Works" to mention app resolution + LLM rich-detail emission.

## Out of scope (deliberately)
- `apps.mode` / `vulnerabilities.status` triage states — promotion IS confirmation; pending IS the candidate state. No new states needed.
- Bundled `POST /api/scans/import` endpoint — CLI does two calls; atomicity not critical for v1.
- Vuln-detail enrichment when a richer finding maps to a sparse existing vuln — leave for v2.

---

## Review

All five phases complete. End-to-end discovery-mode workflow now works:

1. **CLI** (`tools/import_scan.py`) can take `--app-name "Foo" --app-version "1.0"` and create the target app if needed, then run LLM mapping.
2. **LLM** emits rich detail (`title`/`severity`/`description`/`poc`/`remediation`/`code_location`) on findings it can't map.
3. **Backend** persists those fields on `scan_findings` (migration 019, additive/nullable, no impact on existing data).
4. **Frontend** shows the finding title inline on the scan page, and the "+ Vuln" button opens an inline promote form pre-filled from the stored details. Submit hits `POST /api/scans/{id}/findings/{fid}/promote`, which creates a `DISC-NNN` vuln on the app and links the finding to it. The AppDetail empty state now points to scans when an app has scans but no documented vulns.

**Verified:**
- Migration 019 applies cleanly against the dev DB.
- `promote_finding` smoke-tested end-to-end against a real pending finding (auto-generated `DISC-001`, overrides honored, finding linked, cleaned up).
- Frontend build green (`npm run build`, 263KB bundle, no errors).
- `tools/import_scan.py --help` runs and shows the new flags. A pre-existing `IndentationError` in `main()` (dead `if False is not None:` block) was fixed along the way — the script was actually broken before this branch.

**Intentional deferrals:**
- No automatic per-app rematch after promote. The existing "Re-match All" button covers that need; piggybacking it on promote would surprise users.
- No separate read-only "details preview" expander on findings. The promote form *is* the preview (fields are editable but pre-filled); avoiding two expansion mechanisms per row keeps the UI clean.
- No Pydantic finding schema. The scan-submission route reads via `body.get(...)`; no validation layer is in use today, and the new fields are all optional strings.

**Touched files:**
- `migrations/019_finding_details.sql` (new)
- `app/services/scans.py` — `submit_scan` persists new fields; added `promote_finding`, `_check_app_write`, `_next_disc_slug`
- `app/routers/api/scans.py` — added `POST /{scan_id}/findings/{finding_id}/promote`
- `frontend/src/pages/ScanDetail.jsx` — inline promote form + title preview
- `frontend/src/pages/AppDetail.jsx` — empty-state hint
- `tools/import_scan.py` — find-or-create app flow, extended LLM prompt, payload pass-through, dead-block fix
- `AppBuilder.md`, `tools/README.md` — docs

---

# Scanners: multi-select filter + dedicated Scanners page

## Phase A — Dashboard multi-select scanners
- [ ] `frontend/src/pages/Dashboard.jsx`: replace the single `<select>` for "All scanners" with a multi-select widget. The URL param `scanner` becomes comma-separated. Backend already parses CSV (`dashboard.py:_parse_csv`), so no API changes.
- [ ] Reuse a small inline multi-select dropdown (checkbox list in a popover) rather than the native `<select multiple>`, which is ugly. Keep it minimal — match `filter-bar` styling.

## Phase B — Scanners list page
- [ ] New service `app/services/scanners.py` with `list_scanners(db, user)` returning per-scanner aggregates: apps, scans, tp, fp, fn, precision, recall, f1, det_rate. Lift the aggregation logic shared with `dashboard.compute_dashboard` (refactor a private helper if useful, but don't rewrite the dashboard).
- [ ] New API: `GET /api/scanners` — returns `{scanners: [...]}` shaped like the dashboard summary rows.
- [ ] New page `frontend/src/pages/ScannersList.jsx`: table mirroring the Dashboard summary table, each row linking to `/scanners/<name>`.
- [ ] Add `"Scanners"` to `Navbar.jsx` between Scans and Teams.
- [ ] Add `/scanners` route in `App.jsx`.

## Phase C — Scanner detail page
- [ ] New service function `get_scanner_detail(db, user, name)` returning:
  - Overall metrics (same as list row)
  - Time series: for each scan of this scanner the user can see, `{scan_id, app_id, app_name, scan_date, tp, fp, fn, precision, recall, f1, cost, tokens, duration}`
  - Per-app breakdown: for each app this scanner ran on, the latest scan's metrics
  - Labels frequency: `[{name, color, count}]` over scans for this scanner
- [ ] New API: `GET /api/scanners/{name}` (URL-encode name).
- [ ] New page `frontend/src/pages/ScannerDetail.jsx`:
  - Header: name + small back-to-list + overall metric pills
  - Chart 1: Precision/Recall/F1 over time (line chart with 3 series, x = scan_date)
  - Chart 2: TP/FP/FN stacked bar per scan (x = scan_date)
  - Chart 3 (if any scan has cost/tokens/duration): cost & duration over time, dual-axis or stacked
  - Per-app breakdown table (App | Latest scan date | TP | FP | FN | Precision | Recall | F1) — link App name to app page
  - Labels: chips with frequency
  - Scans list at the bottom — same shape as ScansList but pre-filtered
- [ ] Reuse the existing SVG-based chart components from Dashboard.jsx if any; if not, build small inline SVG charts (no extra dependencies). Look at `ScannerComparisonBars`/`SeverityBreakdown` in Dashboard.jsx for the patterns already in use.
- [ ] Add `/scanners/:name` route.

## Phase D — Verify
- [ ] `npm run build` clean.
- [ ] Manual: scanner with one scan, scanner with many scans, scanner with cost data, scanner without cost data.
- [ ] Existing Dashboard still works (scanner CSV filter accepted by backend).

---

# Pentest 2026-05-07 / 2026-05-08 — vulnapps.net

20 findings (`/Users/nuno/Downloads/vulnapps.net/vulnerabilities.md`). All 18
in-code vulnerabilities have been fixed in this branch. The remaining two are
edge-config items that must be applied at the Cloudflare/CDN layer because
TLS termination and (optionally) edge-injected headers live outside the repo.

## In-code fixes applied
- vuln-0001 — removed `GET /api/auth/debug` (`app/routers/api/auth.py`)
- vuln-0002 — HSTS via `security_headers` middleware (`app/main.py`)
- vuln-0003 — API-key scope hierarchy enforced when minting keys; `/api/account/*` and `/api/teams/*` mutations gated behind `require_scope('full')`; API-key callers can no longer rotate name/password/keys to a session JWT
- vuln-0004 — `match_finding` validates `vuln.app_id == scan.app_id`
- vuln-0005 — `get_scan` returns 404 for "exists but not visible" (collapsed with the not-found branch)
- vuln-0006 — `remove_member`/`change_member_role`/`delete_team` protect `teams.created_by`
- vuln-0007 — `app/throttle.py` per-IP rate-limit + per-account lockout on login + password change (+ register rate-limit)
- vuln-0008 — `get_team` returns 404 when the caller is not a member
- vuln-0010 — `services/apps.py::_validate_url` rejects non-http(s) schemes on app.url
- vuln-0012 — register/password-change enforce ≥8 chars, non-empty, ≤72 bytes
- vuln-0013 — `team_id`/`clone_from` parsed via `_optional_int` → generic 400
- vuln-0014 — origin-wide `security_headers` middleware
- vuln-0015 — `get_scan` redacts `cost`/`tokens`/`duration`/`notes` when `can_view_cost` is false
- vuln-0017 — login always runs bcrypt against a dummy hash when the user is missing; register catches the UNIQUE-constraint violation and returns a generic message
- vuln-0018 — scans default `is_public=0`; `update_scan` accepts `is_public`; both paths reject `is_public=1` on non-public apps
- vuln-0019 — JWT carries `pv` (password_version), checked on every request; `update_password` increments `pv` and returns a fresh JWT for the changing client; `POST /api/auth/logout` invalidates outstanding tokens
- vuln-0020 — `add_member` silently no-ops on unknown email (no account-existence oracle)
- vuln-0021 — non-admins can only attach existing labels via `POST /api/scans/{id}/labels`; label color values are validated against `^#[0-9a-fA-F]{3,8}$`; same applies to the `labels[]` array on scan submit
- vuln-0022 — `vulns/import` wraps every parser in generic 400s and the import service coerces lone-surrogate strings to a safe representation before binding to sqlite

Schema change: `migrations/022_password_version.sql` adds `users.password_version`.

## Out-of-code items (must be applied at Cloudflare)
- **vuln-0009 — TLS 1.0/1.1 accepted at edge.** Cloudflare → SSL/TLS → Edge
  Certificates → set "Minimum TLS Version" to **TLS 1.2** (or 1.3), enable the
  TLS 1.3 toggle, and on Business+ set the cipher preset to "Modern" to drop
  CBC suites. Verify with `testssl.sh --protocols vulnapps.net` or Qualys SSL
  Labs — only TLS 1.2/1.3 should appear.
- **vuln-0002 (defence-in-depth).** Cloudflare → SSL/TLS → Edge Certificates
  → enable "Always Use HTTPS" so port 80 traffic is 301-redirected before
  reaching the origin. (The in-code HSTS header already instructs compliant
  browsers to upgrade, but the edge redirect closes the first-hit gap.)

---

# Mobile-responsive overhaul

- [x] Navbar: burger toggle, slide-down panel, click-dropdown, close-on-route-change
- [x] CSS base: `.navbar-toggle` (hidden on desktop), `.nav-dropdown.open` rule
- [x] CSS: `@media (max-width:768px)` block (container, navbar panel, forms, headers, grids, search, cards)
- [x] CSS: `cards-on-mobile` responsive-table pattern (+ `td:empty` hide rule)
- [x] Tag tables with `cards-on-mobile` + per-`td` `data-label`: ScansList, AdminUsers, AdminLabels, TeamsList, TeamDetail, AppDetail, ScanDetail, Account
- [x] Verify: vite build, mobile view (~390px), desktop regression, backend tests

## Review

Made the SPA responsive below 768px. Previously the CSS had **zero `@media` queries**
and the navbar was a fixed horizontal row with a hover-only Admin dropdown.

**Changes**
- `frontend/src/components/Navbar.jsx` — burger button (animated ≡/✕), slide-down panel
  toggled by `menuOpen`; Admin converted from hover-only to a click disclosure (`adminOpen`)
  so it works on touch; `useLocation` effect closes the menu on navigation.
- `app/static/style.css` — base `.navbar-toggle` (hidden on desktop) + `.nav-dropdown.open`
  rule; one `@media (max-width:768px)` block: container padding, navbar slide-down panel,
  single-column forms/detail-grid/card-grid, stacked page-header, full-width search, and the
  opt-in `table.cards-on-mobile` pattern (thead hidden, rows → bordered cards, `td::before`
  shows `data-label`, empty cells hidden).
- 8 listing-table pages tagged `cards-on-mobile` + per-`td` `data-label` (ScansList done by
  hand incl. tfoot totals; the other 7 by parallel agents with column-count checks).
- 2D matrices (ScanCompare, Dashboard heatmap) deliberately kept on smooth horizontal scroll.

**Verified** with Playwright at 390px (real Chromium, seeded TaintedPort data):
- Burger toggles slide-down menu; links stack; Admin disclosure expands; menu closes on nav.
- AppDetail vulns table renders as labelled cards (ID/TITLE/SEVERITY/TYPE/LOCATION), no h-scroll.
- AppForm stacks to single column, full-width inputs.
- Desktop (1280px) unchanged: burger hidden, nav horizontal, tables tabular (regression).
- No console/page errors. Frontend builds clean. Backend 22/22 tests pass.

---

# Ignore finding state

- [x] Migration 023 — `scan_findings.is_ignored INTEGER NOT NULL DEFAULT 0`
- [x] Service: `set_finding_ignored`; match/FP/promote clear `is_ignored`; `_compute_metrics` + compare exclude ignored from Pending and add `ignored` count; scan-list `pending_count` + severity subquery exclude ignored; `rematch_scan` skips ignored findings
- [x] API: `POST /api/scans/{id}/findings/{fid}/ignore` body `{ignored}` (vuln-mapper scope)
- [x] Frontend: Ignore/Restore buttons + grey "Ignored" badge + Ignored metric card (ScanDetail); `.badge-ignored` CSS
- [x] Docs: AppBuilder schema (023), four-state model, metrics, API row
- [x] Verify: pytest 23/23 (incl. ignore round-trip — pending↓/ignored↑, precision/recall/f1 unchanged, restore reverts); vite build clean; Playwright UI (grey badge + Ignored metric + Restore, no console errors)

Precision/recall/F1 need no formula change: Ignore clears match + FP, so an ignored
finding is neither TP nor FP — it simply leaves the Pending bucket. Mutually exclusive
with the other states; rematch treats ignore as a sticky manual decision.
