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
