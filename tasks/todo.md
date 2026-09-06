# Prune scoring redesign to decided subset (A/B/D/E/H/J keep, C/F/G/I delete)

See `/Users/nuno/.claude/plans/playful-marinating-gray.md` for full context/rationale.

## Safety
- [x] Back up vulnapps.db before schema changes

## Migrations
- [x] Delete 026, 027, 029, 031, 033
- [x] Edit 028_chains.sql (drop chain_milestones)
- [x] Edit 032_benchmark_corpus.sql (rename columns directly)
- [x] Apply live-DB reconciliation (drop tables/columns, rename columns, clean _migrations)

## Backend core
- [x] Rewrite app/scoring.py
- [x] Rewrite app/services/scoring.py
- [x] Edit app/routers/api/scans.py
- [x] Edit app/routers/api/apps.py
- [x] Edit app/services/scans.py
- [x] Edit app/services/vulns.py
- [x] Edit app/services/apps.py
- [x] Confirm app/seed.py / app/services/dashboard.py need no changes

## Frontend
- [x] Edit ScanDetail.jsx
- [x] Edit ScanCompare.jsx
- [x] Edit AppDetail.jsx
- [x] Edit AppForm.jsx
- [x] Confirm VulnDetail.jsx / VulnForm.jsx need no changes

## Tests & docs
- [x] Trim tests/test_scoring.py
- [x] Trim tests/test_scoring_revisions.py
- [x] Prune AppBuilder.md
- [x] Minimal fix to tools/import_scan.py (remove milestone POST call)

## Verification
- [x] pytest full suite (38 passed; 1 pre-existing unrelated collection error in test_api_endpoints.py, confirmed present before any of today's changes via git stash)
- [x] Frontend: `npm run build` succeeds (60 modules, no errors)
- [x] Backend: booted the server against the live DB and curled the changed endpoints —
      GET /api/scans/2 (get_scan), GET /api/apps/1/compare (compare_scans), GET
      /api/apps/1/revisions all 200 with the expected trimmed shape (no scorings/
      milestones/binary_weighted/severity_band/corpus_signed_off/config_groups keys
      anywhere); POST /api/apps/1/rescore, /configurations, /benchmark, /scans/2/scorings,
      /scans/2/score all correctly 404 (routes removed)
- [x] compute_metrics sanity: finding_milestones/chain_milestones/scorings were all 0 rows
      before deletion (checked at the start), so old and new weighted_rate are identical —
      the pre-milestone fallback (full credit on match) was already every row's behavior
