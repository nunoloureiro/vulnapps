# Improved Vulnerability Matching Heuristics

## Tasks
- [x] Rewrite `app/matching.py` with scoring-based matching, URL regex, param fuzzy matching, expanded aliases
- [x] Add `badge-pending` CSS style (yellow)
- [x] Update `app/routers/scans.py` — metrics exclude pending, add mark-FP endpoint
- [x] Update `app/templates/scans/detail.html` — pending badge, mark FP button, update JS
- [x] Update `app/templates/scans/compare.html` — exclude pending from FP matrix, add Pending row
- [x] Update `app/routers/api.py` — metrics include pending count
- [x] Update `AppBuilder.md` with new matching spec
- [x] Verify: imports OK, matching tests pass
