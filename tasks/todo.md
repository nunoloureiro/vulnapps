# GitHub Actions deployment

- [x] Prune dangling images on EC2 after successful startup, with warning-only failure.
- [x] Validate the script for publication.

Cleanup review: `bash -n` and diff checks passed. Mocked Docker checks confirmed
cleanup follows healthy startup, cleanup failure is nonfatal, and failed startup
skips cleanup. No live pruning was performed.

- [x] Remove the known-hosts secret requirement and accept the first SSH host key per run.
- [x] Update deployment documentation and validate workflow syntax.

Host-key change review: YAML parsing, all four workflow shell steps (`bash -n`),
and `git diff --check` passed. No live deployment was run.

- [x] Inspect upstream deployment scripts and clean-checkout test requirements.
- [x] Configure existing tests and a container startup check for pull requests and main.
- [x] Configure publishing to Docker Hub and deploying the exact image over SSH on main.
- [x] Document repository secrets, host prerequisites, snapshots, and recovery.
- [x] Validate workflow syntax, shell syntax, and self-contained tests.

Deployment follows the existing EC2 layout: `vulnapps`, `vulnapps-data`, and
`127.0.0.1:8001`. Configuration comes from GitHub Secrets. Deployment runs are
serialized; a failed image pull or database snapshot must leave the old service running.

Review: 90 existing self-contained tests passed on Python 3.12; actionlint,
`bash -n`, and `git diff --check` passed. No new tests were added. The local
Docker daemon is stopped, so image build/startup and live deployment remain
unverified. CI gates deployment on the image build/startup check. Application
settings use individual repository secrets; CI assembles the env-file. No live
deployment has been performed.

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

# Open questions to discuss later

Not action items — flagged for a design discussion, not yet resolved or implemented.

## Sibling-chain scoring fairness

This session (TaintedPort, app 305) we registered `CHAIN-011` as a sibling of the
existing `CHAIN-004` — both reach the identical outcome (forge a genuinely-signed
admin JWT using the real hardcoded secret) via two different entry vectors
(`CHAIN-004` via SSRF reading `jwt.php`; `CHAIN-011` via plain directory-listing
reading the same file). This mirrors an existing precedent, `CHAIN-002`/`CHAIN-003`,
also two sibling chains reaching the same "admin claim forgery" outcome via
different JWT-verification bugs. The `chains`/`chain_members` schema
(`migrations/028_chains.sql`) only supports a flat AND-list of members per chain —
there's no way to express "satisfied by path A's members OR path B's members" as
one chain entity, so registering siblings is the only way to credit either path
today.

Concern raised: because each sibling chain is scored as its own fully independent
ground-truth entity (each contributing its own weight to recall's denominator in
`app/scoring.py`), a scan that fully demonstrates ONE path but not the other shows
the un-demonstrated sibling as a missed/false-negative chain, dragging down
recall — even though the scan demonstrated the exact same real-world outcome via
an equally valid route, and even if it found every individual member vulnerability
involved across both paths (just didn't connect them into a second explicit
end-to-end finding). Not clear this is fair.

Angles to discuss (not decided):
- Should sibling chains for the same outcome count as satisfied for recall if ANY
  one is fully demonstrated — i.e. treat siblings as an OR-group for scoring even
  though they're stored as separate rows?
- Should the schema change to support alternative-path groups directly?
- Is there a way to flag "these N chains are siblings for outcome X" so scoring or
  the UI can present/credit them as one conceptual unit?

## Findings vs. chains list-naming asymmetry on the scan detail page

For individual vulnerabilities, the scan detail page's "Findings" list shows the
scanner's own raw submitted findings (the scanner's claims). But for chains, the
page's "chains" section instead shows the app's registered ground-truth chains
(the catalog's chain entities), NOT the scanner's own submitted chain-claims. So
the same page mixes two different frames: one section is "what did the scanner
report" (findings), the other is "what does the ground truth contain" (chains)
rather than "what chain-findings did the scanner report." Confusing/asymmetric —
flagged for a design discussion (e.g. should there be a distinct "chain findings"
concept surfaced the same way individual findings are, or should the existing
findings list simply also surface which findings were matched via
`matched_chain_id` inline, or something else). Not resolved or implemented.
