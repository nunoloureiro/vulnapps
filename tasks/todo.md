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

# Many-to-many finding matches (one finding → several vulns/chains)

## Why

`scan_findings` has a single `matched_vuln_id` and a single `matched_chain_id`
(mutually exclusive), so a finding can be credited for exactly one thing. Two
real gaps follow from that, both hit on live scan data:

1. Scan 330: three separate findings (path traversal, SSRF, directory listing)
   each explicitly read `jwt.php` and quoted the hardcoded HS256 secret, but all
   three were matched to their own access vuln (TP-014 / TP-027 / TP-013), so
   `CODE-001` scored as missed. Fixed by hand (re-pointed 4733), which cost
   TP-013 its second piece of evidence — a trade, not a fix.
2. A scan that reports ONE clean chain narrative naming its 3 members gets
   either the chain OR one member, never the chain plus its members — while a
   scan that redundantly re-reports each member separately gets all four. Same
   discovery, different score, purely because of how the report was written up.

Fixing the data model removes both, and removes the need for the awkward
"only credit the chain's member if no other finding already covers it"
conditional — under many-to-many nothing is being stolen, matches are additive.

## Decisions to confirm before coding

- [x] `tp` stays "count of DISTINCT in-scope vulns with >= 1 match", so one
      finding covering 3 vulns == three findings covering 1 each (symmetric, no
      precision inflation: the denominator is `tp + fp_groups`, and FP stays
      per-finding).
- [x] A finding MAY match a chain and that chain's member vulns at the same
      time — that is the point. The importer's content rule is unchanged: only
      assert the chain when every member is actually demonstrated.
- [x] Severity accuracy stays an OR over findings per vuln (already the rule),
      so a multi-vuln finding reporting one severity is not penalised per member.
- [x] Legacy columns get dropped in migration 040 (SQLite 3.53 here, DROP COLUMN
      supported, no index references them) rather than left as dead mirrors.
- [x] NOT in scope: sibling-chain fairness (CHAIN-004 vs CHAIN-011) and the
      findings-vs-chains list asymmetry — both are separate open questions below.

## Safety

- [x] Snapshot prod DB before 040 runs there. NOT done by hand — the deploy
      pipeline takes its own snapshot before container replacement
      (aws/setup-ec2.sh), which is what will cover the real run. Verified
      locally instead: ran 040 against a copy of the live DB, 44 vuln matches
      backfilled with zero loss, both columns dropped, CHECK rejects a row
      with neither or both ids.
- [x] Land as one change: the join table becomes the single source of truth, so
      any missed reader must fail loudly rather than read a stale mirror.

## Migration (040_finding_matches.sql)

- [x] `finding_matches(finding_id -> scan_findings ON DELETE CASCADE,
      vuln_id -> vulnerabilities ON DELETE CASCADE NULL,
      chain_id -> chains ON DELETE CASCADE NULL,
      CHECK ((vuln_id IS NOT NULL) + (chain_id IS NOT NULL) = 1))` — the CHECK
      migration 039 said it could not add via ALTER is expressible here.
- [x] Partial unique indexes on `(finding_id, vuln_id)` and `(finding_id, chain_id)`;
      plain index on `finding_id`.
- [x] Backfill every existing non-null `matched_vuln_id` / `matched_chain_id`.
- [x] Verify row counts match pre-migration non-null counts, then
      `ALTER TABLE scan_findings DROP COLUMN matched_vuln_id` / `matched_chain_id`.

## Backend core

- [x] One hydration helper that loads matches for a set of finding ids and
      attaches `matched_vuln_ids` / `matched_chain_ids` lists to each finding
      dict, so downstream Python works on lists instead of doing its own SQL.
- [x] `app/scoring.py`: `matched_ids` union over lists (230-232); `pending` =
      zero matches (257-258); severity accuracy iterates (finding, vuln) pairs
      (278); `chain_direct_matches` union over lists (322-324).
- [x] `app/services/scans.py`, the big surface: SQL joins (190, 201-202),
      `pending_count` subquery (212), `vuln_finding_counts`/`_details` (356-362),
      submit auto-match (477-493), `match_finding` write path (610-703),
      `mark_finding_fp` (728), matched-ids query (769-772), `set_finding_ignored`
      (842), promote (986), `rematch_scan` (1046-1051), comparison/detection
      matrix (1151-1263).
- [x] `app/services/dashboard.py` (285-296), `app/services/scanners.py` (104-105),
      `app/services/vulns.py` (485, the delete-guard count).

## API

- [x] `POST /scans/{id}/findings/{fid}/match` takes `{vuln_ids: [], chain_ids: []}`
      as full replacement (idempotent). Keep legacy `{vuln_id: N|null}` /
      `{chain_id: N|null}` as sugar — a stale copy of the importer exists at
      `~/dev/ai-pentest-agent/scripts/import_scan_to_vuln_apps.py`.
- [x] Response returns both list and scalar shapes for the same reason.
- [x] Audit log records set add/remove, not scalar old -> new.

## Frontend

- [x] `ScanDetail.jsx`: the single `<select>` at ~675 becomes multi-select;
      badge logic at 630-631, 666, 718-721 reads lists; `matchedIds`/chain set
      at 73-76 unchanged in spirit.
- [x] `ScanCompare.jsx`: detection matrix already consumes `matched_vuln_ids`
      per scanner — confirm unaffected.

## Importer (tools/import_scan.py)

- [x] LLM JSON schema: `matched_vuln_db_ids: []` / `matched_chain_db_ids: []`,
      still parsing the singular keys for older prompts/responses.
- [x] `SYSTEM_PROMPT_MAP`: state the rule this unblocks — credit every member
      vuln whose mechanism the finding's own evidence explicitly demonstrates,
      and additionally the chain when all members are demonstrated.
- [x] `_enforce_source_kind`: a chain-source file may now assert chain + members;
      a standalone-source file still may not assert a chain.
- [x] Correction loop in `submit_to_vulnapps`: set comparison, not scalar.

## Tests & docs

- [x] `tests/test_scoring.py`, `test_scoring_revisions.py`: one finding crediting
      N vulns scores identically to N findings crediting one each.
- [x] New: chain + members from a single finding; migration backfill correctness;
      CHECK rejects a row with both/neither id.
- [x] `tests/test_api_endpoints.py`: list body, legacy scalar body, clearing.
- [x] `tests/test_import_scan_validation.py`: list-shaped LLM output, legacy
      singular parse, `_enforce_source_kind` under the new rule.
- [x] AppBuilder.md: schema, scoring semantics, API shape, importer rule.

## Verification

- [x] Full suite green (186 passed).
- [x] Post-deploy check against prod (v1.171, run 36070042467). 040 applied:
      the API serves matched_vuln_ids/matched_chain_ids as lists and the
      scalar columns are gone. Backfill lost nothing — 330 tp45/fp5/pending0
      (70 findings), 331 tp37/fp4/pending0 (44), 332 tp30/fp0/pending0 (32),
      all unchanged from the pre-migration triage, and CODE-001 still reads
      MATCHED on all three (the Detection Matrix gap that started this).
      No finding carries >1 match yet, as expected: nothing has re-imported.
- [x] Re-check catalog/vulnapps count reconciliation per the CLAUDE.md rule.

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
