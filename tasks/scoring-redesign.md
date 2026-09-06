# Scoring Redesign — Benchmark-Grade Measurement

## Goal

Vulnapps currently measures scanners with count-based TP/FP/FN, precision, recall, F1.
That is adequate for comparing DAST scanners. It is not adequate for the new primary
use case: **measuring one product (COS) across different models, reasoning efforts, and
harness versions**, and eventually publishing the methodology so third parties can
reproduce it.

This task adds the measurement machinery required for that: severity weighting,
difficulty tiers, milestone partial credit, exploit chains, configuration fingerprints,
immutable scorings, and a ground-truth revision axis. It also fixes three defects in the
existing metric.

**Non-goals:** no changes to auth, teams, visibility, or the visual design. No changes to
the DAST/SAST heuristic matcher's core scoring gates (`app/matching.py`) beyond what
milestone output requires.

---

## Background: why each change exists

### Defect 1 — precision is inflated by unadjudicated findings

`_compute_metrics` in `app/services/scans.py` excludes `pending` findings from both `tp`
and `fp`. A scan with 5 TP, 0 FP and 50 pending reports `precision = 1.0`. Precision is
only meaningful after full adjudication, and nothing currently signals that.

**Fix:** report precision as a range. Lower bound `tp / (tp + fp + pending)`, upper bound
`tp / (tp + fp)`. The bounds converge as adjudication completes. Add an
`adjudication_complete` flag and suppress precision in comparisons when it is false.

### Defect 2 — TP and FP are counted at different granularities

`tp = len(matched_vuln_ids)` dedupes to the vulnerability. `fp = sum(1 for f in findings
if f["is_false_positive"] == 1)` counts every finding. Three findings describing one real
vuln score 1 TP. Three findings describing one bogus issue score 3 FP.

This systematically depresses precision for verbose scanners and makes precision
non-comparable across tools with different reporting granularity.

**Fix:** cluster false positives the same way true positives are already clustered. Add
`scan_findings.fp_group` and count distinct groups; ungrouped FPs count as one each.

### Defect 3 — recall changes silently when vulns are added

`all_vulns` is read live at request time. Promoting a discovery finding into a vulnerability
immediately changes recall and F1 for every historical scan on that app, with no record.

Retroactive re-scoring is the **desired** behaviour: if a vuln existed in the app all along
and an older run missed it, that miss is real and should count. The problem is that the
change is invisible and irreversible, so no historical number is reproducible and two scans
run months apart are silently compared against different denominators.

**Fix:** two-axis versioning. A `ground_truth_revisions` table per app, a
`existed_since_revision` / `known_since_revision` pair on each vuln, and immutable
`scorings` rows that record which revision and which matcher produced a given number.

### Why configuration fingerprints

The primary use case is comparing configurations of the same product. Today the only
config fields are `scanner_name` and `scanner_version`. Model, reasoning effort, harness
commit, token budget and seed have nowhere to live, and there is no notion of k trials of
one configuration. Given agent run-to-run variance, single-run comparisons are the largest
threat to any conclusion drawn from this tool.

### Why weights, tiers and milestones

Raw counts treat a missed reflected XSS the same as a missed chained authz bypass. Worked
example on a 30-vuln corpus worth 382 weighted points:

| Config | Raw count | Weighted |
|---|---|---|
| A: all 12 commodity + 4 business logic (3 high, 1 crit) | 16/30 = 53% | 94/382 = 25% |
| B: 6 commodity + 9 business logic (5 high, 4 crit) + 2 chained | 17/30 = 57% | 227/382 = 59% |

Indistinguishable on raw counts, more than 2x apart weighted. Config A is a scanner with a
chat interface; Config B is the product being built. The metric has to see that difference.

Milestones exist for a second reason: statistical resolution. With ~100 ground-truth items
and 5 trials per config, differences below roughly 10 points are not resolvable. Splitting
each vuln into four scoreable milestones multiplies scoreable events roughly 4x without
authoring a single new application.

---

## Phase 1 — Configuration fingerprints (P0)

Highest priority. Every run recorded without these fields is a run that cannot be attributed
later.

- [x] Migration `026_scan_config.sql`:

```sql
ALTER TABLE scans ADD COLUMN model              TEXT;
ALTER TABLE scans ADD COLUMN model_version      TEXT;
ALTER TABLE scans ADD COLUMN reasoning_effort   TEXT;
ALTER TABLE scans ADD COLUMN harness_version    TEXT;
ALTER TABLE scans ADD COLUMN token_budget       INTEGER;
ALTER TABLE scans ADD COLUMN seed               TEXT;
ALTER TABLE scans ADD COLUMN config_fingerprint TEXT;
ALTER TABLE scans ADD COLUMN run_group          TEXT;
ALTER TABLE scans ADD COLUMN trial_index        INTEGER;

CREATE INDEX IF NOT EXISTS idx_scans_fingerprint ON scans(config_fingerprint);
CREATE INDEX IF NOT EXISTS idx_scans_run_group   ON scans(run_group);
```

- [x] `config_fingerprint` computed server-side on submit as a stable hash of
      `(scanner_name, scanner_version, model, model_version, reasoning_effort,
      harness_version, token_budget)`. Deliberately excludes `seed` and `trial_index`, so
      k trials of one configuration share a fingerprint.
- [x] `submit_scan` accepts the new fields; all optional, all nullable, existing clients
      unaffected.
- [x] `tools/import_scan.py`: new CLI flags for each field, forwarded on submit.
- [x] Frontend: show config fields on the scan detail page; group by fingerprint on the
      compare view.

## Phase 2 — Immutable scorings (P0)

- [x] Migration `029_scorings.sql`:

```sql
CREATE TABLE scorings (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id               INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scored_at_revision    INTEGER NOT NULL,
    matcher_version       TEXT,
    matcher_prompt_sha256 TEXT,
    weighted_found        REAL,
    weighted_total        REAL,
    weighted_rate         REAL,
    tp                    INTEGER,
    fp_groups             INTEGER,
    fn                    INTEGER,
    pending               INTEGER,
    ignored               INTEGER,
    precision_lower       REAL,
    precision_upper       REAL,
    recall                REAL,
    f1                    REAL,
    adjudication_complete INTEGER NOT NULL DEFAULT 0,
    computed_at           TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scan_id, scored_at_revision, matcher_version)
);

CREATE INDEX IF NOT EXISTS idx_scorings_scan ON scorings(scan_id);
```

- [x] Refactor `_compute_metrics` into a pure function
      `compute_metrics(findings, vulns_in_scope, chains_in_scope) -> dict`, with no DB
      access and no reliance on live app state.
- [x] Keep live computation for the UI's "current" view. Every number that leaves the tool
      (API export, compare view, published chart) must come from a `scorings` row.
- [x] Scoring rows are append-only. Never update, never delete.
- [x] `POST /api/scans/{id}/score` and a bulk `POST /api/apps/{id}/rescore?revision=N`
      that walks every scan on the app and writes new rows. Idempotent via the UNIQUE
      constraint.

## Phase 3 — Ground-truth revisions (P0)

- [x] Migration `025_ground_truth_revisions.sql`:

```sql
CREATE TABLE ground_truth_revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    revision   INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    notes      TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, revision)
);

ALTER TABLE vulnerabilities ADD COLUMN existed_since_revision  INTEGER DEFAULT 1;
ALTER TABLE vulnerabilities ADD COLUMN known_since_revision    INTEGER DEFAULT 1;
ALTER TABLE vulnerabilities ADD COLUMN invalidated_at_revision INTEGER;

ALTER TABLE scans ADD COLUMN corpus_revision INTEGER;
```

`reason` is one of: `new_prior_vuln`, `weight_change`, `vuln_invalidated`, `corpus_change`.

- [x] Every app gets revision 1 on migration. All existing vulns get
      `existed_since_revision = 1`, `known_since_revision = 1`. All existing scans get
      `corpus_revision = 1`.
- [x] **Scope rule.** A vuln is in scope for a scoring at revision R when
      `existed_since_revision <= R` AND (`invalidated_at_revision` IS NULL OR
      `invalidated_at_revision > R`).
- [x] **Promotion rule.** Promoting a discovery finding into a vuln creates a new revision
      with reason `new_prior_vuln`. The operator must state whether the vuln existed in
      earlier revisions:
      - existed all along → `existed_since_revision = 1`, `known_since_revision = N`.
        All prior scans legitimately take the miss.
      - introduced by a code change → `existed_since_revision = N`. Prior scans untouched.
      This choice is the whole point of the two-field split. Do not default it silently;
      make the operator pick.
- [x] **Two scorings per scan.** `as-run` at `scan.corpus_revision`, and `as-known` at the
      app's latest revision. Report `as-known` as the headline, keep `as-run` for audit.
- [x] Changing an `impact_weight` also requires a new revision (reason `weight_change`)
      and a full re-score. Weights are immutable within a revision.
- [x] Expect scores to drift downward over time as ground truth grows. This is correct.
      Every chart must be labelled with the revision it was scored at.

## Phase 4 — Weights and difficulty tiers (P1)

- [x] Migration `024_vuln_weights.sql`:

```sql
ALTER TABLE vulnerabilities ADD COLUMN impact_weight   INTEGER;
ALTER TABLE vulnerabilities ADD COLUMN difficulty_tier TEXT;
```

- [x] Weight scale is `1 / 3 / 9 / 27`. Log spacing is deliberate: with linear weights,
      nine informational findings would outscore two criticals.

| Weight | Class | Examples |
|---|---|---|
| 1 | Informational | version disclosure, verbose errors, missing headers |
| 3 | Medium | reflected XSS, open redirect, unauthenticated read of non-sensitive data |
| 9 | High | IDOR exposing another tenant's data, stored XSS with session theft, SSRF to internal service, single-step authz bypass |
| 27 | Critical | chained exploit reaching admin, cross-tenant write, auth bypass, RCE, business logic abuse with financial impact |

- [x] `difficulty_tier` is one of `commodity`, `business_logic`, `chained`.
- [x] **Difficulty is a reporting axis, not a multiplier.** Do not fold it into the weight.
      Blending the two produces one opaque number and destroys the diagnostic. The point of
      the tier is to see *where on the difficulty curve* a configuration improved.
- [x] Backfill `impact_weight` from `severity`: info→1, low→1, medium→3, high→9,
      critical→27. Backfill `difficulty_tier` to `commodity` as a placeholder.
- [x] ~~`severity` remains the display field. `impact_weight` is the scoring field and is
      allowed to diverge where realized impact in the target app differs from the label.~~
      **Superseded by `tasks/scoring-corrections.md` item 5:** ground-truth severity IS
      contextual severity, so `impact_weight` derives from it 1:1 and divergence is
      exceptional rather than expected.
- [x] SQLite cannot add CHECK constraints via ALTER. Validate in the service layer, or
      rebuild the table following the pattern in `010_version_nullable.sql`.
- [x] Vuln create/edit forms require both fields. Reject a vuln without them.
- [ ] **Manual input required from Nuno:** weights and tiers for TaintedPort's 28 seed
      vulns in `app/seed.py`. Backfill gives a starting point; the values need hand
      correction. Do not guess these.
- [x] Headline metric becomes severity-weighted detection rate:
      `weighted_found / weighted_total`. Precision reported separately. F1 retained as a
      secondary column for continuity.
- [x] Default reporting view is the tier matrix:

```
Tier             Ground truth   Found   Detection rate
Commodity                  12      12            100%
Business logic             14       4             29%
Chained                     4       0              0%
Weighted total         382 pts  94 pts             25%
```

## Phase 5 — False positive grouping (P1)

- [x] Migration: `ALTER TABLE scan_findings ADD COLUMN fp_group TEXT;`
- [x] `fp_groups` counts distinct non-null `fp_group` values plus ungrouped FPs counted
      individually.
- [x] The LLM importer already clusters on the true-positive side. Extend the same
      capability to false positives.
- [x] Precision uses `fp_groups`, not raw FP count.

## Phase 6 — Milestone partial credit (P2)

- [x] Migration `027_milestones.sql`:

```sql
CREATE TABLE finding_milestones (
    finding_id INTEGER NOT NULL REFERENCES scan_findings(id) ON DELETE CASCADE,
    vuln_id    INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    milestone  TEXT NOT NULL,
    achieved   INTEGER NOT NULL DEFAULT 0,
    evidence   TEXT,
    PRIMARY KEY (finding_id, vuln_id, milestone)
);
```

- [x] Milestones and fractions: `surface` 0.15, `flaw` 0.25, `poc` 0.30, `impact` 0.30.
- [x] Per-vuln credit is `impact_weight × Σ(achieved milestone fractions)`, taking the
      **union** of milestones across all findings matched to that vuln, capped at 1.0.
      Not the sum — three partial findings must not exceed the vuln's full weight.
- [x] `tools/import_scan.py`: the matcher must now emit, per finding, which milestones it
      evidences. This is the largest change in the task. Extend `SYSTEM_PROMPT` and the
      output schema accordingly.
- [x] Record `matcher_version` and `matcher_prompt_sha256` on every scoring. When a
      revision bump triggers a re-score, re-score all scans with the same matcher version,
      otherwise a metric change becomes unattributable across three moving parts (model
      under test, corpus revision, matcher).
- [x] Manual milestone override in the UI, since the LLM will get some wrong.

## Phase 7 — Exploit chains (P3)

- [x] Migration `028_chains.sql`:

```sql
CREATE TABLE chains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    chain_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    impact_weight INTEGER NOT NULL,
    description   TEXT,
    existed_since_revision  INTEGER DEFAULT 1,
    invalidated_at_revision INTEGER,
    UNIQUE(app_id, chain_id)
);

CREATE TABLE chain_members (
    chain_pk   INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
    vuln_id    INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    step_order INTEGER NOT NULL,
    PRIMARY KEY (chain_pk, vuln_id)
);
```

- [x] A chain is its own ground-truth entity with its own weight. Members keep their
      individual weights. The partial double-count is deliberate: demonstrating a chain is
      worth more than finding its parts separately.
- [x] Chain milestones are defined at chain level. `impact` means the full chain was
      executed end to end.
- [x] Chains participate in the revision scope rule exactly as vulns do.

## Phase 8 — Reporting guards (P2)

Enforce in the compare endpoint and every export path:

- [x] Refuse to compare scans whose scorings differ in `scored_at_revision` or
      `matcher_version`.
- [x] Refuse to render a configuration comparison with fewer than 5 trials per
      `config_fingerprint`.
- [x] Report mean and min–max band across trials. Never present a single run as a
      configuration result.
- [x] Label every output `app@revision, matcher vX`.
- [x] Suppress precision where `adjudication_complete = 0`; show the bounds instead.
- [x] Detection rate versus `token_budget` must be a query against `scans` joined to
      `scorings`, not a manual export.

## Phase 9 — AppBuilder.md

Per the rule in `AGENTS.md` that AppBuilder.md must stand alone as a build-from-scratch
prompt:

- [x] New normative **Scoring and Measurement** section: weights, tiers, milestones,
      chains, the two revision axes, the as-run vs as-known rule, precision bounds, FP
      grouping, and the reporting guards.
- [x] Database Schema section updated with migrations 024–029.
- [x] Matching section extended with milestone output and matcher versioning.
- [x] Seed section updated to reflect weights, tiers and chain definitions.
- [x] Visual Design section unchanged.

---

## Order of work

1. Phase 1 and Phase 2 first, in that order. Both are P0 and Phase 1 is time-sensitive:
   every scan recorded without a config fingerprint is permanently unattributable.
2. Phase 3 next. Also P0 and also time-sensitive, for the same reason applied to revisions.
3. Phase 4 and 5. Phase 4 blocks on Nuno supplying the seed weights.
4. Phase 6, then 8.
5. Phase 7 last.
6. Phase 9 continuously, not at the end.

## Verification

- [x] Existing scans keep working with all new columns null. No regression in the current
      count-based metrics for apps that have no weights assigned.
- [x] Re-scoring is deterministic: running `rescore` twice at the same revision and matcher
      version produces no new rows and no changed values.
- [x] A promoted `new_prior_vuln` with `existed_since_revision = 1` measurably lowers recall
      on a prior scan after re-score, and the prior scan's original scoring row is unchanged.
- [x] Weighted rate for the worked example above reproduces 94/382 and 227/382 exactly.
- [x] Milestone union across three findings on one vuln caps at the vuln's full weight.

---

## Review

All nine phases implemented. 79 tests pass (`venv/bin/python -m pytest tests/ -q`),
frontend builds clean, and the whole thing was exercised against a copy of the
production snapshot (217 apps, 55,581 vulns, 136 scans, 2,361 findings).

### What was built

| Area | Files |
|---|---|
| Pure metric | `app/scoring.py` (new) — weights, tiers, milestones, fingerprints, `inputs_digest`, `compute_metrics`, `aggregate_trials` |
| Revisions + scorings | `app/services/scoring.py` (new) — revisions, scope queries, append-only scorings, milestones |
| Migrations | `024_vuln_weights` … `030_fp_group` (7 files) |
| Services | `scans.py` (config fields, live metrics via the shared module, compare guards, config groups, benchmark export), `vulns.py` (weight/tier validation, revision bookkeeping, invalidate), `dashboard.py` (clustered FPs, scope-aware ground truth) |
| Routes | `scorings`, `score`, `milestones`, `revisions` (GET/POST), `rescore`, `configurations`, `benchmark`, `invalidate`; `mark-fp` takes `fp_group`; submit takes the config block |
| Importer | `--scan-model`, `--model-version`, `--reasoning-effort`, `--harness-version`, `--token-budget`, `--seed`, `--run-group`, `--trial-index`; matcher self-identification; milestone + `fp_group` emission in `SYSTEM_PROMPT_MAP` |
| Frontend | ScanDetail (config fields, weighted headline, precision bounds, tier matrix, milestone toggles, FP group editor, scorings audit, promote `existed_since`), ScanCompare (guards banner, configurations table, weighted + tier rows, `n/a` cells, metric-toggle trend chart), VulnForm (weight/tier required), VulnDetail (weight/tier/revisions + Invalidate), AppDetail (Ground Truth card + Re-score All) |
| Docs | `AppBuilder.md` — schema 001–030, new normative **Scoring and Measurement** section, matcher versioning + milestone output, route tables, seed section, comparison section; `tools/README.md` — new flags + trial-sweep example |
| Tests | `tests/test_scoring.py` (32, pure), `tests/test_scoring_revisions.py` (21, service-level on a throwaway DB) |

### Verification

- [x] **No regression.** All 136 real scans in the snapshot produce byte-identical
      `tp/fp/pending/ignored/fn/precision/recall/f1` under the new code (diff script over
      the old implementation: 0 differences). F1 deliberately uses `precision_upper`,
      which is what precision always meant here, so historical F1 is unchanged.
- [x] **Deterministic re-scoring.** `rescore_app` twice at the same revision + matcher
      writes 0 rows and changes no values (verified on the snapshot and in tests).
- [x] **Retroactive re-scoring is visible and reversible-by-record.** A promoted
      `new_prior_vuln` with `existed_since_revision = 1` drops the older scan from
      recall 1.0 → 0.5 and 9/9 → 9/36 points at the new revision, while its original
      scoring row stays byte-identical.
- [x] **Worked example reproduces exactly.** 94/382 and 227/382, from a fixture corpus
      built to the spec's weights — the test fails if the scale stops separating the two
      configurations by >2.4x.
- [x] **Milestone union caps at full weight.** Three partial findings on one 27-point
      vuln → exactly 27, not 81.
- [x] Precision bounds on real data: scan 250 reported precision 1.0 before (27 TP,
      0 FP, 14 pending); it now reports 65.9–100% and `adjudication_complete = false`.
- [x] FP clustering: the scan-list SQL and `compute_metrics` agree on the clustered
      count (verified by making a real scan's FPs share a group: 4 findings → 3 groups).
- [x] `GET /api/apps/3/benchmark` → **409** with the specific guard failures;
      `/configurations` → 200 with `publishable: false` and the same reasons.

### Performance

Scoring cost is dominated by fetching the in-scope corpus, so it scales with corpus size,
not scan size. Measured on the snapshot: TaintedPort (32 vulns) is sub-millisecond; a
2,113-vuln app takes 26ms; the 48,004-vuln recon-flood leftover (app 161) takes ~630ms
(365ms SQL fetch / 140ms compute / 124ms digest). Submit writes two scorings, so that app
adds ~1s to a submission and a full `rescore` there costs ~1s per scan. Left unoptimised:
`MAX_VULNS_PER_APP = 1000` means no new app can reach that size, and every realistic
corpus is inside 30ms.

### Deviations from the spec, and why

1. **`scorings` UNIQUE key includes `inputs_digest`** (a hash of adjudication state +
   in-scope corpus + weights), and `matcher_version` is `NOT NULL`. As specified —
   `UNIQUE(scan_id, scored_at_revision, matcher_version)` with a nullable matcher — a
   re-score after a human marked a finding as a false positive would be silently
   swallowed by the constraint and the stored number would stay stale forever, which is
   the exact failure the table exists to prevent. And SQLite treats NULLs as distinct in
   a UNIQUE index, so a nullable `matcher_version` would have made *every* re-score
   insert a duplicate instead. With the digest: unchanged inputs → no row; changed
   inputs → a new row, old one untouched.

2. **The scope rule gained a second clause:** `existed_since_revision <=
   scan.corpus_revision`. Without it, "introduced by a code change → prior scans
   untouched" only held for a scan's as-run scoring; since as-known is the headline, a
   newly-introduced vuln would have counted as a miss for every older scan at the next
   re-score — a decline the scanner did not cause. A vuln that existed all along
   (`existed_since = 1`) still reaches every scan, which is the retroactive behaviour we
   want. Consequence: `weighted_total` can differ per scan at one revision, so the
   compare matrix renders `n/a` (not `✗`) for cells a scan couldn't have found, and
   `corpus_revision_mismatch` is surfaced in the guards.

3. **Phase 8 guards are advisory on `/compare`, blocking on a new `/benchmark` export.**
   Hard-refusing a comparison whose scans differ in revision or matcher — or with fewer
   than 5 trials — would break the tool's daily use, including the F1-over-time chart
   from 7d37b87 and the basic act of viewing an old scan beside a new one. So `/compare`
   and `/configurations` report a `guards`/`problems` payload the UI renders as a banner,
   and `GET /api/apps/{id}/benchmark` (the export path) returns 409 listing every failed
   guard. Flipping compare to blocking is a one-line change if you'd rather.

4. **`fp_group` numbering:** the Phase 5 migration was unnumbered in the spec, so it is
   `030_fp_group.sql` (after scorings — no dependency either way).

5. **`matcher_version` / `matcher_prompt_sha256` are stored on `scans`, not only on
   `scorings`** (2 extra columns in 026). Phase 6 requires a bulk re-score to use "the
   same matcher version" per scan, which is unknowable at rescore time unless the scan
   carries it. Existing scans backfill to `'unknown'`.

6. **Precision's lower bound uses `fp_groups`, not raw FP:** `tp / (tp + fp_groups +
   pending)`. Mixing the clustered TP/FP counts with a raw pending count would
   re-introduce Defect 2 inside the bound. Pending findings are unclustered by
   definition (unadjudicated), so each is counted as its own potential FP — still a true
   lower bound.

7. **A matched vuln with no milestone rows scores full credit** (and all four milestones
   are always written when any are recorded). Not stated in the spec, but the
   alternative silently zeroes every historical weighted score the moment the milestone
   table appears.

8. **Chain credit without chain milestones = `min(credit of each member)`** (weakest
   step). Phase 7 asks for chain-level milestones, so `chain_milestones(scan_id,
   chain_pk, …)` exists and overrides this — a scan-level table, because whether a chain
   was walked end to end is a fact about the run, not about one finding.

9. **Weight/tier are required by the *forms*, defaulted by the *API*.** Rejecting any
   vuln without them (as written) would break `promote_finding`, bulk import and
   seeding. The UI selects require both; programmatic paths derive the weight from
   `severity` (always present and validated) and default the tier to `commodity`. A PUT
   that omits them preserves the stored values, so the inline table editor can't reset a
   hand-corrected weight.

10. **Revision churn control:** a corpus change on an app with no scans stays on the
    current revision. Otherwise authoring 28 seed vulns would create 28 revisions, none
    of which could ever matter — there is nothing to re-score.

11. **Deleting a matched vuln now 409s**, pointing at `invalidate` instead. It already
    failed at the FK layer with an opaque error; Phase 3's `invalidated_at_revision` is
    the correct mechanism, so `POST /api/apps/{id}/vulns/{vid}/invalidate` was added.

### Still open — needs you

- **TaintedPort weights and tiers.** Per the spec's "do not guess these", nothing was
  invented: migration 024 and `app/seed.py` both fall back to the severity map with
  `difficulty_tier = 'commodity'`. `tasks/taintedport-weights.md` has a per-vuln table
  with proposed **tiers** (16 commodity / 10 business logic / 2 chained), the five
  weights I think the severity map gets wrong, and two chain definitions worth
  authoring. Until those land, the tier matrix reports TaintedPort as a flat commodity
  corpus — which is precisely the picture the redesign is meant to correct.
- **No chains authored yet.** The machinery is live but contributes 0 points until a
  `chains` row exists.
