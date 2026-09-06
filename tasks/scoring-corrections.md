# Scoring Corrections — follow-up to scoring-redesign.md

Seven corrections found while reviewing the implemented redesign. Five are metric
correctness, one is a verification check on the importer, one is scoping.

The four disagreements recorded in the review section of `tasks/scoring-redesign.md`
(`inputs_digest` in the UNIQUE key, the second scope clause, advisory-vs-blocking guards,
forms-require-API-defaults) were all correct and stand. Nothing here reverses them.

Items 1 to 4 affect numbers that will be shown externally, so they land before any chart
is published. Item 5 is new capability. Items 6 and 7 are small.

---

## 1. Chain credit must be zero without chain milestones

**Now:** `compute_metrics` falls back to `min(credit of members)` when no
`chain_milestones` rows exist. Members with no milestone rows score 1.0 (the
no-milestones-means-full-credit rule), so a run that finds all three members
independently scores the chain at full weight.

**Why that is wrong:** a chain is a separate ground-truth row carrying its own weight *on
top of* its members. That double-count is deliberate — demonstrating a chain is worth more
than finding its parts. The argument only holds if the chain's weight requires evidence of
chaining. With the fallback, three members worth 9 + 9 + 27 = 45 silently become 72 for
reasons unconnected to capability, which inverts the purpose of the chain row.

- [x] Remove the weakest-step fallback. `credit_by_chain[pk] = 0.0` when no
      `chain_milestones` rows exist for that chain.
- [x] Document the asymmetry in `AppBuilder.md` so it does not get tidied away later:
      **for a vuln, the match is the evidence; for a chain, matching its members is not
      evidence of chaining.** Vulns keep full credit absent milestones. Chains do not.
- [x] Chains contribute nothing until chain milestones are recorded. The manual toggle in
      the UI already exists, so an adjudicator reading a report that plainly demonstrates
      the chain can set it by hand. That is the interim path and it is expected.

## 2. The `surface` milestone should earn nothing

**Now:** `surface` 0.15, `flaw` 0.25, `poc` 0.30, `impact` 0.30.

**Why that is wrong:** a milestone row only exists for a finding already matched to a
vuln. So "surface achieved, flaw not" means the tool reported something at the right
location without identifying the flaw. That is barely distinguishable from a false
positive that happened to land on the right endpoint, and it currently earns 4 points on a
critical.

- [x] New fractions: `surface` 0.0, `flaw` 0.30, `poc` 0.35, `impact` 0.35.
- [x] Keep recording `surface`. It stays useful diagnostically, it just earns nothing.
- [x] Re-score after the change; the fractions are part of `inputs_digest`, so this is a
      new scoring row per scan, not a mutation.

## 3. Two weighted metrics, both always stored

**Now:** one weighted score, milestone-credited where milestone rows exist and
full-credit where they do not.

**Why that is a problem:** it makes the number mean different things for different
scanners without saying so. It is not, however, a reason to score cross-scanner
comparisons as binary — that was considered and rejected. There are two distinct gaps and
they must not be conflated:

- COS demonstrated impact but the matcher failed to record the milestone. An artifact.
- DAST reported "directory listing, Low" and stopped. A real capability gap that should
  cost points.

Telling them apart is an adjudication question, not a scanner-identity question. Provided
milestones are assigned by reading the submitted report rather than self-declared by the
tool, a DAST report genuinely containing no impact evidence correctly earns `flaw` and
`poc` but not `impact`. That is the honest measurement, so **milestone credit applies to
every scanner**.

The binary metric is retained as a secondary, for continuity with the 136 historical scans
and as a sanity check.

- [x] Migration `031`: add `binary_weighted_found`, `binary_weighted_total`,
      `binary_weighted_rate` to `scorings`.
- [x] `compute_metrics` returns both. Binary treats any matched in-scope vuln as full
      weight and ignores milestone rows entirely.
- [x] Both are computed and stored on **every** scoring. This must not be a mode selected
      at scoring time — otherwise switching views later requires a full re-score, and
      comparing a binary-scored run against a milestone-scored one becomes possible by
      accident.
- [x] Milestone-credited rate stays the headline. The chart picks which to display.

## 4. Tier matrix `found` counts any non-zero credit

**Now:** `if credit > 0: bucket["found"] += 1`.

With item 2 applied the floor rises from 0.15 to 0.30, which helps, but the matrix can
still read "business logic 9/14" beside a weighted rate of 22%. In a meeting the first
number is the one that gets quoted.

- [x] Report two counts per tier: `found` (credit > 0) and `fully_demonstrated`
      (credit == 1.0).
- [x] The default UI view shows `fully_demonstrated` alongside the weighted rate.

## 5. Severity-gap scoring, and weight derives from severity

Two changes that turn out to be the same change.

**Ground-truth severity is contextual severity.** TP-013 is a directory listing, Low by
convention, but in TaintedPort it exposes `database.db` and the JWT signing key, so it is
stored as critical. When a DAST scan imports that finding as Low, the delta between
reported and ground-truth severity *is* the measurement: the tool detected the issue and
failed to assess what it meant in this application.

That also removes the need for severity and weight to be independent. The map is 1:1
(info/low→1, medium→3, high→9, critical→27) and there is no remaining case where they
should diverge.

- [x] `impact_weight` derives from `severity` on write. Keep the stored column, since the
      revision scheme needs an immutable per-revision value, but treat an explicit
      override as exceptional rather than expected.
- [x] Remove the "severity is the display field, `impact_weight` is the scoring field and
      is allowed to diverge" language from `AppBuilder.md` and from the background section
      of `tasks/scoring-redesign.md`. It predates this decision.
- [x] New metric: **severity band error.** For each matched finding, compare
      `scan_findings.severity` against the matched vuln's `severity` on the four-band
      scale. Report mean signed band error (negative means under-rated) and percentage of
      matched findings within one band.
- [x] Store on `scorings` alongside the other metrics.
- [x] No schema change needed for the inputs: both severity columns already exist
      (`scan_findings.severity` from 019).

Note for context: nothing in CVE-Bench, BountyBench, WebExploitBench or PACEbench measures
this, because they all score binary exploitation. It is the cleanest available measurement
of what a reasoning layer adds over a signature scanner, so it is worth getting right.

## 6. Verify the importer preserves tool-reported severity

**Blocking check for item 5.** If `tools/import_scan.py` or the matcher normalises
`scan_findings.severity`, or overwrites it with the ground-truth severity when a match is
made, then the gap is erased at import time and the metric silently reports zero error
forever. Nobody would notice, because a zero gap looks like a well-calibrated scanner.

- [x] Confirm `scan_findings.severity` stores exactly what the tool reported, unmodified,
      on both the matched and unmatched paths.
- [x] If it is being rewritten, keep the reported value in a new column and leave the
      existing one alone.
- [x] Add a test: import a finding reporting `low` that matches a `critical` vuln, and
      assert the stored finding severity is still `low` after matching.

## 7. Scope hand-set weights to the benchmark corpus

Migration 024 backfilled all ~55k vulns from severity. Those derived values are fine for
the 214 apps nobody is curating. What must not happen is a weighted comparison silently
spanning hand-set and derived corpora.

- [x] `ALTER TABLE apps ADD COLUMN is_benchmark_corpus INTEGER NOT NULL DEFAULT 0;`
- [x] Only benchmark-corpus apps require hand-set severity and tier; only they appear in
      `/benchmark` exports and configuration comparisons.
- [x] Guard: refuse a benchmark export for an app flagged as corpus that still has vulns
      on placeholder values (`difficulty_tier` untouched since backfill).

---

## Order

1. Item 6 first. It is a five-minute check and item 5 is worthless if it fails.
2. Items 1, 2, 4. Small, local to `compute_metrics`, and they change published numbers.
3. Item 3. Migration plus metric.
4. Item 5. Depends on 6.
5. Item 7.

Re-score everything after 1, 2 and 3. All three change `inputs_digest`, so this appends
new scoring rows and leaves the old ones intact, which is the intended behaviour.

## Verification

- [x] A chain whose members are all matched, with no `chain_milestones` rows, contributes
      exactly 0.
- [x] A vuln whose only achieved milestone is `surface` contributes exactly 0.
- [x] Binary and milestone-credited rates are both present on every new scoring row, and
      binary reproduces the pre-milestone number for a fully-matched scan.
- [x] A DAST-style import reporting `low` against a `critical` ground-truth vuln yields a
      severity band error of -3 for that finding and does not mutate the stored finding
      severity.
- [x] Historical scorings are unchanged by all of the above.

---

## Review

All seven items implemented, in the stated order. 97 tests pass; frontend builds clean;
re-scored against a copy of the production snapshot.

### Item 6 first, as instructed — the check passes

`scan_findings.severity` stores exactly what the tool reported, on both paths:

- `submit_scan` inserts `f.get("severity")` verbatim. Every post-insert `UPDATE` on
  `scan_findings` touches only `matched_vuln_id`, `is_false_positive`, `is_ignored`,
  `fp_group` — verified by grep across all services, no exceptions.
- Real data agrees: of 109 matched findings carrying a reported severity, 80 diverge from
  ground truth in **both** directions (high→medium 15, high→critical 14, medium→high 5,
  high→low 3, critical→low 1). Nothing is collapsing onto the diagonal.
- The only transformation is Probely's numeric codes (0/10/20/30/40 → info…critical),
  which transcribes the tool's own severity rather than rewriting it to ground truth.
- Pinned by `test_import_of_a_low_finding_against_a_critical_vuln_keeps_low`: a `low`
  finding matching a `critical` vuln stays `low` after both auto- and manual matching, and
  yields band error -3.

**But coverage is thin, and that had to be built in.** Only 109 of 426 matched findings
(26%) carry a reported severity at all — the original mapping prompt told the LLM to leave
rich detail blank for matched findings, and history keeps that gap. So the metric stores
`severity_band_scored` / `severity_band_findings`, and the UI prints `20/20` next to the
value rather than hiding coverage in a tooltip. Without that, a mean over a quarter of the
findings reads as a mean over all of them.

First real values, from the snapshot: Snyk API & Web **+0.18** (22/22 scored, 100% within
one band), OpenHack **+0.68** (22/22, 86%), Claude Code Security **-0.20** (20/20, 95%).

### One correction your list implies but does not state

**Items 1 and 2 change outputs without changing any digest input.** The digest hashed
data — findings, corpus, weights, milestone rows — never the rules. So a re-score after
changing the milestone fractions or the chain rule produces a different number from
identical inputs, `INSERT OR IGNORE` drops it, and the stored value silently stays on the
old rules. Exactly the failure the digest exists to prevent, arriving through the code path
instead of the data path.

It happened to work here only because item 5 added severity to the digest, changing every
row's hash as a side effect. That is luck, not design.

Fixed structurally: `SCORING_VERSION` (now `2`) is part of `inputs_digest`, with the rule
that it is bumped whenever a credit rule changes. `test_scoring_version_is_in_the_digest`
holds the line. Without this, any future rule change is unpublishable — the re-score is a
silent no-op.

### Item 7 — no app auto-flagged, and why

Flagging TaintedPort by name looked obvious and is not safe: **this database has two apps
named `TaintedPort` version `1.0`** (ids 1 and 3, with 31 and 32 vulns, 2 and 10 scans).
Migration 010 rebuilt `apps` without carrying over the original `UNIQUE(name, version)`, so
duplicates are possible and exist. A name match would have silently marked an app I know
nothing about as curated ground truth.

So migration 032 flags nothing. Which app is the corpus is a decision, made in the UI
(App edit → "Benchmark corpus") or via `PUT /api/apps/{id}`. `/benchmark` refuses for every
app until then, which is the correct default — no tiers have been reviewed anywhere — and
the App detail page shows the state as a badge so it is discoverable rather than a silent
refusal. Verified end to end: unflagged → 409 "not flagged as a benchmark corpus"; flagged
→ 409 "32 vulns still carry the placeholder difficulty_tier"; and an app edit that omits
the field leaves it set (the flag is tri-state, not a checkbox default).

**Separately, and not fixed here:** the missing `UNIQUE(name, version)` is a live problem
beyond this task. `tools/import_scan.py --create-app` looks up by name+version and takes
the first match, so an import can attach scans to either TaintedPort. Deduplicating needs
your call on which rows to keep, so it is flagged rather than acted on.

### What changed in the numbers

`SCORING_VERSION` moved every digest, so re-scoring appended rather than mutating: 13 rows
→ 25, with every pre-existing row byte-identical.

The credited weighted rate is *unchanged* on real data, because no scan in the snapshot has
milestone rows and no chains exist yet — so credit is 1.0 everywhere and the corrections
have nothing to bite on. They bite the moment milestones or chains are recorded, which is
why landing them before publishing was the right call:

| | Before | After |
|---|---|---|
| Vuln, `surface` only, weight 27 | 4.05 pts | **0 pts** |
| Vuln, `surface`+`flaw`, weight 9 | 3.6 pts | **2.7 pts** |
| Chain w/ all members matched, no chain milestones | 45 pts (members 18 + chain 27) | **18 pts** |
| Tier row, 4 partial + 0 full of 14 | "4/14, 29%" | **"0/14 fully, 4 partial"** |

### Implementation notes

- **Chain asymmetry is documented in three places** so it does not get tidied away: a
  block comment at `credit_by_chain` in `app/scoring.py`, the **Exploit chains** section of
  `AppBuilder.md` (with the one-line statement of the rule), and
  `test_chain_earns_nothing_without_chain_milestones`, whose docstring says why. An
  undemonstrated chain still sits in `weighted_total`, so it costs points rather than
  vanishing.
- **Binary counts a chain when every member matched** — that *is* the pre-milestone reading
  of "found the chain", which is precisely why it cannot be the credited reading.
  `test_binary_counts_a_chain_when_every_member_matched` pins the 45-vs-18 split.
- **`surface` is still recorded and still shown** (italic, muted, tooltip "Diagnostic only:
  earns 0%"), so the UI never implies credit that was not earned.
- **Weight derivation and the inline editor.** `impact_weight` now follows `severity`, but a
  PUT that omits the weight still preserves the stored value — *unless* `severity` changed,
  in which case the weight follows it. That keeps the inline table editor from resetting an
  exceptional override on an unrelated edit while making a severity edit do the obvious
  thing. Two tests cover both directions.
- **`difficulty_tier_reviewed`** was needed to implement "still on placeholder values": a
  deliberately-`commodity` tier is otherwise indistinguishable from the 024 backfill that
  wrote the same value, and inferring it from migration history would rot. Re-confirming
  `commodity` counts as a review.
- **A latent ordering bug surfaced** while updating a test: `list_scorings` ordered by
  `(scored_at_revision, computed_at)`, and `computed_at` has one-second resolution — so two
  rows appended in the same second (a re-score right after an adjudication edit) came back
  in arbitrary order, which matters because callers reach for "the original row" by index.
  Now ordered by `(scored_at_revision, computed_at, id)`.

### Verification

- [x] A chain with all members matched and no `chain_milestones` rows contributes exactly 0
      (and still counts in `weighted_total`).
- [x] A vuln whose only achieved milestone is `surface` contributes exactly 0.
- [x] Binary and credited rates are both present on every new scoring row; binary
      reproduces the credited number exactly when no milestone rows exist anywhere.
- [x] A DAST-style import reporting `low` against a `critical` ground-truth vuln yields
      band error -3 and does not mutate the stored finding severity.
- [x] Historical scorings unchanged: 13 pre-correction rows byte-identical after re-score.
- [x] Editing a finding's severity appends a new scoring row (it is a metric input, so it
      is in the digest).
- [x] Changing a vuln's severity re-derives the weight and opens a `weight_change` revision.
- [x] `/benchmark` refuses an unflagged app, then refuses a flagged app with placeholder
      tiers, then passes once tiers are reviewed.
