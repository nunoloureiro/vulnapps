# Known false positives: a per-app FP corpus

Status: phase 1 implemented 2026-10-29 (see tasks/todo.md review); seeding and phase 2 pending.
As built, phase 1 copies the known FP's id/penalty onto linked findings (scorer unchanged),
has no revisions for known FPs, and uses one `description` field for the debunk.

## Why

Today an FP only exists on the finding that was marked. Every new scan that
flags the same non-issue lands as Pending, and a reviewer has to dismiss it
again by hand: same reasoning, a fresh free-text `fp_group`, and a fresh
penalty choice. TaintedPort now has planted decoys (D1–D7 in
`TaintedPort-Vulns/KnownVulnerabilities.txt`). They are ground truth just like
the TP-* vulns, but vulnapps has nowhere to put them.

A known-FP corpus gives us:

1. **Less review work.** A finding that hits a known FP is filed as an FP when
   it's imported.
2. **Consistent scoring.** Every scan that hits D4 gets the same FP group and
   the same penalty, so precision can be compared across scans. Today two
   reviewers can cluster and weight the same decoy differently.

## The main risk

Decoys are designed to sit right next to real vulns: D4 (receipt, ownership
enforced) next to real IDOR #17 (`GET /orders/:id`), and D1 (self-XSS on login)
next to real reflected XSS #7. Using location to match a known FP will
eventually swallow a true positive. That error is the expensive one: it moves
a scanner's score in the wrong direction and nobody looks again, because the
finding no longer sits in Pending. The plan therefore biases every tie toward
TP and records where each automatic FP came from.

## Decisions (confirmed 2026-10-28)

1. **Remembering is opt-in, ticked by default.** The Mark-FP dialog has
   "Remember as known FP for this app", checked by default. The reviewer
   unticks it for one-off hallucinations and for "real, but not catalogued"
   (promote to a vuln instead). Marking FP can also pick an existing known
   FP, which replaces the free-text `fp_group`.
2. **An automatic FP is final, but labelled and reversible.** It is stored
   with `fp_source = 'known_fp'`, carries a "Known FP D4" badge, and can be
   remapped in one click. It does not make the score provisional.
3. **No separate decoy metric.** Decoy hits are FPs and already move FP
   count and precision. The corpus only makes their grouping and penalty
   consistent.
4. **IDs:** `D1`… for planted decoys and `FP-001`… for FPs remembered from
   review.

### Later: promoting reviewed FPs into the catalog

FPs that recur across scanners will later be written into
`KnownVulnerabilities.txt` as new `D-n` entries. Design for that now:

- `fp_id` and `source` are editable. "Promote to decoy" renames `FP-007` to
  `D8`, sets `source='decoy'`, and opens a revision. Findings link to the
  row's primary key, so the links survive the rename.
- After a promotion, the decoy reconciliation check (catalog `D*` count
  equals vulnapps `source='decoy'` count) must still hold. That makes the
  catalog edit and the promote action one step that is verified together.

## Data model (migration 044_known_false_positives.sql)

- [ ] Table `known_false_positives`: `id`, `app_id`, `fp_id` (D1 / FP-001,
      unique per app), `title`, `vuln_type`, `http_method`, `url`,
      `parameter`, `filename`, `description` (what a scanner reports),
      `why_not_real` (the debunk; the mapper relies on this most),
      `penalty_weight` (1/3/9/27, default 27 like an unreviewed FP), `source`
      (`decoy` | `reviewed`), `created_from_finding_id`, `created_by`,
      `known_since_revision`, `invalidated_at_revision`,
      timestamps.
- [ ] `scan_findings.known_fp_id` (nullable FK) and `scan_findings.fp_source`
      (`report` | `reviewer` | `known_fp`, nullable). Existing FPs are
      backfilled as `reviewer`, or as `report` where the importer set them.
- [ ] Changing the known-FP corpus opens a ground-truth revision (reason
      `corpus_change`), the same way vulns and chains do. It is also audit
      logged like chains (see migration 037).

## Scoring

- [ ] A finding linked to a known FP counts in FP group `known:<fp_id>`, with
      penalty `penalty_weight`, overriding the finding's own `fp_group` and
      `fp_impact_weight`. One decoy therefore counts as one FP, however many
      findings hit it.
- [ ] No other change to `app/scoring.py`. An FP from the corpus is an
      ordinary FP to the scorer.
- [ ] Turning a known FP into a real vuln (as D1 was once vuln #6, in
      reverse): invalidate the known FP at revision N. Findings linked to it
      go back to Pending in any rematch run after that. Scans that have
      already been scored keep their stored `scorings` row.

## Backend / API

- [ ] `app/services/known_fps.py`: list / create / update / invalidate,
      following `app/services/chains.py`. Routes go under
      `/api/apps/{id}/known-fps`.
- [ ] `mark_finding_fp` gains `remember: bool` and `known_fp_id`.
      `remember` creates an `FP-NNN` entry from the finding's fields, and the
      reviewer can edit `why_not_real` and penalty.
- [ ] `get_app` returns `known_fps` and `known_fp_count`. Export CSV gets the
      known FPs as a second section or a second file. **To check: how the
      export handles chains.**
- [ ] Server-side auto-match in `app/matching.py` at submit and rematch:
      **TP first, always.** Known FPs are tried only for findings left with
      no vuln or chain match. The bar is stricter than for vulns: same
      normalized vuln_type, an exact path after placeholder normalisation,
      and the same method and parameter when both sides have them. The
      score-60 fuzzy threshold that vulns use is not enough. Wildcard
      (`/*`) known FPs are never matched automatically.
- [ ] `rematch_scan` only ever turns **Pending** findings into known-FP
      matches. It never overrides a reviewer's TP, FP or Ignore. After a new
      known FP is added, offer "re-check pending findings on N scans".

## Importer (tools/import_scan.py)

- [ ] `VulnappsClient` fetches the app's known FPs next to vulns and chains.
- [ ] `format_known_fps_for_prompt`: ID, title, type, location and
      **why_not_real**, plus the IDs of the real vulns nearby (for example
      "distinct from TP-017 GET /orders/:id"), so the mapper sees the trap
      next to its real neighbour.
- [ ] `SYSTEM_PROMPT_MAP`: a third list, and a new output field
      `matched_known_fp_db_id`. Rules:
      - A known-FP match excludes any vuln or chain match. If a finding fits
        both, the vuln wins and the match is flagged for review.
      - Match only when the finding describes **the same construct the known
        FP debunks**. Same endpoint or same class is not enough. This
        mirrors the existing "same endpoint does NOT imply same
        vulnerability" rule.
      - The existing rule stays unchanged: `is_false_positive` means the
        report itself withdrew the finding. A known-FP match is a separate
        signal, so the two must not merge (see the lesson "Map findings a
        report withdrew for low impact, never FP them").
- [ ] `validate_llm_matches`: apply the same checks to known-FP matches
      (vuln_type gate, title keyword overlap), and reject a known-FP match on
      a finding that the server's algorithm matches to a vuln.
- [ ] Submit sends `known_fp_id`, and `fp_source='known_fp'` is set on the
      server.
- [ ] Mapping table, `--format json` dry run and the KPI printout show
      "FP (known D4)" separately from reviewer and report FPs.
- [ ] Data consistency check (CLAUDE.md): the findings count still has to
      match the source report. Add a printed line: N auto-FP via known FPs
      (D-ids listed).

## Frontend

- [ ] App detail: a "Known false positives (N)" section below Chains, with
      the same table and edit/invalidate pattern.
- [ ] Mark-FP dialog: a picker for existing known FPs, plus the
      "Remember as known FP" checkbox (default on, depending on decision 1)
      and an editable why-not-real field.
- [ ] Scan detail: a "Known FP D4" badge on automatic FPs, with one-click
      remap.

## Seeding TaintedPort

- [ ] Load D1–D7 from `KnownVulnerabilities.txt` as `source='decoy'`, one
      revision bump.
- [ ] Extend the catalog reconciliation rule in CLAUDE.md: the count of `D*`
      in the catalog has to equal the known FPs with `source='decoy'` on
      vulnapps.
- [ ] Rematch the existing TaintedPort scans (pending findings only), then
      report how many findings moved, per decoy, before trusting it.

## Phases

1. Model, migration, service, API and app-detail UI. Seed D1–D7. Marking FP
   can link to an existing known FP or remember a new one (ticked by
   default). Nothing automatic yet.
2. Importer mapping with known FPs, validation, and the dry-run display.
   Server-side strict auto-match at submit and rematch for pending findings.

Phase 1 can ship on its own and already removes the free-text `fp_group`
drift.

## Tests

- Scoring: two findings hitting one known FP count as 1 FP at the corpus
  penalty.
- Precedence: a finding matching both TP-017 and D4 credits TP-017 and
  leaves D4 alone.
- Rematch never changes a reviewer's decision, and only Pending findings
  move.
- Invalidating a known FP sends its findings back to Pending on rematch.
- Importer: the prompt contains why_not_real, validation rejects a known-FP
  match whose type doesn't match, and the dry-run JSON carries known-FP IDs.

## Verification

- The importer dry run against a recent TaintedPort COS report: compare
  known-FP hits by hand with the decoys the report actually flagged.
- Before and after the TaintedPort rematch: TP counts must not change. Only
  FP and Pending move.
