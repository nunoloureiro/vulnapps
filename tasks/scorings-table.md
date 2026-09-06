# Immutable scorings table — deferred, revisit for reproducible benchmark exports

**Status:** dropped from the scoring redesign (2026-09-04), pending a decision below.

## What migration 029 tried to do

`migrations/029_scorings.sql` added an append-only `scorings` table: every published
number (API export, compare view, chart) would read from a row here instead of live
computation, so a published figure could be reproduced later. Each row recorded
`scored_at_revision` (which ground truth), `matcher_version` (who mapped it), and
`inputs_digest` (a hash of every finding's match/FP/ignore/milestone state plus the
in-scope corpus and its weights) — an unchanged re-score would be a no-op, any changed
input would append a new row, old rows stay untouched. Migration 031 later added
`binary_weighted_*` and `severity_band_*` columns to it; migration 033 added
`scoring_version` for provenance.

## Why it's on hold

For now, metrics stay computed live at request time (the pre-redesign behaviour) — no
persisted/reproducible scoring history yet.

## Before rebuilding this

- **Depends on F (config fingerprinting, also deferred — see
  `tasks/config-fingerprinting.md`).** `scorings.matcher_version` needs a real per-scan
  matcher identity to be meaningful; without it every row would just say 'unknown'.
- **Depends on whatever shape A/B/(C)/D end up in.** The table's columns
  (`weighted_found`, `tier_json`, etc.) mirror whatever `compute_metrics` returns, so
  it should be rebuilt after weight/tier/milestone/chain scoring rules are final, not
  before.
- Revisit the reporting-guard rationale in the original migration comments (min trials
  per config, refusing to mix matcher versions) — that's the reason this table existed
  at all, not just storage/caching.
