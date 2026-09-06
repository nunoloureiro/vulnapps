# Config fingerprinting — deferred, revisit before building

**Status:** dropped from the scoring redesign (2026-09-04), pending a decision below.

## What migration 026 tried to do

`migrations/026_scan_config.sql` added dedicated columns to `scans` — `model`,
`model_version`, `reasoning_effort`, `harness_version`, `token_budget`, `seed`,
`run_group`, `trial_index`, and `config_fingerprint` (a stable hash of the first six,
excluding `seed`/`trial_index`, so k trials of one configuration share a fingerprint and
can be aggregated into a mean/min-max band). It also added `matcher_version` /
`matcher_prompt_sha256` to track which matcher mapped a scan's report to findings.

## Why it's on hold

Model, reasoning effort, etc. already exist as free-text scan labels (`labels` /
`scan_labels` tables, migration 014) — `import_scan.py` already auto-adds the scanner's
model as a label (see commit `bd6ba9f`). Adding a parallel column-based fingerprint system
without reconciling it with the label system would leave two overlapping, possibly
inconsistent ways to describe a scan's configuration.

## Decision needed before implementing

Pick one:

1. **Promote labels to columns.** Parse existing model/reasoning-effort labels into the
   new structured columns, and have `import_scan.py` write the columns going forward
   (either alongside or instead of the label).
2. **Build the fingerprint from labels directly.** Compute `config_fingerprint` from a
   scan's existing label set instead of adding new columns — no second source of truth,
   but fingerprinting logic has to parse label text.

Whichever is chosen, `matcher_version` / `matcher_prompt_sha256` tracking (needed by the
scorings table's reporting guards, see the scoring redesign) may not need the same answer
as model/reasoning_effort — it's arguably a separate concern that happened to live in the
same migration file.
