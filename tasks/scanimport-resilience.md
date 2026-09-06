# Scan Importer Resilience — Fixing LLM Mismatched-Vuln Bugs

## Status: implemented (2026-09-06), with one correction to the analysis below

The investigation below (root-cause hypothesis, recommendations #2/#3)
turned out to be *incomplete*, not wrong: a follow-up check that fed the
real incident data directly into `app.matching.match_finding()` — no LLM
involved at all — reproduced every one of these mismatches exactly. The
actual root cause is the **server-side deterministic heuristic matcher**
(`app/matching.py`), which runs on every scan submission (any ingestion
path, not just this importer) *before* any LLM correction ever happens.
Three known vulns (42, 43, 47) are scoped to "any endpoint" (`url == "/*"`),
and the matcher's vuln_type hard-gate (50pts) + flat wildcard bonus (10pts)
alone clears the 60pt threshold for *any* finding sharing that broad
category — no mechanism relevance required. Recommendation #1 below
(vuln_type cross-check) would **not** have caught this: the finding's own
`vuln_type` was byte-identical to the wrongly-matched vuln's in all cases,
since the LLM appears to echo the matched vuln's category rather than
deriving it independently.

**What actually shipped**, in priority order:
1. `app/matching.py`: wildcard-URL vulns are no longer auto-matched on
   category + location score alone — they require the finding's own title
   to share a real keyword with the vuln's title (graded by overlap
   strength, so a tie between two same-category wildcard vulns — e.g. "JWT
   none-algorithm" vs "JWT signature not verified" — is broken by whichever
   title is the closer match, not list order). Validated by replaying the
   entire 311-finding non-FP/non-ignored TaintedPort corpus through
   old-code-vs-new-code on the identical current known-vulns list: 0 of the
   ~24 genuine JWT/headers matches were lost, and all 6 real incidents (plus
   3 more of the same bug found by this same replay, previously unnoticed)
   correctly stopped auto-matching. See `tests/test_matching.py`.
2. `tools/import_scan.py`: fixed the correction-loop gap where the LLM
   could apply a *different* match but never *clear* one the heuristic
   wrongly applied (recommendation #2, extended); added a hallucination
   guard and a title-overlap sanity warning (recommendation #1, adapted
   from vuln_type to title, given the above); persisted the LLM's
   `reasoning` field, previously generated and discarded (recommendation
   #2); restructured the prompt to warn against category-only matching and
   require the model to name a shared mechanism (recommendation #3). See
   `tests/test_import_scan_validation.py`, `tests/test_reasoning_persistence.py`.
3. Not implemented, per the original prioritization ("revisit once 1-4 are
   in"): the standalone confidence field (#4 — largely subsumed by the
   title-overlap check above), second-pass self-review (#5), batching
   limits (#6), model-tier A/B testing (#7), human-in-the-loop gating (#8).

## Goal

Scan 272 (TaintedPort, app_id=3) had three unrelated findings wrongly bucketed under
known vuln #42 ("JWT none-algorithm accepted"): a pass-the-hash login finding, a "2FA
enrollment needs no reauth" finding, and a TOTP-replay finding. Scans 141/142 had a
"default nginx credentials" finding wrongly matched to vuln #47 ("Missing Security
Headers"), and a "TOTP hash algorithm" non-issue wrongly matched to vuln #137
("Hardcoded JWT signing secret"). All were manually corrected via the API this session.
This plan finds the root cause and ranks fixes. **No code changes yet** — this is for
review.

---

## Confirmed current state

- **The model was already sonnet, not haiku.** `tools/import_scan.py:1458` sets
  `args.model = "claude-haiku-4-5" if not vulns else "claude-sonnet-4-6"`. Haiku only
  fires in extract-only mode (zero known vulns yet for the app — nothing to map
  against). Scan 272's matcher was tagged `llm-api:claude-sonnet-4-6`
  (`_matcher_identity`, line ~1021-1030, built as `f"llm-{engine}:{args.model}"`).
  **The user's literal ask — "switch mapping from haiku to sonnet" — is moot; that
  step already happened and still produced these mismatches.** The bug is in the
  method, not the model tier.
- **One giant one-shot call, no batching.** `run_llm_mapping` (line 457) sends the
  *entire* scan report plus *every* known vuln for the app (`client.get_vulns`, no
  chunking, no cap — 31 known vulns for TaintedPort today) in a single prompt/response
  round trip. There is no per-finding isolation and no second pass.
- **Candidate vulns are shown with only a title + broad type + 200-char-truncated
  description.** `format_vulns_for_prompt` (line 423) emits `DB ID`, `Vuln ID`,
  `Title`, `Severity`, `Type`, `URL`, `Parameter`, and `description[:200]`. There is no
  `code_location`, no PoC, no remediation detail for the candidate — exactly the
  fields that would let the LLM tell two mechanically-different bugs apart.
- **`vuln_type` is a coarse, overlapping taxonomy that both sides share.** Querying
  `vulnapps.db` directly: vuln #42 is `vuln_type="Broken Authentication"`; #47 is
  `vuln_type="Security Misconfiguration"`. The three findings wrongly matched to #42
  are all auth/session-flavored ("pass-the-hash", "2FA enrollment", "TOTP replay") and
  the finding wrongly matched to #47 ("default nginx credentials") is also, at the
  category level, a misconfiguration. **The prompt's own explicit anti-pattern rule
  ("Same endpoint does NOT imply same vulnerability... attack class must match") only
  guards against endpoint-based over-matching. It never warns that the reverse error —
  matching on a shared broad category/theme while the underlying mechanism differs —
  is just as easy to make, and the coarse `vuln_type` field it hands the LLM as the
  primary discriminator is exactly what invites that error.**
- **No structured confidence/uncertainty signal.** The prompt has one soft line ("Only
  map if there is a genuine semantic match. Do not force matches") buried among ~15
  other rules, competing with no counterbalancing signal. There is no confidence score,
  no required justification tied to `code_location`/mechanism, and nothing that makes
  "leave unmatched" a first-class, equally-weighted output vs. "matched."
- **The LLM's own `reasoning` field is generated but discarded.** The schema asks for
  `reasoning` per finding and it *is* printed to the terminal in `print_mapping_table`
  (line 629/636), but `submit_to_vulnapps`'s `findings_payload` loop (line 662-676) never
  forwards it to the API — it is not one of the copied keys. **The one artifact that
  would let a human audit *why* the LLM thought #42 matched pass-the-hash is thrown
  away**, unless someone was watching that specific terminal run.
- **No post-hoc sanity check at all.** Nothing in the file cross-checks the LLM's own
  assigned `vuln_type` for a finding against the matched candidate's `vuln_type`, nothing
  validates that `matched_vuln_db_id` is actually a member of the `vulns` list passed in
  (a hallucinated ID would be POSTed to `client.match_finding` as-is), and there is no
  second LLM call to self-review the first call's matches.
- **No default human gate.** `--confirm` and `--dry-run` are opt-in flags (line
  1237/1259); the default path auto-submits every match with no pause.
- **Test coverage.** `tests/test_import_scan_lookup.py` covers only app-lookup
  ambiguity (duplicate name+version apps) — none of `run_llm_mapping`, the prompt, or
  the matching/validation logic has any test today.
- **The two downloaded reports are byte-identical** (`nunoloureiro-TaintedPort-main-findings-2026-08-27.md`
  and `nunoloureiro-TaintedPort-findings-2026-09-04.md`, same md5) — the same raw report
  text was imported at least twice. The 141/142 "TOTP hash algorithm" mismatch isn't
  present verbatim in either file, so that finding likely came from an earlier/different
  report not retained in `~/Downloads`; the pass-the-hash/2FA/TOTP-replay findings
  (against #42) and the default-nginx-creds finding (against #47) are both confirmed
  present in these files and quoted below.

## Root-cause hypothesis

The mapper over-matches on **category-level thematic similarity** ("this smells like
auth" / "this smells like misconfig") because:

1. It is given, in one shot, a large candidate list where each candidate is reduced to a
   title, a broad `vuln_type`, and a truncated description — not enough signal to
   distinguish *mechanism* (JWT signature bypass vs. credential-hash reuse vs. TOTP
   replay window vs. missing reauth) within a shared broad category (auth bypass).
2. The prompt's only explicit false-positive guardrail addresses the *opposite* failure
   mode (same endpoint, different attack class) and never tells the model that sharing a
   `vuln_type`/theme is insufficient grounds for a match on its own.
3. There is no confidence field or equally-weighted "leave unmatched" affordance, so a
   plausible-but-wrong match and a correct match look identical in the schema — nothing
   forces the model to notice or flag its own uncertainty.
4. Nothing downstream catches it: no `vuln_type` cross-check, no second-pass review, no
   persisted `reasoning` to audit, no default human-in-the-loop gate.

This is a prompt/methodology and pipeline-validation gap, not a model-capability gap —
sonnet was already in use.

---

## Ranked recommendations

### 1. Add a cheap, deterministic post-hoc validator (highest value, lowest cost)
Right after the LLM returns matches, before submitting:
- Reject/flag any `matched_vuln_db_id` not present in the `vulns` list passed in
  (hallucination guard — currently unchecked).
- Compare the finding's own LLM-assigned `vuln_type` against the matched candidate's
  `vuln_type`. If they're not equal or clearly synonymous, downgrade the match to
  "needs review" rather than auto-applying it. This alone would have caught all three
  #42 mismatches (Authentication bypass/Missing authentication/Auth bypass vs. Broken
  Authentication is a near-miss on category, but the *mechanism* words — "pass-the-hash",
  "2FA enrollment", "replay" vs. "JWT none-algorithm" — never overlap) and the #47
  mismatch. Cheap, deterministic, no extra LLM call, immediately testable.

### 2. Persist the `reasoning` field
Add `reasoning` to the copied keys in `submit_to_vulnapps`'s `findings_payload` loop
(currently omitted at line ~671). Requires a DB column/API field on findings. This is
close to free relative to its audit value — it's the one piece of the LLM's own
justification that already exists and is just being discarded.

### 3. Restructure the prompt to fight thematic over-matching directly
- Add an explicit counter-example next to the existing "same endpoint ≠ same vuln" rule:
  "Sharing a broad category or theme (e.g. both are 'auth bypass', both are
  'misconfiguration') is NOT sufficient grounds for a match. The specific mechanism —
  what the attacker actually does and why the code allows it — must match, not just the
  category label."
- Require the model to cite the matched candidate's distinguishing mechanism (not just
  its title) in `reasoning`, e.g. "matches because both exploit missing signature
  verification on the token", forcing a mechanism-level comparison instead of a
  category-level one.
- Give candidates richer context where available (`code_location`, not just a truncated
  description) so mechanism, not just theme, is comparable.

### 4. Add a first-class low-confidence / "leave unmatched" affordance
Add a `confidence` field (e.g. `high|medium|low`) or a boolean
`mechanism_verified` alongside `matched_vuln_db_id`. Instruct the model: if confidence
is not high, prefer `null` over forcing a match, and surface low-confidence matches
distinctly in `print_mapping_table` and to reviewers (not lumped in with clean matches).
This makes "I'm not sure" a legitimate, visible output instead of a binary match/no-match
that hides uncertainty.

### 5. Second-pass self-review call for matched (non-null) findings only
After the first mapping pass, send back just the *matched* findings (finding text +
the single candidate it was matched to, this time with full detail) and ask the model
to confirm or retract each match independently, one at a time or in a small batch. This
catches exactly the class of error seen here — the first pass over-trusts thematic
similarity across a big list; a focused one-vs-one recheck removes the "closest of many"
pressure that likely drove the original over-match. More expensive (extra call(s)), so
gate it behind a flag initially or only run it for matches whose `vuln_type` cross-check
(#1) already flagged disagreement, to bound cost.

### 6. Batching limits
No limit exists today (31 vulns did fit in one call for TaintedPort, but nothing stops
this degrading further as apps accumulate more known vulns). Consider capping the
candidate list per call (e.g. pre-filter to vulns whose `vuln_type` loosely matches the
finding's extracted type before the detailed match step, only falling back to the full
list when the pre-filter finds nothing) once #1's data shows whether over-matching
correlates with candidate-list size.

### 7. Model choice guidance
- **Mapping default (sonnet)**: keep. It's already the default when there are known
  vulns to map against; this incident does not indict the model tier.
- **Extract-only default (haiku)**: leave as-is for now — that mode never faces this
  failure class (nothing to map against, so there's no wrong-match risk, only
  extraction-quality risk, which is a separate concern). Revisit only if extraction
  quality (not matching) becomes a complaint.
- **Opus for high-stakes mapping**: not recommended as a first lever. The evidence here
  is a methodology gap (weak discriminating signal + no self-check), not sonnet failing
  to reason correctly given the same inputs opus would see. Opus is worth an A/B test
  *after* #1–#3 land, to see if it still improves precision once the prompt/validation
  gaps are closed — spending the opus premium before fixing the prompt would likely just
  buy a more articulate wrong answer.
- Consider lowering temperature (currently unset → API default) for the mapping call
  specifically, since consistency matters more than creativity here.

### 8. Human-in-the-loop default for low-confidence or flagged matches
Given #1 and #4 above, make `--confirm`-style behavior automatic (not opt-in) whenever
any finding is flagged by the deterministic validator or reports low confidence, even
if the run isn't using `--confirm` globally. Leave full auto-submit for the common case
of clean, cross-check-passing matches.

### 9. New automated tests
- Unit tests for a new "vuln_type cross-check" validator function (recommendation #1):
  feed a hand-built LLM mapping result (mirroring the actual #42/#47 mismatches: finding
  `vuln_type="Auth bypass"` matched to candidate `vuln_type="Broken Authentication"`
  with no mechanism overlap) and assert it gets flagged/rejected rather than silently
  applied.
- A regression fixture built directly from this incident: replay the actual
  `nunoloureiro-TaintedPort-*-findings-*.md` report content (already in `~/Downloads`,
  byte-identical across the two dated copies) against a stubbed/recorded LLM response,
  and assert the pass-the-hash / 2FA-enrollment / TOTP-replay findings do NOT end up
  matched to the JWT-none-alg vuln. This can run without live API calls if the LLM
  response is recorded/mocked, matching the style of `test_import_scan_lookup.py`
  (module loaded via `importlib`, fake HTTP client).
- A hallucination-guard test: LLM returns `matched_vuln_db_id` not present in the
  `vulns` list — assert it's rejected before `client.match_finding` is called.
- Once `reasoning` is persisted (#2), a test asserting it round-trips into
  `findings_payload`.

---

## Priority order for implementation (when approved)

1. `vuln_type` cross-check validator + hallucination guard (#1) — cheap, deterministic,
   catches the exact bug class seen, unit-testable today.
2. Persist `reasoning` (#2) — small, high audit value.
3. Prompt restructuring against thematic over-matching + mechanism-citation requirement
   (#3).
4. Confidence/low-confidence affordance (#4) and routing flagged/low-confidence matches
   to a review gate (#8).
5. New tests (#9) — should land alongside 1-4, not after.
6. Second-pass self-review (#5) and batching limits (#6) — higher cost/complexity,
   revisit once 1-4 are in and it's clear whether they're sufficient.
7. Model tier A/B test (opus vs. sonnet) (#7) — only after the above, as a follow-up
   experiment, not a fix.
