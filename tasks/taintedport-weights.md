# TaintedPort weights and tiers — needs your sign-off

`tasks/scoring-redesign.md` says: *"Manual input required from Nuno: weights and tiers
for TaintedPort's 28 seed vulns in `app/seed.py`. Backfill gives a starting point; the
values need hand correction. Do not guess these."*

So nothing here is committed. Migration 024 backfilled every existing vuln from its
severity (`info/low→1, medium→3, high→9, critical→27`) and set every tier to
`commodity`, and `app/seed.py` applies the same fallback for a fresh database. Both are
placeholders.

**Why the tier placeholder is the more urgent of the two:** with everything marked
`commodity`, the tier matrix claims TaintedPort contains no business-logic and no chained
ground truth at all. That is the one table the whole redesign exists to produce, and right
now it reads as a flat 28-item commodity corpus — which is exactly the picture that makes
a chat-interface scanner look equivalent to an agent that pivots.

## How to apply your decisions

Add the keys to the entry in `app/seed.py` (both are optional per entry, so only edit what
you change):

```python
{
    "vuln_id": "TP-019",
    "title": "Price Manipulation on Cart",
    # Contextual severity: what this is worth in THIS app. impact_weight
    # derives from it (critical → 27), so setting the weight is not needed.
    "severity": "critical",
    "difficulty_tier": "business_logic",
    ...
}
```

For the **live database**, seed.py won't re-run. Either edit inline on the vuln page /
app table, or `PUT /api/apps/{id}/vulns/{vid}`. Changing `severity` re-derives the weight
and opens a `weight_change` revision automatically, so follow it with
`POST /api/apps/{id}/rescore`; changing only a `difficulty_tier` does not, since it never
moves the weighted total — but it does mark the tier reviewed, which the benchmark export
requires.

> **Updated after `tasks/scoring-corrections.md`.** Two things changed here:
>
> 1. **`impact_weight` now derives from `severity`.** So the weight column below is no
>    longer a separate decision — correcting a weight means correcting the *severity*, and
>    ground-truth severity is contextual severity ("what is this worth in *this* app?"),
>    not the CVSS-ish convention. The notes below are therefore severity corrections.
> 2. **A chain scores 0 until chain milestones are recorded.** The chain candidates at the
>    bottom are no longer "nice to have": authoring them adds their weight to
>    `weighted_total` immediately, and they contribute nothing until an adjudicator marks
>    the chain as walked. Author them when you are ready to adjudicate them.
>
> Also: `difficulty_tier_reviewed` now tracks which tiers you have actually looked at, and
> the benchmark export refuses while any remain unreviewed. Re-confirming `commodity`
> counts as a review, so working straight down the table below clears the guard.

## Proposed tiers (mine — please correct)

Tier is the more objective of the two axes — "would a scanner with a signature find this?"
— so I've proposed a value for each. **Weights below are the severity-derived value, which
is now the rule rather than a placeholder; where I think it is wrong, the severity is what
needs changing.**

| ID | Title | Severity | Weight (derived) | Proposed tier | Why |
|----|-------|----------|------------------|---------------|-----|
| TP-001 | SQL Injection - Login Email | high | 9 | commodity | signature-detectable ⚠ see note 1 |
| TP-002 | SQL Injection - Wine Detail (ID in URL) | high | 9 | commodity | signature-detectable |
| TP-003 | SQL Injection - Wine Search | high | 9 | commodity | signature-detectable |
| TP-004 | SQL Injection - Wine Reviews | high | 9 | commodity | signature-detectable |
| TP-005 | Blind SQL Injection - Order Status Filter | high | 9 | commodity | time-based, still a standard check |
| TP-006 | Reflected XSS - Login Email | medium | 3 | commodity | |
| TP-007 | Reflected XSS - Wine Search | medium | 3 | commodity | |
| TP-008 | Stored XSS - User Name (Profile) | medium | 3 | commodity | ⚠ note 2 |
| TP-009 | Stored XSS - Shipping Name (Checkout) | medium | 3 | commodity | ⚠ note 2 |
| TP-010 | Stored XSS - Wine Review Comment | medium | 3 | commodity | ⚠ note 2 |
| TP-011 | JWT 'none' Algorithm Accepted | high | 9 | commodity | standard JWT check |
| TP-012 | JWT Signature Not Verified | high | 9 | commodity | standard JWT check |
| TP-013 | Directory Listing | medium | 3 | commodity | ⚠ note 3 — weight looks wrong |
| TP-014 | Path Traversal - Wine Export | high | 9 | commodity | ⚠ note 3 — weight looks wrong |
| TP-015 | Open Redirect on Login | medium | 3 | commodity | |
| TP-016 | Missing Security Headers | low | 1 | commodity | |
| TP-017 | BOLA (IDOR) on Order Details | high | 9 | business_logic | needs two accounts and a notion of ownership |
| TP-018 | BOLA / Mass Assignment on Profile Update | high | 9 | business_logic | requires guessing an undocumented `user_id` field |
| TP-019 | Price Manipulation on Cart | high | 9 | business_logic | requires knowing what a cart is *for* ⚠ note 4 |
| TP-020 | Broken Access Control on 2FA Disable | high | 9 | business_logic | undocumented `user_id` on a security action |
| TP-021 | Discount Code Bypass | high | 9 | business_logic | requires knowing what a discount is *for* ⚠ note 4 |
| TP-022 | Privilege Escalation via Mass Assignment on Registration | critical | 27 | business_logic | undocumented `is_admin` field |
| TP-023 | Privilege Escalation via JWT Claim Forgery | critical | 27 | **chained** | its own description says "combined with #11, #12" |
| TP-024 | BOPLA - Excessive Data Exposure on Order Details | high | 9 | business_logic | needs reading the response for fields that shouldn't be there |
| TP-025 | BFLA - Broken Function Level Authorization on Order Status | high | 9 | business_logic | undocumented `is_admin` in body |
| TP-027 | SSRF via Wine Import URL | high | 9 | business_logic | ⚠ note 5 — chain candidate |
| TP-028 | SQLi → TOTP Extraction → 2FA Bypass → Account Takeover | critical | 27 | **chained** | four-step chain by definition |
| TP-029 | Reflected XSS - Contact Form Preview (Server-Side) | medium | 3 | commodity | |

Proposed distribution: 16 commodity, 10 business logic, 2 chained. Weighted total 245 pts
at the derived weights.

## Severity corrections I think are needed (weight follows automatically)

1. **TP-001 (login SQLi)** — derived weight 9, but the description says it can "bypass
   authentication". Auth bypass is in the 27 band. Same question for TP-002/003/005, which
   can dump `password_hash` and `totp_secret`.
2. **Stored XSS (TP-008/009/010)** — derived 3 (medium). The weight table puts "stored XSS
   with session theft" at 9, and TP-008 renders in the navbar on every page load with
   `document.cookie` in the PoC. Probably 9, not 3.
3. **TP-013 / TP-014** — the directory listing exposes "all PHP source code, the SQLite
   database file, and configuration files including the JWT secret"; the traversal reads
   `jwt.php` and `database.db` directly. A full-database read plus the signing key is not
   a 3 and probably not a 9 either.
4. **TP-019 / TP-021** — "business logic abuse with financial impact" is explicitly in the
   27 band, and both give free/near-free orders. Derived 9 likely understates them.
5. **TP-027 (SSRF)** — the description already spells out a chain: read `jwt.php` → extract
   the secret → forge a signed admin token. If you want that scored as a chain, it should
   become a `chains` row (its own weight, with TP-027 + TP-023 as members) rather than a
   `chained` tier tag on one vuln.

## Chains worth defining (Phase 7 is implemented; no chains exist yet)

The machinery is in place (`chains`, `chain_members`, `chain_milestones`, revision-scoped
like vulns), but no chain has been authored, so no chain currently contributes weight.

**Note the asymmetry before authoring one:** a chain earns credit only from
`chain_milestones` — matching its members is not evidence of chaining. So a newly authored
chain immediately raises `weighted_total` and scores 0 until an adjudicator marks it walked
(the toggle is on the scan page). That is intended: an undemonstrated chain should cost
points. It does mean every existing scan's weighted rate drops the moment a chain is
authored, so author chains and adjudicate them in the same sitting.
Two candidates fall straight out of the seed data:

| Chain | Steps | Suggested weight |
|---|---|---|
| SSRF → JWT secret → forged admin token | TP-027 → TP-023 | 27 |
| SQLi → TOTP secret → 2FA bypass → ATO | TP-003 (or TP-028's own SQLi) → TP-028 | 27 |

Note that TP-028 is currently modelled as a single vuln that *describes* a chain. With
Phase 7 available, it is arguably a `chains` row whose members are the underlying SQLi and
the TOTP exposure. That is a corpus-modelling decision, so it's yours — and it needs a
`corpus_change` revision plus a re-score either way.
