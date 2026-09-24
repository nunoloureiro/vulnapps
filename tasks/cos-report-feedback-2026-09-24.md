# Feedback on the COS scan of TaintedPort — scan 330

**Prepared:** 2026-09-24
**Scan under review:** vulnapps scan **330** — scanner `Snyk COS`, labels `claude-opus-4-8` + `greybox`
**Report bundle reviewed:** 57 standalone findings (`vulnerabilities/`) + 4 chain write-ups (`vulnerability_chains/`), plus `vulnerabilities.csv`, `vulnerability_chains.csv`, `stats.jsonl`
**Target:** TaintedPort @ corpus revision 9 — a deliberately vulnerable PHP/Next.js commerce app with a hand-maintained ground-truth catalog of **57 in-scope vulnerabilities and 12 registered multi-step chains**
**Scan record:** https://vulnapps.net/scans/330

Everything below was re-derived from the live scan record and the report files. This covers scan 330 only; other scans in our benchmark are different scanners and are not discussed.

---

## Summary

**This scan is good.** Against a 57-vuln catalog it found 45 of them — **78.9% recall at 90% precision** (F1 0.84), with only 5 false positives across 70 adjudicated findings. Several findings are genuinely excellent: the SHA-256 length-extension forgery on the order-tracking MAC, the keyless AES-CBC bit-flip that mints store credit, and the unkeyed `sha256(user_id:timestamp)` password-reset token are all things that require real cryptographic reasoning, and each came with a working, independently-verified PoC. On the two easier difficulty tiers the scan is strong: **31/38 commodity** bugs and **14/19 business-logic** bugs.

The gap is concentrated in one place. On **chained** vulnerabilities — outcomes that require composing two or three separate bugs — the scan credited **4 of 12**. That single tier is why the weighted score lands at 59.8% instead of the high 70s, and it is not a discovery problem: for three of the eight missed chains, COS found *every* constituent bug except one, and two of its own chain write-ups walked right past that one bug while holding the exact data needed to spot it.

The issues worth your attention, in order of impact:

1. **Three of the four chain write-ups substitute offline password cracking for the app's actual authentication bypass.** One missed vuln (pass-the-hash login) is a member of 4 of the 12 chains and is the *only* thing missing from 3 of them — 84 of 911 weighted points.
2. **Three "individual" findings are actually multi-bug chains** filed under `vulnerabilities/` with a single CWE, while the correctly-structured `vulnerability_chains/` directory exists and doesn't contain them.
3. **The hardcoded JWT signing secret has no finding of its own** — its literal value is quoted in three findings and used to forge an admin token in a fourth, but nothing in the findings table says "rotate this key."
4. **`chain-0002` is not a chain, and says so itself.**
5. **Two of the four chains list the same finding twice as two different "steps"** — in the machine-readable CSV, not just the prose.
6. **Three duplicate finding pairs**, one of them assigning `critical` and `medium` to the same bug.
7. **Severity calibration is inverted between SQLi and XSS** — all four SQL injections rated below our catalog, all three reflected-XSS findings rated above it.

A section near the end separates out **three problems that were ours, not yours** — including one thing that looked like a COS bug and wasn't.

> **How scoring works, briefly.** A vuln is credited (`tp`) if at least one finding matches it. Precision counts distinct false-positive groups against you; findings marked *ignored* are excluded entirely — neither credit nor penalty. A registered chain is credited either by a finding that demonstrates the chain end-to-end, or by all of its member vulns being found *and* the chain being explicitly confirmed. Weighted score uses severity weights (critical 27 / high 9 / medium 3 / low 1); each chain carries a critical weight of 27, which is why the chained tier dominates the weighted number.

---

## Issue 1 — Three of four chain write-ups replace the app's real auth bypass with offline password cracking

**Impact: high.** This is the single largest scoring loss in the scan and the only one that would also mislead a real customer.

### What the report did

TaintedPort's `POST /auth/login` has a specific flaw: `User::authenticateDirect()` never calls `password_verify()`, so the endpoint **accepts a raw bcrypt hash verbatim in the `password` field**. Anyone who leaks a `password_hash` logs in as that user immediately — no cracking, no password knowledge. This is catalog vuln **TP-036**, and it is the terminal step of four registered chains (CHAIN-001, CHAIN-008, CHAIN-009, CHAIN-010).

COS found the endpoints that leak the hash. `vuln-0030` correctly reports that ungated `GET /orders/{id}` returns `owner_password_hash` and `owner_totp_secret`; `vuln-0053` correctly reports the length-extension forgery that leaks the same columns to an unauthenticated caller. Both write-ups then take the wrong next step:

- `chain-0003` (`.../chain-0003-description-unauthenticated-account-2fa-takeover-...md`), step 2:
  > "**The leaked bcrypt hash is cracked offline** to recover the password factor and the leaked TOTP seed generates a valid RFC-6238 code for the 2FA factor"

  and in its detail section:
  > "The leaked bcrypt hash is cracked offline (weak/reused password; **the app seeds `password123`**) to recover the first login factor."

- `chain-0004` (`.../chain-0004-description-horizontal-to-vertical-account-takeover-...md`), step 2:
  > "**vuln-0029** — Weak/default credentials (`'password123'` on seed accounts incl. `admin@example.com`) turn the leaked bcrypt hash into a usable plaintext password via an **instant offline crack**, defeating bcrypt's work factor."

  and in the attack flow:
  > `bcrypt.checkpw("password123", leaked_hash) → True   (attacker hardware, no throttle)`

A full-text search of the entire bundle for `pass-the-hash`, `authenticateDirect`, or any description of a hash being replayed verbatim as a password returns **nothing**. The mechanism was never found.

### Why it's a problem

The two write-ups had the leaked hash in hand and reached for a dictionary instead of trying it as-is. That's a reasonable instinct on a real target — but here it substituted an *environmental* weakness (the container's seeded fixture password) for a *code* defect, and in doing so:

- **The real bug went unreported.** TP-036 is a one-line authentication bypass in `User.php`. It is the highest-leverage fix in the app, and the report never names it.
- **The demonstrated route doesn't survive deployment.** `password123` is a seed fixture created on container restart. Change the seed data and `chain-0003`/`chain-0004` stop working. TP-036 keeps working forever. A customer reading `chain-0004` would fix their weak passwords and remain fully exploitable.
- **Severity was justified with the wrong evidence.** `chain-0003` is rated CVSS 9.8, with likelihood argued as "the easiest complete route (a weak/reused-password account, e.g. the seeded `password123`) is demonstrably exploitable via unlimited offline cracking." The 9.8 is correct; the justification rests on fixture data. (`chain-0004` is fair here — it notes its own step 3 is redundant because step 1 also leaks the TOTP seed.)

### Consequence

TP-036 was scored a miss. Because it is the terminal member of four chains, that one miss took the chains with it:

| Registered chain | Members | COS result |
|---|---|---|
| CHAIN-001 SQLi → Pass-the-Hash | TP-001 ✅, TP-036 ❌ | **not credited — one step short** |
| CHAIN-008 BOLA → BOPLA → Pass-the-Hash | TP-017 ✅, TP-024 ✅, TP-036 ❌ | **not credited — one step short** |
| CHAIN-010 Length-Ext → BOPLA → Pass-the-Hash | TP-053 ✅, TP-024 ✅, TP-036 ❌ | **not credited — one step short** |
| CHAIN-009 Role Mass-Assign → BOPLA → Pass-the-Hash | TP-049 ❌, TP-051 ❌, TP-036 ❌ | not credited |

Three of those four were complete except for TP-036. At 27 weighted points per chain plus 3 for the vuln itself, **84 of the scan's 911 available weighted points (9.2%) trace back to this one mechanism** — and `chain-0003` and `chain-0004` are, structurally, COS's own attempts at CHAIN-010 and CHAIN-008. They got steps 1 and 2 right and stopped one inference short.

### Suggested fix

When a finding discloses authentication material (`password_hash`, `totp_secret`, a session token, an API key), add an explicit verification step that **replays the material as-is against the authentication endpoint before attempting to crack, decode, or brute-force it**. It is one request, it is the cheapest possible test, and a pass is a critical finding in its own right. Framed as a rule: *before assuming a credential must be recovered, test whether it is accepted directly.*

Relatedly — treat obviously-seeded credentials (`password123`, `admin@example.com`, anything the app's own seed script writes) as **environment, not as an exploitation primitive**. If a route's feasibility depends on one, either find a route that doesn't, or state plainly that the step is environment-dependent and would not transfer to a production deployment. That distinction changes what a customer does on Monday morning.

---

## Issue 2 — Three "individual" findings are actually multi-bug chains

**Impact: high.** Structural, easy to fix, and it directly inverts your chained-tier score.

### What the report did

Three files in `vulnerabilities/` are complete multi-bug chains. Each carries a single top-level `**CWE:**` field naming only one of its components, and none appears in `vulnerability_chains/`:

**`vuln-0032`** — title: *"CSRF on POST /api/contact/preview chained with reflected XSS to exfiltrate JWT from localStorage (one-click account takeover)"*. CVSS 9.3, `**CWE:** CWE-352`. Its own ROOT CAUSES block lists four:
> ```
> ROOT CAUSES
>   A. CWE-352 — /api/contact/preview has no CSRF defence
>   B. CWE-79  — same endpoint reflects POST fields into HTML unescaped
>   C. CWE-922 — SPA stores the JWT in localStorage on the same origin
>   D. CWE-693 — no CSP / XFO / nosniff / HSTS / Referrer-Policy
> ```

**`vuln-0046`** — title: *"Stored XSS in Navbar via Mass-Assignment IDOR on PUT /auth/profile — Zero-Click Account Takeover on Every SPA Page"*, `**CWE:** CWE-79`. The body is explicit that it is two bugs:
> "**Primitive 1** — Cross-user write (CWE-639) on `PUT .../auth/profile` … **Primitive 2** — Unsanitised rendering (CWE-79) in the Navbar."

**`vuln-0045`** — title: *"Stored XSS in Order Shipping Name Delivered Cross-User via IDOR on /orders/{id}"*, `**CWE:** CWE-79`. Root cause:
> "the frontend treats a user-controlled string as trusted HTML, and the backend fails both to sanitize on write **and** to enforce object-level authorization on read."

### Why it's a problem

The bundle already has the right structure for this. `vulnerability_chains.csv` has a `constituent_vulns` column; the four files in `vulnerability_chains/` have a `## Chain Steps` section with per-step vuln references. That schema exists and is well designed — these three findings simply didn't use it. The result is that the classification is title-shaped rather than data-shaped: you can only tell `vuln-0032` is a chain by reading the title and prose, and the one machine-readable CWE field actively misleads (`vuln-0046` and `vuln-0045` both declare CWE-79, hiding the CWE-639 authorization bug that is arguably the more serious half).

There is also a routing inconsistency worth noting: `vuln-0032`'s CSRF and localStorage components have no standalone findings anywhere in the bundle. They exist only inside the chain-shaped file. So the same underlying bug is sometimes a member with its own finding and sometimes not, with no rule distinguishing the cases.

### Consequence

All three had to be **manually decomposed** during our review. We split them into their components so the component bugs could be credited — `vuln-0032` into a CSRF finding and a localStorage-JWT finding (both then credited to registered chain CHAIN-012), `vuln-0046` and `vuln-0045` into their IDOR and XSS halves. That is 3 findings turned into 6 by hand.

For a customer the cost is different and worse: **a four-root-cause finding is a four-team ticket.** `vuln-0032`'s components belong to the API team (CSRF middleware), the templating layer (output encoding), the frontend team (token storage), and platform (response headers). Filed as one finding it cannot be assigned, cannot be partially closed, and cannot be tracked — and its single CWE-352 tag routes the whole thing to whoever owns CSRF.

### Suggested fix

Make the standalone-vs-chain decision a structural check rather than a titling choice: **if a finding's root-cause list has more than one entry, or its title contains "chained with" / "→" / "via", it is a chain.** Emit it into `vulnerability_chains/` with a populated `constituent_vulns`, and emit each component as its own standalone finding with its own CWE and severity. Chains reference components by id; components are independently assignable and closeable. Your existing chain schema supports all of this already.

---

## Issue 3 — The hardcoded JWT signing secret never got a finding of its own

**Impact: high.** The most urgent remediation action in the app is absent from the findings table.

### What the report did

The secret's literal value appears verbatim in **three** findings, each time as supporting evidence for a different disclosure mechanism:

- `vuln-0007` (unauthenticated path traversal), line 18:
  > "The most damaging single disclosure is `api/config/jwt.php`, which contains the **hard-coded HS256 signing secret `pTg7Kz9mQxR4vL2wN8jF5dY1hA6cB3eS0uI`**."
- `vuln-0011` (SSRF), line 128:
  > "Application secret disclosure. The application's **hard-coded HS256 JWT signing secret** was read out of `/var/www/backend/api/config/jwt.php`."
- `vuln-0015` (public directory listing), line 125:
  > "**Hardcoded secret in source.** `api/config/jwt.php` defines `private static $secret = 'pTg7Kz9mQxR4vL2wN8jF5dY1hA6cB3eS0uI';` Because (1) leaks that file, **the production signing key is now public.**"

A **fourth** finding uses it: `vuln-0001` HMAC-signs a forged `is_admin: true` token with that real secret and confirms exploitation —
> "Submitting it to `/admin/orders` and `/admin/orders/44` → HTTP 200 with the full admin order listing"

But no file in `vulnerabilities/` has the secret as its subject. Search the 57 findings for one titled after a hardcoded signing key and there isn't one. (`vuln-0015`'s own words — "the production signing key is now public" — are the clearest statement of the problem anywhere in the bundle, and they appear as a consequence bullet inside a finding about directory indexing.)

There is a second, related oddity in `vuln-0001`. It is **titled** *"JWT `exp` Claim Not Required — Tokens Without Expiration Are Accepted Indefinitely"* and **rated critical**. The `exp` issue alone is not critical — it is a token-lifetime hygiene bug. What makes that finding critical is the admin-token forgery in its PoC, which is a *different* bug, and which has no finding of its own either. Title, severity, and evidence are describing three different things.

### Why it's a problem

Remediation and disclosure are different actions with different urgency. Fixing the path traversal, the SSRF, and the directory listing closes the three doors — and leaves an already-exfiltrated signing key in production, minting valid admin tokens for anyone who read the source at any point. **Key rotation is the only action that undoes the damage, and no finding asks for it.** Whoever works this report from the findings table down will never see that task.

The same reasoning applies to what `vuln-0001` actually demonstrates: a validly-signed forged admin token survives fixing every JWT *verification* bug in the app, because nothing is being bypassed — the signature is genuine. That is the property that makes it critical, and it is documented only as PoC scaffolding inside a finding about `exp`.

### Consequence

Our catalog has `CODE-001` (Hardcoded JWT Signing Secret) and `CHAIN-011` (Directory Listing → Hardcoded Secret → Admin Token Forgery) as separate entries. Both had to be credited by hand: `CODE-001` off `vuln-0015`'s quoted value, `CHAIN-011` off `vuln-0001`'s forged-token PoC. Neither would have been credited by any title- or CWE-based matching. (Part of why this was painful was a limitation on our side — see the next section.)

### Suggested fix

**Treat a disclosed secret as a finding, not as evidence.** When a PoC recovers a credential, key, or token-signing secret, emit a standalone finding whose subject is the secret — with the remediation action being *rotate*, and the access paths listed as references. One secret, one finding, however many doors led to it. That finding is what tells the customer the key is burned.

Separately: **a finding's title and severity should describe the same bug.** If the PoC for finding X demonstrates bug Y, and Y is what drives the severity, Y needs its own finding. A title check against the assigned severity would have caught `vuln-0001`.

---

## Issue 4 — `chain-0002` is not a chain, by its own admission

**Impact: medium.** Costs precision and inflates the chain count.

### What the report did

`chain-0002` — *"Financial-Fraud Chain: Forged Store Credit + Client-Controlled Price + Client-Controlled Discount → Free Merchandise & Unbounded Money Minting"*, CVSS 6.5 but severity `CRITICAL` — presents three steps: `vuln-0051` (gift-card CBC bit-flip), `vuln-0054` (client-controlled cart price), `vuln-0039` (client-controlled `discount_percent`). Its own analysis section then states:

> "Server code (`Order::create`) computes `orders.total` as cart-total → apply `discount_percent` → subtract store credit. All three attacker inputs feed the same sink. **Each alone drives the total to zero**; combined they guarantee free merchandise…"

### Why it's a problem

A chain is a composition where the outcome is unreachable by any single member. Here the write-up explicitly says each member reaches the outcome alone — so this is three independent findings hitting one sink, which is a useful observation about `Order::create` but not a chain. All three members were also already reported as standalone findings in the same bundle and all three were credited individually (TP-054, TP-019, TP-021).

The severity field compounds it: `CRITICAL` against a CVSS of **6.5** is the only internal severity/CVSS contradiction in the bundle, and 6.5 is roughly what "three ways to zero the same total" deserves.

### Consequence

Marked false positive — the fourth of five FPs, and directly responsible for part of the 90% precision ceiling. Because the three members were already credited standalone, the write-up added no score and cost precision.

### Suggested fix

Add an **independence test** before emitting a chain: for each member, ask whether removing it still reaches the stated outcome. If the answer is yes for every member, it isn't a chain — it is either N standalone findings (which you already have) or, better, one finding about the shared sink: *"`Order::create` derives `orders.total` from three independently client-controlled inputs with no server-side re-derivation."* That framing is genuinely valuable and is what the analysis section is actually arguing.

And make severity derive from CVSS, or flag the disagreement when it doesn't.

---

## Issue 5 — Two chains list the same finding twice as two different steps

**Impact: medium.** A data-integrity bug, and it hides missing findings.

### What the report did

From `vulnerability_chains.csv`, verbatim:

| id | `constituent_vulns` |
|---|---|
| chain-0001 | `vuln-0050 + vuln-0050` |
| chain-0002 | `vuln-0051 + vuln-0054 + vuln-0039` |
| chain-0003 | `vuln-0053 + vuln-0053` |
| chain-0004 | `vuln-0030 + vuln-0029 + vuln-0035` |

Two of four chains cite a single vuln as both of their steps. This is not a prose slip — it is the machine-readable column, and the prose matches it. `chain-0001`'s `## Chain Steps`:

> 1. **vuln-0050** — Unauthenticated `GET /password-reset-log` leaks the victim's `user_id` and `requested_at` …
> 2. **vuln-0050** — The reset token is an unkeyed `sha256(user_id:requested_at)`; the values leaked in step 1 are hashed to forge the exact expected token …

Same shape in `chain-0003`: step 1 is the length-extension forgery and disclosure, step 2 is the offline crack — both attributed to `vuln-0053`.

### Why it's a problem

In both cases step 2 is a real, distinct bug that has no standalone finding. `chain-0001` step 2 is a **predictable unkeyed reset token** — our TP-043, and the write-up describes its derivation precisely (`hash('sha256', $user['id'].':'.$issuedAt)`, "no server-side secret and no random component") — but it exists only as a chain step, so there is nothing to file, assign, or close. TP-043 was scored a miss despite being fully and correctly analysed inside `chain-0001`.

So the duplicate id is a symptom: a chain step was identified without a corresponding standalone finding being emitted, and the generator filled the reference with the nearest available id rather than failing.

### Consequence

`chain-0001` was credited (it demonstrates CHAIN-005 end-to-end, so the chain scored). But its step-2 bug, TP-043, counts as a miss — a vuln the scan found, analysed correctly, and got no credit for because it never became a finding.

### Suggested fix

Two things:

1. **Validate `constituent_vulns` at emit time:** every id must be distinct and must resolve to a standalone finding in the same bundle. If a step has no finding, emit the finding — don't reuse a sibling's id.
2. That check would have surfaced TP-043 as a standalone finding for free. Generally: **every chain step deserves its own finding**, even when it is only interesting as part of the chain. A predictable password-reset token is worth a ticket on its own.

---

## Issue 6 — Three duplicate finding pairs, one with contradictory severities

**Impact: medium.** Triage noise, and a symptom worth chasing.

### What the report did

Three pairs of findings in `vulnerabilities/` describe the same bug at the same endpoint:

| Pair | Findings | Severities |
|---|---|---|
| PHP object injection, `POST /cart/restore` | `vuln-0047` *"PHP Object Injection (Insecure Deserialization) in POST /cart/restore Leading to…"* / `vuln-0049` *"PHP Object Injection via unserialize() in POST /cart/restore Yielding Arbitrary File Write"* | critical / critical (both CVSS 8.8, CWE-502) |
| PHP fatal-error stack trace via type confusion | `vuln-0008` *"…via TOTP Type Confusion at POST /auth/login"* / `vuln-0028` *"…via JSON Type Confusion"* | medium / medium |
| Reflected XSS, `/api/contact/preview` | `vuln-0037` *"Reflected HTML Injection with Base-Tag Hijack on POST /api/contact/preview"* / `vuln-0052` *"Unauthenticated Reflected XSS in POST /contact/preview (name, email, subject, message)"* | **critical / medium** |

`vuln-0047` and `vuln-0049` are the cleanest case: same endpoint, same CWE, same CVSS, same severity, same impact chain (object injection → arbitrary file write → RCE), two files.

### Why it's a problem

5% of the report is redundant, which is survivable. The severity split on the third pair is not: the **same reflected-XSS bug on the same endpoint is filed once as `critical` and once as `medium`**. Whichever a customer's triage queue sorts on determines whether this gets paged or backlogged, and the report gives both answers. (For reference, our catalog rates it medium — so the `medium` copy is the accurate one and the `critical` copy is the one that would drive behaviour.)

The pattern across all three pairs — same bug, different discovery route, different framing, occasionally different severity — reads like output from independent analysis passes that were merged without a reconciliation step. If that's the architecture, the dedupe/merge stage is the thing to add, and it would also fix the severity inconsistency for free.

### Consequence

Low scoring impact: duplicates that both match a known vuln cost nothing under our model (credit is per distinct vuln, so two findings on one vuln score once, and neither is a false positive). The cost lands on whoever reads the report — three redundant tickets and one unresolvable severity question.

### Suggested fix

A **merge pass keyed on (endpoint, CWE, sink)** before emit. When candidates collide, produce one finding that keeps the best PoC from each and takes the **max** severity, with a note on the alternate exploitation route. The base-tag-hijack variant in `vuln-0037` is a genuinely better PoC than `vuln-0052`'s — it deserves to survive as the PoC of a single merged finding rather than as a second finding with a contradictory severity.

---

## Issue 7 — Severity calibration: SQLi rated down, XSS rated up

**Impact: low-medium.** Consistent and directional, so it should be correctable.

### What the report did

Across the 45 credited vulns, COS severity matches our catalog on **22 (48.9%)**. Restricting to the 40 bundle findings with a primary match: 18 agree, **13 rate above** our catalog, **9 rate below**. The disagreements are not noise — they cluster by vulnerability class:

**Every SQL injection rated below catalog:**
| Finding | COS | Catalog |
|---|---|---|
| `vuln-0009` SQLi in `GET /orders` `status` — cross-tenant disclosure | medium | **critical** |
| `vuln-0006` UNION SQLi, `GET /wines/{id}/reviews` | high | critical |
| `vuln-0036` UNION SQLi, `GET /wines/{id}` | high | critical |
| `vuln-0044` UNION SQLi, `GET /wines` search | high | critical |

**Every reflected/stored-XSS finding rated above catalog:**
| Finding | COS | Catalog |
|---|---|---|
| `vuln-0042` Reflected DOM XSS on `/login` | **critical** | medium |
| `vuln-0037` Reflected HTML injection + base-tag hijack | **critical** | medium |
| `vuln-0033` Reflected XSS on `/wines` search | high | medium |

Also rated above catalog: JWT verification bugs (`vuln-0004`, `vuln-0013`), crypto-forgery bugs (`vuln-0051`, `vuln-0053`), SSRF (`vuln-0011`), deserialization (`vuln-0047`), directory listing (`vuln-0015`) — all +1. Rated below: credential disclosure (`vuln-0030` high vs critical) and business-logic authorization (`vuln-0035`, `vuln-0039` medium vs high).

### Why it's a problem

`vuln-0009` is the clearest miss: SQL injection that reads other tenants' orders, rated `medium`. Some of the spread is legitimate methodology difference — our catalog weighs unauthenticated reachability and data-scope heavily, and rates client-side injection lower than server-side. But the *direction* being perfectly consistent within each class (4/4 SQLi low, 3/3 XSS high) suggests a systematic rather than a case-by-case judgment.

The broader pattern: **server-side data-access bugs get rated down and client-side injection bugs get rated up.** Combined with Issue 1 — where a real authentication bypass was missed while a fixture password was treated as the exploitation route — it reads as a consistent under-weighting of direct server-side data and auth access relative to client-side delivery.

### Consequence

No direct scoring cost — severity accuracy is reported separately (48.9%) and doesn't feed recall, precision, or the weighted score. The cost is ordering: a customer sorting by severity works the XSS findings before the cross-tenant SQL injection.

### Suggested fix

Two calibration anchors would move most of this:
- **SQL injection that crosses a tenant or user boundary is critical**, independent of exploitation difficulty — the blast radius is the whole table.
- **Reflected XSS is medium by default**, and escalates on a demonstrated concrete impact (a stolen session token, an actioned state change) rather than on the availability of a sink.

Worth also reviewing the +1 drift on CVSS-anchored classes (JWT, crypto, SSRF, deserialization) — nine findings sit one band above our rating there, which looks like a rounding-up convention more than a disagreement.

---

## Problems on our side, not COS's

Included for fairness and because two of these shaped the numbers above. **None of these are COS issues.**

### Ours (importer / scoring model)

**Our finding→vuln mapping only had one slot, so a correct COS finding scored as a miss.** Until this week our schema stored a single `matched_vuln_id` per finding. `vuln-0015` (the `/files/` directory listing) legitimately demonstrates *two* catalog vulns: TP-013 (the directory listing) and CODE-001 (the hardcoded secret, whose value it quotes). We could credit only one. We hand-fixed scan 330 by re-pointing that finding at CODE-001 — safe only because another finding independently covered TP-013 — and have since shipped a `finding_matches` join table plus an `additional_vuln_db_ids` field in the importer so one finding can credit every vuln it demonstrates. **Any apparent "COS missed CODE-001" signal was our bug, not yours.** It is worth noting that this limitation was only exposed because COS's finding was *more* comprehensive than our data model assumed.

**Our chain model credits only registered compositions, which is why two of your chain write-ups are false positives.** `chain-0003` and `chain-0004` are real, working, end-to-end takeover routes. We marked both FP because their member sets don't match any of our 12 registered chains — `chain-0004` (order leak → crack → 2FA-disable IDOR) is close to CHAIN-008 but ends differently, and `chain-0003` is close to CHAIN-010 with the same substitution. A scanner that finds a genuine composition we haven't catalogued gets penalised. We have this on our backlog. The COS-side part of those two findings is Issue 1 (the cracking substitution and the missed TP-036), not the fact that they were marked FP.

**Our scan record diverges from your bundle because we edited it.** Scan 330 now holds 70 findings against the bundle's 61 items. That is entirely our doing: we decomposed the three chain-shaped findings from Issue 2 into their components and split a few multi-bug findings so component vulns could be credited. If you diff the bundle against our scan record, the 13 extra findings and 4 missing ones are our edits. Anything in this document attributed to COS was verified against `/tmp/report-output` — the original bundle — not against our edited scan.

### Ours (ground-truth catalog)

**One of our own catalog entries had a chain-shaped title.** `TP-028` was titled *"SQLi → TOTP Secret Extraction → 2FA Bypass → Account Takeover"* — a chain title on a single-vuln entry, which is exactly the Issue 2 problem in our own data. We retitled it today to describe the single defect it actually covers (a TOTP secret stored alongside the credentials it protects). This is worth stating because it is the mirror image of `vuln-0032`: both of us made the same classification mistake, and ours was in the ground truth.

---

## Appendix A — Findings marked false positive (5)

These count against precision. One FP group each, no grouping.

| # | Finding | Why |
|---|---|---|
| 4718 | Missing email-ownership verification on `/auth/register` and `PUT /auth/email` | The described behaviour — an email address becoming re-registrable after its owner changes it — is normal application behaviour, not a defect. The write-up's severity case rests on speculative downstream conditions. |
| 4742 | Missing order lifecycle state machine on `PUT /admin/orders/{id}/status` | Any-to-any admin status transitions are a legitimate feature. An admin who marks the wrong order delivered needs to revert it. |
| 4780 | `chain-0002` — financial-fraud chain | Not a chain; see **Issue 4**. All three members already reported and credited standalone. |
| 4781 | `chain-0004` — horizontal-to-vertical takeover | Real working route, but the composition isn't a registered chain and step 2 depends on cracking a seeded password. See **Issue 1** and the "ours" note above. |
| 4782 | `chain-0003` — unauthenticated account + 2FA takeover | Same shape as 4781. |

## Appendix B — Findings marked ignored (7)

*Ignored* means excluded from scoring entirely — no credit, **no penalty**. These are legitimate observations that fall outside what this corpus scores, mostly because the catalog has no counterpart mechanism or because the subject is the test harness rather than the application.

| # | Finding | Note |
|---|---|---|
| 4720 | Email-change endpoint drops `is_admin` from the reissued JWT | A privilege *downgrade* — the inverse of every escalation vuln in the catalog. Real code inconsistency, not a security defect. |
| 4728 | Public `/vulns` redirect discloses maintainer console behind unhardened HTTP Basic | Benchmark platform infrastructure, not the target application. |
| 4730 | Missing `Cache-Control` on authenticated API responses | Distinct from our security-headers entry (TP-016, which covers HSTS/XCTO/XFO). Valid hygiene finding, no catalog counterpart. |
| 4739 | Verbose server/framework version disclosure | No banner-disclosure entry in the catalog. |
| 4749 | Per-line cart quantity cap bypassed via `PUT /cart/update` | Missing upper-bound validation; distinct from our price (TP-019) and discount (TP-021) entries. Reasonable finding, no counterpart. |
| 4751 | Default/weak credentials on pre-seeded accounts (`password123`) | Seed fixture written by the container's setup script — environment, not application code. Relevant to **Issue 1**: this is the credential two chain write-ups built their exploitation route on. |
| 4770 | Hardcoded partner API credentials in `PartnerController.php` | Distinct mechanism from CODE-001 and TP-045; not a live credential path in the deployed app. |

Both appendices are worth a second look from your side: seven ignored findings means seven pieces of real analysis work that produced no score in either direction. Several (4730, 4749, 4739) are findings a customer would want. The ignore was our catalog's scope, not a judgment on the finding.

---

## In short

The detection work here is strong, and the hardest individual findings in the bundle — length-extension MAC forgery, keyless CBC bit-flipping, unkeyed reset-token derivation — are better than we expected. Almost all of the lost score is downstream of two things: **how findings get classified and structured** (Issues 2, 3, 4, 5 — a chain in the wrong directory, a secret that never became a finding, a non-chain filed as a chain, chain steps with no findings behind them), and **one missed inference** (Issue 1 — replaying a leaked hash as a password rather than cracking it).

The structural items are the cheap wins. A multi-root-cause finding routed to `vulnerability_chains/`, a disclosed secret promoted to its own finding, a distinctness check on `constituent_vulns`, an independence test before emitting a chain, and a dedupe pass before emit — none of those require finding anything new. They would have turned several already-correct pieces of analysis in this scan into credited, assignable, closeable findings.

Happy to walk through any of this, re-run against the corpus after changes, or share the raw scan record and adjudication decisions.
