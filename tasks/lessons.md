# Lessons

## Make chart variation controls searchable and keep grouping names readable

Do not expose every label as a checkbox wall or build point names from repeated
negative labels. Reuse the searchable multi-select with removable chips. Show
matched variation names and one “Other variations” group for unselected labels.

## NEVER broad-kill the user's applications
**Mistake:** Ran `pkill -f "Google Chrome"` to clean up headless renders. This
killed the user's real Chrome — 100+ open tabs lost, history wiped (no restore
prompt). Unacceptable, irreversible damage.

**Rule:** Never use `pkill`/`killall` with a pattern that can match a user-facing
app. For a headless browser, always launch with a dedicated
`--user-data-dir=<scratch>`, capture the launched PID (`$!`), and kill only that
exact PID — never a process I didn't start.

## Verify the actual failing environment before diagnosing
**Mistake:** Diagnosed a prod "blank page" as a memory bomb, then as browser
cache-skew — both wrong — without first reproducing against the exact prod state
(which DB the container actually loaded + Cloudflare + a fresh browser).

**Rule:** Reproduce the real symptom end-to-end first. For a blank SPA: verify
server-side state (the DB the running container opened) AND capture the real
browser console/network against prod in an isolated profile, before theorizing.

## Verify field constraints from the code, never assume from a UI widget type

**Mistake:** Claimed `scan.scan_date` was "date-only granularity" because the
inline editor uses `<input type="date">`. Wrong — `scan_date` is stored as free
TEXT and rendered verbatim, so it fully supports an optional `HH:MM` time
(e.g. `2026-05-19 07:01`), and `parse_scan_start` already accepts
`YYYY-MM-DD HH:MM`. I even wrote an importer prompt forcing `YYYY-MM-DD`, which
would have discarded start times from reports.

**Rule:** Before stating what a field can/can't hold, check the storage layer
(schema/migration + how it's read/written), not just one input widget. A
`type="date"` editor is a *widget limitation*, not a *data constraint* — say so
precisely and don't generalize it to the whole field.

## Always validate finding/chain counts after a scan import or catalog change

**Mistake:** Trusted that a scan import produced one vulnapps finding per
report source item without ever counting. Scan 330 (TaintedPort, app 305)
turned out to have 70 findings on vulnapps against only 61 distinct source
items in the report (57 `vulnerabilities/` files + 4 `vulnerability_chains/`
files). Root cause: the importer's per-file LLM extraction doesn't reliably
clamp to one finding per source file — when a file bundles multiple root
causes (e.g. a CSRF+XSS+localStorage-theft+account-takeover chain) or
mentions a sub-detail in passing (e.g. a `setup_db.php` aside inside a
directory-listing finding), it sometimes peels those off as separate DB
findings. All 9 excess findings traced back to real report content (no
fabrications) and 6 of the 9 were already correctly matched to the right
vuln, so the practical damage here was low — but it was only luck, and it
went undetected until explicitly counted.

**Rule:** After importing a scan, count distinct source items in the report
(one per file under `vulnerabilities/` + `vulnerability_chains/`, cross-checked
against the report's own `vulnerabilities.csv`/`vulnerability_chains.csv` row
counts or `penetration_test_report.json`'s array lengths) and compare against
the finding count on vulnapps. Same discipline after any catalog edit: the
count of vuln/chain entries in `KnownVulnerabilities.txt` should reconcile
with the count of `TP-*`/`CODE-*`/`PRBL*` vulns and `CHAIN-*` chains
registered for that app on vulnapps. A mismatch doesn't necessarily mean
something's wrong (could be a harmless duplicate match), but it must be
explained, not assumed away. (Also added to CLAUDE.md as a standing rule.)

## The vulnapps API authenticates with `Authorization: Bearer`, not `X-API-Key`

**Mistake:** Verifying migration 040 on prod, queried
`https://vulnapps.net/api/scans` with an `X-API-Key` header. The API ignored
it and served the *anonymous* view: scan 330 came back `{"detail": "Scan not
found"}` and the scan list held 2 rows instead of the real set. That is
exactly what a wiped database looks like, moments after a deploy that ran a
destructive migration (two `DROP COLUMN`s). Almost reported data loss to the
user. Re-running with `Authorization: Bearer` returned all three scans intact
with unchanged metrics.

**Why it's dangerous:** `get_scan` deliberately collapses "not authorized"
into "not found" so private scans can't be enumerated (`app/services/scans.py`,
the vuln-0005/vuln-0008 fix). So a bad credential is indistinguishable from a
missing row by design — silence and 404 are the *intended* response, not a
signal.

**Rule:** Use `Authorization: Bearer $VULNAPPS_API_KEY` (the importer's own
header, `tools/import_scan.py`). Before concluding that prod data is missing,
prove the request was authenticated — query a row that is definitely visible,
or check that the response isn't the public-only subset. Never report data
loss on the strength of a 404 alone.

## Scan discovery separates filtering from aggregation
For scan labels, support combining multiple labels with explicit all/any matching.
When asked for group by, show aggregate metrics first with optional drill-down;
sectioning the original scan list alone does not meet the aggregation use case.

For this scan-filter work, keep verification focused on desktop; responsive redesign is out of scope.

Grouped scan metrics need statistical summaries (mean, standard deviation, range, sample count), not only averages or collapsible lists. Keep grouping optional.

## Verify a permission boundary by exercising it, not by reading the check

**Mistake:** Shipped an admin-only endpoint by copying the surrounding
convention (`_require_admin`) and called it done. Probing the deployed route
with a deliberately *narrow* API key returned 200 where 403 was expected: every
route in the admin router checked `user["role"] == "admin"` and never consulted
`api_key_scope`, so a `read` or `vuln-mapper` key minted by an admin reached all
of them, user management included. The scope was a label, not a limit. Matching
the local convention reproduced the convention's bug.

**Rule:** When adding an endpoint behind an authorization check, test it with a
credential that *should* be refused, not only one that should pass. For this
codebase the axes are independent — `role` (who) and `api_key_scope` (what this
credential may do) — so a role check alone never constrains a key. Ask "which
credential would I expect to bounce here?" and send it.

## A test module that configures the app at import time is ordering-dependent

**Mistake:** Adding `tests/test_admin_scope.py` broke `tests/test_api_endpoints.py`
at collection with "unable to open database file". Nothing was wrong with either
file. `app/config.py` reads DATABASE_PATH once, at import, after `load_dotenv()`;
test_api_endpoints set that env var at module scope before importing the app, and
that only worked because it sorted first alphabetically. A new file starting with
"adm" imported `app.*` earlier, so `.env`'s DATABASE_PATH won instead.

**Rule:** Process-wide setup that must happen before the app is imported belongs
in `tests/conftest.py`, which pytest loads before any test module — never at the
top of a test file, where correctness depends on filename sort order. When a
seemingly unrelated new test file breaks an existing one, suspect import order
before suspecting the new test, and fix the ordering dependency rather than
renaming the file to dodge it.

## "Don't rely on the published credentials" is narrow — don't widen it

**Mistake:** The user said no chain may rely on the TaintedPort test credentials,
which are printed on the login page on purpose. I stretched that into "no chain
may involve a weak password", and argued for two rounds that the COS takeover
chains were not chains because each one cracks a leaked bcrypt hash. Those are
different things: reading a password off the login page is using information
the app hands out deliberately; cracking a hash the chain itself leaked is real
attacker work on stolen data. The user had to spell it out.

**Rule:** When the user states a constraint, apply it at the scope they stated
it, and if a case is near the edge, ask which side it falls on instead of
deciding and arguing. Here the test is *where the attacker got the secret*: off
the published login page = excluded; out of data the chain leaked = fine (its
difficulty informs severity, e.g. a length-only password policy makes a crack
likely). The same wrong reasoning was already written into the catalog (the
"Deliberately not a chain: #28" note) — after correcting a principle, grep for
the places it was already applied.

## Gate a commit on the test command's own exit status

**Mistake:** Ran `pytest ... | tail -1 && git commit && git push`. The pipeline's
exit status is `tail`'s, which always succeeds, so a failing test was committed
and pushed to main (and deployed). Caught only because I read the output line.

**Rule:** Never put a pipe between a verification command and `&&`. Capture the
status first — `pytest > log; rc=$?; tail log; [ $rc -eq 0 ] && git commit ...` —
or use `set -o pipefail`. Applies to any check that gates a commit, push or deploy.

## Check the stored data before predicting an edit's effect

**Mistake:** Told the user adding TP-013/CODE-001/TP-023/CHAIN-011 to a scan-330 finding
would not change the score, "each already credited elsewhere". TP-023 was not — I had
taken that from a dry run of the importer, which was never submitted. The score moved
46 -> 47 after the user had agreed on the basis of "no change".

**Rule:** Before stating the effect of a re-credit ("no score change", "TP 30 -> 29"),
query the stored scan for every vuln involved and check which other findings credit it.
A dry run, an audit file, or an earlier session's numbers are not the stored state. If
the check wasn't done, say the effect is unverified instead of asserting it.

**Recurrence (2026-11-05):** Told the user the app 329 sink seed changed no score because
"329 has no scans yet" — remembered from an earlier session, not checked. It had a COS scan,
so the seed re-scored it and opened 16 revisions. Before any ground-truth write, query the
app's scans (`/api/scans?app_id=`) and say up front how many revisions it will open.

## Rebase dependent scan UI changes before integration
When updating a PR that touches the same scan table as a newly merged change, fetch
main and rebase first. Preserve the approved individual layout while integrating
scoring changes in their requested views.


## Scan types and scanner variations are independent

Scan type is recorded metadata or an unambiguous recognized assessment label. Do not infer it
from a scanner name, model or source access. RIFT is whitebox only; the chart must still support
scanners that have multiple recorded types, and preserve unknown or conflicting metadata.

A scanner can vary by harness, model and other settings. Use existing labels for those variations
and let users choose which labels split grouped points. Do not hardcode model parsing or group
by every label automatically. Scanner/type averages blend unselected variations and must say so.

## Timestamp is a default, not a restriction on ordering
When paginating a sortable table, preserve every existing order in both directions.
Apply ordering globally before paging, use deterministic ties and explicit missing-value
rules, and test non-default orders across page boundaries. Use native header buttons
and aria-sort so keyboard and screen-reader users can operate and identify the sort.
## Don't add a metric an existing one already measures

**Mistake:** Proposed a separate "decoys hit / decoys planted" metric (column, panel,
compare row) for the known-FP corpus. Decoy hits are false positives, so FP count and
precision already score them; the user rejected it as redundant.

**Rule:** Before proposing a new metric, column or score, name which existing metric
the same events already feed. If they already move FP/precision/recall/weighted
detection, improve the *inputs* (consistent grouping, penalties) instead of adding a
parallel number.

## Limit PR actions to the requested authors

When the user scopes PR work to their own PRs, only update those branches. Do not attempt to merge another author's PR as adjacent cleanup.

## New tools that call HTTPS must use the OS trust store

**Mistake:** Wrote tools/seed_chain_sinks.py with a plain httpx client. Zscaler (always on)
re-signs TLS with a root only the macOS Keychain trusts, so it failed with
CERTIFICATE_VERIFY_FAILED; I then worked around it with an exported cert bundle instead of
using the pattern tools/import_scan.py already had.

**Rule:** Any script that makes HTTPS calls starts with `import truststore;
truststore.inject_into_ssl()` before importing httpx, as import_scan.py does. Check the
existing tools for the pattern before writing a new client.

## Run the CI test command, not just the local one

**Mistake:** Added an API test that passed locally (tests copy the real vulnapps.db) but failed in
CI, which runs `pytest --ignore=tests/test_api_endpoints.py` against an empty DATABASE_PATH. The
deploy failed with "no such table: users".

**Rule:** Before pushing a new test, also run it CI's way:
`DATABASE_PATH=$(mktemp -d)/ci.db .venv/bin/python -m pytest -q --ignore=tests/test_api_endpoints.py`.
Tests that need the app over HTTP must not depend on rows in the real database.

## Never give the benchmarked scanner the answer key

**Mistake:** A cyberAgent development session asked how vulnapps models chains. I answered
with real TaintedPort chains as examples and pointed it at tests/test_chain_sinks.py and
AppBuilder.md, which list the full chain answer key. The session itself refused to read
KnownVulnerabilities.txt "(answer key)"; I had to send a retraction.

**Rule:** Scanner-development sessions get methodology only. Before sending, strip every
catalog id, endpoint, decoy and concrete chain; use invented examples. Don't point them at
TaintedPort-Vulns, test fixtures or tools that seed TaintedPort data, or the TaintedPort
examples in AppBuilder.md. Generic code is fine to reference.

## A worse bug elsewhere doesn't make a real finding ignorable

**Mistake:** Recommended Ignoring "no rate limit on discount-code validation" because another
catalogued bug (any discount % accepted at checkout) already gives more. Nuno: if the client
fixes the worse bug, this one is still a real issue that needs fixing.

**Rule:** Judge a finding on its own: real + needs a fix = it belongs in the catalog (credit
it), whatever else the app gets wrong. Ignore only fixtures (published test accounts) and
behaviour with no security consequence of its own. When several findings share one root
cause (e.g. no rate limiting anywhere), catalog one entry covering the affected sensitive
actions rather than ignoring each.

## Don't infer what was deployed from commit-count versions

**Mistake:** Told Nuno a scan predated the /files/ narrowing "which came in v1.47", reading the
version off commit counts. He builds containers from the working tree, so changes were live
before they were committed: version arithmetic doesn't say what a scan tested.

**Rule:** Place a scan by what it observed (listing contents, a 409 on reuse, a table in the
dumped DB), and say which behaviours its findings don't cover. Only Nuno knows the deploy
history; ask rather than derive it from git.

## Tier by what it takes to recognise the bug, not by a neighbour's tier

**Mistake:** Registered TP-069 (one payment backs several orders, via a checkout race) as
commodity because #48's race was commodity. Nuno: commodity is XSS, SQLi and the like, which you
can identify with no context; here you must understand that two successful orders used the same
payment transaction. That takes "brains": business logic.

**Rule:** Commodity = a generic, app-independent class recognisable without knowing what the app
is for. Business logic = recognising it as a bug requires the app's own rules (money, codes,
ownership, checkout, payments). Decide the tier from that test for each vuln; never copy it from
a similar-looking one, and follow the catalog's section when it has one.

## A converter that bypasses the extraction prompt must re-apply its rules
User, 2026-11-12: "I don't want CWE as the title of vulns ... we're back to square 1." The extraction
prompt says vuln_type is a short readable class ("SQLi", "IDOR"), and that had fixed this once. The new
direct COS converter (cos_findings) skipped the model, so the prompt's rule never ran, and I copied the
report's `cwe` field into vuln_type, which is the finding's heading on the scan page.
- Rule: when a deterministic converter replaces model extraction, go through SYSTEM_PROMPT_EXTRACT's field
  rules one by one and implement each (vuln_type readable, never a CWE number; scan_date = start; etc.).
- Rule: before calling an import done, look at the scan page as the user will (first rows of Findings),
  not only at counts. A count check can't catch a bad heading.

## Copied check scripts carry their side effects
2026-11-12, self-caught: I reused the 1454 check script (which also SETS the coverage note) for scan 1457 by
sed-replacing the scan id, and it wrote a cyberAgent coverage note onto the Claude Code scan.
- Rule: keep read-only checks and writes in separate scripts; never reuse a script that writes for another scan.
