# Lessons

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
