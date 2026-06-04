# Lessons

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
