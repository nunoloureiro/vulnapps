"""Tests for the scan-comparison reporting guards (_reporting_guards).

Real incident (2026-09-24): the compare view warned "these scans ran against
different corpus revisions ... cells for later additions read n/a rather than
as a miss" on every TaintedPort comparison, because it fired whenever the
scans' revision STAMPS differed. Stamps drift every time ground truth grows
(app 305 went 1 -> 9 in a single afternoon of adding vulns), but a vuln whose
existed_since_revision is 1 -- the default, meaning the flaw was always in the
app and only got documented later -- stays in scope for every scan. All 57 of
that app's vulns were existed_since_revision=1, so no cell could ever read
"n/a" and the warning was explaining a non-event. What matters is whether any
cell is actually out of scope, which is what it now counts.
"""

from app.services.scans import _reporting_guards


def _scanner(scan_id, corpus_revision, complete=True):
    return {
        "scan": {"id": scan_id, "corpus_revision": corpus_revision},
        "metrics": {"adjudication_complete": complete},
    }


def _row(applicable):
    return {"applicable": applicable}


def test_differing_revision_stamps_alone_do_not_warn():
    """The exact real-incident shape: stamps 1/7/8, but every vuln in scope
    for every scan, so there is no "n/a" cell to explain."""
    scanners = [_scanner(330, 1), _scanner(331, 7), _scanner(332, 8)]
    matrix = [_row([True, True, True]) for _ in range(57)]

    guards = _reporting_guards(scanners, revision=9, matrix=matrix)

    assert guards["corpus_revisions"] == [1, 7, 8]
    assert guards["out_of_scope_cells"] == 0


def test_out_of_scope_cells_are_counted():
    """A vuln introduced by a later code change is not in scope for the older
    scans, so those cells read n/a and the warning has something to explain."""
    scanners = [_scanner(330, 1), _scanner(331, 7)]
    matrix = [
        _row([True, True]),
        _row([False, True]),   # postdates scan 330
        _row([False, True]),
    ]

    guards = _reporting_guards(scanners, revision=9, matrix=matrix)

    assert guards["out_of_scope_cells"] == 2


def test_same_revision_and_all_in_scope_is_silent():
    scanners = [_scanner(330, 9), _scanner(331, 9)]
    matrix = [_row([True, True])]

    guards = _reporting_guards(scanners, revision=9, matrix=matrix)

    assert guards["corpus_revisions"] == [9]
    assert guards["out_of_scope_cells"] == 0
    assert guards["suppress_precision"] is False


def test_incomplete_adjudication_still_suppresses_precision():
    """Unrelated to revision scoping -- the other guard must keep working."""
    scanners = [_scanner(330, 9), _scanner(331, 9, complete=False)]
    matrix = [_row([True, True])]

    guards = _reporting_guards(scanners, revision=9, matrix=matrix)

    assert guards["adjudication_incomplete_scans"] == [331]
    assert guards["suppress_precision"] is True
