"""Tests for import_scan.py's _discover_findings_dirs -- which directory
(or directories) the importer reads .md files from when given a project/run
root rather than the findings dir directly.

Real incident (2026-09-18): a report root had both a single combined
~1.3MB `penetration_test_report.md` at its top level AND sibling
`vulnerabilities/` (57 files) + `vulnerability_chains/` (4 chains) findings
directories. The old rule order let the top-level combined file win
outright, so the importer sent that one giant file through a single
non-chunked LLM call -- and the response came back too large to parse as
valid JSON ("Expecting ',' delimiter"), on both the initial attempt and the
retry. The per-finding subdirectories were silently never read at all.
"""

import importlib.util
import pathlib
import tempfile

_SPEC = importlib.util.spec_from_file_location(
    "import_scan", pathlib.Path(__file__).parent.parent / "tools" / "import_scan.py"
)
import_scan = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(import_scan)


def _touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("content")


def test_sibling_findings_dirs_win_over_a_combined_report_at_root():
    """The exact real-incident shape."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        _touch(root / "penetration_test_report.md")
        _touch(root / "vulnerabilities" / "vuln-0001-x.md")
        _touch(root / "vulnerabilities" / "vuln-0002-x.md")
        _touch(root / "vulnerability_chains" / "chain-0001-x.md")

        dirs = import_scan._discover_findings_dirs(root)

        assert set(dirs) == {root / "vulnerabilities", root / "vulnerability_chains"}
        assert root not in dirs


def test_root_md_used_when_no_subdirectory_has_any():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        _touch(root / "scan_report.md")

        assert import_scan._discover_findings_dirs(root) == [root]


def test_single_findings_subdirectory_still_works():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        _touch(root / "vulnerabilities" / "vuln-0001-x.md")

        assert import_scan._discover_findings_dirs(root) == [root / "vulnerabilities"]


def test_falls_back_to_a_child_named_report_when_nothing_has_md():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        report_dir = root / "my-report-run"
        report_dir.mkdir()
        (report_dir / "results.json").write_text("{}")

        assert import_scan._discover_findings_dirs(root) == [report_dir]


def test_hidden_and_underscore_children_are_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        _touch(root / ".git" / "notes.md")
        _touch(root / "_private" / "notes.md")
        _touch(root / "vulnerabilities" / "vuln-0001-x.md")

        assert import_scan._discover_findings_dirs(root) == [root / "vulnerabilities"]
