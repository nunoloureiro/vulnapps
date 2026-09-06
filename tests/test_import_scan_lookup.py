"""App lookup in the CLI importer must refuse an ambiguous name+version.

Migration 010 rebuilt `apps` without the original UNIQUE(name, version), so a
lookup can match several rows with different ground truth and different scan
histories. This DB has such a pair (two `TaintedPort` version `1.0`). Taking the
first row would attach a scan to whichever duplicate came back first, and it
would then be scored against that app's corpus with nothing to reveal the error.
"""

import importlib.util
import pathlib

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "import_scan", pathlib.Path(__file__).parent.parent / "tools" / "import_scan.py"
)
import_scan = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(import_scan)


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeHttp:
    def __init__(self, apps):
        self._apps = apps
        self.calls = []

    def get(self, path, params=None):
        self.calls.append((path, params))
        return _FakeResponse({"apps": self._apps})


def _client(apps):
    client = import_scan.VulnappsClient.__new__(import_scan.VulnappsClient)
    client.base_url = "http://test"
    client.client = _FakeHttp(apps)
    return client


def test_single_match_resolves():
    client = _client([
        {"id": 7, "name": "TaintedPort", "version": "1.0", "visibility": "team"},
        {"id": 8, "name": "TaintedPortal", "version": "1.0"},
    ])
    assert client.find_app("TaintedPort", "1.0")["id"] == 7


def test_no_match_returns_none():
    client = _client([{"id": 8, "name": "Other", "version": "2.0"}])
    assert client.find_app("TaintedPort", "1.0") is None


def test_version_is_part_of_the_match():
    client = _client([
        {"id": 7, "name": "TaintedPort", "version": "1.0"},
        {"id": 9, "name": "TaintedPort", "version": "2.0"},
    ])
    assert client.find_app("TaintedPort", "2.0")["id"] == 9
    assert client.find_app("TaintedPort", "") is None


def test_duplicate_name_and_version_refuses():
    """The real case: ids 1 and 3, both TaintedPort 1.0, different corpora."""
    client = _client([
        {"id": 1, "name": "TaintedPort", "version": "1.0", "visibility": "public", "vuln_count": 31},
        {"id": 3, "name": "TaintedPort", "version": "1.0", "visibility": "team", "vuln_count": 32},
    ])
    with pytest.raises(import_scan.AmbiguousAppError) as exc:
        client.find_app("TaintedPort", "1.0")
    assert [a["id"] for a in exc.value.matches] == [1, 3]
    assert "2 apps match" in str(exc.value)


def test_null_version_matches_empty_string():
    client = _client([{"id": 7, "name": "Solo", "version": None}])
    assert client.find_app("Solo", "")["id"] == 7
    assert client.find_app("Solo", None)["id"] == 7
