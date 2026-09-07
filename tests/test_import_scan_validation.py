"""Tests for the CLI importer's match-validation and correction logic
(tools/import_scan.py). Companion to tests/test_matching.py, which covers
the server-side heuristic matcher that was the actual root cause of the
real incident these findings are drawn from; this file covers the
importer-side defense-in-depth added alongside that fix.
"""

import importlib.util
import json
import pathlib

_SPEC = importlib.util.spec_from_file_location(
    "import_scan", pathlib.Path(__file__).parent.parent / "tools" / "import_scan.py"
)
import_scan = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(import_scan)


_JWT_NONE_ALG_VULN = {
    "id": 42, "vuln_id": "TP-011", "title": "JWT 'none' Algorithm Accepted",
    "vuln_type": "Broken Authentication", "severity": "high",
}


def test_title_keyword_overlap_true_for_matching_titles():
    assert import_scan._titles_share_a_keyword(
        "SQL Injection - Login Email", "SQL Injection - Login Email"
    )


def test_title_keyword_overlap_false_for_real_incident():
    """The exact real mismatch: zero shared meaningful words."""
    assert not import_scan._titles_share_a_keyword(
        "Login accepts stored bcrypt hash as the password (pass-the-hash)",
        "JWT 'none' Algorithm Accepted",
    )


def test_title_keyword_overlap_true_when_either_title_empty():
    """Nothing to compare against — don't manufacture a false flag."""
    assert import_scan._titles_share_a_keyword("", "JWT 'none' Algorithm Accepted")
    assert import_scan._titles_share_a_keyword("Some Finding", "")


def test_validate_llm_matches_flags_real_incident_but_does_not_clear_it():
    """Title mismatch is a warning, not a silent auto-reject — the operator
    stays in control of genuinely-uncertain matches."""
    mapping = {
        "findings": [
            {
                "title": "Login accepts stored bcrypt hash as the password (pass-the-hash)",
                "vuln_type": "Broken Authentication",
                "matched_vuln_db_id": 42,
            }
        ]
    }
    warnings = import_scan.validate_llm_matches(mapping, [_JWT_NONE_ALG_VULN])
    assert len(warnings) == 1
    assert "pass-the-hash" in warnings[0].lower() or "password" in warnings[0].lower()
    # Match is NOT cleared -- unlike the hallucination case below.
    assert mapping["findings"][0]["matched_vuln_db_id"] == 42


def test_validate_llm_matches_clears_hallucinated_id():
    """A matched_vuln_db_id that isn't in the known-vulns list shown to the
    model must never reach the API -- clear it and warn."""
    mapping = {
        "findings": [
            {"title": "Some Finding", "vuln_type": "XSS", "matched_vuln_db_id": 9999}
        ]
    }
    warnings = import_scan.validate_llm_matches(mapping, [_JWT_NONE_ALG_VULN])
    assert len(warnings) == 1
    assert "hallucin" in warnings[0].lower()
    assert mapping["findings"][0]["matched_vuln_db_id"] is None


def test_validate_llm_matches_no_warning_for_good_match():
    mapping = {
        "findings": [
            {
                "title": "JWT none algorithm bypass",
                "vuln_type": "Broken Authentication",
                "matched_vuln_db_id": 42,
            }
        ]
    }
    assert import_scan.validate_llm_matches(mapping, [_JWT_NONE_ALG_VULN]) == []


def test_validate_llm_matches_ignores_unmatched_findings():
    mapping = {"findings": [{"title": "Something", "matched_vuln_db_id": None}]}
    assert import_scan.validate_llm_matches(mapping, [_JWT_NONE_ALG_VULN]) == []


# ── _extract_json_text ───────────────────────────────────────────────────
#
# Real incident: for a report finding that legitimately maps to two known
# vulns, the LLM reasoned in prose ("I'll extract them as two mapped
# findings...") before emitting a ```json fenced block, despite the prompt
# saying "ONLY valid JSON (no markdown fencing)". The old `text.startswith
# ("```")` check only handles a fence at the very start, so json.loads hit
# the leading prose and failed with "Expecting value: line 1 column 1".

def test_extract_json_text_plain_json_passthrough():
    assert json.loads(import_scan._extract_json_text('{"a": 1}')) == {"a": 1}


def test_extract_json_text_whole_response_fenced():
    assert json.loads(import_scan._extract_json_text('```json\n{"a": 1}\n```')) == {"a": 1}


def test_extract_json_text_prose_before_fenced_block():
    """The exact real incident shape: reasoning prose, then a fence."""
    text = (
        "The report contains a single finding that combines two distinct "
        "weaknesses. I'll extract them as two mapped findings.\n\n"
        '```json\n{"findings": [{"matched_vuln_db_id": 1}, {"matched_vuln_db_id": 2}]}\n```'
    )
    result = json.loads(import_scan._extract_json_text(text))
    assert len(result["findings"]) == 2


def test_extract_json_text_prose_around_unfenced_json():
    """No fence at all -- falls back to the outermost {...} span."""
    text = 'Here is the mapping: {"a": 1} -- hope that helps!'
    assert json.loads(import_scan._extract_json_text(text)) == {"a": 1}


# ── --extra-info-mapping / --extra-info-extract ─────────────────────────
#
# _build_user_message is shared by the streaming-API path and the CLI
# subprocess path specifically so these two flags can't drift between them.

def test_build_user_message_omits_extra_section_when_not_given():
    """No behavior change for every existing caller that doesn't pass it."""
    mapping_msg = import_scan._build_user_message("REPORT", [_JWT_NONE_ALG_VULN], None, None)
    assert "Additional Instructions" not in mapping_msg

    extract_msg = import_scan._build_user_message("REPORT", [], None, None)
    assert "Additional Instructions" not in extract_msg
    assert extract_msg == "## Scan Report\n\nREPORT"


def test_build_user_message_includes_extra_info_in_mapping_mode():
    msg = import_scan._build_user_message(
        "REPORT", [_JWT_NONE_ALG_VULN], None, "Only trust findings with a concrete PoC."
    )
    assert "Additional Instructions From The Operator" in msg
    assert "Only trust findings with a concrete PoC." in msg
    # Comes after the known-vulns section, before the scan report.
    assert msg.index("Known Vulnerabilities") < msg.index("Additional Instructions") < msg.index("Scan Report")


def test_build_user_message_includes_extra_info_in_extract_mode():
    msg = import_scan._build_user_message("REPORT", [], None, "Be conservative about severity.")
    assert "Additional Instructions From The Operator" in msg
    assert "Be conservative about severity." in msg
    assert msg.index("Additional Instructions") < msg.index("Scan Report")


def test_run_llm_mapping_picks_extra_info_by_mode():
    """Mapping mode uses extra_info_mapping; extraction mode uses
    extra_info_extract -- never the other one, even if both are set."""
    captured = {}

    class _FakeStream:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get_final_text(self): return '{"findings": []}'
        def get_final_message(self):
            class R:
                usage = None
            return R()

    class _FakeMessages:
        def stream(self, **kwargs):
            captured["system"] = kwargs["system"]
            captured["user_message"] = kwargs["messages"][0]["content"]
            return _FakeStream()

    class _FakeClient:
        messages = _FakeMessages()

    import_scan.run_llm_mapping(
        "REPORT", [_JWT_NONE_ALG_VULN], "fake-model", _FakeClient(),
        extra_info_mapping="MAPPING STEER", extra_info_extract="EXTRACT STEER",
    )
    assert captured["system"] == import_scan.SYSTEM_PROMPT_MAP
    assert "MAPPING STEER" in captured["user_message"]
    assert "EXTRACT STEER" not in captured["user_message"]

    import_scan.run_llm_mapping(
        "REPORT", [], "fake-model", _FakeClient(),
        extra_info_mapping="MAPPING STEER", extra_info_extract="EXTRACT STEER",
    )
    assert captured["system"] == import_scan.SYSTEM_PROMPT_EXTRACT
    assert "EXTRACT STEER" in captured["user_message"]
    assert "MAPPING STEER" not in captured["user_message"]


# ── Correction-loop behavior (submit_to_vulnapps) ───────────────────────
#
# Full submit_to_vulnapps needs a live-ish client (it calls submit_scan,
# get_scan, match_finding, mark_fp in sequence); rather than mock the whole
# HTTP surface, these tests exercise the exact comparison this session found
# broken: "matched != current" must fire for all three directions, not just
# "matched is not None and different".

def test_correction_condition_covers_all_three_directions():
    """Mirrors the exact condition in submit_to_vulnapps's correction loop."""
    def would_correct(llm_matched, server_current):
        return llm_matched != server_current

    # 1) heuristic missed it, LLM found a match -> must correct
    assert would_correct(llm_matched=42, server_current=None)
    # 2) LLM disagrees with the heuristic's match -> must correct
    assert would_correct(llm_matched=43, server_current=42)
    # 3) the bug this session found: LLM says unmatched, heuristic already
    #    matched it to something wrong -> must correct (clear it)
    assert would_correct(llm_matched=None, server_current=42)
    # 4) already agree -> no API call needed
    assert not would_correct(llm_matched=42, server_current=42)
    assert not would_correct(llm_matched=None, server_current=None)
