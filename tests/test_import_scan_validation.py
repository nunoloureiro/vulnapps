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


# ── Source-file-type enforcement for chain vs. individual-vuln credit ──
#
# Real incident (2026-09-21): the model over-credited standalone findings
# as full chains -- once by stating a further step's consequence without
# demonstrating it, once by ignoring an explicit "not performed / withheld"
# disclaimer, once by ignoring an explicit "scored separately" disclaimer --
# and separately under-credited a genuine chain finding by splitting it
# into one sub-finding per mechanism, each matched to an individual vuln
# instead of the chain. _enforce_source_kind is the mechanical backstop:
# a file's own directory (when the scan separates dedicated chain write-ups
# from standalone findings) hard-caps which field its findings can ever
# populate, regardless of what the model returns.

def test_enforce_source_kind_clears_vuln_match_on_a_chain_source_file():
    result = {"findings": [{"matched_vuln_db_id": 55987, "matched_chain_db_id": None}]}
    import_scan._enforce_source_kind(result, is_chain_source=True)
    assert result["findings"][0]["matched_vuln_db_id"] is None


def test_enforce_source_kind_clears_chain_match_on_a_standalone_source_file():
    """The exact real-incident shape: a standalone SSRF finding that only
    claimed (never demonstrated) a further token-forgery step got
    matched_chain_db_id set anyway."""
    result = {"findings": [{"matched_vuln_db_id": None, "matched_chain_db_id": 15}]}
    import_scan._enforce_source_kind(result, is_chain_source=False)
    assert result["findings"][0]["matched_chain_db_id"] is None


def test_enforce_source_kind_is_a_noop_without_a_directory_signal():
    """No directory-based signal (e.g. a single combined report, or --file)
    -- the content rule in SYSTEM_PROMPT_MAP still applies, but there is
    nothing here to enforce mechanically."""
    result = {"findings": [{"matched_vuln_db_id": 1, "matched_chain_db_id": 2}]}
    import_scan._enforce_source_kind(result, is_chain_source=None)
    assert result["findings"][0] == {"matched_vuln_db_id": 1, "matched_chain_db_id": 2}


def test_enforce_source_kind_handles_multiple_findings_and_missing_keys():
    result = {"findings": [
        {"matched_vuln_db_id": 1, "matched_chain_db_id": None},
        {"matched_vuln_db_id": 2},  # matched_chain_db_id absent entirely
    ]}
    import_scan._enforce_source_kind(result, is_chain_source=True)
    assert all(f["matched_vuln_db_id"] is None for f in result["findings"])


def test_source_kind_prompt_section_matches_content_rule_wording():
    """The per-file source-type note must frame itself as secondary to the
    content-based rule in SYSTEM_PROMPT_MAP, not a replacement for it, and
    for a chain file must warn against splitting one narrative into
    per-mechanism findings (the exact way a genuine chain lost its credit)."""
    vulns = [{"id": 1, "vuln_id": "TP-001", "title": "SQLi", "severity": "high"}]

    chain_msg = import_scan._build_user_message("REPORT", vulns, None, None, True)
    assert "do not split one connected chain narrative" in chain_msg
    assert "matched_vuln_db_id must stay null" in chain_msg

    standalone_msg = import_scan._build_user_message("REPORT", vulns, None, None, False)
    assert "matched_chain_db_id must stay null" in standalone_msg

    no_signal_msg = import_scan._build_user_message("REPORT", vulns, None, None, None)
    assert "Source File Type" not in no_signal_msg


def test_system_prompt_map_rejects_claim_without_demonstration():
    """The universal, directory-independent rule: explaining a further
    step's consequence, stating it was withheld/not performed, or saying
    the combined outcome is scored separately, must never by itself justify
    matched_chain_db_id -- this must hold even with no directory signal at
    all, which is why it lives in SYSTEM_PROMPT_MAP itself, not only in the
    per-file source-type note."""
    prompt = import_scan.SYSTEM_PROMPT_MAP
    assert "not performed" in prompt
    assert "withheld" in prompt
    assert "scored separately" in prompt or "reported separately" in prompt


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


# ── _scan_date_from_iso / _read_scan_stats ──
# Real incident (2026-09-21): cost/tokens/duration/model live in a separate
# stats.jsonl (an append-only per-agent metrics stream the scanning tool
# writes), not anywhere in the report's own JSON/markdown -- so the importer
# had no way to see them and the fields stayed empty on the submitted scan.

def test_scan_date_from_iso_takes_leading_date_hour_minute():
    assert import_scan._scan_date_from_iso("2026-09-17T23:14:20.425412Z") == "2026-09-17 23:14"


def test_scan_date_from_iso_none_for_missing_or_too_short():
    assert import_scan._scan_date_from_iso(None) is None
    assert import_scan._scan_date_from_iso("2026-09-17") is None


def test_read_scan_stats_none_when_file_absent(tmp_path):
    assert import_scan._read_scan_stats(tmp_path) is None


def test_read_scan_stats_prefers_the_snapshot_marked_final(tmp_path):
    lines = [
        {"event": "agent_finished", "agent_id": "a1"},
        {"event": "run_snapshot", "totals": {"cost_usd": 1.0, "tokens_used": 100},
         "duration_seconds": 10, "started_at": "2026-09-17T23:14:20.425412Z",
         "agents": {"a1": {"model_name": "claude-sonnet-5"}}},
        {"event": "run_snapshot", "totals": {"cost_usd": 12.34, "tokens_used": 999888},
         "duration_seconds": 4321, "started_at": "2026-09-17T23:14:20.425412Z",
         "agents": {"a1": {"model_name": "claude-sonnet-5"}, "a2": {"model_name": "claude-opus-5"}},
         "final": True},
    ]
    (tmp_path / "stats.jsonl").write_text("\n".join(json.dumps(l) for l in lines))

    stats = import_scan._read_scan_stats(tmp_path)

    assert stats["cost_usd"] == 12.34
    assert stats["tokens_used"] == 999888
    assert stats["duration_seconds"] == 4321
    assert stats["started_at"] == "2026-09-17T23:14:20.425412Z"
    assert stats["model_names"] == {"claude-sonnet-5", "claude-opus-5"}
    assert stats["is_final"] is True
    assert stats["source_files"] == ["stats.jsonl"]


def test_read_scan_stats_finds_the_file_regardless_of_name_or_nesting(tmp_path):
    """The filename 'stats.jsonl' is a convention from the one tool we've
    seen emit this, not a contract -- a differently-named file, nested in a
    subdirectory, must still be picked up by its content shape."""
    lines = [
        {"event": "run_snapshot", "totals": {"cost_usd": 5.0, "tokens_used": 500},
         "duration_seconds": 50, "started_at": "2026-09-17T23:14:20Z",
         "agents": {}, "final": True},
    ]
    nested = tmp_path / "logs" / "run-metrics.jsonl"
    nested.parent.mkdir(parents=True)
    nested.write_text("\n".join(json.dumps(l) for l in lines))

    stats = import_scan._read_scan_stats(tmp_path)

    assert stats["cost_usd"] == 5.0
    assert stats["source_files"] == ["logs/run-metrics.jsonl"]


def test_read_scan_stats_skips_hidden_and_underscore_directories(tmp_path):
    lines = [
        {"event": "run_snapshot", "totals": {"cost_usd": 5.0, "tokens_used": 500},
         "duration_seconds": 50, "started_at": "2026-09-17T23:14:20Z",
         "agents": {}, "final": True},
    ]
    hidden = tmp_path / ".git" / "stats.jsonl"
    hidden.parent.mkdir(parents=True)
    hidden.write_text("\n".join(json.dumps(l) for l in lines))
    private = tmp_path / "_scratch" / "stats.jsonl"
    private.parent.mkdir(parents=True)
    private.write_text("\n".join(json.dumps(l) for l in lines))

    assert import_scan._read_scan_stats(tmp_path) is None


def test_find_stats_files_ignores_jsonl_without_an_event_key(tmp_path):
    """A .jsonl file that happens to live in the report dir but isn't a
    metrics stream (e.g. some unrelated per-line data export) must not be
    mistaken for one."""
    (tmp_path / "vulnerabilities.jsonl").write_text(
        "\n".join(json.dumps(r) for r in [{"id": 1, "title": "SQLi"}, {"id": 2, "title": "XSS"}])
    )

    assert import_scan._find_stats_files(tmp_path) == []
    assert import_scan._read_scan_stats(tmp_path) is None


def test_read_scan_stats_falls_back_to_last_snapshot_when_none_is_final():
    """The run may have been interrupted before a final=true record was
    written -- fall back to the last run_snapshot seen and say so."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        lines = [
            {"event": "run_snapshot", "totals": {"cost_usd": 1.0, "tokens_used": 100},
             "duration_seconds": 10, "started_at": "2026-09-17T23:14:20Z", "agents": {}},
            {"event": "run_snapshot", "totals": {"cost_usd": 2.5, "tokens_used": 200},
             "duration_seconds": 20, "started_at": "2026-09-17T23:14:20Z", "agents": {}},
        ]
        (tmp_path / "stats.jsonl").write_text("\n".join(json.dumps(l) for l in lines))

        stats = import_scan._read_scan_stats(tmp_path)

        assert stats["cost_usd"] == 2.5
        assert stats["is_final"] is False


def test_read_scan_stats_ignores_non_snapshot_events_and_malformed_lines():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        raw = "\n".join([
            json.dumps({"event": "agent_finished", "agent_id": "a1"}),
            "not json at all",
            "",
            json.dumps({"event": "run_snapshot", "totals": {"cost_usd": 3.0, "tokens_used": 300},
                        "duration_seconds": 30, "started_at": "2026-09-17T23:14:20Z",
                        "agents": {}, "final": True}),
        ])
        (tmp_path / "stats.jsonl").write_text(raw)

        stats = import_scan._read_scan_stats(tmp_path)

        assert stats["cost_usd"] == 3.0
        assert stats["is_final"] is True


# ── _stats_fields_to_confirm ──
# Real incident (2026-09-21): the metadata confirmation used to be one
# bundled yes/no covering cost/tokens/duration/date together. An operator
# who had already passed --duration explicitly (the scanning tool only
# recorded wall time until they manually exited, not real scan time) still
# wanted the metrics file's cost/tokens accepted -- but declining the
# bundled question discarded all four fields AND aborted the whole
# submission outright, after the (expensive) LLM mapping pass had already
# run. Fields must be asked about individually, and a field the operator
# already settled via CLI flag must not be asked about at all.

_STATS_ALL_FIELDS = {
    "cost_usd": 145.8855, "tokens_used": 14404361, "duration_seconds": 35241.438,
    "started_at": "2026-09-17T23:14:20.425412Z",
}


class _FakeArgs:
    cost = None
    tokens = None
    duration = None
    scan_start = None


def test_stats_fields_to_confirm_asks_about_every_field_with_no_cli_override():
    fields = import_scan._stats_fields_to_confirm(_FakeArgs(), _STATS_ALL_FIELDS)
    assert [f for f, _, _ in fields] == ["cost", "tokens", "duration", "scan_date"]


def test_stats_fields_to_confirm_skips_a_field_already_settled_by_cli():
    """The exact real-incident shape: --duration was already passed by the
    operator (to correct for wall-clock time that included idle time after
    the last real finding) -- it must not be asked about, while cost/tokens
    still are."""
    args = _FakeArgs()
    args.duration = 57.0

    fields = import_scan._stats_fields_to_confirm(args, _STATS_ALL_FIELDS)

    assert [f for f, _, _ in fields] == ["cost", "tokens", "scan_date"]


def test_stats_fields_to_confirm_skips_fields_the_metrics_file_has_nothing_for():
    fields = import_scan._stats_fields_to_confirm(_FakeArgs(), {"cost_usd": 1.0})
    assert [f for f, _, _ in fields] == ["cost"]


def test_stats_fields_to_confirm_value_desc_is_human_readable():
    fields = import_scan._stats_fields_to_confirm(_FakeArgs(), _STATS_ALL_FIELDS)
    by_field = {f: v for f, _, v in fields}
    assert by_field["cost"] == "$145.89"
    assert by_field["tokens"] == "14,404,361"
    assert by_field["scan_date"] == "2026-09-17 23:14"
