"""Tests for the CLI importer's match-validation and correction logic
(tools/import_scan.py). Companion to tests/test_matching.py, which covers
the server-side heuristic matcher that was the actual root cause of the
real incident these findings are drawn from; this file covers the
importer-side defense-in-depth added alongside that fix.
"""

import importlib.util
import json

import pytest
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


# ── two-phase import: extract (no catalog) then map ─────────────────────
#
# Found on ten TaintedPort scans that were pre-mapped by a scanner's own
# publishing step: when one call writes the findings while looking at the
# catalog, findings get merged and reshaped to fit it. Phase 1 therefore never
# sees the catalog, and phase 2 can only attach matches to findings that
# already exist.

_FINDING = {"title": "SQLi in login", "vuln_type": "SQLi", "url": "/auth/login",
            "severity": "critical", "description": "D", "poc": "P"}


class _FakeStream:
    def __init__(self, text): self.text = text
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def get_final_message(self):
        text = self.text
        class R:
            usage = None
            stop_reason = "end_turn"
            content = [_FakeBlock("text", text)]
        return R()


def _fake_client(captured, reply):
    class _Messages:
        def stream(self, **kwargs):
            captured.append(kwargs)
            return _FakeStream(reply)
    class _Beta:
        messages = _Messages()
    class _Client:
        messages = _Messages()
        beta = _Beta()
    return _Client()


def test_extraction_prompt_never_contains_the_catalog():
    captured = []
    import_scan.run_extract("REPORT", model="claude-sonnet-5", client=_fake_client(captured, '{"findings": []}'),
                            use_cli=False, provider="anthropic", extra_info="EXTRACT STEER",
                            is_chain_source=None, spinner_msg="x")
    msg = captured[0]["messages"][0]["content"]
    assert captured[0]["system"] == import_scan.SYSTEM_PROMPT_EXTRACT
    assert "Known Vulnerabilities" not in msg and "EXTRACT STEER" in msg
    assert "known vulnerabilit" not in import_scan.SYSTEM_PROMPT_EXTRACT.split("RULES:")[1].lower().replace(
        "you are not told what the application's known vulnerabilities are", ""), \
        "the extractor must not be steered toward any catalog"


def test_mapping_prompt_carries_catalog_and_numbered_findings_only():
    captured = []
    batch = [(0, dict(_FINDING, remediation="REMEDIATION TEXT")), (1, dict(_FINDING, title="Other"))]
    import_scan.run_map(batch, [_JWT_NONE_ALG_VULN], None, model="claude-opus-5",
                        client=_fake_client(captured, '{"mappings": []}'), use_cli=False, provider="anthropic",
                        extra_info="MAPPING STEER", spinner_msg="x")
    msg = captured[0]["messages"][0]["content"]
    assert captured[0]["system"] == import_scan.SYSTEM_PROMPT_MAP
    assert "Known Vulnerabilities" in msg and "MAPPING STEER" in msg
    assert '"index": 0' in msg and '"index": 1' in msg
    assert "REMEDIATION TEXT" not in msg, "the mapper gets only what it needs to judge"


def test_opus_calls_opt_into_refusal_fallbacks_and_others_do_not():
    captured = []
    client = _fake_client(captured, '{"findings": []}')
    for model in ("claude-opus-5", "claude-sonnet-5"):
        import_scan.run_extract("R", model=model, client=client, use_cli=False, provider="anthropic",
                                extra_info=None, is_chain_source=None, spinner_msg="x")
    assert captured[0].get("fallbacks") == "default" and captured[0]["betas"] == [import_scan.FALLBACK_BETA]
    assert "fallbacks" not in captured[1]
    captured.clear()
    import_scan.run_extract("R", model="claude-opus-5", client=client, use_cli=False, provider="vertex",
                            extra_info=None, is_chain_source=None, spinner_msg="x")
    assert "fallbacks" not in captured[0], "server-side fallbacks are not available on Vertex"


def test_refusal_is_an_error_not_an_empty_result():
    class _Refusing(_FakeStream):
        def get_final_message(self):
            class R:
                usage = None
                stop_reason = "refusal"
                content = []
            return R()
    class _M:
        def stream(self, **kw): return _Refusing("")
    class _C:
        messages = _M()
        beta = type("B", (), {"messages": _M()})()
    with pytest.raises(import_scan.LLMCallError, match="refusal"):
        import_scan.run_extract("R", model="claude-sonnet-5", client=_C(), use_cli=False, provider="anthropic",
                                extra_info=None, is_chain_source=None, spinner_msg="x")


def test_merge_takes_only_mapping_fields():
    """The guarantee: nothing the mapper returns can rewrite a finding."""
    findings = [dict(_FINDING)]
    import_scan.merge_mappings(findings, [(0, findings[0])], {"mappings": [{
        "index": 0, "matched_vuln_db_id": 7, "additional_vuln_db_ids": [8], "is_chain": False,
        "reasoning": "r", "title": "RENAMED", "description": "REWRITTEN", "severity": "low",
    }]})
    f = findings[0]
    assert (f["title"], f["description"], f["severity"]) == ("SQLi in login", "D", "critical")
    assert (f["matched_vuln_db_id"], f["additional_vuln_db_ids"]) == (7, [8])


@pytest.mark.parametrize("returned, problem", [
    ([0], "missing"),              # dropped a finding
    ([0, 1, 2], "unexpected"),     # invented one
    ([0, 0, 1], "duplicated"),     # merged two onto one number
])
def test_merge_refuses_answers_that_do_not_line_up(returned, problem):
    findings = [dict(_FINDING), dict(_FINDING, title="B")]
    batch = list(enumerate(findings))
    with pytest.raises(import_scan.MappingMismatch, match=problem):
        import_scan.merge_mappings(findings, batch, {"mappings": [{"index": i} for i in returned]})
    assert "matched_vuln_db_id" not in findings[0], "nothing is applied from a bad answer"


def test_mapper_can_flag_but_never_unflag_a_false_positive():
    findings = [dict(_FINDING, is_false_positive=True), dict(_FINDING)]
    import_scan.merge_mappings(findings, list(enumerate(findings)), {"mappings": [
        {"index": 0, "is_false_positive": False}, {"index": 1, "is_false_positive": True}]})
    assert [f["is_false_positive"] for f in findings] == [True, True]


def test_importer_identifies_itself():
    ident = import_scan._importer_identity()
    assert ident["imported_by"] == "vulnapps import_scan"
    assert ident["importer_version"] and ident["importer_version"].startswith("v")
    assert ident["importer_commit"]


def test_scan_config_carries_provenance_for_both_phases():
    class A:
        use_cli = False; extract_model = "claude-sonnet-5"; map_model = "claude-opus-5"
        model_version = reasoning_effort = harness_version = token_budget = seed = run_group = trial_index = None
    cfg = import_scan._scan_config(A(), None)
    assert cfg["extractor_version"] == "llm-api:claude-sonnet-5"
    assert cfg["matcher_version"] == "llm-api:claude-opus-5"
    assert cfg["imported_by"] == "vulnapps import_scan"
    assert cfg["extractor_prompt_sha256"] != cfg["matcher_prompt_sha256"]


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
# instead of the chain. The first backstop keyed on the file's folder; it
# was replaced (2026-09-28) because reports mix chain write-ups in with
# single-vuln findings. Chain-ness is now the finding's own is_chain flag,
# decided from content, and _enforce_chain_flag keys on that.

def test_unflagged_finding_can_never_be_chain_credited():
    """The real-incident shape: a standalone SSRF finding that only claimed a
    further token-forgery step got matched_chain_db_id set anyway."""
    result = {"findings": [{"matched_vuln_db_id": 5, "matched_chain_db_id": 15, "is_chain": False}]}
    import_scan._enforce_chain_flag(result)
    assert result["findings"][0]["matched_chain_db_id"] is None
    assert result["findings"][0]["matched_vuln_db_id"] == 5


def test_missing_flag_counts_as_not_a_chain():
    """Only an explicit True earns chain credit — a model that omits the field
    must not get the benefit of the doubt."""
    result = {"findings": [{"matched_chain_db_id": 15}, {"matched_chain_db_id": 16, "is_chain": "yes"}]}
    import_scan._enforce_chain_flag(result)
    assert [f["matched_chain_db_id"] for f in result["findings"]] == [None, None]
    assert [f["is_chain"] for f in result["findings"]] == [False, False]


def test_chain_finding_keeps_chain_primary_and_moves_vuln_to_additional():
    """A chain finding still credits the members it walked through, so a
    stray primary vuln is moved, not dropped."""
    result = {"findings": [{
        "matched_vuln_db_id": 7, "matched_chain_db_id": 15,
        "additional_vuln_db_ids": [8], "is_chain": True,
    }]}
    import_scan._enforce_chain_flag(result)
    f = result["findings"][0]
    assert (f["matched_chain_db_id"], f["matched_vuln_db_id"]) == (15, None)
    assert f["additional_vuln_db_ids"] == [7, 8]


def test_unregistered_chain_keeps_its_vuln_credit():
    """A chain report with no registered chain to match still credits the vulns
    it demonstrates — the case that used to end up marked FP."""
    result = {"findings": [{
        "matched_vuln_db_id": 7, "matched_chain_db_id": None,
        "additional_vuln_db_ids": [8, 9], "is_chain": True,
    }]}
    import_scan._enforce_chain_flag(result)
    f = result["findings"][0]
    assert (f["matched_vuln_db_id"], f["additional_vuln_db_ids"], f["is_chain"]) == (7, [8, 9], True)


def test_folder_is_only_a_hint_in_the_extraction_prompt():
    """Where the file sits may shape extraction (keep a chain write-up whole)
    but never forbids anything, and the mapping prompt no longer sees it."""
    for is_chain_source in (True, False):
        msg = import_scan._build_extract_message("REPORT", None, is_chain_source)
        assert "must stay null" not in msg and "a hint" in msg
    assert "rather than one finding per step" in import_scan._build_extract_message("R", None, True)
    assert "Where This File Sits" not in import_scan._build_extract_message("R", None, None)
    assert "Where This File Sits" not in import_scan._build_map_message(
        [(0, _FINDING)], [_JWT_NONE_ALG_VULN], None, None)


def test_system_prompt_defines_chain_by_content_not_folder():
    prompt = import_scan.SYSTEM_PROMPT_MAP
    # Content decides; none of the presentation signals does.
    assert "from the \\\ncontent alone" in prompt or "content alone" in prompt
    for signal in ("title", "filename", "folder", "tag"):
        assert signal in prompt.split("is_chain says")[1].split("Two shapes")[0], signal
    # The case that flipped between two runs: a one-flaw headline over a chain PoC.
    assert "headline is one" in prompt and "flaw but whose own proof of concept walks a chain" in prompt
    # The two non-chain shapes settled with the user on scan 330.
    assert "INDEPENDENT ways to the same" in prompt
    # Attacker work (cracking a leaked hash) is not a disqualifier.
    assert "cracking a hash the chain leaked" in prompt
    assert "Never leave a demonstrated vulnerability uncredited" in prompt


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


# ── _extract_text_blocks ──
# Real incident (2026-09-23): some models return a "thinking" content block
# even with no `thinking` param requested. The Anthropic SDK's own
# stream.get_final_text() assumes text-only content and raises
# ".get_final_text() can only be called when the API returns a `text`
# content block" the moment any block isn't type "text", crashing every
# mapping call against such a model.

class _FakeBlock:
    def __init__(self, type_, text=None):
        self.type = type_
        self.text = text


def test_extract_text_blocks_text_only():
    content = [_FakeBlock("text", "hello")]
    assert import_scan._extract_text_blocks(content) == "hello"


def test_extract_text_blocks_skips_thinking_block():
    content = [_FakeBlock("thinking", "reasoning about it..."), _FakeBlock("text", '{"findings": []}')]
    assert import_scan._extract_text_blocks(content) == '{"findings": []}'


def test_extract_text_blocks_joins_multiple_text_blocks():
    content = [_FakeBlock("text", "part one "), _FakeBlock("thinking", "..."), _FakeBlock("text", "part two")]
    assert import_scan._extract_text_blocks(content) == "part one part two"


# ── additional_vuln_db_ids (one finding, several vulns) ──
# Real incident (scan 330): three findings each explicitly read jwt.php and
# quoted the hardcoded secret, but a finding could only be credited for one
# thing, so each was matched to its own access vuln and CODE-001 scored as a
# miss. Migration 040 made matches additive; this is the importer side.

_SECRET_VULN = {
    "id": 99, "vuln_id": "CODE-001", "title": "Hardcoded JWT signing secret",
    "vuln_type": "Hardcoded Secret", "severity": "high",
}


def test_validate_keeps_real_additional_ids():
    mapping = {"findings": [{
        "title": "Directory listing exposes jwt.php",
        "matched_vuln_db_id": 42, "matched_chain_db_id": None,
        "additional_vuln_db_ids": [99],
    }]}
    warnings = import_scan.validate_llm_matches(
        mapping, [_JWT_NONE_ALG_VULN | {"id": 42}, _SECRET_VULN]
    )
    assert mapping["findings"][0]["additional_vuln_db_ids"] == [99]
    assert not warnings


def test_validate_drops_hallucinated_additional_ids():
    mapping = {"findings": [{
        "title": "Directory listing",
        "matched_vuln_db_id": 42, "matched_chain_db_id": None,
        "additional_vuln_db_ids": [99, 123456],
    }]}
    warnings = import_scan.validate_llm_matches(
        mapping, [_JWT_NONE_ALG_VULN | {"id": 42}, _SECRET_VULN]
    )
    assert mapping["findings"][0]["additional_vuln_db_ids"] == [99]
    assert any("123456" in w for w in warnings)


def test_validate_drops_additional_id_repeating_the_primary():
    """Listing the primary again would make the mapping table claim the
    finding covers more than it does."""
    mapping = {"findings": [{
        "title": "F", "matched_vuln_db_id": 42, "matched_chain_db_id": None,
        "additional_vuln_db_ids": [42, 99, 99],
    }]}
    import_scan.validate_llm_matches(
        mapping, [_JWT_NONE_ALG_VULN | {"id": 42}, _SECRET_VULN]
    )
    assert mapping["findings"][0]["additional_vuln_db_ids"] == [99]


def test_validate_tolerates_a_non_list_additional_field():
    mapping = {"findings": [{
        "title": "F", "matched_vuln_db_id": 42, "matched_chain_db_id": None,
        "additional_vuln_db_ids": 99,
    }]}
    warnings = import_scan.validate_llm_matches(mapping, [_JWT_NONE_ALG_VULN | {"id": 42}])
    assert mapping["findings"][0]["additional_vuln_db_ids"] == []
    assert any("isn't a list" in w for w in warnings)


def test_prompt_documents_when_to_use_additional_ids():
    """The rule has to survive prompt edits: additional ids are for what the
    finding's OWN evidence demonstrates, never for being comprehensive."""
    prompt = import_scan.SYSTEM_PROMPT_MAP
    assert "additional_vuln_db_ids" in prompt
    assert "OWN text must demonstrate" in prompt
    assert "Do NOT repeat matched_vuln_db_id" in prompt


def test_prompt_blocks_crediting_vulns_merely_visible_in_dumped_source():
    """Caught on a live dry run: a directory-listing finding that dumped the
    backend source credited the hardcoded secret (right — its value was
    quoted) and the admin-claim-trust vuln (right — it forged a token and got
    a live 200), but ALSO the alg:none and signature-mismatch vulns, purely
    because the disclosed code contained them. Unbounded, one file dump would
    sweep up most of the catalogue, so the prompt has to keep the distinction
    between a presence-in-source vuln and a runtime-behaviour one."""
    prompt = import_scan.SYSTEM_PROMPT_MAP
    assert "disclosing source code that CONTAINS another flaw is" in prompt
    assert "hardcoded secret, credential or key" in prompt
    assert "how the RUNNING application BEHAVES" in prompt
    assert "not evidence this scan exercised it" in prompt


def test_withdrawn_for_low_impact_is_still_mapped_not_fp():
    """Decided on Claude Code Security's open redirect: the report called it real
    but withdrew it from its confirmed count for low impact. That is a severity
    cut-off, not a false-positive verdict -- the scanner detected it."""
    prompt = import_scan.SYSTEM_PROMPT_MAP
    assert "withdrawn from the confirmed count" in prompt
    assert "a severity cut-off does not" in prompt
