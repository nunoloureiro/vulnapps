"""Benchmark-grade scoring primitives — pure functions, no DB, no HTTP.

Everything in this module is deterministic in its arguments: given the same
findings, ground-truth scope, and weights, it always returns the same numbers.

Contents:
  * the weight scale (1/3/9/27) and difficulty tiers
  * the revision-scope rule (``in_scope``)
  * ``compute_metrics`` — the single implementation of every metric
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------
# Log spacing is deliberate. With linear weights, nine informational findings
# would outscore two criticals — which is exactly the failure mode that makes
# raw counts useless for comparing a chat-interface scanner against an agent
# that chains authz bypasses.

WEIGHT_SCALE = (1, 3, 9, 27)

WEIGHT_CLASSES = {
    1: "informational",
    3: "medium",
    9: "high",
    27: "critical",
}

# `severity` stays the display field; `impact_weight` is the scoring field and
# is allowed to diverge from it. This map is only a starting point (backfill and
# promotion default).
SEVERITY_WEIGHTS = {
    "critical": 27,
    "high": 9,
    "medium": 3,
    "low": 1,
    "info": 1,
}

DEFAULT_WEIGHT = 3

# A reporting axis, never a multiplier. Blending difficulty into the weight
# produces one opaque number and destroys the diagnostic: the point of the tier
# is to see *where on the difficulty curve* a configuration improved.
DIFFICULTY_TIERS = ("commodity", "business_logic", "chained")
DEFAULT_TIER = "commodity"


# ---------------------------------------------------------------------------
# Row access helpers
# ---------------------------------------------------------------------------

def field(row, key, default=None):
    """Read *key* from a dict or an ``sqlite3.Row``, defaulting when absent/NULL.

    ``sqlite3.Row`` raises ``IndexError`` for an unknown column and ``dict``
    raises ``KeyError``; callers should not have to care which they hold.
    """
    try:
        value = row[key]
    except (KeyError, IndexError):
        return default
    return default if value is None else value


def weight_of(row) -> int:
    """Scoring weight of a vuln/chain row: ``impact_weight``, else from severity."""
    weight = field(row, "impact_weight")
    if weight is not None:
        try:
            return int(weight)
        except (TypeError, ValueError):
            pass
    severity = str(field(row, "severity", "") or "").strip().lower()
    return SEVERITY_WEIGHTS.get(severity, DEFAULT_WEIGHT)


def weight_from_severity(severity) -> int:
    """Backfill/default weight for a severity label."""
    return SEVERITY_WEIGHTS.get(str(severity or "").strip().lower(), DEFAULT_WEIGHT)


def tier_of(row) -> str:
    """Difficulty tier of a vuln row, defaulting to ``commodity``."""
    tier = str(field(row, "difficulty_tier", "") or "").strip().lower()
    return tier if tier in DIFFICULTY_TIERS else DEFAULT_TIER


def validate_weight(value):
    """Return *value* as a valid weight, or raise ``ValueError``.

    SQLite cannot add CHECK constraints via ALTER TABLE, so the constraint lives
    here and is applied by every write path.
    """
    if value in (None, ""):
        return None
    try:
        weight = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"impact_weight must be one of {list(WEIGHT_SCALE)}")
    if weight not in WEIGHT_SCALE:
        raise ValueError(f"impact_weight must be one of {list(WEIGHT_SCALE)}")
    return weight


def validate_tier(value):
    """Return *value* as a valid difficulty tier, or raise ``ValueError``."""
    if value in (None, ""):
        return None
    tier = str(value).strip().lower()
    if tier not in DIFFICULTY_TIERS:
        raise ValueError(f"difficulty_tier must be one of {list(DIFFICULTY_TIERS)}")
    return tier


def _chain_members(chain) -> list:
    members = field(chain, "members", []) or []
    out = []
    for m in members:
        out.append(m if isinstance(m, int) else field(m, "vuln_id"))
    return [m for m in out if m is not None]


def in_scope(row, revision: int) -> bool:
    """Revision scope rule, applied identically to vulns and chains.

    In scope at revision R when it existed by R and had not been invalidated
    at or before R.
    """
    existed = field(row, "existed_since_revision", 1)
    invalidated = field(row, "invalidated_at_revision")
    try:
        existed = int(existed)
    except (TypeError, ValueError):
        existed = 1
    if existed > revision:
        return False
    if invalidated is not None:
        try:
            if int(invalidated) <= revision:
                return False
        except (TypeError, ValueError):
            pass
    return True


# ---------------------------------------------------------------------------
# The metric
# ---------------------------------------------------------------------------

def compute_metrics(
    findings,
    vulns_in_scope,
    chains_in_scope=(),
) -> dict:
    """Compute every metric for one scan. Pure — no DB, no live app state.

    *findings* are that scan's ``scan_findings`` rows; *vulns_in_scope* and
    *chains_in_scope* are the ground truth for the revision being scored at.

    Returns a dict of:

    ``tp`` / ``fn``
        Vulns in scope with / without at least one matched finding.
    ``fp`` / ``fp_groups``
        Raw false-positive findings, and distinct FP *clusters* — an ungrouped
        FP counts as one. Precision uses the clustered count so a verbose
        scanner is not penalised for describing one non-issue three times.
    ``precision_lower`` / ``precision_upper``
        Precision is only meaningful after full adjudication. The lower bound
        assumes every pending finding turns out to be its own false positive,
        the upper bound assumes none do. They converge as adjudication
        completes; ``adjudication_complete`` says whether they have.
    ``weighted_rate``
        The headline metric: ``weighted_found / weighted_total``. A matched
        vuln scores its full weight; a chain scores its full weight only when
        every member is matched.
    ``tiers``
        The default reporting view: per-tier count/found/weighted totals.
        Chains are reported in the ``chained`` tier alongside vulns tagged
        ``chained``.
    """
    findings = list(findings)
    vulns = list(vulns_in_scope)
    chains = list(chains_in_scope)

    scope_ids = {field(v, "id") for v in vulns}

    # --- findings by adjudication state -----------------------------------
    matched_ids = {
        field(f, "matched_vuln_id")
        for f in findings
        if field(f, "matched_vuln_id") is not None
    }
    in_scope_matched = matched_ids & scope_ids
    # A finding matched to a vuln that is out of scope at this revision (e.g.
    # invalidated, or not yet introduced) is neither a TP nor an FP here.
    out_of_scope_matches = len(matched_ids - scope_ids)

    fp_findings = [f for f in findings if int(field(f, "is_false_positive", 0) or 0) == 1]
    fp = len(fp_findings)

    # Cluster FPs the same way TPs are already clustered: distinct group keys,
    # plus one for each ungrouped FP.
    fp_group_keys = set()
    ungrouped_fp = 0
    for f in fp_findings:
        group = str(field(f, "fp_group", "") or "").strip()
        if group:
            fp_group_keys.add(group.lower())
        else:
            ungrouped_fp += 1
    fp_groups = len(fp_group_keys) + ungrouped_fp

    ignored = sum(1 for f in findings if int(field(f, "is_ignored", 0) or 0) == 1)
    pending = sum(
        1 for f in findings
        if field(f, "matched_vuln_id") is None
        and int(field(f, "is_false_positive", 0) or 0) == 0
        and int(field(f, "is_ignored", 0) or 0) == 0
    )

    tp = len(in_scope_matched)
    missed_vuln_ids = [field(v, "id") for v in vulns if field(v, "id") not in in_scope_matched]
    fn = len(missed_vuln_ids)

    # --- count-based metrics ---------------------------------------------
    adjudication_complete = pending == 0
    precision_upper = tp / (tp + fp_groups) if (tp + fp_groups) > 0 else 0.0
    precision_lower = (
        tp / (tp + fp_groups + pending) if (tp + fp_groups + pending) > 0 else 0.0
    )
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    # F1 uses the upper bound, which is what precision has always meant here —
    # so F1 is unchanged for fully adjudicated scans and stays comparable with
    # every number recorded before this change.
    f1 = (
        2 * precision_upper * recall / (precision_upper + recall)
        if (precision_upper + recall) > 0 else 0.0
    )

    # --- credit per vuln / chain -------------------------------------------
    # A matched vuln scores full credit. A chain scores full credit only when
    # every one of its members is matched — demonstrating a chain end to end
    # is a fact about its members, not something recorded separately.
    credit_by_vuln = {
        field(v, "id"): (1.0 if field(v, "id") in in_scope_matched else 0.0)
        for v in vulns
    }

    credit_by_chain = {}
    for c in chains:
        pk = field(c, "id")
        members = _chain_members(c)
        credit_by_chain[pk] = (
            1.0 if members and all(vid in in_scope_matched for vid in members) else 0.0
        )

    # --- weighted totals and the tier matrix ------------------------------
    tiers = {
        t: {"count": 0, "found": 0, "weighted_total": 0.0, "weighted_found": 0.0}
        for t in DIFFICULTY_TIERS
    }

    weighted_total = 0.0
    weighted_found = 0.0
    for v in vulns:
        vid = field(v, "id")
        weight = weight_of(v)
        credit = credit_by_vuln.get(vid, 0.0)
        weighted_total += weight
        weighted_found += weight * credit
        bucket = tiers[tier_of(v)]
        bucket["count"] += 1
        bucket["weighted_total"] += weight
        bucket["weighted_found"] += weight * credit
        if credit > 0:
            bucket["found"] += 1

    for c in chains:
        pk = field(c, "id")
        weight = weight_of(c)
        credit = credit_by_chain.get(pk, 0.0)
        weighted_total += weight
        weighted_found += weight * credit
        bucket = tiers["chained"]
        bucket["count"] += 1
        bucket["weighted_total"] += weight
        bucket["weighted_found"] += weight * credit
        if credit > 0:
            bucket["found"] += 1

    for bucket in tiers.values():
        bucket["rate"] = bucket["found"] / bucket["count"] if bucket["count"] else 0.0
        bucket["weighted_rate"] = (
            bucket["weighted_found"] / bucket["weighted_total"]
            if bucket["weighted_total"] else 0.0
        )
        bucket["weighted_found"] = round(bucket["weighted_found"], 4)

    weighted_found = round(weighted_found, 4)
    weighted_rate = weighted_found / weighted_total if weighted_total else 0.0

    return {
        # counts
        "tp": tp,
        "fp": fp,
        "fp_groups": fp_groups,
        "pending": pending,
        "ignored": ignored,
        "fn": fn,
        "out_of_scope_matches": out_of_scope_matches,
        # rates
        "precision": precision_upper,   # retained name: always meant the upper bound
        "precision_lower": precision_lower,
        "precision_upper": precision_upper,
        "recall": recall,
        "f1": f1,
        "adjudication_complete": adjudication_complete,
        # weighted
        "weighted_found": weighted_found,
        "weighted_total": float(weighted_total),
        "weighted_rate": weighted_rate,
        "tiers": tiers,
        # detail for the UI / matrix builders
        "matched_vuln_ids": in_scope_matched,
        "missed_vuln_ids": missed_vuln_ids,
        "credit_by_vuln": credit_by_vuln,
        "credit_by_chain": credit_by_chain,
    }


def json_metrics(metrics: dict) -> dict:
    """JSON-safe view of a ``compute_metrics`` result for API responses.

    ``matched_vuln_ids`` is a set and the credit maps are keyed by int, neither
    of which survives JSON cleanly; the internal callers that need them use the
    raw dict instead.
    """
    out = {k: v for k, v in metrics.items() if k not in ("matched_vuln_ids", "credit_by_vuln", "credit_by_chain")}
    out["matched_vuln_ids"] = sorted(metrics.get("matched_vuln_ids", []))
    out["credit_by_vuln"] = {
        str(k): v for k, v in (metrics.get("credit_by_vuln") or {}).items()
    }
    out["credit_by_chain"] = {
        str(k): v for k, v in (metrics.get("credit_by_chain") or {}).items()
    }
    return out
