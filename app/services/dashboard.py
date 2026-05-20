from __future__ import annotations

from app.visibility import app_visibility_filter, scan_visibility_filter


# Label family taxonomy. Mirrors the conventions documented in
# tools/import_scan.py:--labels help. Keep in sync.
LABEL_FAMILIES = ("methodology", "model", "judge", "thinking", "tools")


def _label_family(label_name: str) -> str | None:
    """Map a label name to its family, or None if it doesn't match any."""
    n = (label_name or "").lower()
    if n in ("blackbox", "greybox"):
        return "methodology"
    if n.startswith("judge-"):
        return "judge"
    if n.startswith("claude-") or n.startswith("gpt-"):
        return "model"
    if n.startswith("thinking-"):
        return "thinking"
    if n.startswith("used-"):
        return "tools"
    return None


def _parse_csv(value: str | None) -> list[str] | None:
    """Parse a comma-separated string into a list, or return None."""
    if not value:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items or None


async def get_dashboard(
    db, user,
    scanner=None, severity=None, label=None, tech=None,
    app_id=None, team=None, group_by=None,
) -> dict:
    """Aggregate scanner benchmarking data across all visible apps.

    Returns per-scanner metrics (TP/FP/FN/precision/recall/F1),
    breakdowns by severity and app, and available filter options.

    *group_by* (optional): a label family name (methodology, model, judge,
    thinking, tools). When set, results are keyed by (scanner_name, family_value)
    instead of just scanner_name — i.e. a scanner that's been run with two
    different models shows up as two rows. Scans that have no label in the
    chosen family are dropped from the comparison.
    """
    scanners_filter = _parse_csv(scanner)
    severities_filter = _parse_csv(severity)
    labels_filter = _parse_csv(label)
    techs_filter = _parse_csv(tech)
    app_ids_filter = _parse_csv(app_id)
    grouping = group_by if group_by in LABEL_FAMILIES else None

    # ------------------------------------------------------------------
    # 1. Visible apps (with optional tech / app_id filters)
    # ------------------------------------------------------------------
    app_vis_clause, app_vis_params = app_visibility_filter(user)

    apps_sql = f"SELECT * FROM apps WHERE {app_vis_clause}"
    apps_params = list(app_vis_params)

    if app_ids_filter:
        placeholders = ",".join("?" * len(app_ids_filter))
        apps_sql += f" AND apps.id IN ({placeholders})"
        apps_params.extend(app_ids_filter)

    if techs_filter:
        placeholders = ",".join("?" * len(techs_filter))
        apps_sql += (
            f" AND apps.id IN ("
            f"SELECT app_id FROM app_technologies WHERE name IN ({placeholders}))"
        )
        apps_params.extend(techs_filter)

    if team:
        try:
            team_id = int(team)
            apps_sql += " AND apps.team_id = ?"
            apps_params.append(team_id)
        except ValueError:
            pass

    cursor = await db.execute(apps_sql, apps_params)
    visible_apps = await cursor.fetchall()
    visible_app_ids = [a["id"] for a in visible_apps]

    if not visible_app_ids:
        return {
            "scanners": [],
            "filters": await _collect_filters(db, user),
        }

    # ------------------------------------------------------------------
    # 2. Known vulnerabilities for visible apps (with severity filter)
    # ------------------------------------------------------------------
    app_placeholders = ",".join("?" * len(visible_app_ids))
    vulns_sql = f"SELECT * FROM vulnerabilities WHERE app_id IN ({app_placeholders})"
    vulns_params: list = list(visible_app_ids)

    if severities_filter:
        sev_placeholders = ",".join("?" * len(severities_filter))
        vulns_sql += f" AND severity IN ({sev_placeholders})"
        vulns_params.extend(severities_filter)

    cursor = await db.execute(vulns_sql, vulns_params)
    all_vulns = await cursor.fetchall()

    # Group vulns by app_id for quick lookup
    vulns_by_app: dict[int, list] = {}
    for v in all_vulns:
        vulns_by_app.setdefault(v["app_id"], []).append(v)

    # ------------------------------------------------------------------
    # 3. Latest scan per scanner per app (with filters)
    # ------------------------------------------------------------------
    scan_vis_clause, scan_vis_params = scan_visibility_filter(user)

    extra_filters = ""
    extra_params: list = []

    # Restrict to visible apps
    extra_filters += f" AND scans.app_id IN ({app_placeholders})"
    extra_params.extend(visible_app_ids)

    if scanners_filter:
        placeholders = ",".join("?" * len(scanners_filter))
        extra_filters += f" AND scans.scanner_name IN ({placeholders})"
        extra_params.extend(scanners_filter)

    if labels_filter:
        placeholders = ",".join("?" * len(labels_filter))
        extra_filters += (
            " AND scans.id IN ("
            "SELECT scan_id FROM scan_labels JOIN labels ON scan_labels.label_id = labels.id "
            f"WHERE labels.name IN ({placeholders}))"
        )
        extra_params.extend(labels_filter)


    # Fetch all scans matching filters (ordered newest first). We need this
    # full set both for the "scan_count" column (all history) and to drive the
    # latest-per-(scanner, app[, family]) dedup below.
    all_matching_sql = f"""
        SELECT scans.*
        FROM scans
        LEFT JOIN apps ON scans.app_id = apps.id
        WHERE {scan_vis_clause}{extra_filters}
        ORDER BY scans.scan_date DESC, scans.created_at DESC
    """
    cursor = await db.execute(all_matching_sql, scan_vis_params + extra_params)
    all_matching = await cursor.fetchall()

    if not all_matching:
        return {
            "scanners": [],
            "filters": await _collect_filters(db, user),
        }

    # Derive family_value per scan if grouping. Scans with no label in the
    # chosen family get None and are excluded from the grouped comparison.
    family_value_by_scan: dict[int, str] = {}
    if grouping:
        all_scan_ids = [s["id"] for s in all_matching]
        ph = ",".join("?" * len(all_scan_ids))
        cursor = await db.execute(
            f"""SELECT sl.scan_id, l.name
                FROM scan_labels sl JOIN labels l ON sl.label_id = l.id
                WHERE sl.scan_id IN ({ph})""",
            all_scan_ids,
        )
        labels_by_scan: dict[int, list[str]] = {}
        for row in await cursor.fetchall():
            labels_by_scan.setdefault(row["scan_id"], []).append(row["name"])
        for sid, names in labels_by_scan.items():
            for name in names:
                if _label_family(name) == grouping:
                    family_value_by_scan[sid] = name
                    break

    # Dedup to latest scan per group key:
    #   group_by=None     -> key = (scanner_name, app_id)
    #   group_by=<family> -> key = (scanner_name, app_id, family_value)
    # all_matching is already in newest-first order, so first-seen wins.
    latest_scans = []
    seen_keys: set[tuple] = set()
    for s in all_matching:
        if grouping:
            fv = family_value_by_scan.get(s["id"])
            if fv is None:
                continue
            key = (s["scanner_name"], s["app_id"], fv)
        else:
            key = (s["scanner_name"], s["app_id"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        latest_scans.append(s)

    if not latest_scans:
        return {
            "scanners": [],
            "filters": await _collect_filters(db, user),
        }

    # Total visible scan count per group key (all history, not just latest-per-app).
    # Metrics still use latest-per-(scanner, app[, family]) to avoid double-counting
    # findings; this count is just the user-facing "Scans" column.
    total_scan_counts: dict[tuple, int] = {}
    for s in all_matching:
        if grouping:
            fv = family_value_by_scan.get(s["id"])
            if fv is None:
                continue
            k = (s["scanner_name"], fv)
        else:
            k = (s["scanner_name"],)
        total_scan_counts[k] = total_scan_counts.get(k, 0) + 1

    # ------------------------------------------------------------------
    # 4. Fetch findings for selected scans
    # ------------------------------------------------------------------
    scan_ids = [s["id"] for s in latest_scans]
    scan_placeholders = ",".join("?" * len(scan_ids))
    cursor = await db.execute(
        f"SELECT * FROM scan_findings WHERE scan_id IN ({scan_placeholders})",
        scan_ids,
    )
    all_findings = await cursor.fetchall()

    # Group findings by scan_id
    findings_by_scan: dict[int, list] = {}
    for f in all_findings:
        findings_by_scan.setdefault(f["scan_id"], []).append(f)

    # ------------------------------------------------------------------
    # 5. Aggregate per group (scanner_name, or (scanner_name, family_value))
    # ------------------------------------------------------------------
    scans_by_group: dict[tuple, list] = {}
    for s in latest_scans:
        if grouping:
            gk = (s["scanner_name"], family_value_by_scan[s["id"]])
        else:
            gk = (s["scanner_name"],)
        scans_by_group.setdefault(gk, []).append(s)

    # Build app lookup
    app_map = {a["id"]: a for a in visible_apps}

    scanner_results = []
    for group_key, scans in sorted(scans_by_group.items()):
        scanner_name = group_key[0]
        mode_value = group_key[1] if grouping else None
        # Collect all matched vuln ids across all scans for this scanner
        # keyed by (app_id, matched_vuln_id)
        tp_pairs: set[tuple[int, int]] = set()
        fp_count = 0
        total_cost = 0.0
        cost_count = 0
        total_tokens = 0
        tokens_count = 0
        total_duration = 0
        duration_count = 0

        # Per-app breakdown
        per_app: dict[int, dict] = {}
        # Per-severity breakdown
        per_severity: dict[str, dict] = {}

        for scan in scans:
            aid = scan["app_id"]
            findings = findings_by_scan.get(scan["id"], [])
            app_vulns = vulns_by_app.get(aid, [])
            app_vuln_ids = {v["id"] for v in app_vulns}

            # TP: unique (app_id, matched_vuln_id) where matched to an in-scope vuln
            scan_matched = set()
            scan_fp = 0
            for f in findings:
                if f["matched_vuln_id"] is not None and f["matched_vuln_id"] in app_vuln_ids:
                    tp_pairs.add((aid, f["matched_vuln_id"]))
                    scan_matched.add(f["matched_vuln_id"])
                if f["is_false_positive"] == 1:
                    fp_count += 1
                    scan_fp += 1

            # Per-app metrics
            scan_tp = len(scan_matched)
            scan_fn = len(app_vuln_ids - scan_matched)
            scan_precision = scan_tp / (scan_tp + scan_fp) if (scan_tp + scan_fp) > 0 else 0
            scan_recall = scan_tp / (scan_tp + scan_fn) if (scan_tp + scan_fn) > 0 else 0
            scan_f1 = (
                2 * scan_precision * scan_recall / (scan_precision + scan_recall)
                if (scan_precision + scan_recall) > 0 else 0
            )

            app_info = app_map.get(aid)
            per_app[aid] = {
                "app_id": aid,
                "app_name": app_info["name"] if app_info else str(aid),
                "tp": scan_tp,
                "fp": scan_fp,
                "fn": scan_fn,
                "total_vulns": len(app_vuln_ids),
                "precision": round(scan_precision, 4),
                "recall": round(scan_recall, 4),
                "f1": round(scan_f1, 4),
            }

            # Per-severity: tally detected/total per severity from this scan's app vulns
            for v in app_vulns:
                sev = v["severity"]
                if sev not in per_severity:
                    per_severity[sev] = {"total": 0, "detected": 0}
                per_severity[sev]["total"] += 1
                if v["id"] in scan_matched:
                    per_severity[sev]["detected"] += 1

            # Cost/tokens/duration
            if scan["cost"] is not None:
                total_cost += scan["cost"]
                cost_count += 1
            if scan["tokens"] is not None:
                total_tokens += scan["tokens"]
                tokens_count += 1
            if scan["duration"] is not None:
                total_duration += scan["duration"]
                duration_count += 1

        # Global metrics for this scanner
        tp = len(tp_pairs)
        # FN: count of in-scope vulns not detected by any scan of this scanner
        all_detected_by_scanner: dict[int, set[int]] = {}
        for a_id, v_id in tp_pairs:
            all_detected_by_scanner.setdefault(a_id, set()).add(v_id)

        fn = 0
        for scan in scans:
            aid = scan["app_id"]
            app_vulns = vulns_by_app.get(aid, [])
            detected = all_detected_by_scanner.get(aid, set())
            for v in app_vulns:
                if v["id"] not in detected:
                    fn += 1

        # Deduplicate FN: we already counted per-app above, but multiple scans
        # on same app would double-count. Since we took latest per scanner per app,
        # each app appears exactly once per scanner, so no dedup needed.

        precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # Severity breakdown with recall
        severity_breakdown = []
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in per_severity:
                s = per_severity[sev]
                sev_recall = s["detected"] / s["total"] if s["total"] > 0 else 0
                severity_breakdown.append({
                    "severity": sev,
                    "total": s["total"],
                    "detected": s["detected"],
                    "recall": round(sev_recall, 4),
                })

        sev_dict = {}
        for s in severity_breakdown:
            sev_dict[s["severity"]] = {
                "total": s["total"],
                "detected": s["detected"],
                "recall": s["recall"],
            }

        avg_cost = round(total_cost / cost_count, 4) if cost_count > 0 else None
        # value = F1 per $1k (cost-aware quality). None when cost data is missing
        # or zero (avoid divide-by-zero / spurious infinity).
        value = round(f1 / (avg_cost / 1000.0), 4) if (avg_cost and avg_cost > 0) else None

        entry = {
            "name": scanner_name,
            "scan_count": total_scan_counts.get(group_key, len(scans)),
            "app_count": len(per_app),
            "metrics": {
                "tp": tp,
                "fp": fp_count,
                "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            },
            "avg_cost": avg_cost,
            "avg_tokens": round(total_tokens / tokens_count) if tokens_count > 0 else None,
            "avg_duration": round(total_duration / duration_count) if duration_count > 0 else None,
            "value": value,
            "by_severity": sev_dict,
            "by_app": sorted(per_app.values(), key=lambda x: x["app_name"]),
        }
        if mode_value is not None:
            entry["mode"] = mode_value
        scanner_results.append(entry)

    # Sort by F1 descending
    scanner_results.sort(key=lambda s: -s["metrics"]["f1"])

    return {
        "scanners": scanner_results,
        "filters": await _collect_filters(db, user),
    }


async def _collect_filters(db, user) -> dict:
    """Collect available filter options scoped to what the user can see."""
    scan_vis_clause, scan_vis_params = scan_visibility_filter(user)
    app_vis_clause, app_vis_params = app_visibility_filter(user)

    # Distinct scanner names
    cursor = await db.execute(
        f"""SELECT DISTINCT scans.scanner_name
            FROM scans LEFT JOIN apps ON scans.app_id = apps.id
            WHERE {scan_vis_clause}
            ORDER BY scans.scanner_name""",
        scan_vis_params,
    )
    scanners = [row["scanner_name"] for row in await cursor.fetchall()]

    # All labels
    cursor = await db.execute("SELECT DISTINCT name FROM labels ORDER BY name")
    labels = [row["name"] for row in await cursor.fetchall()]

    # Tech from visible apps
    cursor = await db.execute(
        f"""SELECT DISTINCT at.name
            FROM app_technologies at
            JOIN apps ON at.app_id = apps.id
            WHERE {app_vis_clause}
            ORDER BY at.name""",
        app_vis_params,
    )
    techs = [row["name"] for row in await cursor.fetchall()]

    # Visible apps
    cursor = await db.execute(
        f"""SELECT apps.id, apps.name
            FROM apps WHERE {app_vis_clause}
            ORDER BY apps.name""",
        app_vis_params,
    )
    apps = [{"id": row["id"], "name": row["name"]} for row in await cursor.fetchall()]

    # Teams (from visible team-scoped apps)
    cursor = await db.execute(
        f"""SELECT DISTINCT teams.id, teams.name
            FROM teams
            JOIN apps ON apps.team_id = teams.id
            WHERE {app_vis_clause}
            ORDER BY teams.name""",
        app_vis_params,
    )
    teams = [{"id": row["id"], "name": row["name"]} for row in await cursor.fetchall()]

    return {
        "scanners": scanners,
        "labels": labels,
        "techs": techs,
        "apps": apps,
        "teams": teams,
    }
