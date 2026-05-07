from __future__ import annotations

from app.visibility import app_visibility_filter, scan_visibility_filter


def _parse_csv(value: str | None) -> list[str] | None:
    """Parse a comma-separated string into a list, or return None."""
    if not value:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items or None


async def get_dashboard(
    db, user,
    scanner=None, severity=None, label=None, tech=None,
    app_id=None, team=None,
) -> dict:
    """Aggregate scanner benchmarking data across all visible apps.

    Returns per-scanner metrics (TP/FP/FN/precision/recall/F1),
    breakdowns by severity and app, and available filter options.
    """
    scanners_filter = _parse_csv(scanner)
    severities_filter = _parse_csv(severity)
    labels_filter = _parse_csv(label)
    techs_filter = _parse_csv(tech)
    app_ids_filter = _parse_csv(app_id)

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


    ranked_sql = f"""
        WITH ranked AS (
            SELECT scans.*, ROW_NUMBER() OVER (
                PARTITION BY scans.scanner_name, scans.app_id
                ORDER BY scans.scan_date DESC, scans.created_at DESC
            ) as rn
            FROM scans
            LEFT JOIN apps ON scans.app_id = apps.id
            WHERE {scan_vis_clause}{extra_filters}
        )
        SELECT * FROM ranked WHERE rn = 1
    """
    cursor = await db.execute(ranked_sql, scan_vis_params + extra_params)
    latest_scans = await cursor.fetchall()

    if not latest_scans:
        return {
            "scanners": [],
            "filters": await _collect_filters(db, user),
        }

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
    # 5. Aggregate per scanner
    # ------------------------------------------------------------------
    # Group scans by scanner_name
    scans_by_scanner: dict[str, list] = {}
    for s in latest_scans:
        scans_by_scanner.setdefault(s["scanner_name"], []).append(s)

    # Build app lookup
    app_map = {a["id"]: a for a in visible_apps}

    scanner_results = []
    for scanner_name, scans in sorted(scans_by_scanner.items()):
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

        scanner_results.append({
            "name": scanner_name,
            "scan_count": len(scans),
            "app_count": len(per_app),
            "metrics": {
                "tp": tp,
                "fp": fp_count,
                "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            },
            "avg_cost": round(total_cost / cost_count, 4) if cost_count > 0 else None,
            "avg_tokens": round(total_tokens / tokens_count) if tokens_count > 0 else None,
            "avg_duration": round(total_duration / duration_count) if duration_count > 0 else None,
            "by_severity": sev_dict,
            "by_app": sorted(per_app.values(), key=lambda x: x["app_name"]),
        })

    # Sort scanners by F1 descending
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
