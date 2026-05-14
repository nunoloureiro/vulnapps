from __future__ import annotations

from app.visibility import scan_visibility_filter
from app.services.dashboard import get_dashboard


async def list_scanners(db, user) -> list:
    """Per-scanner aggregate metrics across all visible apps.

    Reuses the dashboard aggregation so the numbers stay consistent.
    """
    data = await get_dashboard(db, user)
    return data["scanners"]


async def get_scanner_detail(db, user, name: str, app_id: str | None = None) -> dict:
    """Detailed view of a single scanner.

    *app_id* (CSV) filters every section: summary metrics, charts, per-app table,
    scans table — so all numbers stay internally consistent.

    Returns:
        summary: same shape as one entry from list_scanners() — overall metrics +
            severity breakdown + per-app latest-scan breakdown.
        time_series: every visible scan for this scanner (or only those on the
            selected apps if filtered), oldest first, with tp/fp/fn/precision/
            recall/f1 computed per scan plus cost/tokens/duration.
        labels: distinct labels applied to this scanner's scans (after the app
            filter), with frequency.
        available_apps: every app this scanner has ever scanned that the user
            can see (full list, unfiltered) — used to populate the filter UI.

    Raises ValueError if no scans for this scanner are visible.
    """
    overall = await get_dashboard(db, user, scanner=name, app_id=app_id)
    summary = next((s for s in overall["scanners"] if s["name"] == name), None)
    if not summary:
        raise ValueError("Scanner not found")

    scan_vis, scan_params = scan_visibility_filter(user)

    # Available apps (unfiltered) for the filter UI
    cursor = await db.execute(
        f"""SELECT DISTINCT apps.id, apps.name
            FROM scans LEFT JOIN apps ON scans.app_id = apps.id
            WHERE scans.scanner_name = ? AND {scan_vis}
            ORDER BY apps.name""",
        [name] + scan_params,
    )
    available_apps = [{"id": r["id"], "name": r["name"]} for r in await cursor.fetchall()]

    # Time-series scans (filtered)
    app_filter_sql = ""
    app_filter_params: list = []
    if app_id:
        ids = [int(x) for x in app_id.split(",") if x.strip().isdigit()]
        if ids:
            placeholders = ",".join("?" * len(ids))
            app_filter_sql = f" AND scans.app_id IN ({placeholders})"
            app_filter_params = ids

    cursor = await db.execute(
        f"""SELECT scans.*, apps.name as app_name
            FROM scans LEFT JOIN apps ON scans.app_id = apps.id
            WHERE scans.scanner_name = ? AND {scan_vis}{app_filter_sql}
            ORDER BY scans.scan_date, scans.created_at""",
        [name] + scan_params + app_filter_params,
    )
    scans = await cursor.fetchall()

    if not scans:
        raise ValueError("No visible scans for this scanner")

    scan_ids = [s["id"] for s in scans]
    app_ids = list({s["app_id"] for s in scans})

    scan_placeholders = ",".join("?" * len(scan_ids))
    cursor = await db.execute(
        f"SELECT * FROM scan_findings WHERE scan_id IN ({scan_placeholders})",
        scan_ids,
    )
    findings_by_scan: dict[int, list] = {}
    for f in await cursor.fetchall():
        findings_by_scan.setdefault(f["scan_id"], []).append(f)

    app_placeholders = ",".join("?" * len(app_ids))
    cursor = await db.execute(
        f"SELECT * FROM vulnerabilities WHERE app_id IN ({app_placeholders})",
        app_ids,
    )
    vulns_by_app: dict[int, list] = {}
    for v in await cursor.fetchall():
        vulns_by_app.setdefault(v["app_id"], []).append(v)

    time_series = []
    for s in scans:
        findings = findings_by_scan.get(s["id"], [])
        app_vulns = vulns_by_app.get(s["app_id"], [])
        app_vuln_ids = {v["id"] for v in app_vulns}

        matched: set[int] = set()
        fp = 0
        for f in findings:
            if f["matched_vuln_id"] is not None and f["matched_vuln_id"] in app_vuln_ids:
                matched.add(f["matched_vuln_id"])
            if f["is_false_positive"] == 1:
                fp += 1

        tp = len(matched)
        fn = len(app_vuln_ids) - tp
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0 else 0
        )

        time_series.append({
            "scan_id": s["id"],
            "app_id": s["app_id"],
            "app_name": s["app_name"],
            "scan_date": s["scan_date"],
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "cost": s["cost"],
            "tokens": s["tokens"],
            "duration": s["duration"],
        })

    cursor = await db.execute(
        f"""SELECT l.id, l.name, l.color, COUNT(*) as count
            FROM labels l
            JOIN scan_labels sl ON sl.label_id = l.id
            WHERE sl.scan_id IN ({scan_placeholders})
            GROUP BY l.id, l.name, l.color
            ORDER BY count DESC, l.name""",
        scan_ids,
    )
    labels = [dict(row) for row in await cursor.fetchall()]

    return {
        "name": name,
        "summary": summary,
        "time_series": time_series,
        "labels": labels,
        "available_apps": available_apps,
    }
