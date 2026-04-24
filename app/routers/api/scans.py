from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.services import scans as scans_service
from app.services import labels as labels_service
from app.dependencies import require_user, require_scope, get_current_user

router = APIRouter()
submit_router = APIRouter()
labels_router = APIRouter()


# ---------------------------------------------------------------------------
# Scan CRUD (mounted at /api/scans)
# ---------------------------------------------------------------------------

@router.get("")
async def list_scans(
    request: Request,
    app_id: str = "",
    scanner: str = "",
    latest: str = "",
    q: str = "",
    authenticated: str = "",
    label: str = "",
    filter: str = "",
):
    user = request.state.user
    db = await get_connection()
    try:
        parsed_app_id = None
        if app_id:
            try:
                parsed_app_id = int(app_id)
            except ValueError:
                raise HTTPException(status_code=404, detail="Invalid app_id")

        result = await scans_service.list_scans(
            db, user,
            app_id=parsed_app_id,
            scanner=scanner,
            latest=latest,
            q=q,
            authenticated=authenticated,
            label=label,
            filter=filter,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {
        "scans": [dict(s) for s in result["scans"]],
        "scan_labels_map": result["scan_labels_map"],
        "scanners": result["scanners"],
        "apps_list": [dict(a) for a in result["apps_list"]],
        "all_labels": result["all_labels"],
    }


@router.get("/{scan_id}")
async def get_scan(request: Request, scan_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        result = await scans_service.get_scan(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.delete("/{scan_id}")
async def delete_scan(request: Request, scan_id: int):
    user = await require_user(request)
    db = await get_connection()
    try:
        await scans_service.delete_scan(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"ok": True}


# ---------------------------------------------------------------------------
# Finding operations (mounted at /api/scans)
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/findings/{finding_id}/match")
async def match_finding(request: Request, scan_id: int, finding_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()
    vuln_id = body.get("vuln_id")

    db = await get_connection()
    try:
        result = await scans_service.match_finding(db, user, scan_id, finding_id, vuln_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.post("/{scan_id}/findings/{finding_id}/mark-fp")
async def mark_finding_fp(request: Request, scan_id: int, finding_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")

    db = await get_connection()
    try:
        await scans_service.mark_finding_fp(db, user, scan_id, finding_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"ok": True}


@router.post("/{scan_id}/rematch")
async def rematch_scan(request: Request, scan_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")

    db = await get_connection()
    try:
        result = await scans_service.rematch_scan(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


# ---------------------------------------------------------------------------
# Labels on scans (mounted at /api/scans)
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/labels")
async def add_label(request: Request, scan_id: int):
    user = await require_user(request)
    body = await request.json()
    name = body.get("name", "")
    color = body.get("color", "#f97316")

    db = await get_connection()
    try:
        result = await labels_service.add_label_to_scan(db, user, scan_id, name, color)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.delete("/{scan_id}/labels/{label_id}")
async def remove_label(request: Request, scan_id: int, label_id: int):
    user = await require_user(request)

    db = await get_connection()
    try:
        await labels_service.remove_label_from_scan(db, user, scan_id, label_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"ok": True}


# ---------------------------------------------------------------------------
# Scan submission (mounted at /api/apps)
# ---------------------------------------------------------------------------

@submit_router.post("/{app_id}/scans")
async def submit_scan(request: Request, app_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()

    scanner_name = body.get("scanner_name", "")
    scan_date = body.get("scan_date", "")
    authenticated = 1 if body.get("authenticated") else 0
    is_public = 1 if body.get("is_public", True) else 0
    notes = body.get("notes")
    cost = body.get("cost")
    if cost is not None:
        try:
            cost = float(cost)
        except (TypeError, ValueError):
            cost = None
    findings_data = body.get("findings", [])
    scan_labels = body.get("labels")

    db = await get_connection()
    try:
        scan_id = await scans_service.submit_scan(
            db, user, app_id,
            scanner_name=scanner_name,
            scan_date=scan_date,
            authenticated=authenticated,
            is_public=is_public,
            notes=notes,
            cost=cost,
            findings_data=findings_data,
            labels=scan_labels,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"scan_id": scan_id}


# ---------------------------------------------------------------------------
# Compare (mounted at /api/apps)
# ---------------------------------------------------------------------------

@submit_router.get("/{app_id}/compare")
async def compare_scans(request: Request, app_id: int, scans: str = ""):
    user = request.state.user

    db = await get_connection()
    try:
        if scans:
            scan_ids = [int(s) for s in scans.split(",") if s.strip().isdigit()][:7]
            result = await scans_service.compare_scans(db, user, app_id, scan_ids)
        else:
            available = await scans_service.get_available_scans(db, user, app_id)
            result = {"available_scans": [dict(s) for s in available]}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


# ---------------------------------------------------------------------------
# Labels list (mounted at /api/labels)
# ---------------------------------------------------------------------------

@labels_router.get("")
async def list_labels():
    db = await get_connection()
    try:
        labels = await labels_service.list_labels(db)
    finally:
        await db.close()

    return {"labels": labels}
