from __future__ import annotations

import csv
import io
import json
import re
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from fastapi.responses import Response
from app.database import get_connection
from app.dependencies import require_scope
from app.services import vulns as vulns_service

router = APIRouter()


def _safe_filename(name: str | None) -> str:
    """Reduce an app name to a filename-safe stem for Content-Disposition.

    Strips anything that isn't alnum/dot/dash/space/underscore so a crafted
    app name can't inject extra header directives, then collapses spaces.
    """
    stem = re.sub(r"[^A-Za-z0-9._ -]", "", name or "").strip()
    stem = re.sub(r"\s+", "-", stem)
    return stem or "app"


@router.get("/{app_id}/vulns")
async def list_vulns(request: Request, app_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        result = await vulns_service.list_vulns(db, user, app_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await db.close()
    return {"vulnerabilities": result}


@router.get("/{app_id}/vulns/export")
async def export_vulns(request: Request, app_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        csv_text, app_name = await vulns_service.export_vulns_csv(db, user, app_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await db.close()
    filename = _safe_filename(app_name) + "-vulns.csv"
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{app_id}/vulns/{vuln_id}")
async def get_vuln(request: Request, app_id: int, vuln_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        result = await vulns_service.get_vuln(db, user, app_id, vuln_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await db.close()
    return result


@router.post("/{app_id}/vulns")
async def create_vuln(request: Request, app_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    db = await get_connection()
    try:
        vuln = await vulns_service.create_vuln(db, user, app_id, body)
    except ValueError as e:
        # "maximum ... vulnerabilities" is a capacity limit and an invalid
        # impact_weight/difficulty_tier is a bad request (400) — neither is a
        # missing-app error (404).
        msg = str(e)
        status = 400 if ("maximum" in msg or "must be one of" in msg) else 404
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"vulnerability": vuln}


@router.put("/{app_id}/vulns/{vuln_id}")
async def update_vuln(request: Request, app_id: int, vuln_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    db = await get_connection()
    try:
        vuln = await vulns_service.update_vuln(db, user, app_id, vuln_id, body)
    except ValueError as e:
        msg = str(e)
        raise HTTPException(status_code=400 if "must be one of" in msg else 404, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"vulnerability": vuln}


@router.delete("/{app_id}/vulns/{vuln_id}")
async def delete_vuln(request: Request, app_id: int, vuln_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    db = await get_connection()
    try:
        await vulns_service.delete_vuln(db, user, app_id, vuln_id)
    except ValueError as e:
        msg = str(e)
        # A matched vuln can't be deleted — that's a conflict with recorded
        # measurements, not a missing resource.
        status = 409 if "cannot be deleted" in msg else 404
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


@router.post("/{app_id}/vulns/{vuln_id}/invalidate")
async def invalidate_vuln(request: Request, app_id: int, vuln_id: int):
    """Retire a vuln from ground truth from the next revision onward.

    Body (optional): ``{"notes": "why"}``. Historical scorings keep the vuln in
    scope and stay reproducible; the current revision drops it.
    """
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    raw = await request.body()
    notes = None
    if raw:
        try:
            notes = (json.loads(raw) or {}).get("notes")
        except (ValueError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="Invalid JSON body")

    db = await get_connection()
    try:
        result = await vulns_service.invalidate_vuln(db, user, app_id, vuln_id, notes)
    except ValueError as e:
        msg = str(e)
        status = 409 if "already invalidated" in msg else 404
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return result


@router.post("/{app_id}/vulns/import")
async def import_vulns(
    request: Request,
    app_id: int,
    file: Optional[UploadFile] = File(None),
):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    vulns_data: list[dict] = []
    # Whether the imported flaws were present all along. Query param so the
    # multipart upload path can set it too; a JSON body may override it below.
    existed_since = request.query_params.get("existed_since")

    if file and file.filename:
        # File upload path. Each parser failure becomes a generic 400 so the
        # response never reflects the raw Python exception message — which
        # previously leaked stack-trace style content (vuln-0022).
        content = await file.read()
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File must be UTF-8")

        filename = file.filename.lower()
        if filename.endswith(".json"):
            try:
                parsed = json.loads(text)
            except (ValueError, json.JSONDecodeError):
                raise HTTPException(status_code=400, detail="Invalid JSON")
            if isinstance(parsed, list):
                vulns_data = parsed
            elif isinstance(parsed, dict) and isinstance(parsed.get("vulnerabilities"), list):
                vulns_data = parsed["vulnerabilities"]
            else:
                raise HTTPException(
                    status_code=400,
                    detail="JSON must be an array or {vulnerabilities: [...]}",
                )
        elif filename.endswith(".csv"):
            try:
                reader = csv.DictReader(io.StringIO(text))
                vulns_data = list(reader)
            except csv.Error:
                raise HTTPException(status_code=400, detail="Invalid CSV")
        else:
            raise HTTPException(
                status_code=400, detail="Unsupported file type. Use .json or .csv"
            )
    else:
        # JSON body path
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="Body must be a JSON object")
        vulns_data = body.get("vulnerabilities", [])
        existed_since = body.get("existed_since", existed_since)

    if not isinstance(vulns_data, list) or not all(
        isinstance(v, dict) for v in vulns_data
    ):
        raise HTTPException(
            status_code=400,
            detail="Expected a list of vulnerability objects",
        )

    db = await get_connection()
    try:
        result = await vulns_service.import_vulns(
            db, user, app_id, vulns_data, existed_since=existed_since
        )
    except ValueError as e:
        # Domain-level errors only ("App not found"). UnicodeEncodeError is a
        # subclass of ValueError; map it to a generic 400 instead of leaking
        # the raw codec message (vuln-0022).
        if isinstance(e, UnicodeError):
            raise HTTPException(status_code=400, detail="Invalid characters in input")
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    # result: {imported, skipped_over_cap, truncated_fields}. `imported` stays
    # top-level for backward compatibility with existing clients.
    return result
