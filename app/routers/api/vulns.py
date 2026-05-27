from __future__ import annotations

import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from app.database import get_connection
from app.dependencies import require_scope
from app.services import vulns as vulns_service

router = APIRouter()


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
        raise HTTPException(status_code=404, detail=str(e))
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
        raise HTTPException(status_code=404, detail=str(e))
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
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


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

    if not isinstance(vulns_data, list) or not all(
        isinstance(v, dict) for v in vulns_data
    ):
        raise HTTPException(
            status_code=400,
            detail="Expected a list of vulnerability objects",
        )

    db = await get_connection()
    try:
        count = await vulns_service.import_vulns(db, user, app_id, vulns_data)
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
    return {"imported": count}
