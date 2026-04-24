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

    vulns_data: list[dict] = []

    if file and file.filename:
        # File upload path
        content = await file.read()
        text = content.decode("utf-8")

        if file.filename.endswith(".json"):
            parsed = json.loads(text)
            if isinstance(parsed, list):
                vulns_data = parsed
            elif isinstance(parsed, dict) and "vulnerabilities" in parsed:
                vulns_data = parsed["vulnerabilities"]
            else:
                raise HTTPException(
                    status_code=400,
                    detail="JSON must be an array or {vulnerabilities: [...]}",
                )
        elif file.filename.endswith(".csv"):
            reader = csv.DictReader(io.StringIO(text))
            vulns_data = list(reader)
        else:
            raise HTTPException(
                status_code=400, detail="Unsupported file type. Use .json or .csv"
            )
    else:
        # JSON body path
        body = await request.json()
        vulns_data = body.get("vulnerabilities", [])

    db = await get_connection()
    try:
        count = await vulns_service.import_vulns(db, user, app_id, vulns_data)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"imported": count}
