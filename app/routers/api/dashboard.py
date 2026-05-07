from fastapi import APIRouter, Request
from app.database import get_connection
from app.services import dashboard as dashboard_service

router = APIRouter()


@router.get("")
async def dashboard(
    request: Request,
    scanner: str = "",
    severity: str = "",
    label: str = "",
    tech: str = "",
    app_id: str = "",
    authenticated: str = "",
):
    user = request.state.user
    db = await get_connection()
    try:
        result = await dashboard_service.get_dashboard(
            db, user,
            scanner=scanner or None,
            severity=severity or None,
            label=label or None,
            tech=tech or None,
            app_id=app_id or None,
            authenticated=authenticated or None,
        )
    finally:
        await db.close()
    return result
