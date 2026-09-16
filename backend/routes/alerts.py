from fastapi import APIRouter

from backend.services.alert_service import build_alerts


router = APIRouter()


@router.get("/alerts")
def alerts():
    return build_alerts()
