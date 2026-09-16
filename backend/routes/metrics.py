from fastapi import APIRouter

from backend.services.intelligence_service import get_metrics


router = APIRouter()


@router.get("/metrics")
def metrics():
    return get_metrics()
