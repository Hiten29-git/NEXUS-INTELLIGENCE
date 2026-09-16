from fastapi import APIRouter

from backend.services.asset_service import get_assets


router = APIRouter()


@router.get("/assets")
def assets():
    """
    Return the current NEXUS live asset inventory.
    """

    return get_assets()
