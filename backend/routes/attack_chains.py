from fastapi import APIRouter

from backend.services.attack_path_service import get_attack_chains


router = APIRouter()


@router.get("/attack-chains")
def attack_chains():
    return get_attack_chains()
