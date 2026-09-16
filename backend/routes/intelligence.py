from fastapi import APIRouter
from backend.services.intelligence_fusion_service import get_intelligence

router = APIRouter(
    prefix="/intelligence",
    tags=["Intelligence"],
)


@router.get("")
def intelligence():
    return get_intelligence()
