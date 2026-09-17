from fastapi import APIRouter, Query

from backend.services.blast_radius_service import (
    calculate_blast_radius
)


router = APIRouter(
    prefix="/blast-radius",
    tags=["Blast Radius"]
)


@router.get("")
def blast_radius(
    start_node: str = Query(...),
    max_hops: int = Query(3, ge=1, le=5)
):
    return calculate_blast_radius(
        start_node=start_node,
        max_hops=max_hops
    )
