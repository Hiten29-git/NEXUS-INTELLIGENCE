from fastapi import APIRouter

from backend.services.graph_service import (
    check_connection,
    ingest_live_events,
    get_topology,
)


router = APIRouter()


@router.get("/graph/health")
def graph_health():
    return {
        "neo4j_connected": check_connection()
    }


@router.post("/graph/ingest")
def graph_ingest():
    return ingest_live_events()


@router.get("/graph/topology")
def graph_topology():
    return get_topology()
