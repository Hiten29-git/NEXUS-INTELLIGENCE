from fastapi import APIRouter

from backend.services.graph_service import (
    check_connection,
    ingest_live_events,
    rebuild_live_graph,
    get_topology
)

from backend.services.graph_evidence_service import (
    get_graph_evidence
)


router = APIRouter()


@router.get("/graph/health")
def graph_health():

    return {
        "neo4j_connected":
            check_connection()
    }


@router.post("/graph/ingest")
def graph_ingest():

    return ingest_live_events()


@router.post("/graph/rebuild")
def graph_rebuild():

    return rebuild_live_graph()


@router.get("/graph/topology")
def graph_topology():

    return get_topology()


@router.get("/graph/evidence")
def graph_evidence():

    return get_graph_evidence()
