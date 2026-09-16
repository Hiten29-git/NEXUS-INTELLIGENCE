from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes.metrics import router as metrics_router
from backend.routes.alerts import router as alerts_router
from backend.routes.graph import router as graph_router
from backend.routes.attack_chains import router as attack_chains_router


app = FastAPI(
    title="NEXUS Intelligence API",
    version="1.0.0",
    description="Backend integration API for NEXUS Intelligence"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    metrics_router,
    prefix="/api/v1"
)

app.include_router(
    alerts_router,
    prefix="/api/v1"
)

app.include_router(
    graph_router,
    prefix="/api/v1"
)


@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "engine": "NEXUS-Intelligence-Engine"
    }

app.include_router(
    attack_chains_router,
    prefix="/api/v1"
)
