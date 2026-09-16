from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes.metrics import router as metrics_router
from backend.routes.alerts import router as alerts_router
from backend.routes.graph import router as graph_router
from backend.routes.attack_chains import router as attack_chains_router
from backend.routes.assets import router as assets_router
from backend.routes.intelligence import router as intelligence_router


app = FastAPI(
    title="NEXUS INTELLIGENCE API",
    description="AI-driven cybersecurity intelligence and threat analysis backend",
    version="1.0.0",
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# ROOT
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "NEXUS INTELLIGENCE",
        "status": "online",
        "version": "1.0.0",
        "description": "AI-driven cybersecurity intelligence platform",
    }


# ---------------------------------------------------------
# HEALTH
# ---------------------------------------------------------

@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "service": "NEXUS INTELLIGENCE API",
        "version": "1.0.0",
    }


# ---------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------

app.include_router(
    metrics_router,
    prefix="/api/v1",
)

app.include_router(
    alerts_router,
    prefix="/api/v1",
)

app.include_router(
    graph_router,
    prefix="/api/v1",
)

app.include_router(
    attack_chains_router,
    prefix="/api/v1",
)

app.include_router(
    assets_router,
    prefix="/api/v1",
)

app.include_router(
    intelligence_router,
    prefix="/api/v1",
)


# ---------------------------------------------------------
# STARTUP
# ---------------------------------------------------------

@app.on_event("startup")
def startup_event():
    print("=" * 60)
    print("NEXUS INTELLIGENCE API")
    print("Backend startup successful")
    print("API: http://127.0.0.1:8000")
    print("Docs: http://127.0.0.1:8000/docs")
    print("=" * 60)
