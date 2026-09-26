import os
from pathlib import Path
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from ingestion.api import router as ingestion_router
from dashboard.api import router as dashboard_router

app = FastAPI(
    title="CyberGuard — AI Threat Detection System",
    description="Multi-engine threat detection pipeline, correlation graph, risk scoring, and SOC dashboard",
    version="1.0.0",
)

# Enable CORS for frontend / dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for dashboard web UI
STATIC_DIR = Path(__file__).resolve().parent / "dashboard" / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def serve_dashboard():
    """Serves the main CyberGuard SOC interactive dashboard."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "CyberGuard API running. Access /docs for Swagger UI."}


# Include API routers
app.include_router(ingestion_router)
app.include_router(dashboard_router)


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
