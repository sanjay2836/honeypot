"""
FastAPI Main Application for Honeypot Analytics Engine & SOC Dashboard.
"""
import os
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .database import init_db
from .ws_manager import ws_manager
from . import recovery
from .api import events, analytics, services, simulator
from .api import recovery as recovery_api

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("honeypot.backend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify the threat store BEFORE touching it; auto-restore if damaged
    logger.info("Verifying Honeypot Threat Store integrity...")
    outcome = await asyncio.to_thread(recovery.auto_recover)
    if outcome["action"] != "none":
        logger.warning("Startup recovery performed: %s", outcome)

    logger.info("Initializing Honeypot Threat Store & Database Schema...")
    init_db()

    # Snapshot on boot (covers fresh installs) and keep snapshotting in the background
    await asyncio.to_thread(recovery.create_backup, "startup")
    maintenance = asyncio.create_task(recovery.maintenance_loop())
    logger.info("Honeypot Backend ready.")
    yield
    logger.info("Honeypot Backend shutting down.")
    maintenance.cancel()
    try:
        await maintenance
    except asyncio.CancelledError:
        pass
    await asyncio.to_thread(recovery.create_backup, "shutdown")

app = FastAPI(
    title="Honeypot Threat Intelligence Engine",
    description="Real-time deception-based attack pattern analysis and threat intelligence platform.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local dev and dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(events.router)
app.include_router(analytics.router)
app.include_router(services.router)
app.include_router(simulator.router)
app.include_router(recovery_api.router)

# WebSocket Endpoint for real-time dashboard updates
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and accept any client heartbeats/pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "PONG"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket client error: {e}")
        ws_manager.disconnect(websocket)

# Serve dashboard static files if directory exists
DASHBOARD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dashboard"))

if os.path.exists(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @app.get("/")
    async def serve_dashboard():
        index_path = os.path.join(DASHBOARD_DIR, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Honeypot API is running. Dashboard index.html not found."}
else:
    @app.get("/")
    async def root():
        return {"status": "online", "message": "Honeypot Analytics API is operational"}
