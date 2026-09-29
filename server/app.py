import os
import json
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from engine.core_engine import CoreEngine
from server.websocket_manager import WebSocketManager
from server.routes_incidents import create_incidents_router
from server.routes_simulator import create_simulator_router
from server.routes_threat_lab import create_threat_lab_router
from server.routes_recovery import create_recovery_router
from server.routes_config import create_config_router

# Load Configuration
CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config.json"))
config = {}
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        print(f"[App] Error loading config: {e}")

# Global Engine & WS Manager
engine = CoreEngine(config)
ws_manager = WebSocketManager()

# Forward Engine Alerts to WebSocket Clients in Real-Time
def on_alert_dispatched(alert):
    try:
        # Schedule async broadcast in loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast({
                "type": "ALERT",
                "data": alert.model_dump()
            }))
    except Exception:
        pass

engine.alert_dispatcher.register_listener(on_alert_dispatched)

# Background Telemetry Ticker
async def telemetry_broadcaster():
    while True:
        try:
            if len(ws_manager.active_connections) > 0:
                telemetry = engine.get_telemetry()
                recent_activity = engine.fs_sensor.get_recent_activity(10)
                await ws_manager.broadcast({
                    "type": "TELEMETRY",
                    "data": telemetry.model_dump(),
                    "recent_activity": recent_activity
                })
        except Exception as e:
            pass
        await asyncio.sleep(1.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start Core Engine & Telemetry Broadcaster
    engine.start()
    ticker_task = asyncio.create_task(telemetry_broadcaster())
    yield
    # Shutdown: Stop Engine
    ticker_task.cancel()
    engine.stop()

app = FastAPI(
    title="RansomVanguard EDR",
    description="Autonomous Windows Server Ransomware Detection, Containment & Self-Healing Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attach API Routers
app.include_router(create_incidents_router(engine))
app.include_router(create_simulator_router(engine))
app.include_router(create_threat_lab_router(engine))
app.include_router(create_recovery_router(engine))
app.include_router(create_config_router(engine))

# WebSocket Endpoint
@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open and accept any ping messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)

# Serve Web UI
WEB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "web"))
if os.path.exists(WEB_DIR):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(WEB_DIR, "index.html"))
