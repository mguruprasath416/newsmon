from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, Set
import asyncio
import json
import structlog

log = structlog.get_logger()
router = APIRouter()

# Connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str):
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = set()
        self.active_connections[channel].add(websocket)
        log.info("WS connected", channel=channel, total=len(self.active_connections.get(channel, [])))

    def disconnect(self, websocket: WebSocket, channel: str):
        if channel in self.active_connections:
            self.active_connections[channel].discard(websocket)

    async def send_to_channel(self, channel: str, data: dict):
        if channel in self.active_connections:
            dead = set()
            for ws in self.active_connections[channel]:
                try:
                    await ws.send_json(data)
                except Exception:
                    dead.add(ws)
            self.active_connections[channel] -= dead

    async def broadcast(self, data: dict):
        for channel_ws in self.active_connections.values():
            dead = set()
            for ws in channel_ws:
                try:
                    await ws.send_json(data)
                except Exception:
                    dead.add(ws)
            channel_ws -= dead


manager = ConnectionManager()


@router.websocket("/lens/{job_id}")
async def lens_progress(websocket: WebSocket, job_id: str):
    """Stream Advisory Lens analysis progress."""
    channel = f"lens:{job_id}"
    await manager.connect(websocket, channel)
    try:
        from app.db.mongodb import get_reports_collection
        col = get_reports_collection()

        # Poll job status and stream updates
        last_status = None
        last_progress = -1
        while True:
            doc = await col.find_one({"job_id": job_id}, {"status": 1, "progress": 1, "error": 1})
            if doc:
                current_status = doc.get("status")
                current_progress = doc.get("progress", 0)

                if current_status != last_status or current_progress != last_progress:
                    await websocket.send_json({
                        "job_id": job_id,
                        "status": current_status,
                        "progress": current_progress,
                        "error": doc.get("error"),
                    })
                    last_status = current_status
                    last_progress = current_progress

                if current_status in ("complete", "failed"):
                    break

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)


@router.websocket("/feed")
async def feed_updates(websocket: WebSocket):
    """Stream real-time new article notifications."""
    channel = "feed"
    await manager.connect(websocket, channel)
    try:
        while True:
            await asyncio.sleep(30)  # Heartbeat
            await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)


# Export manager for use in services
ws_manager = manager
