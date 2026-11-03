"""
WebSocket Connection Manager for live real-time dashboard telemetry streaming.
"""
from typing import List
import json
import logging
from fastapi import WebSocket

logger = logging.getLogger("honeypot.ws")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast_event(self, event_data: dict):
        """Broadcast a new honeypot event or alert to all active dashboard connections."""
        if not self.active_connections:
            return

        message = {
            "type": "NEW_EVENT",
            "data": event_data
        }
        json_payload = json.dumps(message)
        
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json_payload)
            except Exception as e:
                logger.warning(f"Error sending message to client: {e}")
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    async def broadcast_status(self, status_data: dict):
        """Broadcast service status updates."""
        if not self.active_connections:
            return

        message = {
            "type": "SERVICE_STATUS",
            "data": status_data
        }
        json_payload = json.dumps(message)
        for connection in list(self.active_connections):
            try:
                await connection.send_text(json_payload)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()
