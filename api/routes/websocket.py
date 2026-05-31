"""WebSocket endpoint for live prediction updates."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends

from api.dependencies import get_ws_manager
from infrastructure.websocket.manager import ConnectionManager

router = APIRouter()


@router.websocket("/ws/predictions")
async def ws_predictions(ws: WebSocket):
    from api.dependencies import get_ws_manager
    manager = get_ws_manager()
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
