from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["realtime"])


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ws.app.state.ws_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws.app.state.ws_clients.discard(ws)