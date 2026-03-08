import asyncio
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import settings
from .db import Base, engine, SessionLocal
from .mqtt_client import MQTTClient
from .models import Event, Device
from .ids.rules import (
    rule_failed_login_bruteforce,
    rule_device_flood,
    rule_unlock_without_recent_motion,
)
from .response_engine import decide_and_act
from .routes.auth import router as auth_router
from .routes.devices import router as devices_router
from .routes.commands import router as commands_router
from .routes.logs import router as logs_router
from .routes.realtime import router as realtime_router

app = FastAPI(title="Smart Home Security Hub (Phase 1)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(commands_router)
app.include_router(logs_router)
app.include_router(realtime_router)

app.state.ws_clients = set()


def db_session() -> Session:
    return SessionLocal()


async def broadcast(obj: dict):
    dead = []
    for ws in list(app.state.ws_clients):
        try:
            await ws.send_json(obj)
        except Exception:
            dead.append(ws)
    for ws in dead:
        app.state.ws_clients.discard(ws)


def push_ws(obj: dict):
    loop = asyncio.get_event_loop()
    loop.create_task(broadcast(obj))


def handle_mqtt_event(topic: str, payload: dict):
    # home/<device_id>/event
    parts = topic.split("/")
    if len(parts) < 3:
        return
    device_id = parts[1]

    event_type = payload.get("event_type", "unknown")
    data = payload.get("data", payload)

    alerts_created = []

    with db_session() as db:
        device = db.query(Device).filter(Device.device_id == device_id).first()

        # Ignore events from quarantined devices
        if device and device.quarantined:
            return

        if device:
            device.last_seen_at = datetime.now(timezone.utc)

        db.add(Event(device_id=device_id, event_type=event_type, payload=data))
        db.commit()

        # IDS checks
        a1 = rule_device_flood(db, device_id=device_id, threshold_per_min=settings.ids_device_flood_threshold_per_min)
        if a1:
            alerts_created.append(a1)

        if device and device.type == "lock":
            a2 = rule_unlock_without_recent_motion(db, lock_device_id=device_id, window_seconds=settings.ids_unlock_without_motion_window_seconds)
            if a2:
                alerts_created.append(a2)

        a3 = rule_failed_login_bruteforce(db, threshold=settings.ids_failed_login_threshold, window_seconds=settings.ids_failed_login_window_seconds)
        if a3:
            alerts_created.append(a3)

        # RESPONSE: detect -> act
        for alert in alerts_created:
            decide_and_act(db, alert=alert)

            if alert.rule == "unlock_without_motion":
                # Siren ON
                siren = db.query(Device).filter(Device.type == "siren").first()
                if siren and not siren.quarantined:
                    app.state.mqtt.publish_command(siren.device_id, {"command_id": "AUTO-SIREN", "action": "siren:on"})

                # Auto-lock ALL locks
                locks = db.query(Device).filter(Device.type == "lock").all()
                for lk in locks:
                    if lk.quarantined:
                        continue
                    app.state.mqtt.publish_command(lk.device_id, {"command_id": f"AUTO-LOCK-{lk.device_id}", "action": "lock:lock"})

    # push to frontend
    push_ws({"type": "event", "device_id": device_id, "event_type": event_type, "data": data})
    for alert in alerts_created:
        push_ws({"type": "alert", "rule": alert.rule, "severity": alert.severity.value, "title": alert.title, "evidence": alert.evidence})


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    mqtt = MQTTClient()
    mqtt.set_event_handler(handle_mqtt_event)
    mqtt.connect()
    mqtt.subscribe_events()
    app.state.mqtt = mqtt


@app.get("/health")
def health():
    return {"ok": True}