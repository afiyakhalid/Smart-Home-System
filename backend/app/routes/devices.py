from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Device
from ..security.auth import get_current_user

router = APIRouter(prefix="/devices", tags=["devices"])


class DeviceIn(BaseModel):
    device_id: str
    name: str
    type: str
    capabilities: dict = {}
    shared_secret: str = "dev-secret"


@router.get("")
def list_devices(db: Session = Depends(get_db), user=Depends(get_current_user)):
    devices = db.query(Device).all()
    return [
        {
            "device_id": d.device_id,
            "name": d.name,
            "type": d.type,
            "capabilities": d.capabilities,
            "quarantined": d.quarantined,
            "last_seen_at": str(d.last_seen_at) if d.last_seen_at else None,
        }
        for d in devices
    ]


@router.post("")
def register_device(payload: DeviceIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    d = db.query(Device).filter(Device.device_id == payload.device_id).first()
    if d:
        d.name = payload.name
        d.type = payload.type
        d.capabilities = payload.capabilities
        d.shared_secret = payload.shared_secret
    else:
        d = Device(device_id=payload.device_id, name=payload.name, type=payload.type, capabilities=payload.capabilities, shared_secret=payload.shared_secret)
        db.add(d)
    db.commit()
    return {"ok": True}