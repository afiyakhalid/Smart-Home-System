import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Device, AuditLog, AuditActorType, AuditResult
from ..security.auth import get_current_user
from ..security.policy import check_permission
from ..mqtt_client import MQTTClient

router = APIRouter(prefix="/commands", tags=["commands"])


class CommandIn(BaseModel):
    action: str
    pin: str | None = None


def get_mqtt(request: Request) -> MQTTClient:
    return request.app.state.mqtt


@router.post("/{device_id}")
def send_command(device_id: str, payload: CommandIn, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user)):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    decision = check_permission(db=db, user=user, action=payload.action, device=device, request=request, provided_pin=payload.pin)

    db.add(AuditLog(actor_type=AuditActorType.user, actor_id=user.email, action=f"cmd:{payload.action}",
                    result=AuditResult.allow if decision.allowed else AuditResult.deny,
                    meta={"device_id": device_id, "reason": decision.reason, **decision.meta}))
    db.commit()

    if not decision.allowed:
        raise HTTPException(status_code=403, detail=f"Denied: {decision.reason}")

    command_id = str(uuid.uuid4())
    get_mqtt(request).publish_command(device_id, {"command_id": command_id, "action": payload.action})
    return {"ok": True, "command_id": command_id}