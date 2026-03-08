from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from .models import (
    IDSAlert,
    SecurityState,
    SecurityMode,
    ResponseAction,
    Device,
    AuditLog,
    AuditActorType,
    AuditResult,
)


def get_or_create_security_state(db: Session) -> SecurityState:
    state = db.query(SecurityState).first()
    if not state:
        state = SecurityState(mode=SecurityMode.normal, mode_until=None)
        db.add(state)
        db.commit()
        db.refresh(state)
    return state


def set_high_alert_mode(db: Session, *, minutes: int, alert: IDSAlert):
    state = get_or_create_security_state(db)
    state.mode = SecurityMode.high_alert
    state.mode_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    db.add(state)

    db.add(ResponseAction(alert_id=alert.id, action_type="escalate_mode", details={"mode": "high_alert", "minutes": minutes}))
    db.add(AuditLog(actor_type=AuditActorType.system, actor_id="ids", action="response:escalate_mode", result=AuditResult.info,
                    meta={"alert_id": alert.id, "mode": "high_alert", "minutes": minutes}))
    db.commit()


def quarantine_device(db: Session, *, device_id: str, alert: IDSAlert):
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if dev:
        dev.quarantined = True
        db.add(dev)

    db.add(ResponseAction(alert_id=alert.id, action_type="quarantine_device", details={"device_id": device_id}))
    db.add(AuditLog(actor_type=AuditActorType.system, actor_id="ids", action="response:quarantine_device", result=AuditResult.info,
                    meta={"alert_id": alert.id, "device_id": device_id}))
    db.commit()


def record_action(db: Session, *, alert_id: int, action_type: str, details: dict):
    db.add(ResponseAction(alert_id=alert_id, action_type=action_type, details=details))
    db.add(AuditLog(actor_type=AuditActorType.system, actor_id="ids", action=f"response:{action_type}", result=AuditResult.info,
                    meta={"alert_id": alert_id, **details}))
    db.commit()


def decide_and_act(db: Session, *, alert: IDSAlert):
    if alert.rule == "device_flood":
        device_id = (alert.evidence or {}).get("device_id")
        if device_id:
            quarantine_device(db, device_id=device_id, alert=alert)

    if alert.rule in ("failed_login_bruteforce", "unlock_without_motion"):
        set_high_alert_mode(db, minutes=10, alert=alert)

    if alert.rule == "unlock_without_motion":
        record_action(db, alert_id=alert.id, action_type="siren_on", details={})
        record_action(db, alert_id=alert.id, action_type="auto_lock_all", details={})