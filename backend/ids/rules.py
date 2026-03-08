from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..models import AuditLog, AuditActorType, AuditResult, IDSAlert, Severity, Event


def create_alert(db: Session, *, severity: Severity, rule: str, title: str, evidence: dict):
    alert = IDSAlert(severity=severity, rule=rule, title=title, evidence=evidence)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def rule_failed_login_bruteforce(db: Session, *, threshold: int, window_seconds: int):
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)
    failures = (
        db.query(AuditLog)
        .filter(AuditLog.actor_type == AuditActorType.user)
        .filter(AuditLog.action == "auth:login")
        .filter(AuditLog.result == AuditResult.deny)
        .filter(AuditLog.ts >= window_start)
        .order_by(desc(AuditLog.ts))
        .all()
    )
    if len(failures) >= threshold:
        return create_alert(
            db,
            severity=Severity.high,
            rule="failed_login_bruteforce",
            title="Possible brute-force login attempt detected",
            evidence={"count": len(failures), "window_seconds": window_seconds},
        )
    return None


def rule_device_flood(db: Session, *, device_id: str, threshold_per_min: int):
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=60)
    count = db.query(Event).filter(Event.device_id == device_id).filter(Event.ts >= window_start).count()
    if count > threshold_per_min:
        return create_alert(
            db,
            severity=Severity.medium,
            rule="device_flood",
            title=f"Possible event flooding from device {device_id}",
            evidence={"device_id": device_id, "count_last_min": count, "threshold": threshold_per_min},
        )
    return None


def rule_unlock_without_recent_motion(db: Session, *, lock_device_id: str, window_seconds: int):
    unlock = (
        db.query(Event)
        .filter(Event.device_id == lock_device_id)
        .filter(Event.event_type == "lock_state")
        .order_by(desc(Event.ts))
        .first()
    )
    if not unlock:
        return None
    if (unlock.payload or {}).get("state") != "unlocked":
        return None

    cutoff = unlock.ts - timedelta(seconds=window_seconds)
    motion_recent = db.query(Event).filter(Event.event_type == "motion").filter(Event.ts >= cutoff).order_by(desc(Event.ts)).first()
    if not motion_recent:
        return create_alert(
            db,
            severity=Severity.critical,
            rule="unlock_without_motion",
            title="Unlock detected without recent motion (suspicious physical context)",
            evidence={"lock_device_id": lock_device_id, "unlock_ts": str(unlock.ts), "motion_window_seconds": window_seconds},
        )
    return None