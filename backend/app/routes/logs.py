from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..db import get_db
from ..models import AuditLog, IDSAlert, ResponseAction
from ..security.auth import get_current_user

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/audit")
def audit_logs(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(AuditLog).order_by(desc(AuditLog.ts)).limit(200).all()
    return [{"ts": str(r.ts), "actor_type": r.actor_type.value, "actor_id": r.actor_id, "action": r.action, "result": r.result.value, "meta": r.meta} for r in rows]


@router.get("/alerts")
def ids_alerts(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(IDSAlert).order_by(desc(IDSAlert.ts)).limit(200).all()
    return [{"ts": str(r.ts), "severity": r.severity.value, "rule": r.rule, "title": r.title, "evidence": r.evidence} for r in rows]


@router.get("/responses")
def responses(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(ResponseAction).order_by(desc(ResponseAction.ts)).limit(200).all()
    return [{"ts": str(r.ts), "alert_id": r.alert_id, "action_type": r.action_type, "details": r.details} for r in rows]