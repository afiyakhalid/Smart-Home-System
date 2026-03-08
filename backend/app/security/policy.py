from dataclasses import dataclass
from datetime import datetime, timezone
from fastapi import Request
from sqlalchemy.orm import Session

from ..config import settings
from ..models import User, UserRole, SecurityState, SecurityMode, Device


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    meta: dict


def is_local_request(request: Request) -> bool:
    client = request.client.host if request.client else ""
    return client in ("127.0.0.1", "localhost", "::1")


def current_security_mode(db: Session) -> SecurityMode:
    state = db.query(SecurityState).first()
    if not state:
        return SecurityMode.normal

    if state.mode == SecurityMode.high_alert and state.mode_until:
        now = datetime.now(timezone.utc)
        if now > state.mode_until:
            state.mode = SecurityMode.normal
            state.mode_until = None
            db.add(state)
            db.commit()
            return SecurityMode.normal
    return state.mode


def check_permission(
    *,
    db: Session,
    user: User,
    action: str,
    device: Device,
    request: Request,
    provided_pin: str | None = None,
) -> PolicyDecision:
    if device.quarantined:
        return PolicyDecision(False, "Device is quarantined by IDS", {"response": "quarantine"})

    mode = current_security_mode(db)

    # Tighten policy if system is under attack
    if mode == SecurityMode.high_alert:
        if user.role != UserRole.owner:
            return PolicyDecision(False, "High Alert: only owner allowed", {"mode": "high_alert"})
        if action == "lock:unlock" and provided_pin != "1234":
            return PolicyDecision(False, "High Alert: PIN required for unlock", {"mode": "high_alert", "abac": "pin_required"})

    if user.role == UserRole.owner:
        return PolicyDecision(True, "Owner allowed", {"rbac": "owner", "mode": mode.value})

    if user.role == UserRole.guest:
        hour = datetime.now().hour
        if not (settings.guest_allowed_start_hour <= hour < settings.guest_allowed_end_hour):
            return PolicyDecision(False, "Guest not allowed at this time", {"abac": "time_window", "hour": hour})

        if action in ("lock:unlock", "siren:off"):
            if action == "lock:unlock" and (is_local_request(request) or provided_pin == "1234"):
                return PolicyDecision(True, "Guest unlock allowed with local/PIN", {"abac": "local_or_pin"})
            return PolicyDecision(False, "Guest not permitted for high-risk action", {"rbac": "guest"})

        return PolicyDecision(True, "Guest allowed", {"rbac": "guest", "mode": mode.value})

    return PolicyDecision(False, "Unknown role", {"rbac": "unknown"})