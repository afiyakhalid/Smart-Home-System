import enum
from sqlalchemy import String, Integer, DateTime, JSON, Enum, func, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


class UserRole(str, enum.Enum):
    owner = "owner"
    guest = "guest"


class AuditActorType(str, enum.Enum):
    user = "user"
    device = "device"
    system = "system"


class AuditResult(str, enum.Enum):
    allow = "allow"
    deny = "deny"
    info = "info"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class SecurityMode(str, enum.Enum):
    normal = "normal"
    high_alert = "high_alert"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False, default=UserRole.owner)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)  # lock, motion, door, siren
    capabilities: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    shared_secret: Mapped[str] = mapped_column(String(128), nullable=False, default="dev-secret")
    quarantined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_seen_at: Mapped[str | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ts: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_type: Mapped[AuditActorType] = mapped_column(Enum(AuditActorType), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    result: Mapped[AuditResult] = mapped_column(Enum(AuditResult), nullable=False)
    meta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ts: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class IDSAlert(Base):
    __tablename__ = "ids_alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    rule: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ts: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class SecurityState(Base):
    __tablename__ = "security_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mode: Mapped[SecurityMode] = mapped_column(Enum(SecurityMode), nullable=False, default=SecurityMode.normal)
    mode_until: Mapped[str | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(Integer, nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ts: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)