from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User, UserRole, AuditLog, AuditActorType, AuditResult
from ..security.auth import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.owner


class LoginIn(BaseModel):
    email: EmailStr
    password: str


@router.post("/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=payload.email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    db.refresh(user)

    db.add(AuditLog(actor_type=AuditActorType.user, actor_id=payload.email, action="auth:register", result=AuditResult.info, meta={"role": payload.role.value}))
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role.value}


@router.post("/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        db.add(AuditLog(actor_type=AuditActorType.user, actor_id=payload.email, action="auth:login", result=AuditResult.deny, meta={"reason": "bad_credentials"}))
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(sub=user.email, role=user.role.value)
    db.add(AuditLog(actor_type=AuditActorType.user, actor_id=user.email, action="auth:login", result=AuditResult.allow, meta={"role": user.role.value}))
    db.commit()
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}