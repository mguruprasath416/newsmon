from datetime import datetime, timezone, timedelta
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel
import uuid

from app.config import settings


class TokenData(BaseModel):
    sub: str
    email: str
    role: str
    jti: str
    type: str  # access | refresh


def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')[:72]  # bcrypt max 72 bytes
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode('utf-8')[:72]
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hashed_bytes)


def create_access_token(user_id: str, email: str, role: str) -> str:
    jti = str(uuid.uuid4())
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "jti": jti,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str, email: str, role: str) -> str:
    jti = str(uuid.uuid4())
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "jti": jti,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return TokenData(**payload)
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


# ── RBAC ──────────────────────────────────────────────────────────────────────

ROLE_HIERARCHY = {
    "admin": 4,
    "analyst": 3,
    "viewer": 2,
    "api_user": 1,
}

ROLE_PERMISSIONS = {
    "admin": [
        "articles:read", "articles:write", "articles:delete",
        "lens:read", "lens:write",
        "reports:read", "reports:write", "reports:delete",
        "kev:read", "kev:write",
        "threat-entities:read", "threat-entities:write",
        "sources:read", "sources:write",
        "users:read", "users:write",
        "admin:all",
        "digest:read", "digest:write",
        "analytics:read",
        "settings:read", "settings:write",
    ],
    "analyst": [
        "articles:read", "articles:write",
        "lens:read", "lens:write",
        "reports:read", "reports:write",
        "kev:read",
        "threat-entities:read", "threat-entities:write",
        "sources:read",
        "digest:read",
        "analytics:read",
    ],
    "viewer": [
        "articles:read",
        "lens:read",
        "reports:read",
        "kev:read",
        "threat-entities:read",
        "digest:read",
    ],
    "api_user": [
        "articles:read",
        "lens:read", "lens:write",
        "reports:read",
        "kev:read",
        "threat-entities:read",
    ],
}




def has_permission(role: str, permission: str) -> bool:
    permissions = ROLE_PERMISSIONS.get(role, [])
    return permission in permissions or "admin:all" in permissions
