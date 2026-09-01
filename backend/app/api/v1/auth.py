from fastapi import APIRouter, HTTPException, Depends, status, Body
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
from app.core.dependencies import get_current_user
from app.db.mongodb import get_users_collection
from app.db.redis_client import RedisClient
from app.config import settings
import uuid
import hashlib
import structlog

log = structlog.get_logger()
router = APIRouter()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(req: RegisterRequest):
    users_col = get_users_collection()
    existing = await users_col.find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "email": req.email,
        "password_hash": hash_password(req.password),
        "full_name": req.full_name,
        "role": "analyst",
        "is_active": True,
        "is_verified": True,
        "api_key": None,
        "preferences": {
            "theme": "dark",
            "email_digest": False,
            "digest_frequency": "24h",
        },
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = await users_col.insert_one(user_doc)
    user_id = str(result.inserted_id)

    access_token = create_access_token(user_id, req.email, "analyst")
    refresh_token = create_refresh_token(user_id, req.email, "analyst")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={"id": user_id, "email": req.email, "role": "analyst", "full_name": req.full_name},
    )


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    users_col = get_users_collection()
    user = await users_col.find_one({"email": req.email})
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")

    user_id = str(user["_id"])
    role = user.get("role", "analyst")
    access_token = create_access_token(user_id, req.email, role)
    refresh_token = create_refresh_token(user_id, req.email, role)

    # Update last login
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login_at": datetime.now(timezone.utc)}}
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={"id": user_id, "email": req.email, "role": role, "full_name": user.get("full_name", "")},
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest):
    try:
        token_data = decode_token(req.refresh_token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if token_data.type != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    if await RedisClient.is_token_blocked(token_data.jti):
        raise HTTPException(status_code=401, detail="Token revoked")

    # Blocklist old refresh token
    await RedisClient.blocklist_token(token_data.jti, settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400)

    access_token = create_access_token(token_data.sub, token_data.email, token_data.role)
    new_refresh = create_refresh_token(token_data.sub, token_data.email, token_data.role)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        user={"id": token_data.sub, "email": token_data.email, "role": token_data.role},
    )


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    if current_user.get("jti"):
        await RedisClient.blocklist_token(
            current_user["jti"],
            settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    return {"message": "Logged out successfully"}


@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    users_col = get_users_collection()
    from bson import ObjectId
    user = await users_col.find_one({"_id": ObjectId(current_user["id"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user["role"],
        "preferences": user.get("preferences", {}),
        "created_at": user.get("created_at"),
        "last_login_at": user.get("last_login_at"),
    }


@router.post("/api-key")
async def generate_api_key(current_user: dict = Depends(get_current_user)):
    """Generate a new API key for the current user."""
    raw_key = f"cti_{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    users_col = get_users_collection()
    from bson import ObjectId
    await users_col.update_one(
        {"_id": ObjectId(current_user["id"])},
        {"$set": {"api_key_hash": key_hash, "updated_at": datetime.now(timezone.utc)}}
    )

    return {"api_key": raw_key, "note": "Save this key — it will not be shown again"}
