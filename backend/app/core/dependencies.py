from fastapi import Depends, Header
from typing import Optional
from bson import ObjectId

# Default mock user when authentication is disabled
DEFAULT_USER = {
    "id": "60c72b2f9b1d8b0015b6d9a0",
    "email": "analyst@clarityti.io",
    "role": "admin",
    "full_name": "Security Analyst",
    "jti": "default_session",
}


async def get_current_user() -> dict:
    """Authentication disabled — returns default admin user for seamless access."""
    return DEFAULT_USER


def require_permission(permission: str):
    """Bypass permission checks — allow all access."""
    async def _check(current_user: dict = Depends(get_current_user)):
        return current_user
    return _check


def require_role(*roles: str):
    """Bypass role checks — allow all access."""
    async def _check(current_user: dict = Depends(get_current_user)):
        return current_user
    return _check


async def get_current_user_or_api_key(
    x_api_key: Optional[str] = Header(None),
) -> dict:
    """Bypass API key checks — allow all access."""
    return DEFAULT_USER
