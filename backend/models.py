"""Pydantic request/response models for auth, users, and the scan cache."""

import re
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")


class UserRegister(BaseModel):
    email: str
    password: str = Field(min_length=8)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_RE.match(value):
            raise ValueError("Invalid email address")
        return value


class UserLogin(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class UserResponse(BaseModel):
    id: str
    email: str
    created_at: str
    scan_count: int
    role: str = "user"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class ScanCacheEntry(BaseModel):
    repo_url: str
    scanned_by: str
    result: dict
    created_at: datetime
    expires_at: datetime


def user_to_response(user: dict) -> UserResponse:
    """Map a MongoDB user document onto the public UserResponse shape."""
    created_at = user.get("created_at")
    if isinstance(created_at, datetime):
        # Mongo hands back naive UTC datetimes; tag them so clients do not
        # read the timestamp as local time.
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        created_at = created_at.isoformat()
    return UserResponse(
        id=str(user["_id"]),
        email=user["email"],
        created_at=str(created_at),
        scan_count=int(user.get("scan_count", 0)),
        # Accounts created before roles existed are plain users.
        role=user.get("role", "user"),
    )
