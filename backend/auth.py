"""Password hashing, JWT issuing/decoding, and the current-user dependency."""

import os
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, Header, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from passlib.context import CryptContext

from database import get_users

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "change_this_to_a_random_64_char_string")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))

# bcrypt caps input at 72 bytes; longer passwords are truncated before hashing
# so that hash and verify always agree instead of raising.
BCRYPT_MAX_BYTES = 72

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


def _clip(plain: str) -> str:
    encoded = plain.encode("utf-8")
    if len(encoded) <= BCRYPT_MAX_BYTES:
        return plain
    return encoded[:BCRYPT_MAX_BYTES].decode("utf-8", errors="ignore")


def hash_password(plain: str) -> str:
    return pwd_context.hash(_clip(plain))


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(_clip(plain), hashed)
    except Exception:
        return False


def create_access_token(data: dict) -> str:
    payload = dict(data)
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """Return the payload, or None when the token is expired/invalid/malformed."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


def public_user(user: dict) -> dict:
    """Strip the password hash before a user document leaves the backend."""
    return {k: v for k, v in user.items() if k != "password_hash"}


async def user_from_token(token: str | None) -> dict | None:
    """Resolve a bearer token to a user document, or None."""
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    email = payload.get("sub")
    if not email:
        return None
    user = await get_users().find_one({"email": email})
    if not user:
        return None
    return public_user(user)


async def get_current_user(token: str | None = Depends(oauth2_scheme)) -> dict:
    """Require a valid bearer token; 401 when missing, invalid, or unknown user."""
    user = await user_from_token(token)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_optional_user(
    authorization: str | None = Header(default=None),
) -> dict | None:
    """Authenticate if a bearer token is present; stay anonymous otherwise."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    return await user_from_token(parts[1].strip())


def to_object_id(value: str) -> ObjectId | None:
    try:
        return ObjectId(value)
    except Exception:
        return None
