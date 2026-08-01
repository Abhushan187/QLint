"""Registration, login, session lookup, and logout."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pymongo.errors import DuplicateKeyError, PyMongoError

from auth import create_access_token, get_current_user, hash_password, verify_password
from database import get_users
from models import TokenResponse, UserLogin, UserRegister, UserResponse, user_to_response

router = APIRouter(prefix="/auth")

DB_UNAVAILABLE = "Database unavailable. Is MongoDB running on port 27017?"


def _token_response(user: dict) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token({"sub": user["email"]}),
        token_type="bearer",
        user=user_to_response(user),
    )


@router.post("/register", response_model=TokenResponse)
async def register(body: UserRegister):
    users = get_users()
    try:
        if await users.find_one({"email": body.email}):
            raise HTTPException(status_code=409, detail="Email already registered")
        document = {
            "email": body.email,
            "password_hash": hash_password(body.password),
            "created_at": datetime.now(timezone.utc),
            "scan_count": 0,
            "role": "user",
        }
        result = await users.insert_one(document)
    except DuplicateKeyError as exc:
        # Lost a race against a concurrent registration for the same email.
        raise HTTPException(status_code=409, detail="Email already registered") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc
    document["_id"] = result.inserted_id
    return _token_response(document)


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLogin):
    try:
        user = await get_users().find_one({"email": body.email})
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=DB_UNAVAILABLE) from exc
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return _token_response(user)


@router.get("/me", response_model=UserResponse)
async def me(user: dict = Depends(get_current_user)):
    return user_to_response(user)


@router.post("/logout")
async def logout(user: dict = Depends(get_current_user)):
    # JWTs are stateless — the client drops the token. No server-side blocklist.
    return {"message": "logged out"}
