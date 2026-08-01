"""Unit tests for password hashing, JWT handling, and the auth models.

These cover the pure functions only — the routes are exercised against a live
MongoDB, which the rest of the suite deliberately does not require.
"""

from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt
from pydantic import ValidationError

import auth
from models import UserRegister, UserResponse, user_to_response


def test_hash_password_is_salted_and_verifiable():
    hashed = auth.hash_password("hunter2hunter2")
    assert hashed != "hunter2hunter2"
    assert auth.verify_password("hunter2hunter2", hashed)
    # A second hash of the same password uses a fresh salt.
    assert auth.hash_password("hunter2hunter2") != hashed


def test_verify_password_rejects_wrong_password_and_garbage_hash():
    hashed = auth.hash_password("hunter2hunter2")
    assert not auth.verify_password("wrongpassword", hashed)
    assert not auth.verify_password("hunter2hunter2", "not-a-bcrypt-hash")


def test_password_longer_than_bcrypt_limit_still_round_trips():
    long_password = "a" * 200
    hashed = auth.hash_password(long_password)
    assert auth.verify_password(long_password, hashed)


def test_create_and_decode_access_token():
    token = auth.create_access_token({"sub": "user@example.com"})
    payload = auth.decode_access_token(token)
    assert payload["sub"] == "user@example.com"
    assert "exp" in payload


def test_decode_access_token_returns_none_for_invalid_tokens():
    assert auth.decode_access_token("not.a.token") is None
    assert auth.decode_access_token("") is None
    # Correct shape, wrong signing key.
    foreign = jwt.encode({"sub": "a@b.dev"}, "another-secret", algorithm="HS256")
    assert auth.decode_access_token(foreign) is None


def test_decode_access_token_returns_none_when_expired():
    expired = jwt.encode(
        {"sub": "a@b.dev", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        auth.JWT_SECRET,
        algorithm=auth.JWT_ALGORITHM,
    )
    assert auth.decode_access_token(expired) is None


def test_public_user_drops_the_password_hash():
    user = {"_id": 1, "email": "a@b.dev", "password_hash": "secret"}
    assert "password_hash" not in auth.public_user(user)
    assert auth.public_user(user)["email"] == "a@b.dev"


def test_to_object_id_returns_none_for_malformed_ids():
    assert auth.to_object_id("nope") is None
    assert auth.to_object_id("6a6de8541e0cc2c4a20cf646") is not None


@pytest.mark.parametrize("email", ["a@b.dev", "First.Last+tag@sub.example.com"])
def test_user_register_accepts_valid_emails(email):
    assert UserRegister(email=email, password="longenough").email == email.lower()


@pytest.mark.parametrize(
    "email", ["notanemail", "no@tld", "@nothing.dev", "spaces in@mail.dev", ""]
)
def test_user_register_rejects_invalid_emails(email):
    with pytest.raises(ValidationError):
        UserRegister(email=email, password="longenough")


def test_user_register_rejects_short_passwords():
    with pytest.raises(ValidationError):
        UserRegister(email="a@b.dev", password="short")


def test_user_to_response_tags_naive_timestamps_as_utc():
    response = user_to_response(
        {
            "_id": "abc",
            "email": "a@b.dev",
            "created_at": datetime(2026, 7, 19, 22, 32),
            "scan_count": 3,
        }
    )
    assert isinstance(response, UserResponse)
    assert response.created_at == "2026-07-19T22:32:00+00:00"
    assert response.scan_count == 3
