"""Shared fixtures for the QLint backend test suite."""

import sys
from pathlib import Path

import pytest

# Make backend/ importable when pytest runs from the backend directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def sample_rsa_source():
    """Python source with a quantum-vulnerable RSA import and usage."""
    return """
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
"""


@pytest.fixture
def sample_safe_source():
    """Python source using only quantum-safe primitives (AES-256, SHA-512)."""
    return """
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = os.urandom(32)  # AES-256
aesgcm = AESGCM(key)
digest = hashlib.sha512(b"data").hexdigest()
"""


@pytest.fixture
def mock_github_file_list():
    """Fake .py file paths as returned by get_repo_files."""
    return ["src/crypto.py", "src/utils.py", "app/models.py"]


@pytest.fixture
def mock_rate_limit_response():
    """Fake rate limit dict as returned by check_rate_limit."""
    return {"remaining": 4990, "reset_at": "2026-07-20 12:00:00 UTC"}
