"""Unit tests for GitHub OAuth helpers and the scan credential priority."""

import routers.oauth_router as oauth
from routers.scan_router import ScanRequest, _resolve_token


def test_frontend_redirect_builds_an_encoded_callback_url():
    response = oauth._frontend_redirect(github_token="abc.def", github_user="a@b.dev")
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(f"{oauth.FRONTEND_URL}/?")
    assert "github_token=abc.def" in location
    assert "github_user=a%40b.dev" in location  # the @ must be percent-encoded


def test_frontend_redirect_carries_the_error_flag():
    response = oauth._frontend_redirect(github_error="auth_failed")
    assert response.headers["location"].endswith("/?github_error=auth_failed")


def test_manual_token_wins_over_everything(monkeypatch):
    monkeypatch.setattr("routers.scan_router.GITHUB_TOKEN", "env_token")
    body = ScanRequest(repo_url="https://github.com/a/b", github_token="  manual  ")
    connected = {"github_connected": True, "github_access_token": "oauth_token"}
    # Also confirms the pasted value is trimmed.
    assert _resolve_token(body, connected) == "manual"


def test_connected_github_account_beats_the_env_token(monkeypatch):
    monkeypatch.setattr("routers.scan_router.GITHUB_TOKEN", "env_token")
    body = ScanRequest(repo_url="https://github.com/a/b")
    connected = {"github_connected": True, "github_access_token": "oauth_token"}
    assert _resolve_token(body, connected) == "oauth_token"


def test_env_token_is_the_fallback(monkeypatch):
    monkeypatch.setattr("routers.scan_router.GITHUB_TOKEN", "env_token")
    body = ScanRequest(repo_url="https://github.com/a/b")
    assert _resolve_token(body, None) == "env_token"
    # Disconnected, or connected but with the token already cleared.
    assert _resolve_token(body, {"github_connected": False}) == "env_token"
    assert (
        _resolve_token(body, {"github_connected": True, "github_access_token": None})
        == "env_token"
    )


def test_anonymous_scan_without_any_token_is_a_clear_error(monkeypatch):
    monkeypatch.setattr("routers.scan_router.GITHUB_TOKEN", None)
    body = ScanRequest(repo_url="https://github.com/a/b")
    try:
        _resolve_token(body, None)
    except Exception as exc:  # HTTPException
        assert exc.status_code == 500
        assert "GITHUB_TOKEN" in exc.detail
    else:
        raise AssertionError("expected an HTTPException")
