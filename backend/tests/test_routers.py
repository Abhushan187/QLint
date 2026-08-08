"""Unit tests for the pure helpers behind the scan cache and history routes,
plus route-level tests for the HNDL calculator endpoints."""

from datetime import datetime, timezone

import pytest
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from routers import hndl_router as hndl_module
from routers.hndl_router import router as hndl_router
from routers.scan_router import _canonical_url, _iso
from routers.user_router import _algo_severity, _summarize


def test_canonical_url_normalizes_cache_keys():
    canonical = "https://github.com/psf/requests"
    for variant in [
        "https://github.com/psf/requests",
        "https://github.com/psf/requests/",
        "https://github.com/psf/requests.git",
        "https://github.com/psf/requests.git/",
    ]:
        assert _canonical_url(variant) == canonical


def test_canonical_url_passes_unparseable_input_through():
    # Deep links and junk are left alone; the scan itself rejects them with a
    # 400, so they must not silently collapse onto another repo's cache key.
    assert _canonical_url("  not a url  ") == "not a url"
    deep = "https://github.com/psf/requests/tree/main"
    assert _canonical_url(deep) == deep


def test_iso_tags_naive_datetimes_as_utc():
    assert _iso(datetime(2026, 7, 19, 22, 32)) == "2026-07-19T22:32:00+00:00"
    aware = datetime(2026, 7, 19, 22, 32, tzinfo=timezone.utc)
    assert _iso(aware) == "2026-07-19T22:32:00+00:00"
    assert _iso(None) is None


def test_algo_severity_keeps_the_worst_severity_per_algorithm():
    result = {
        "findings_by_file": {
            "a.py": [
                {"algorithm": "RSA", "severity": "warning"},
                {"algorithm": "RSA", "severity": "critical"},
            ],
            "b.py": [
                {"algorithm": "SHA-256", "severity": "warning"},
                {"algorithm": "hashlib", "severity": "bogus"},
            ],
        }
    }
    assert _algo_severity(result) == {"RSA": "critical", "SHA-256": "warning"}


def test_summarize_returns_only_history_fields():
    entry = {
        "_id": "abc",
        "repo_url": "https://github.com/psf/requests",
        "created_at": datetime(2026, 7, 19, 22, 32),
        "result": {
            "pqc_readiness_score": 42,
            "total_findings": 2,
            "scanned_files": 18,
            "algorithms_found": ["RSA"],
            "cached": False,
            "findings_by_file": {"a.py": [{"algorithm": "RSA", "severity": "critical"}]},
        },
    }
    summary = _summarize(entry)
    assert summary["id"] == "abc"
    assert summary["pqc_readiness_score"] == 42
    assert summary["algo_severity"] == {"RSA": "critical"}
    assert summary["created_at"] == "2026-07-19T22:32:00+00:00"
    # The full report must never ride along in the list response.
    assert "findings_by_file" not in summary


def test_summarize_tolerates_a_missing_result_blob():
    summary = _summarize({"_id": "abc", "repo_url": "u", "created_at": None})
    assert summary["pqc_readiness_score"] == 0
    assert summary["algorithms_found"] == []
    assert summary["cached"] is False


# --------------------------------------------------------------- HNDL routes
#
# Mounted on a bare app rather than main.app so the tests never open a Mongo
# connection through the lifespan handler. The scans collection is faked.

OWNER_ID = "507f1f77bcf86cd799439011"
OTHER_ID = "507f1f77bcf86cd799439022"
SCAN_ID = "652f1f77bcf86cd799439033"

STORED_SCAN = {
    "_id": ObjectId(SCAN_ID),
    "repo_url": "https://github.com/golang-jwt/jwt",
    "user_id": OWNER_ID,
    "result": {
        "severity_summary": {"critical": 72, "warning": 4, "safe": 8, "info": 0},
        "total_findings": 84,
    },
}


class FakeScans:
    """Just enough of a Motor collection for the one query the router makes."""

    def __init__(self, documents):
        self.documents = documents

    async def find_one(self, query):
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(hndl_module, "get_scans", lambda: FakeScans([STORED_SCAN]))
    app = FastAPI()
    app.include_router(hndl_router)
    return TestClient(app), app


@pytest.fixture
def signed_in(client):
    """The same client, with requests authenticated as the scan's owner."""
    test_client, app = client
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OWNER_ID,
        "email": "owner@qlint.dev",
    }
    yield test_client
    app.dependency_overrides.clear()


def test_profiles_returns_both_dicts_without_auth(client):
    test_client, _ = client
    response = test_client.get("/hndl/profiles")
    assert response.status_code == 200
    body = response.json()
    assert "healthcare_records" in body["data_sensitivity_profiles"]
    assert body["data_sensitivity_profiles"]["healthcare_records"] == {
        "label": "Healthcare Records",
        "shelf_life_years": 50,
    }
    assert set(body["crqc_scenarios"]) == {"aggressive", "moderate", "conservative"}
    assert body["crqc_scenarios"]["moderate"]["years_from_now"] == 10


def test_calculate_requires_a_jwt(client):
    test_client, _ = client
    response = test_client.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "healthcare_records"},
    )
    assert response.status_code == 401


def test_calculate_returns_the_full_result_for_an_owned_scan(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={
            "scan_id": SCAN_ID,
            "data_sensitivity": "healthcare_records",
            "crqc_scenario": "moderate",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["exposed"] is True
    assert body["migration_time_years"] == 3.0
    assert body["risk_window_years"] == 7.0
    assert body["data_sensitivity_label"] == "Healthcare Records"
    assert len(body["all_scenarios"]) == 3
    assert body["scan_id"] == SCAN_ID
    assert body["verdict"] and body["recommendation"]


def test_calculate_defaults_to_the_moderate_scenario(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "api_keys"},
    )
    assert response.status_code == 200
    assert response.json()["crqc_scenario"] == "moderate"


def test_calculate_404s_on_another_users_scan(client):
    test_client, app = client
    app.dependency_overrides[get_current_user] = lambda: {
        "_id": OTHER_ID,
        "email": "stranger@qlint.dev",
    }
    response = test_client.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "healthcare_records"},
    )
    app.dependency_overrides.clear()
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_calculate_404s_on_an_unknown_or_malformed_scan_id(signed_in):
    for scan_id in ["652f1f77bcf86cd799439099", "not-an-object-id"]:
        response = signed_in.post(
            "/hndl/calculate",
            json={"scan_id": scan_id, "data_sensitivity": "api_keys"},
        )
        assert response.status_code == 404


def test_calculate_400s_on_an_invalid_data_sensitivity(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={"scan_id": SCAN_ID, "data_sensitivity": "nuclear_codes"},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "nuclear_codes" in detail
    assert "healthcare_records" in detail  # the valid options are listed


def test_calculate_400s_on_an_invalid_crqc_scenario(signed_in):
    response = signed_in.post(
        "/hndl/calculate",
        json={
            "scan_id": SCAN_ID,
            "data_sensitivity": "api_keys",
            "crqc_scenario": "tomorrow",
        },
    )
    assert response.status_code == 400
    assert "tomorrow" in response.json()["detail"]
