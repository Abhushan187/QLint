"""Unit tests for the pure helpers behind the scan cache and history routes."""

from datetime import datetime, timezone

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
