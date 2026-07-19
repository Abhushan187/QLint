"""Tests for scanner_engine.scan_repository.

The github_client layer is replaced with fakes via monkeypatch —
no real API calls are made.
"""

import asyncio

import scanner_engine

REPORT_KEYS = {
    "repo",
    "scanned_files",
    "skipped_files",
    "total_findings",
    "pqc_readiness_score",
    "severity_summary",
    "findings_by_file",
    "algorithms_found",
    "rate_limit_remaining",
}


def run_scan(monkeypatch, contents, rate_limit_response):
    """Run scan_repository against a fake repo defined by {path: source}."""

    async def fake_check_rate_limit(token, client=None):
        return rate_limit_response

    async def fake_get_repo_files(repo_url, token, client=None):
        return list(contents)

    async def fake_get_file_content(owner, repo, path, token, client=None):
        return contents[path]

    monkeypatch.setattr(scanner_engine, "check_rate_limit", fake_check_rate_limit)
    monkeypatch.setattr(scanner_engine, "get_repo_files", fake_get_repo_files)
    monkeypatch.setattr(scanner_engine, "get_file_content", fake_get_file_content)

    return asyncio.run(
        scanner_engine.scan_repository(
            "https://github.com/acme/demo", "token", None
        )
    )


class TestScanRepository:
    def test_empty_repo(self, monkeypatch, mock_rate_limit_response):
        report = run_scan(monkeypatch, {}, mock_rate_limit_response)
        assert report["scanned_files"] == 0
        assert report["total_findings"] == 0
        assert report["pqc_readiness_score"] == 100
        assert report["findings_by_file"] == {}

    def test_repo_with_rsa_file(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        report = run_scan(
            monkeypatch, {"src/crypto.py": sample_rsa_source}, mock_rate_limit_response
        )
        assert report["total_findings"] > 0
        assert "RSA" in report["algorithms_found"]
        assert report["pqc_readiness_score"] < 100
        assert "src/crypto.py" in report["findings_by_file"]
        for finding in report["findings_by_file"]["src/crypto.py"]:
            assert finding["file"] == "src/crypto.py"

    def test_skipped_files_are_reported(
        self, monkeypatch, sample_safe_source, mock_rate_limit_response
    ):
        contents = {"src/ok.py": sample_safe_source, "src/huge.py": None}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert report["skipped_files"] == ["src/huge.py"]
        assert report["scanned_files"] == 1

    def test_report_structure(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        report = run_scan(
            monkeypatch, {"a.py": sample_rsa_source}, mock_rate_limit_response
        )
        assert set(report) == REPORT_KEYS
        assert report["repo"] == "acme/demo"
        assert (
            report["rate_limit_remaining"] == mock_rate_limit_response["remaining"]
        )

    def test_severity_summary_keys(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        report = run_scan(
            monkeypatch, {"a.py": sample_rsa_source}, mock_rate_limit_response
        )
        assert set(report["severity_summary"]) == {
            "critical",
            "warning",
            "safe",
            "info",
        }
