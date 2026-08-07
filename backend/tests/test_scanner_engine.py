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
    "languages_scanned",
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

    def test_javascript_file_is_scanned_with_the_js_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {"src/auth.js": "const s = crypto.createSign('RSA-SHA256');\n"}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "RSA" in report["algorithms_found"]
        assert report["languages_scanned"] == ["javascript"]
        finding = report["findings_by_file"]["src/auth.js"][0]
        assert finding["language"] == "javascript"

    def test_typescript_file_is_scanned_with_the_js_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {"src/hash.ts": "const h = crypto.createHash('md5');\n"}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "MD5" in report["algorithms_found"]
        assert report["languages_scanned"] == ["typescript"]

    def test_go_file_is_scanned_with_the_go_scanner(
        self, monkeypatch, mock_rate_limit_response
    ):
        contents = {"cmd/keys.go": "priv, _ := rsa.GenerateKey(rand.Reader, 2048)\n"}
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert "RSA" in report["algorithms_found"]
        assert report["languages_scanned"] == ["go"]
        finding = report["findings_by_file"]["cmd/keys.go"][0]
        assert finding["language"] == "go"
        # The Go fix snippet, not the Python one, reaches the report.
        assert "mlkem768" in finding["fix_snippet"]

    def test_mixed_language_repo_reports_every_language(
        self, monkeypatch, sample_rsa_source, mock_rate_limit_response
    ):
        contents = {
            "server.py": sample_rsa_source,
            "src/hash.js": "const h = crypto.createHash('md5');\n",
            "src/sign.tsx": "const s = crypto.createSign('RSA-SHA256');\n",
        }
        report = run_scan(monkeypatch, contents, mock_rate_limit_response)
        assert report["scanned_files"] == 3
        assert report["languages_scanned"] == ["javascript", "python", "typescript"]
        assert "RSA" in report["algorithms_found"]
        assert "MD5" in report["algorithms_found"]
        languages = {
            finding["language"]
            for findings in report["findings_by_file"].values()
            for finding in findings
        }
        assert languages == {"python", "javascript", "typescript"}

    def test_file_entries_may_be_dicts_with_a_language(
        self, monkeypatch, mock_rate_limit_response
    ):
        """get_repo_files returns {"path", "language"} dicts since F13."""

        async def fake_check_rate_limit(token, client=None):
            return mock_rate_limit_response

        async def fake_get_repo_files(repo_url, token, client=None):
            return [{"path": "a.js", "language": "javascript"}]

        async def fake_get_file_content(owner, repo, path, token, client=None):
            return "const h = crypto.createHash('md5');\n"

        monkeypatch.setattr(scanner_engine, "check_rate_limit", fake_check_rate_limit)
        monkeypatch.setattr(scanner_engine, "get_repo_files", fake_get_repo_files)
        monkeypatch.setattr(scanner_engine, "get_file_content", fake_get_file_content)

        report = asyncio.run(
            scanner_engine.scan_repository("https://github.com/acme/demo", "t", None)
        )
        assert report["languages_scanned"] == ["javascript"]
        assert "MD5" in report["algorithms_found"]

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
