"""Tests for ast_scanner.scan_python_source."""

from ast_scanner import scan_python_source

REQUIRED_FIELDS = {
    "line",
    "col",
    "identifier",
    "match_type",
    "algorithm",
    "severity",
    "fix_snippet",
}


def algorithms(findings):
    return {f["algorithm"] for f in findings}


class TestEdgeCases:
    def test_empty_string_returns_empty_list(self):
        assert scan_python_source("") == []

    def test_whitespace_only_returns_empty_list(self):
        assert scan_python_source("   \n\n  ") == []

    def test_unparseable_source_returns_empty_without_raising(self):
        assert scan_python_source("def broken(:") == []

    def test_comment_only_file_has_no_crypto_findings(self):
        source = "# rsa is old\n# md5 was used here\nx = 1"
        assert scan_python_source(source) == []


class TestDetection:
    def test_detects_cryptography_rsa_import(self):
        source = "from cryptography.hazmat.primitives.asymmetric import rsa"
        assert "RSA" in algorithms(scan_python_source(source))

    def test_detects_rsa_function_call(self, sample_rsa_source):
        findings = scan_python_source(sample_rsa_source)
        call_findings = [
            f
            for f in findings
            if f["algorithm"] == "RSA" and f["match_type"] == "function_call"
        ]
        assert call_findings, findings

    def test_detects_hashlib_md5_call(self):
        source = "import hashlib\nh = hashlib.md5()"
        assert "MD5" in algorithms(scan_python_source(source))

    def test_detects_hashlib_new_string_arg(self):
        source = 'import hashlib\nh = hashlib.new("sha1")'
        findings = scan_python_source(source)
        sha1 = [f for f in findings if f["algorithm"] == "SHA-1"]
        assert sha1
        assert sha1[0]["match_type"] == "string_arg"

    def test_detects_pycryptodome_rsa_import(self):
        source = "from Crypto.PublicKey import RSA"
        assert "RSA" in algorithms(scan_python_source(source))


class TestOutputShape:
    def test_results_sorted_by_line_number(self):
        source = (
            "from Crypto.Hash import MD5\n"
            "from Crypto.PublicKey import RSA\n"
            "x = 1\n"
            "h = MD5.new()\n"
            "k = RSA.generate(2048)\n"
        )
        findings = scan_python_source(source)
        lines = [f["line"] for f in findings]
        assert lines == sorted(lines)
        assert len(findings) >= 4

    def test_findings_have_required_fields(self, sample_rsa_source):
        findings = scan_python_source(sample_rsa_source)
        assert findings
        for finding in findings:
            missing = REQUIRED_FIELDS - finding.keys()
            assert not missing, f"finding missing fields: {missing}"
