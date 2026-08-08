"""Tests for ai_explainer. All HTTP is served by httpx.MockTransport — no
real OpenRouter calls.
"""

import asyncio

import httpx
import pytest

import ai_explainer
from ai_explainer import AIExplainerError, explain_finding


def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


SAMPLE_FINDING = {
    "file": "src/crypto.py",
    "line": 12,
    "language": "python",
    "algorithm": "RSA",
    "severity": "critical",
    "quantum_vulnerable": True,
    "classical_vulnerable": False,
    "attack_vector": "Shor's Algorithm",
    "replacement": "ML-KEM (FIPS 203)",
    "replacement_reason": "Shor's Algorithm factors RSA in polynomial time.",
    "identifier": "rsa.generate_private_key",
    "match_type": "call",
}


def openrouter_success_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/api/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer test-key"
    return httpx.Response(
        200,
        json={
            "model": "openai/gpt-4o-mini",
            "choices": [
                {"message": {"content": "RSA breaks under Shor's Algorithm."}}
            ],
        },
    )


def run_explain(monkeypatch, handler, finding=None, api_key="test-key"):
    monkeypatch.setattr(ai_explainer, "OPENROUTER_API_KEY", api_key)

    async def run():
        async with make_client(handler) as client:
            return await explain_finding(finding or SAMPLE_FINDING, client)

    return asyncio.run(run())


class TestExplainFinding:
    def test_missing_api_key_raises(self, monkeypatch):
        with pytest.raises(AIExplainerError, match="OPENROUTER_API_KEY"):
            run_explain(monkeypatch, openrouter_success_handler, api_key=None)

    def test_missing_algorithm_raises(self, monkeypatch):
        with pytest.raises(AIExplainerError, match="algorithm"):
            run_explain(
                monkeypatch,
                openrouter_success_handler,
                finding={**SAMPLE_FINDING, "algorithm": ""},
            )

    def test_success_returns_content_and_model(self, monkeypatch):
        text, model = run_explain(monkeypatch, openrouter_success_handler)
        assert text == "RSA breaks under Shor's Algorithm."
        assert model == "openai/gpt-4o-mini"

    def test_non_200_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(401, text="invalid api key")

        with pytest.raises(AIExplainerError, match="401"):
            run_explain(monkeypatch, handler)

    def test_malformed_response_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(200, json={"unexpected": "shape"})

        with pytest.raises(AIExplainerError, match="missing content"):
            run_explain(monkeypatch, handler)

    def test_empty_content_raises(self, monkeypatch):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "model": "openai/gpt-4o-mini",
                    "choices": [{"message": {"content": "   "}}],
                },
            )

        with pytest.raises(AIExplainerError, match="empty"):
            run_explain(monkeypatch, handler)

    def test_network_error_raises(self, monkeypatch):
        def handler(request):
            raise httpx.ConnectError("connection refused")

        with pytest.raises(AIExplainerError, match="Could not reach OpenRouter"):
            run_explain(monkeypatch, handler)


class TestBuildPrompt:
    def test_includes_core_fields(self):
        prompt = ai_explainer._build_prompt(SAMPLE_FINDING)
        assert "RSA" in prompt
        assert "critical" in prompt
        assert "Shor's Algorithm" in prompt
        assert "src/crypto.py:12" in prompt

    def test_omits_missing_optional_fields(self):
        prompt = ai_explainer._build_prompt({"algorithm": "RSA"})
        assert "Algorithm: RSA" in prompt
        assert "Location" not in prompt
