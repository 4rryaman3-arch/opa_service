"""Hosted LLM (Azure OpenAI) client: explicit opt-in, Azure hosts only, same interface as the local client.

No network: every call goes to an httpx.MockTransport. The key below is a placeholder, not a credential."""
from __future__ import annotations

import json

import httpx
import pytest

from regintel import __main__ as cli
from regintel.db import CatalogError
from regintel.llm import AzureOpenAIClient, LlmError, azure_chat_url

KEY = "placeholder-not-a-key"
PROJECT = "https://example-resource.services.ai.azure.com/api/projects/example-project"


def client(handler, **kw):
    return AzureOpenAIClient(PROJECT, "gpt-test", KEY, transport=httpx.MockTransport(handler), sleep=lambda _s: None,
                             **kw)


def reply(content, finish="stop"):
    return httpx.Response(200, json={"choices": [{"message": {"content": content}, "finish_reason": finish}]})


def test_project_url_maps_to_the_resource_v1_endpoint_and_only_azure_hosts_are_allowed():
    assert azure_chat_url(PROJECT) == "https://example-resource.services.ai.azure.com/openai/v1/chat/completions"
    assert azure_chat_url("https://x.openai.azure.com/").endswith("x.openai.azure.com/openai/v1/chat/completions")
    for bad in ("https://api.openai.com/v1", "http://x.openai.azure.com", "https://evil.example/x.openai.azure.com"):
        with pytest.raises(LlmError):
            azure_chat_url(bad)


def test_structured_call_sends_schema_key_header_and_returns_raw_content():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["key"] = request.headers.get("api-key")
        seen["url"] = str(request.url)
        return reply('{"ok": true}')

    llm = client(handler)
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    assert llm.generate_json("sys", "prompt", schema) == {"ok": True}
    body = seen["body"]
    assert seen["key"] == KEY and seen["url"].endswith("/openai/v1/chat/completions")
    assert body["model"] == "gpt-test" and body["temperature"] == 0
    assert body["response_format"]["json_schema"]["schema"] == schema
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert llm.info.model == "gpt-test" and llm.info.runtime.startswith("azure-openai")


def test_text_call_has_no_grammar_and_truncation_is_reported():
    def handler(request):
        assert "response_format" not in json.loads(request.content)
        return reply("VERDICT: NOT_TESTABLE", finish="length")

    out = client(handler).generate_text("sys", "prompt", max_tokens=200)
    assert out.content == "VERDICT: NOT_TESTABLE" and out.truncated


def test_rejected_parameters_are_dropped_and_rate_limits_retried():
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(sorted(body))
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "1"}, json={"error": "busy"})
        if "temperature" in body:
            return httpx.Response(400, json={"error": {"message": "Unsupported parameter: 'temperature'"}})
        return reply("{}")

    llm = client(handler)
    llm.generate_raw("s", "p", {"type": "object"})
    assert "temperature" not in calls[-1] and len(calls) == 3
    llm.generate_raw("s", "p", {"type": "object"})  # remembered: no second rejection
    assert len(calls) == 4


def test_errors_never_echo_the_key():
    llm = client(lambda request: httpx.Response(401, json={"error": "denied"}))
    with pytest.raises(LlmError) as exc:
        llm.generate_text("s", "p")
    assert KEY not in str(exc.value) and "401" in str(exc.value)


def test_provider_needs_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("OPM_REGINTEL_LLM_PROVIDER", "azure_openai")
    monkeypatch.setenv("OPM_REGINTEL_AZURE_ENDPOINT", PROJECT)
    monkeypatch.setenv("OPM_REGINTEL_AZURE_DEPLOYMENT", "gpt-test")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", KEY)
    monkeypatch.delenv("OPM_REGINTEL_ALLOW_HOSTED_LLM", raising=False)
    with pytest.raises(CatalogError) as exc:
        cli._llm()
    assert "OPM_REGINTEL_ALLOW_HOSTED_LLM" in exc.value.message
    monkeypatch.setenv("OPM_REGINTEL_ALLOW_HOSTED_LLM", "1")
    with cli._llm() as llm:
        assert isinstance(llm, AzureOpenAIClient) and llm.model == "gpt-test"
    monkeypatch.setenv("OPM_REGINTEL_LLM_PROVIDER", "other")
    with pytest.raises(CatalogError):
        cli._llm()
