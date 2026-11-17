"""Ollama protocol failures and operator configuration without a live model."""

from __future__ import annotations

import json

import httpx
import pytest

from regintel import __main__ as cli
from regintel.llm import LlmError, OllamaClient


def runtime(chat=None, *, gpu=True):
    def handler(request):
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "test"})
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "local:latest", "digest": "sha256:" + "a" * 64}]})
        if request.url.path == "/api/ps":
            return httpx.Response(200, json={"models": [{"name": "local:latest", "size_vram": 100 if gpu else 0}]})
        body = json.loads(request.content)
        assert body["model"] == "local:latest"
        assert body["options"]["num_ctx"] == 4096
        assert body["options"]["num_predict"] == 2048
        assert body["keep_alive"] == "5m"
        assert json.dumps(body["format"]) in body["messages"][-1]["content"]
        return httpx.Response(200, json=chat if chat is not None else {"message": {"content": '{"ok": true}'}, "done": True})
    return httpx.MockTransport(handler)


def test_untagged_model_uses_canonical_name_for_gpu_check_and_preserves_digest():
    with OllamaClient("http://127.0.0.1:11434", "local", transport=runtime(), require_gpu=True) as client:
        assert client.info.model == "local:latest"
        assert client.info.version == "sha256:" + "a" * 64
        assert client.generate_json("system", "prompt", {"type": "object"}) == {"ok": True}
    assert client._client.is_closed


@pytest.mark.parametrize(("response", "message"), [
    ([], "non-object"),
    ({"error": "model failed"}, "model failed"),
    ({"message": {"content": '{"ok": true}'}, "done_reason": "length"}, "truncated"),
    ({"message": {"content": '{"ok": true}'}, "done": False}, "truncated"),
    ({"message": {"content": "invalid JSON"}}, "not valid JSON"),
    ({}, "no message content"),
])
def test_runtime_failures_are_not_accepted_as_model_output(response, message):
    with OllamaClient("http://127.0.0.1:11434", "local", transport=runtime(response)) as client:
        with pytest.raises(LlmError, match=message):
            client.generate_json("system", "prompt", {})


def test_gpu_required_rejects_cpu_only_response():
    with OllamaClient("http://127.0.0.1:11434", "local", transport=runtime(gpu=False), require_gpu=True) as client:
        with pytest.raises(LlmError, match="CPU-only"):
            client.generate_json("system", "prompt", {})


def test_cli_loads_dotenv_and_preserves_shell_overrides(tmp_path, monkeypatch, capsys):
    from regintel import llm

    monkeypatch.setattr(cli.os, "environ", cli.os.environ.copy())
    for key in tuple(cli.os.environ):
        if key.startswith("OPM_REGINTEL_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    (tmp_path / ".env").write_text(
        'OPM_REGINTEL_LLM_MODEL="local"\nOPM_REGINTEL_REQUIRE_GPU=1\n'
        'OPM_REGINTEL_LLM_NUM_CTX=8192\n', encoding="utf-8")
    monkeypatch.setenv("OPM_REGINTEL_LLM_NUM_CTX", "4096")
    def factory(*args, **kwargs):
        return OllamaClient(*args, **kwargs, transport=runtime())
    monkeypatch.setattr(llm, "OllamaClient", factory)
    assert cli.main(["llm-check"]) == 0
    assert json.loads(capsys.readouterr().out)["model"] == "local:latest"


def test_cli_check_rejects_wrong_json_content(tmp_path, monkeypatch, capsys):
    from regintel import llm

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setenv("OPM_REGINTEL_LLM_MODEL", "local")
    monkeypatch.setenv("OPM_REGINTEL_LLM_NUM_CTX", "4096")
    def factory(*args, **kwargs):
        return OllamaClient(*args, **kwargs, transport=runtime({"message": {"content": '{"ok": false}'}}))
    monkeypatch.setattr(llm, "OllamaClient", factory)
    assert cli.main(["llm-check"]) == 2
    assert "LLM_CHECK_FAILED" in capsys.readouterr().err
