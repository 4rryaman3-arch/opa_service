"""Local LLM client (Ollama HTTP API on the OMEN's NVIDIA GPU).

Hard rule: inference never leaves the machine / private network. The endpoint
must resolve exclusively to loopback or private addresses, otherwise the
client refuses to construct. There is no code path to a hosted LLM API.

Outputs are requested with a JSON schema (Ollama structured outputs) at
temperature 0 and are *still* treated as untrusted: callers validate them
strictly (see ``extraction.py``).
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx


class LlmError(Exception):
    pass


@dataclass(frozen=True)
class ModelInfo:
    model: str
    version: str  # model digest reported by the runtime: identifies the exact weights
    runtime: str


class LocalLlm(Protocol):
    info: ModelInfo

    def generate_json(self, system: str, prompt: str, schema: dict[str, Any]) -> Any: ...

    def generate_raw(self, system: str, prompt: str, schema: dict[str, Any]) -> "RawOutput": ...

    # optional: plain-text reasoning (rule generation uses it when present)
    # def generate_text(self, system: str, prompt: str, *, max_tokens: int = 400) -> "RawOutput": ...


@dataclass(frozen=True)
class RawOutput:
    """The model's generated text exactly as returned, before any parsing.

    ``truncated`` is True when the runtime stopped at the output limit, so the
    content may be malformed JSON. Callers that persist attempts use this to
    retain the raw output instead of discarding it."""

    content: str
    truncated: bool = False


def assert_local_endpoint(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LlmError(f"invalid LLM endpoint: {url!r}")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise LlmError(f"LLM endpoint host '{parts.hostname}' does not resolve") from exc
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if not (ip.is_loopback or ip.is_private or ip.is_link_local):
            raise LlmError(
                f"LLM endpoint '{parts.hostname}' resolves to public address {ip}; "
                "external LLM APIs are not permitted for regulatory processing")


class OllamaClient:
    def __init__(self, base_url: str, model: str, *, timeout: float = 600.0, num_ctx: int = 4096,
                 num_predict: int = 2048, keep_alive: str = "5m",
                 transport: httpx.BaseTransport | None = None, require_gpu: bool = False) -> None:
        if timeout <= 0 or num_ctx <= 0 or num_predict <= 0:
            raise LlmError("LLM timeout, context size and output limit must be positive")
        assert_local_endpoint(base_url)
        self._client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout, transport=transport, trust_env=False)
        self.model = model
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.keep_alive = keep_alive
        self.require_gpu = require_gpu
        try:
            self.info = self._describe()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> OllamaClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _call(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        try:
            resp = self._client.request(method, path, **kw)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LlmError(f"local LLM runtime call {path} failed: {type(exc).__name__}: {exc}") from exc
        if not isinstance(data, dict):
            raise LlmError(f"local LLM runtime call {path} returned a non-object response")
        if data.get("error"):
            raise LlmError(f"local LLM runtime call {path} failed: {data['error']}")
        return data

    def _describe(self) -> ModelInfo:
        runtime = self._call("GET", "/api/version").get("version", "unknown")
        models = self._call("GET", "/api/tags").get("models", [])
        tag = self.model if ":" in self.model.rsplit("/", 1)[-1] else f"{self.model}:latest"
        match = next((m for m in models if m.get("name") in (self.model, tag)
                      or m.get("model") in (self.model, tag)), None)
        if match is None:
            raise LlmError(f"model '{self.model}' is not installed in the local runtime (ollama pull {self.model})")
        self.model = match.get("name") or match.get("model") or self.model
        return ModelInfo(self.model, str(match.get("digest", "unknown")), f"ollama {runtime}")

    def gpu_status(self) -> dict[str, Any]:
        """Which loaded models are on the GPU (size_vram > 0)."""
        loaded = self._call("GET", "/api/ps").get("models", [])
        return {m.get("name"): {"size": m.get("size"), "size_vram": m.get("size_vram")} for m in loaded}

    def generate_raw(self, system: str, prompt: str, schema: dict[str, Any]) -> RawOutput:
        """One inference call; returns the generated text verbatim (even when it
        was truncated at the output limit) so callers can persist it. Raises
        ``LlmError`` only when no output came back at all."""
        body = {
            "model": self.model,
            "stream": False,
            "format": schema,
            "keep_alive": self.keep_alive,
            # stop at a newline + code fence: valid JSON never contains a raw newline inside a string, and small
            # models otherwise repeat the answer as a markdown block until num_predict (minutes per call)
            "options": {"temperature": 0, "seed": 0, "num_ctx": self.num_ctx, "num_predict": self.num_predict,
                        "stop": ["\n```"]},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt + "\n\nReturn JSON matching this schema:\n"
                          + json.dumps(schema, separators=(",", ":"))}],
        }
        data = self._call("POST", "/api/chat", json=body)
        # Ollama silently drops the start of a prompt longer than num_ctx; the model then answers without the
        # instructions or the input. Fail closed instead of returning that output.
        used = int(data.get("prompt_eval_count") or 0) + int(data.get("eval_count") or 0)
        if used >= self.num_ctx:
            raise LlmError(f"prompt and output filled the {self.num_ctx}-token context window; the input was "
                           "truncated. Raise OPM_REGINTEL_LLM_NUM_CTX or shorten the prompt")
        if self.require_gpu:
            status = self.gpu_status().get(self.model) or {}
            if not status.get("size_vram"):
                raise LlmError("model is not loaded on the GPU (size_vram is 0); refusing CPU-only inference")
        content = (data.get("message") or {}).get("content")
        if not isinstance(content, str):
            raise LlmError("local LLM returned no message content")
        return RawOutput(content, truncated=data.get("done") is False or data.get("done_reason") == "length")

    def generate_text(self, system: str, prompt: str, *, max_tokens: int = 400) -> RawOutput:
        """One unconstrained call (no JSON grammar) for short reasoning: small models reason far worse while
        decoding under a grammar, so the rule generator thinks in plain text first and writes JSON second."""
        body = {
            "model": self.model, "stream": False, "keep_alive": self.keep_alive,
            "options": {"temperature": 0, "seed": 0, "num_ctx": self.num_ctx,
                        "num_predict": min(self.num_predict, max_tokens)},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        data = self._call("POST", "/api/chat", json=body)
        used = int(data.get("prompt_eval_count") or 0) + int(data.get("eval_count") or 0)
        if used >= self.num_ctx:
            raise LlmError(f"prompt and output filled the {self.num_ctx}-token context window; the input was "
                           "truncated. Raise OPM_REGINTEL_LLM_NUM_CTX or shorten the prompt")
        content = (data.get("message") or {}).get("content")
        if not isinstance(content, str):
            raise LlmError("local LLM returned no message content")
        return RawOutput(content, truncated=data.get("done") is False or data.get("done_reason") == "length")

    def generate_json(self, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        raw = self.generate_raw(system, prompt, schema)
        if raw.truncated:
            raise LlmError("local LLM output was truncated; increase OPM_REGINTEL_LLM_NUM_PREDICT")
        try:
            return json.loads(raw.content)
        except json.JSONDecodeError as exc:
            raise LlmError("local LLM returned output that is not valid JSON") from exc
