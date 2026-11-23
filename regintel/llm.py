"""LLM clients: local Ollama (default) and, only by explicit opt-in, an Azure OpenAI deployment.

Default rule: inference never leaves the machine / private network. The Ollama
endpoint must resolve exclusively to loopback or private addresses, otherwise
the client refuses to construct. The hosted path (``AzureOpenAIClient``) exists
only when the operator sets ``OPM_REGINTEL_LLM_PROVIDER=azure_openai`` together
with ``OPM_REGINTEL_ALLOW_HOSTED_LLM=1``, and only to Azure OpenAI hosts
(``*.openai.azure.com``, ``*.services.ai.azure.com``). With it, requirement text
and uploaded documents are sent to that deployment: never use it for material
whose licence forbids AI or third-party processing.

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


# ------------------------------------------------------------------ hosted (explicit opt-in only)

AZURE_HOST_SUFFIXES = (".openai.azure.com", ".services.ai.azure.com", ".cognitiveservices.azure.com")


def azure_chat_url(endpoint: str) -> str:
    """The OpenAI v1 chat-completions URL of an Azure resource. Accepts the resource URL or an Azure AI Foundry
    project URL (``https://<resource>.services.ai.azure.com/api/projects/<project>``): the deployment is served by
    the resource, so the path is dropped."""
    parts = urlsplit(endpoint.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host.endswith(AZURE_HOST_SUFFIXES):
        raise LlmError(f"hosted LLM endpoint must be an https Azure OpenAI host ({', '.join(AZURE_HOST_SUFFIXES)}); "
                       f"got {endpoint!r}")
    return f"https://{host}/openai/v1/chat/completions"


class AzureOpenAIClient:
    """Chat completions on an Azure OpenAI deployment, with the same interface as ``OllamaClient``.

    Structured output uses ``response_format: json_schema`` (non-strict: the grammars contain ``anyOf`` and optional
    keys); outputs stay untrusted and are validated by the callers exactly as with the local model. Parameters a
    model rejects (``temperature``/``seed`` on reasoning models, ``json_schema`` on old ones) are dropped once and
    remembered. 429 and 5xx are retried with backoff."""

    def __init__(self, endpoint: str, deployment: str, api_key: str, *, timeout: float = 600.0,
                 max_tokens: int = 4096, transport: httpx.BaseTransport | None = None,
                 sleep: Any = None) -> None:
        if not deployment:
            raise LlmError("set OPM_REGINTEL_AZURE_DEPLOYMENT to the Azure OpenAI deployment name")
        if not api_key:
            raise LlmError("set AZURE_OPENAI_API_KEY (or OPM_REGINTEL_AZURE_API_KEY) for the hosted deployment")
        if timeout <= 0 or max_tokens <= 0:
            raise LlmError("LLM timeout and output limit must be positive")
        self.url = azure_chat_url(endpoint)
        self.model = deployment
        self.max_tokens = max_tokens
        self._client = httpx.Client(timeout=timeout, transport=transport, trust_env=False,
                                    headers={"api-key": api_key, "content-type": "application/json"})
        self._drop: set[str] = set()
        self._sleep = sleep
        self.info = ModelInfo(deployment, f"azure-openai:{deployment}", "azure-openai v1")

    def __enter__(self) -> "AzureOpenAIClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        import time

        sleep = self._sleep or time.sleep
        for attempt in range(6):
            send = {k: v for k, v in body.items() if k not in self._drop}
            try:
                resp = self._client.post(self.url, json=send)
            except httpx.HTTPError as exc:
                if attempt == 5:
                    raise LlmError(f"hosted LLM call failed: {type(exc).__name__}") from exc
                sleep(min(60, 2 ** attempt))
                continue
            if resp.status_code == 400:
                msg = resp.text[:600]
                dropped = [k for k in ("temperature", "seed", "response_format") if k in send and k in msg]
                if dropped:
                    self._drop.update(dropped)
                    continue
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < 5:
                wait = resp.headers.get("retry-after")
                sleep(min(60, float(wait)) if wait and wait.replace(".", "", 1).isdigit() else min(60, 2 ** attempt))
                continue
            if resp.status_code >= 400:
                # the body is the service's error message; it never contains the key
                raise LlmError(f"hosted LLM call failed: HTTP {resp.status_code}: {resp.text[:300]}")
            try:
                data = resp.json()
            except ValueError as exc:
                raise LlmError("hosted LLM returned a non-JSON response") from exc
            if not isinstance(data, dict):
                raise LlmError("hosted LLM returned a non-object response")
            return data
        raise LlmError("hosted LLM call failed after retries")

    def _complete(self, system: str, user: str, max_tokens: int, response_format: dict[str, Any] | None) -> RawOutput:
        body: dict[str, Any] = {"model": self.model, "temperature": 0, "seed": 0, "max_completion_tokens": max_tokens,
                                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if response_format is not None:
            body["response_format"] = response_format
        data = self._post(body)
        choice = (data.get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content")
        if not isinstance(content, str):
            raise LlmError(f"hosted LLM returned no message content (finish_reason {choice.get('finish_reason')})")
        return RawOutput(content, truncated=choice.get("finish_reason") == "length")

    def generate_raw(self, system: str, prompt: str, schema: dict[str, Any]) -> RawOutput:
        fmt = {"type": "json_schema", "json_schema": {"name": "answer", "schema": schema, "strict": False}}
        return self._complete(system, prompt + "\n\nReturn JSON matching this schema:\n"
                              + json.dumps(schema, separators=(",", ":")), self.max_tokens, fmt)

    def generate_text(self, system: str, prompt: str, *, max_tokens: int = 400) -> RawOutput:
        # floor: reasoning deployments spend completion tokens on hidden reasoning before the visible answer
        return self._complete(system, prompt, min(self.max_tokens, max(max_tokens, 1024)), None)

    def generate_json(self, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        raw = self.generate_raw(system, prompt, schema)
        if raw.truncated:
            raise LlmError("hosted LLM output was truncated; increase OPM_REGINTEL_LLM_NUM_PREDICT")
        try:
            return json.loads(raw.content)
        except json.JSONDecodeError as exc:
            raise LlmError("hosted LLM returned output that is not valid JSON") from exc
