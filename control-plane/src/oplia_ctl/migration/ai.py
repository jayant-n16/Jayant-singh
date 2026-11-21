"""Pluggable AI providers for the migration engine: Anthropic Claude API, Azure OpenAI, Amazon Bedrock
and Google Vertex AI. None is required: every feature has a deterministic path (SQLGlot), and AI
output is only ever a *proposal* that a person reviews and approves through the safety gate.

Configured as ``OPLIA_MIGRATION_AI_PROVIDERS`` (JSON list); keys are secret *names* resolved from
Vault / the secret provider when a call is made, never stored here. The request and response shapes
follow each vendor's API reference (see docs/migration-engine.md for the links):

* Anthropic - ``POST https://api.anthropic.com/v1/messages`` with ``x-api-key`` and
  ``anthropic-version: 2023-06-01``; text = ``content[].text`` of ``type == "text"`` blocks.
  Anthropic has no embeddings endpoint, so ``embed`` raises ``NotSupportedError``.
* Azure OpenAI - ``POST {endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...``
  and ``/embeddings`` with the ``api-key`` header (or an Entra ID bearer token).
* Amazon Bedrock - ``bedrock-runtime`` ``converse`` (``output.message.content[].text``); embeddings
  with ``invoke_model`` on a Titan Text Embeddings V2 model (``{"inputText"}`` -> ``embedding``).
* Vertex AI - ``POST https://{location}-aiplatform.googleapis.com/v1/projects/{p}/locations/{l}/
  publishers/google/models/{model}:generateContent`` (``candidates[].content.parts[].text``) and
  ``:predict`` for text embeddings (``predictions[].embeddings.values``), with an OAuth token from
  Application Default Credentials (scope ``cloud-platform``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

ProviderKind = Literal["anthropic", "azure_openai", "bedrock", "vertex"]
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
_MODEL = re.compile(r"^[A-Za-z0-9._:/@-]{1,200}$")


class NotSupportedError(RuntimeError):
    pass


class AIProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    kind: ProviderKind
    model: str                                   # Anthropic model / Azure deployment / Bedrock modelId / Vertex model
    embedding_model: str = ""                    # Azure deployment / Bedrock modelId / Vertex model ("" = none)
    api_key_secret: str = ""                     # anthropic, azure_openai (empty for azure = Entra ID token)
    endpoint: str = ""                           # azure_openai: https://<resource>.openai.azure.com
    api_version: str = "2024-10-21"              # azure_openai
    region: str = ""                             # bedrock region / vertex location
    project: str = ""                            # vertex
    max_tokens: int = Field(default=4096, ge=1, le=64000)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check(self) -> AIProviderConfig:
        for m in (self.model, self.embedding_model):
            if m and not _MODEL.fullmatch(m):
                raise ValueError(f"{self.name}: invalid model name {m!r}")
        if self.kind == "anthropic" and not self.api_key_secret:
            raise ValueError(f"{self.name}: anthropic needs api_key_secret")
        if self.kind == "azure_openai":
            u = urlsplit(self.endpoint)
            if u.scheme != "https" or not u.hostname or u.path not in ("", "/") or u.query:
                raise ValueError(f"{self.name}: endpoint must be https://<resource>.openai.azure.com")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(-preview)?", self.api_version):
                raise ValueError(f"{self.name}: api_version must look like 2024-10-21")
        if self.kind in ("bedrock", "vertex") and not re.fullmatch(r"[a-z0-9-]{2,40}", self.region):
            raise ValueError(f"{self.name}: {self.kind} needs region (Bedrock region / Vertex location)")
        if self.kind == "vertex" and not re.fullmatch(r"[a-z][a-z0-9-]{4,62}", self.project):
            raise ValueError(f"{self.name}: vertex needs project")
        return self


@dataclass
class Completion:
    text: str
    provider: str
    model: str
    stop_reason: str | None
    usage: dict[str, Any]


class AIProvider(Protocol):
    cfg: AIProviderConfig

    def complete(self, system: str, prompt: str) -> Completion: ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class _Http(Protocol):
    def request(self, method: str, url: str, *, expected: set[int] | None = None, **kw: Any) -> Any: ...


class AnthropicProvider:
    def __init__(self, cfg: AIProviderConfig, http: _Http, secrets: Any) -> None:
        self.cfg, self._http, self._secrets = cfg, http, secrets

    def complete(self, system: str, prompt: str) -> Completion:
        r = self._http.request("POST", ANTHROPIC_URL, expected={200}, headers={
            "x-api-key": self._secrets.get(self.cfg.api_key_secret), "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json"}, json={
            "model": self.cfg.model, "max_tokens": self.cfg.max_tokens, "temperature": self.cfg.temperature,
            "system": system, "messages": [{"role": "user", "content": prompt}]})
        d = r.json()
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        return Completion(text, self.cfg.name, str(d.get("model", self.cfg.model)), d.get("stop_reason"),
                          dict(d.get("usage") or {}))

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotSupportedError("the Anthropic API has no embeddings endpoint; configure an embedding_model on an "
                                "azure_openai, bedrock or vertex provider")


class AzureOpenAIProvider:
    def __init__(self, cfg: AIProviderConfig, http: _Http, secrets: Any,
                 token: Callable[[], str] | None = None) -> None:
        self.cfg, self._http, self._secrets, self._token = cfg, http, secrets, token

    def _headers(self) -> dict[str, str]:
        if self.cfg.api_key_secret:
            return {"api-key": self._secrets.get(self.cfg.api_key_secret)}
        if self._token is None:
            from azure.identity import DefaultAzureCredential

            cred = DefaultAzureCredential()
            self._token = lambda: str(cred.get_token("https://cognitiveservices.azure.com/.default").token)
        return {"Authorization": f"Bearer {self._token()}"}

    def _url(self, deployment: str, op: str) -> str:
        base = self.cfg.endpoint.rstrip("/")
        return f"{base}/openai/deployments/{quote(deployment, safe='')}/{op}?api-version={self.cfg.api_version}"

    def complete(self, system: str, prompt: str) -> Completion:
        r = self._http.request("POST", self._url(self.cfg.model, "chat/completions"), expected={200},
                               headers=self._headers(), json={
                                   "messages": [{"role": "system", "content": system},
                                                {"role": "user", "content": prompt}],
                                   "max_tokens": self.cfg.max_tokens, "temperature": self.cfg.temperature})
        d = r.json()
        ch = (d.get("choices") or [{}])[0]
        return Completion(str((ch.get("message") or {}).get("content") or ""), self.cfg.name,
                          str(d.get("model", self.cfg.model)), ch.get("finish_reason"), dict(d.get("usage") or {}))

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not self.cfg.embedding_model:
            raise NotSupportedError(f"{self.cfg.name}: no embedding_model (deployment) configured")
        r = self._http.request("POST", self._url(self.cfg.embedding_model, "embeddings"), expected={200},
                               headers=self._headers(), json={"input": texts})
        rows = sorted(r.json()["data"], key=lambda x: x["index"])
        return [list(map(float, x["embedding"])) for x in rows]


class BedrockProvider:
    def __init__(self, cfg: AIProviderConfig, client: Any = None) -> None:
        self.cfg = cfg
        if client is None:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=cfg.region)
        self._c = client

    def complete(self, system: str, prompt: str) -> Completion:
        d = self._c.converse(modelId=self.cfg.model, system=[{"text": system}],
                             messages=[{"role": "user", "content": [{"text": prompt}]}],
                             inferenceConfig={"maxTokens": self.cfg.max_tokens, "temperature": self.cfg.temperature})
        msg = d["output"]["message"]
        text = "".join(b.get("text", "") for b in msg.get("content", []))
        return Completion(text, self.cfg.name, self.cfg.model, d.get("stopReason"), dict(d.get("usage") or {}))

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not self.cfg.embedding_model:
            raise NotSupportedError(f"{self.cfg.name}: no embedding_model configured")
        out = []
        for t in texts:   # Titan Text Embeddings V2 embeds one text per call
            r = self._c.invoke_model(modelId=self.cfg.embedding_model, contentType="application/json",
                                     accept="application/json", body=json.dumps({"inputText": t}))
            out.append([float(x) for x in json.loads(r["body"].read())["embedding"]])
        return out


class VertexProvider:
    def __init__(self, cfg: AIProviderConfig, http: _Http, token: Callable[[], str] | None = None) -> None:
        self.cfg, self._http = cfg, http
        if token is None:
            import google.auth
            import google.auth.transport.requests

            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])

            def token() -> str:
                if not creds.valid:
                    creds.refresh(google.auth.transport.requests.Request())  # type: ignore[no-untyped-call]
                return str(creds.token)
        self._token = token

    def _url(self, model: str, method: str) -> str:
        c = self.cfg
        return (f"https://{c.region}-aiplatform.googleapis.com/v1/projects/{c.project}/locations/{c.region}/"
                f"publishers/google/models/{quote(model, safe='')}:{method}")

    def complete(self, system: str, prompt: str) -> Completion:
        r = self._http.request("POST", self._url(self.cfg.model, "generateContent"), expected={200},
                               headers={"Authorization": f"Bearer {self._token()}"}, json={
                                   "systemInstruction": {"parts": [{"text": system}]},
                                   "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                                   "generationConfig": {"maxOutputTokens": self.cfg.max_tokens,
                                                        "temperature": self.cfg.temperature}})
        d = r.json()
        cand = (d.get("candidates") or [{}])[0]
        text = "".join(p.get("text", "") for p in (cand.get("content") or {}).get("parts", []))
        return Completion(text, self.cfg.name, self.cfg.model, cand.get("finishReason"),
                          dict(d.get("usageMetadata") or {}))

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not self.cfg.embedding_model:
            raise NotSupportedError(f"{self.cfg.name}: no embedding_model configured")
        per = 1 if self.cfg.embedding_model.startswith("gemini-embedding") else 5   # documented per-request limits
        out: list[list[float]] = []
        for i in range(0, len(texts), per):
            r = self._http.request("POST", self._url(self.cfg.embedding_model, "predict"), expected={200},
                                   headers={"Authorization": f"Bearer {self._token()}"},
                                   json={"instances": [{"content": t} for t in texts[i:i + per]]})
            out += [[float(v) for v in p["embeddings"]["values"]] for p in r.json()["predictions"]]
        return out


def build_providers(configs: list[AIProviderConfig], http: _Http, secrets: Any) -> dict[str, AIProvider]:
    out: dict[str, AIProvider] = {}
    for c in configs:
        if c.name in out:
            raise ValueError(f"duplicate AI provider name {c.name}")
        if c.kind == "anthropic":
            out[c.name] = AnthropicProvider(c, http, secrets)
        elif c.kind == "azure_openai":
            out[c.name] = AzureOpenAIProvider(c, http, secrets)
        elif c.kind == "bedrock":
            out[c.name] = BedrockProvider(c)
        else:
            out[c.name] = VertexProvider(c, http)
    return out


_FENCE = re.compile(r"```(?:[a-zA-Z]+)?\n(.*?)```", re.S)


def extract_code(text: str) -> str:
    """The first fenced code block of a model answer, or the whole answer when there is none."""
    m = _FENCE.search(text)
    return (m.group(1) if m else text).strip()
