"""Explicit opt-in configuration for local advisory inference."""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import Field, field_validator

from systemsense.domain.evidence import FrozenModel

OLLAMA_CHAT_ENDPOINT = "http://127.0.0.1:11434/api/chat"
OLLAMA_SHOW_ENDPOINT = "http://127.0.0.1:11434/api/show"
OLLAMA_TAGS_ENDPOINT = "http://127.0.0.1:11434/api/tags"


class LocalInferenceConfig(FrozenModel):
    """Local-only settings; defaults cannot start inference or use a GPU."""

    enabled: bool = False
    endpoint: str = OLLAMA_CHAT_ENDPOINT
    decision_model: str | None = Field(default=None, min_length=1, max_length=120)
    reasoning_model: str | None = Field(default=None, min_length=1, max_length=120)
    reasoning_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    tokenizer_path: Path | None = None
    tokenizer_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    allow_gpu: bool = False
    keep_alive_seconds: int = Field(default=0, ge=0, le=300)
    timeout_seconds: float = Field(default=10, gt=0, le=180)
    context_tokens: int = Field(default=8192, ge=2048, le=32768)
    output_tokens: int = Field(default=1200, ge=128, le=4096)
    cpu_threads: int = Field(default=4, ge=1, le=16)
    thinking: bool = False
    max_request_bytes: int = Field(default=131_072, ge=1024, le=1_048_576)
    max_response_bytes: int = Field(default=65_536, ge=1024, le=262_144)

    @field_validator("endpoint")
    @classmethod
    def fixed_loopback_endpoint(cls, value: str) -> str:
        match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{4,5})/api/chat", value)
        if match is None or not 1024 <= int(match[1]) <= 65535:
            raise ValueError("endpoint must use a fixed loopback IPv4 address and /api/chat")
        return value

    @field_validator("decision_model", "reasoning_model")
    @classmethod
    def local_model_only(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.casefold()
        if "cloud" in normalized:
            raise ValueError("cloud model suffixes are not allowed")
        if "://" in value or any(character.isspace() for character in value):
            raise ValueError("remote model references are not allowed")
        return value


class ProviderStatus(FrozenModel):
    provider_id: str
    enabled: bool
    available: bool
    detail: str = Field(min_length=1, max_length=120)
