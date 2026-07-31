"""Minimal standard-library transport for the OpenAI Responses API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import cast


class OpenAIResponsesTransport:
    _ENDPOINT = "https://api.openai.com/v1/responses"

    def __init__(self, *, api_key: str, timeout_seconds: int = 180) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds

    def create_response(self, payload: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            self._ENDPOINT,
            data=json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read(16_384).decode("utf-8", errors="replace")
            message = f"OpenAI Responses API returned HTTP {error.code}: {detail}"
            raise RuntimeError(message) from error
        parsed: object = json.loads(raw)
        if not isinstance(parsed, dict):
            raise RuntimeError("OpenAI Responses API returned a non-object response")
        return cast("dict[str, object]", parsed)
