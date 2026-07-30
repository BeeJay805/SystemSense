"""Conservative redaction for agent-visible diagnostic text."""

import re

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class RedactionResult(FrozenModel):
    text: str
    replacements: int = Field(ge=0)


class Redactor:
    """Remove common credentials and personal path components without inference."""

    _patterns: tuple[tuple[re.Pattern[str], str], ...] = (
        (
            re.compile(
                r"(?i)\b([a-z][a-z0-9_.-]*(?:key|token|secret|password|passwd|credential)"
                r"[a-z0-9_.-]*)\s*([=:])\s*[^\s,;]+"
            ),
            r"\1\2<redacted-secret>",
        ),
        (
            re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
            "Bearer <redacted-token>",
        ),
        (
            re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b"),
            "<redacted-token>",
        ),
        (
            re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+"),
            "<redacted-url>",
        ),
        (
            re.compile(
                r"(?i)(?<![\w])(?:[a-z]:\\users\\)[^\\\s\"'<>|]+"
                r"(?:\\[^\s\"'<>|]*)?"
            ),
            "<redacted-user-path>",
        ),
        (
            re.compile(r"(?i)(?<![\w])/(?:home|users)/[^/\s]+(?:/[^\s\"'<>]*)?"),
            "<redacted-user-path>",
        ),
        (
            re.compile(
                r"(?im)\b(USERPROFILE|USERNAME|HOME|HOMEPATH|APPDATA|LOCALAPPDATA|TEMP|TMP)"
                r"\s*=\s*[^\r\n;]+"
            ),
            r"\1=<redacted-environment>",
        ),
        (
            re.compile(r"(?i)\b(user(?:name)?|account|owner)\s*([=:])\s*[^\s,;]+"),
            r"\1\2<redacted-user>",
        ),
    )
    _sensitive_field_tokens = frozenset(
        {
            "authorization",
            "credential",
            "key",
            "pass",
            "passwd",
            "password",
            "secret",
            "token",
        }
    )

    def redact_text(self, text: str) -> RedactionResult:
        redacted = text
        replacements = 0
        for pattern, replacement in self._patterns:
            redacted, count = pattern.subn(replacement, redacted)
            replacements += count
        return RedactionResult(text=redacted, replacements=replacements)

    def redact_field(self, field_name: str, value: str) -> str:
        field_tokens = frozenset(
            token for token in re.split(r"[^a-z]+", field_name.lower()) if token
        )
        if field_tokens & self._sensitive_field_tokens:
            return "<redacted-secret>"
        return self.redact_text(value).text
