import pytest

from systemsense.evidence.redaction import Redactor


@pytest.mark.parametrize(
    ("source", "secret"),
    [
        (r"C:\Users\brennan\AppData\Local\Crash\dump.txt", "brennan"),
        ("/home/brennan/.config/tool/settings.json", "brennan"),
        ("username=brennan", "brennan"),
        ("API_KEY=abc123-super-secret", "abc123-super-secret"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature", "eyJhbGci"),
        ("https://user:pass@example.test/api?token=abc123", "user:pass"),
        (r"USERPROFILE=C:\Users\brennan", "brennan"),
        ("HOME=/home/brennan", "brennan"),
        ("ghp_0123456789abcdefghijklmnopqrstuvwxyz", "ghp_012345"),
    ],
)
def test_sensitive_text_fixtures_are_redacted(source: str, secret: str) -> None:
    result = Redactor().redact_text(source)

    assert secret not in result.text
    assert result.replacements >= 1
    assert "<redacted-" in result.text


def test_non_sensitive_diagnostic_facts_are_preserved() -> None:
    source = "event_id=1000 error_code=0xc0000005 module=example.dll"

    result = Redactor().redact_text(source)

    assert result.text == source
    assert result.replacements == 0


@pytest.mark.parametrize("field_name", ["password", "client_secret", "access_token", "api_key"])
def test_sensitive_fields_are_redacted_without_pattern_guessing(field_name: str) -> None:
    assert Redactor().redact_field(field_name, "unstructured value") == "<redacted-secret>"
