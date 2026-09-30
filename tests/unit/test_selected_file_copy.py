"""Create-only repairs exercise disposable Windows files, never user files."""

import hashlib
import os
from pathlib import Path

import pytest

from systemsense.platform.windows import selected_file, selected_file_copy

# Controlled write/verification failure seams are explicitly synthetic.
# pyright: reportPrivateUsage=false

pytestmark = pytest.mark.skipif(os.name != "nt", reason="real Windows copy test")


def _copy(path: Path, contents: bytes = b'{"private-marker":42}'):
    return selected_file_copy.create_selected_file_copy(
        str(path), contents, hashlib.sha256(contents).hexdigest()
    )


def test_create_copy_verifies_exact_bytes_identity_and_private_result(tmp_path: Path) -> None:
    target = tmp_path / "copie-\u00e9-\u65e5\u672c.json"
    contents = b'{"private-marker":42}'
    result = _copy(target, contents)
    assert result.created
    assert result.outcome == "verified"
    assert result.error_code == "none"
    assert target.read_bytes() == contents
    assert result.verification is not None
    assert result.verification.identity_sha256 == result.created_identity_sha256
    assert result.verification.content_sha256 == hashlib.sha256(contents).hexdigest()
    assert result.verification.size_bytes == len(contents)
    outward = result.model_dump_json() + repr(result)
    assert "private-marker" not in outward
    assert str(target) not in outward


def test_existing_destination_is_preserved_and_terminal(tmp_path: Path) -> None:
    target = tmp_path / "existing.json"
    original = b'\xef\xbb\xbf{"original":true}'
    target.write_bytes(original)
    before = selected_file.capture_selected_file(str(target)).observation
    result = _copy(target)
    assert not result.created
    assert result.outcome == "not_created"
    assert result.error_code == "destination_exists"
    assert target.read_bytes() == original
    assert selected_file.capture_selected_file(str(target)).observation.identity_sha256 == (
        before.identity_sha256
    )


@pytest.mark.parametrize(
    ("contents", "error"),
    [
        (b"{", "invalid_json"),
        (b"\xff", "invalid_json"),
        (b"\xef\xbb\xbf{}", "invalid_json"),
        (b"NaN", "invalid_json"),
        (b"1e999", "invalid_json"),
        (b"[" * 129 + b"0" + b"]" * 129, "invalid_json"),
        (b" " * (selected_file.MAX_SELECTED_FILE_BYTES + 1), "too_large"),
    ],
    ids=["syntax", "encoding", "bom", "nan", "infinite", "nesting", "oversized"],
)
def test_invalid_payload_never_creates_file(tmp_path: Path, contents: bytes, error: str) -> None:
    target = tmp_path / "rejected.json"
    result = _copy(target, contents)
    assert not result.created
    assert result.error_code == error
    assert not target.exists()


def test_expected_hash_must_match_before_create(tmp_path: Path) -> None:
    target = tmp_path / "hash.json"
    result = selected_file_copy.create_selected_file_copy(str(target), b"{}", "0" * 64)
    assert not result.created
    assert result.error_code == "hash_mismatch"
    assert not target.exists()


def test_junction_parent_and_existing_directory_are_refused(tmp_path: Path) -> None:
    from _winapi import CreateJunction

    actual = tmp_path / "actual"
    actual.mkdir()
    junction = tmp_path / "junction"
    CreateJunction(str(actual), str(junction))
    try:
        result = _copy(junction / "copy.json")
        assert not result.created
        assert result.error_code == "path_not_supported"
        assert not (actual / "copy.json").exists()
        existing = _copy(actual)
        assert not existing.created
        assert existing.error_code == "destination_exists"
    finally:
        junction.rmdir()


def test_synthetic_changed_verification_reports_created_without_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "copy.json"
    original_capture = selected_file_copy.capture_selected_file
    calls = 0

    def changed_capture(path: str, *, expected_identity_sha256: str | None = None):
        nonlocal calls
        calls += 1
        assert expected_identity_sha256 is not None
        target.rename(tmp_path / "created-original.json")
        target.write_bytes(b"{}")
        return original_capture(path, expected_identity_sha256=expected_identity_sha256)

    monkeypatch.setattr(selected_file_copy, "capture_selected_file", changed_capture)
    result = _copy(target)
    assert result.created
    assert result.outcome == "created_unverified"
    assert result.error_code == "verification_failed"
    assert result.verification is not None
    assert result.verification.error_code == "identity_mismatch"
    assert calls == 1
    assert target.read_bytes() == b"{}"
    assert (tmp_path / "created-original.json").exists()
