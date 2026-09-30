"""Selected-file diagnostics use only disposable files and synthetic failure seams."""

import dataclasses
import hashlib
import json
import os
import pickle
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from systemsense.platform.windows import selected_file

# Synthetic reader seams are local to this module's focused collector tests.
# pyright: reportPrivateUsage=false


@pytest.mark.skipif(os.name != "nt", reason="real Windows handle test")
def test_real_selected_file_capture_is_private_and_checks_share_exact_hash(tmp_path: Path) -> None:
    target = tmp_path / "private-name.json"
    contents = b'{"private-content-marker":42}'
    target.write_bytes(contents)

    capture = selected_file.capture_selected_file(str(target))

    assert capture.observation.outcome == "read_ok"
    assert capture.observation.size_bytes == len(contents)
    assert capture.observation.content_sha256 == hashlib.sha256(contents).hexdigest()
    assert capture.observation.identity_sha256
    assert selected_file.check_utf8(capture).outcome == "valid_utf8"
    result = selected_file.check_json(capture)
    assert result.outcome == "valid_json"
    assert result.content_sha256 == capture.observation.content_sha256
    assert result.identity_sha256 == capture.observation.identity_sha256
    outward = capture.observation.model_dump_json() + result.model_dump_json() + repr(capture)
    assert "private-content-marker" not in outward
    assert str(target) not in outward
    with pytest.raises(TypeError):
        dataclasses.asdict(capture)  # type: ignore[arg-type]
    with pytest.raises((AttributeError, TypeError)):
        json.dumps(capture)
    with pytest.raises(TypeError):
        pickle.dumps(capture)
    with pytest.raises(AttributeError):
        capture.observation = capture.observation  # type: ignore[misc]


@pytest.mark.skipif(os.name != "nt", reason="real Windows handle test")
@pytest.mark.parametrize(
    ("contents", "utf8", "json_outcome", "code"),
    [
        (b'{"secret": }', "valid_utf8", "invalid_json", "json_syntax"),
        (b"\xff", "invalid_utf8", "invalid_utf8", "invalid_utf8"),
        (b"\xef\xbb\xbf{}", "valid_utf8", "invalid_json", "utf8_bom"),
        (b"", "valid_utf8", "invalid_json", "empty_document"),
        (b"NaN", "valid_utf8", "invalid_json", "non_finite_number"),
        (b"1e99999", "valid_utf8", "invalid_json", "non_finite_number"),
        (b"[" * 1100 + b"0" + b"]" * 1100, "valid_utf8", "invalid_json", "nesting_limit"),
        (b"9" * 4301, "valid_utf8", "invalid_json", "number_limit"),
        ("\u00a0".encode(), "valid_utf8", "invalid_json", "json_syntax"),
    ],
    ids=[
        "syntax",
        "encoding",
        "bom",
        "empty",
        "nan",
        "infinite-float",
        "nesting",
        "integer-limit",
        "non-json-whitespace",
    ],
)
def test_real_file_encoding_and_json_controls(
    tmp_path: Path, contents: bytes, utf8: str, json_outcome: str, code: str
) -> None:
    target = tmp_path / "sample.json"
    target.write_bytes(contents)
    capture = selected_file.capture_selected_file(str(target))
    assert capture.observation.outcome == "read_ok"
    assert selected_file.check_utf8(capture).outcome == utf8
    result = selected_file.check_json(capture)
    assert result.outcome == json_outcome
    assert result.error_code == code


@pytest.mark.skipif(os.name != "nt", reason="real Windows handle test")
def test_real_file_missing_directory_size_and_replaced_identity_controls(tmp_path: Path) -> None:
    missing = selected_file.capture_selected_file(str(tmp_path / "missing.json"))
    assert missing.observation.outcome == "missing"
    directory = selected_file.capture_selected_file(str(tmp_path))
    assert directory.observation.outcome == "unsupported"
    assert directory.observation.error_code == "not_regular_file"
    target = tmp_path / "bounded.json"
    target.write_bytes(b" " * (selected_file.MAX_SELECTED_FILE_BYTES + 1))
    oversized = selected_file.capture_selected_file(str(target))
    assert oversized.observation.outcome == "too_large"
    assert oversized.observation.content_sha256 is None
    assert selected_file.check_json(oversized).outcome == "read_unavailable"
    target.write_bytes(b"{}" + b" " * (selected_file.MAX_SELECTED_FILE_BYTES - 2))
    original = selected_file.capture_selected_file(str(target))
    assert original.observation.outcome == "read_ok"
    assert selected_file.check_json(original).outcome == "valid_json"
    # Keep the original inode alive so replacement cannot recycle its file ID.
    target.rename(tmp_path / "original.json")
    target.write_bytes(b"{}")
    replaced = selected_file.capture_selected_file(
        str(target), expected_identity_sha256=original.observation.identity_sha256
    )
    assert replaced.observation.outcome == "changed_during_read"
    assert replaced.observation.error_code == "identity_mismatch"
    assert replaced.observation.content_sha256 is None
    # Pure checks do not silently reopen the replaced pathname.
    assert selected_file.check_json(original).content_sha256 == original.observation.content_sha256


@pytest.mark.skipif(os.name != "nt", reason="real Windows handle test")
@pytest.mark.parametrize("parent_link", [False, True], ids=["leaf-link", "parent-link"])
def test_real_windows_symlink_is_not_followed(tmp_path: Path, parent_link: bool) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    target = actual / "target.json"
    target.write_bytes(b"{}")
    link = tmp_path / "link"
    try:
        link.symlink_to(actual if parent_link else target, target_is_directory=parent_link)
    except OSError as error:
        if error.winerror == 1314:
            pytest.skip("Windows developer mode or symlink privilege unavailable")
        raise
    selected = link / "target.json" if parent_link else link
    capture = selected_file.capture_selected_file(str(selected))
    assert capture.observation.outcome == "unsupported"
    assert capture.observation.error_code == "reparse_point"
    assert capture.observation.content_sha256 is None


@pytest.mark.skipif(os.name != "nt", reason="real Windows junction test")
def test_real_windows_junction_parent_is_not_followed(tmp_path: Path) -> None:
    # CPython's Windows test helper creates an NTFS junction without changing
    # privileges or ACLs. Both the junction and its target belong to this test.
    from _winapi import CreateJunction

    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "file.json").write_bytes(b"{}")
    junction = tmp_path / "junction"
    CreateJunction(str(actual), str(junction))
    try:
        assert (junction / "file.json").read_bytes() == b"{}"
        result = selected_file.capture_selected_file(str(junction / "file.json"))
        assert result.observation.outcome == "unsupported"
        assert result.observation.error_code == "reparse_point"
        assert result.observation.content_sha256 is None
    finally:
        # Unlink only the exact test-owned junction, never recurse through it.
        junction.rmdir()


@pytest.mark.parametrize(
    "path",
    [
        r"\\server\share\file.json",
        r"\\?\C:\file.json",
        r"\\.\PhysicalDrive0",
        r"C:\file.json:secret",
        r"C:relative.json",
        r"relative.json",
        r"C:\CON.json",
        r"C:\COM1.json",
        "C:\\trailing. ",
        r"C:\parent\..\file.json",
        "C:/file.json",
        "C:\\bad\x00.json",
        "C:\\bad\ud800.json",
        r"C:\\double\file.json",
    ],
)
def test_disallowed_paths_are_rejected_before_filesystem_calls(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    def forbidden(*_args: object) -> None:
        pytest.fail("unsupported path reached filesystem")

    monkeypatch.setattr(selected_file, "_open_selected_file", forbidden)
    result = selected_file.capture_selected_file(path)
    assert result.observation.outcome == "unsupported"
    assert result.observation.error_code == "path_not_supported"


def test_synthetic_denied_read_has_no_exception_or_path_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def denied(_root: str, _components: tuple[str, ...]) -> Generator[selected_file._FileReader]:
        raise selected_file._ReadFailure("read_denied", "read_denied")
        yield  # pragma: no cover

    monkeypatch.setattr(selected_file, "_open_selected_file", denied)
    capture = selected_file.capture_selected_file(r"C:\private\secret.json")
    assert capture.observation.outcome == "read_denied"
    assert "private" not in capture.observation.model_dump_json()
    assert selected_file.check_utf8(capture).outcome == "read_unavailable"


@pytest.mark.parametrize("change", ["size", "identity", "mtime", "change_time", "short_read"])
def test_synthetic_mid_read_change_discards_bytes_and_hash(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    original = selected_file._FileState("a" * 64, 2, 10000000, 10000000)

    class Reader:
        reads = 0

        def state(self) -> selected_file._FileState:
            if not self.reads:
                return original
            return dataclasses.replace(
                original,
                size_bytes=3 if change == "size" else 2,
                identity_sha256="b" * 64 if change == "identity" else original.identity_sha256,
                modified_ticks=20000000 if change == "mtime" else original.modified_ticks,
                changed_ticks=20000000 if change == "change_time" else original.changed_ticks,
            )

        def read(self, limit: int) -> bytes:
            assert limit == selected_file.MAX_SELECTED_FILE_BYTES
            self.reads += 1
            return b"{" if change == "short_read" else b"{}"

    @contextmanager
    def opened(_root: str, _components: tuple[str, ...]) -> Generator[selected_file._FileReader]:
        yield Reader()

    monkeypatch.setattr(selected_file, "_open_selected_file", opened)
    capture = selected_file.capture_selected_file(r"C:\selected.json")
    assert capture.observation.outcome == "changed_during_read"
    assert capture.observation.content_sha256 is None
    assert selected_file.check_json(capture).outcome == "read_unavailable"


@pytest.mark.skipif(
    os.name != "nt", reason="real Windows handle test with controlled test-file write"
)
def test_real_capture_detects_owned_file_change_before_final_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "changing.json"
    target.write_bytes(b"{}")
    original_read = selected_file._WindowsFile.read

    def changed_read(source: selected_file._WindowsFile, limit: int) -> bytes:
        captured = original_read(source, limit)
        target.write_bytes(b'{"changed":true}')
        return captured

    monkeypatch.setattr(selected_file._WindowsFile, "read", changed_read)
    capture = selected_file.capture_selected_file(str(target))
    assert capture.observation.outcome == "changed_during_read"
    assert capture.observation.content_sha256 is None


@pytest.mark.skipif(os.name != "nt", reason="real Windows handle test")
def test_json_limit_does_not_count_brackets_inside_escaped_strings(tmp_path: Path) -> None:
    target = tmp_path / "strings.json"
    target.write_text(json.dumps({"data": '\\"' + "[" * 2000}), encoding="utf-8")
    capture = selected_file.capture_selected_file(str(target))
    assert selected_file.check_json(capture).outcome == "valid_json"


@pytest.mark.skipif(os.name != "nt", reason="real Windows handle test")
def test_parser_reports_only_line_column_code_for_private_error(tmp_path: Path) -> None:
    target = tmp_path / "line.json"
    target.write_bytes(b'{\n  "SECRET_MARKER":\n}')
    result = selected_file.check_json(selected_file.capture_selected_file(str(target)))
    assert result.outcome == "invalid_json"
    assert (result.line, result.column) == (3, 1)
    assert result.error_code == "json_syntax"
    assert "SECRET_MARKER" not in result.model_dump_json()


@pytest.mark.skipif(os.name != "nt", reason="real Windows handle test")
def test_capture_rejects_mutable_or_substituted_private_bytes(tmp_path: Path) -> None:
    target = tmp_path / "capture.json"
    target.write_bytes(b"{}")
    observation = selected_file.capture_selected_file(str(target)).observation
    with pytest.raises(ValueError, match="capture_binding_invalid"):
        selected_file.SelectedFileCapture(observation, bytearray(b"{}"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="capture_binding_invalid"):
        selected_file.SelectedFileCapture(observation, b"[]")
