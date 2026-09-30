"""The private fixed worker accepts no extra targets/options and never prints failures."""

import io
import json

import pytest

from systemsense.platform.windows import selected_file_worker


@pytest.mark.parametrize(
    "encoded_request",
    [
        b"not-json",
        b'{"selected_path":7}',
        b'{"selected_path":"C:\\\\file.json","command":"unexpected"}',
        b"x" * (selected_file_worker.MAX_REQUEST_BYTES + 1),
    ],
    ids=["invalid-json", "non-string", "extra-authority", "oversized"],
)
def test_worker_rejects_malformed_request_without_capturing_or_echoing(
    monkeypatch: pytest.MonkeyPatch, encoded_request: bytes
) -> None:
    input_stream = io.TextIOWrapper(io.BytesIO(encoded_request), encoding="cp1252")
    output_stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")

    def forbidden(_path: str) -> None:
        pytest.fail("malformed request reached capture")

    monkeypatch.setattr(selected_file_worker.sys, "stdin", input_stream)
    monkeypatch.setattr(selected_file_worker.sys, "stdout", output_stream)
    monkeypatch.setattr(selected_file_worker, "capture_selected_file", forbidden)
    assert selected_file_worker.main() == 2
    assert output_stream.buffer.getvalue() == b""  # type: ignore[attr-defined]


def test_worker_reads_utf8_bytes_even_with_legacy_stdin_text_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "C:\\selected-é-文.json"
    input_stream = io.TextIOWrapper(
        io.BytesIO(json.dumps({"selected_path": path}, ensure_ascii=False).encode("utf-8")),
        encoding="cp1252",
    )
    output_stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    received: list[str] = []

    def fail_capture(selected_path: str) -> None:
        received.append(selected_path)
        raise OSError("PRIVATE_EXCEPTION_MARKER")

    monkeypatch.setattr(selected_file_worker.sys, "stdin", input_stream)
    monkeypatch.setattr(selected_file_worker.sys, "stdout", output_stream)
    monkeypatch.setattr(selected_file_worker, "capture_selected_file", fail_capture)
    assert selected_file_worker.main() == 2
    assert received == [path]
    assert output_stream.buffer.getvalue() == b""  # type: ignore[attr-defined]
