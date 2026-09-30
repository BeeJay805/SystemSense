"""Private helper transport, deterministic shutdown controls and actual Windows smoke."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from systemsense.application import native_file_capture
from systemsense.platform.windows.selected_file import SelectedFileObservation, check_json
from systemsense.platform.windows.selected_file_worker import NativeFileResponse


def _unavailable_response() -> bytes:
    now = datetime.now(UTC)
    observation = SelectedFileObservation(
        outcome="missing",
        error_code="missing",
        collection_started_at=now,
        collection_completed_at=now,
    )
    return NativeFileResponse(observation=observation).model_dump_json().encode()


class FakeHelper:
    def __init__(
        self,
        *,
        response: bytes | None = None,
        cancel: threading.Event | None = None,
        blocked_input: bool = False,
    ) -> None:
        self.response = response
        self.cancel = cancel
        self.returncode: int | None = None
        self.killed = False
        self.waited = False
        self.inputs: list[bytes] = []
        self.stopped = threading.Event()
        helper = self

        class Input(io.BytesIO):
            def write(self, buffer: object) -> int:
                assert isinstance(buffer, bytes)
                helper.inputs.append(buffer)
                if blocked_input:
                    assert helper.stopped.wait(2)
                    raise BrokenPipeError
                return len(buffer)

        class Output(io.BytesIO):
            def read(self, size: int | None = -1) -> bytes:
                assert size == native_file_capture.MAX_RESPONSE_BYTES + 1
                if helper.cancel is not None:
                    helper.cancel.set()
                if helper.response is None:
                    assert helper.stopped.wait(2)
                    return b""
                helper.returncode = 0
                return helper.response[:size]

        self.stdin = Input()
        self.stdout = Output()

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = 1
        self.stopped.set()

    def wait(self, timeout: float) -> int:
        assert timeout <= 1
        self.waited = True
        assert self.returncode is not None
        return self.returncode


def _install_helper(monkeypatch: pytest.MonkeyPatch, helper: FakeHelper) -> None:
    def launch(command: list[str], **options: object) -> subprocess.Popen[bytes]:
        assert command[1:] == ["-m", "systemsense.platform.windows.selected_file_worker"]
        assert all("selected-secret" not in item for item in command)
        assert options["stderr"] == subprocess.DEVNULL
        assert options["creationflags"] == (0x08000000 if os.name == "nt" else 0)
        return cast("subprocess.Popen[bytes]", helper)

    monkeypatch.setattr(native_file_capture.subprocess, "Popen", launch)


def test_fake_timeout_kills_and_reaps_only_owned_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    helper = FakeHelper()
    _install_helper(monkeypatch, helper)
    with pytest.raises(native_file_capture.NativeFileCaptureError, match=r"^timeout$"):
        native_file_capture.capture_selected_file_bounded(
            r"C:\selected-secret.json", threading.Event(), timeout_seconds=0.15
        )
    assert helper.killed and helper.waited
    assert len(helper.inputs) == 1


def test_fake_cancel_kills_and_reaps_only_owned_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    cancellation = threading.Event()
    helper = FakeHelper(cancel=cancellation)
    _install_helper(monkeypatch, helper)
    with pytest.raises(native_file_capture.NativeFileCaptureError, match=r"^cancelled$"):
        native_file_capture.capture_selected_file_bounded(r"C:\selected-secret.json", cancellation)
    assert helper.killed and helper.waited


def test_blocked_long_path_pipe_write_cannot_bypass_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = FakeHelper(blocked_input=True)
    _install_helper(monkeypatch, helper)
    path = "C:\\" + "\\".join(["a" * 250] * 64)
    with pytest.raises(native_file_capture.NativeFileCaptureError, match=r"^timeout$"):
        native_file_capture.capture_selected_file_bounded(
            path, threading.Event(), timeout_seconds=0.1
        )
    assert helper.killed and helper.waited
    assert helper.stdin.closed and helper.stdout.closed


@pytest.mark.parametrize(
    "response",
    [b"private-content-is-not-json", b"{}", b"x" * (401 * 1024)],
    ids=["invalid-json", "invalid-schema", "oversized"],
)
def test_invalid_private_response_is_rejected_without_echo(
    monkeypatch: pytest.MonkeyPatch, response: bytes
) -> None:
    helper = FakeHelper(response=response)
    _install_helper(monkeypatch, helper)
    with pytest.raises(native_file_capture.NativeFileCaptureError) as raised:
        native_file_capture.capture_selected_file_bounded(
            r"C:\selected-secret.json", threading.Event()
        )
    assert str(raised.value) in {"invalid_response", "output_limit"}
    assert helper.waited


def test_valid_failure_observation_roundtrips_and_path_is_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = FakeHelper(response=_unavailable_response())
    _install_helper(monkeypatch, helper)
    capture = native_file_capture.capture_selected_file_bounded(
        r"C:\selected-secret.json", threading.Event()
    )
    assert capture.observation.outcome == "missing"
    assert helper.inputs[0] is not None
    assert json.loads(helper.inputs[0])["selected_path"] == r"C:\selected-secret.json"
    assert "selected-secret" not in repr(capture)
    assert helper.waited


@pytest.mark.parametrize("mutation", ["wrong-hash", "wrong-size", "bad-base64", "oversized-bytes"])
def test_private_response_requires_exact_content_binding(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    now = datetime.now(UTC)
    observation = SelectedFileObservation(
        outcome="read_ok",
        identity_sha256="a" * 64,
        size_bytes=3 if mutation == "wrong-size" else 2,
        modified_at=now,
        collection_started_at=now,
        collection_completed_at=now,
        content_sha256=hashlib.sha256(b"{}").hexdigest(),
    )
    contents = (
        b"[]"
        if mutation == "wrong-hash"
        else b"x" * (256 * 1024 + 1)
        if mutation == "oversized-bytes"
        else b"{}"
    )
    response = json.dumps(
        {
            "observation": observation.model_dump(mode="json"),
            "contents_base64": "!!"
            if mutation == "bad-base64"
            else base64.b64encode(contents).decode(),
        }
    ).encode()
    helper = FakeHelper(response=response)
    _install_helper(monkeypatch, helper)
    with pytest.raises(native_file_capture.NativeFileCaptureError, match=r"^invalid_response$"):
        native_file_capture.capture_selected_file_bounded(
            r"C:\selected-secret.json", threading.Event()
        )
    assert helper.waited


def test_cancelled_grant_never_spawns_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("cancelled capture launched a process")

    monkeypatch.setattr(native_file_capture.subprocess, "Popen", forbidden)
    cancellation = threading.Event()
    cancellation.set()
    with pytest.raises(native_file_capture.NativeFileCaptureError, match=r"^cancelled$"):
        native_file_capture.capture_selected_file_bounded(r"C:\selected-secret.json", cancellation)


@pytest.mark.skipif(os.name != "nt", reason="actual Windows helper smoke")
def test_actual_helper_reads_unicode_selected_path_without_content_in_metadata(
    tmp_path: Path,
) -> None:
    path = tmp_path / "selected-é-文.json"
    path.write_bytes(b'{"private-content-marker":42}')
    capture = native_file_capture.capture_selected_file_bounded(str(path), threading.Event())
    assert capture.observation.outcome == "read_ok"
    assert check_json(capture).outcome == "valid_json"
    assert "private-content-marker" not in capture.observation.model_dump_json()
    assert str(path) not in repr(capture)
