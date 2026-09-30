"""Cancellable, bounded subprocess capture for a native-only selected-file grant."""

from __future__ import annotations

import math
import os
import subprocess
import sys
import threading
import time
from typing import Literal

from systemsense.platform.windows.selected_file import SelectedFileCapture
from systemsense.platform.windows.selected_file_worker import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    NativeFileRequest,
    NativeFileResponse,
)

_WORKER = "systemsense.platform.windows.selected_file_worker"


class NativeFileCaptureError(RuntimeError):
    """Fixed safe error code; never includes selected path, response or exception text."""

    def __init__(
        self,
        code: Literal[
            "cancelled", "timeout", "helper_unavailable", "invalid_response", "output_limit"
        ],
    ) -> None:
        super().__init__(code)
        self.code = code


def _stop_owned_helper(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    # The fixed helper never spawns children. Bound cleanup separately from its
    # five-second read deadline, and never imply success without observed exit.
    process.wait(timeout=1)


class _PrivateExchange:
    """Keep Windows pipe writes and bounded reads outside the deadline owner.

    Windows communicate(timeout=...) writes stdin synchronously and its reader
    consumes unbounded stdout. Both can violate this private protocol's limits.
    """

    def __init__(self, process: subprocess.Popen[bytes], request: bytes) -> None:
        sink, source = process.stdin, process.stdout
        if sink is None or source is None:
            raise NativeFileCaptureError("helper_unavailable")
        self.output = b""
        self.failed = False
        self.read_done = threading.Event()
        self.write_done = threading.Event()

        def write() -> None:
            try:
                with sink:
                    sink.write(request)
                    sink.flush()
            except (OSError, ValueError):
                self.failed = True
            finally:
                self.write_done.set()

        def read() -> None:
            try:
                with source:
                    self.output = source.read(MAX_RESPONSE_BYTES + 1)
            except (OSError, ValueError):
                self.failed = True
            finally:
                self.read_done.set()

        self.threads = (
            threading.Thread(target=write, name="selected-file-input", daemon=True),
            threading.Thread(target=read, name="selected-file-output", daemon=True),
        )
        for thread in self.threads:
            thread.start()

    def join(self) -> None:
        deadline = time.monotonic() + 1
        for thread in self.threads:
            thread.join(max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in self.threads):
            raise NativeFileCaptureError("helper_unavailable")


def capture_selected_file_bounded(
    path: str, cancel_event: threading.Event, timeout_seconds: float = 5.0
) -> SelectedFileCapture:
    """Read exactly one selected file in an owned hidden helper, without blocking shutdown."""
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 5:
        raise ValueError("capture_timeout_out_of_bounds")
    try:
        request = NativeFileRequest(selected_path=path).model_dump_json().encode("utf-8")
    except ValueError:
        raise NativeFileCaptureError("invalid_response") from None
    if len(request) > MAX_REQUEST_BYTES:
        raise NativeFileCaptureError("invalid_response")
    if cancel_event.is_set():
        raise NativeFileCaptureError("cancelled")
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", _WORKER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
    except OSError:
        raise NativeFileCaptureError("helper_unavailable") from None
    exchange: _PrivateExchange | None = None
    try:
        exchange = _PrivateExchange(process, request)
        while True:
            if cancel_event.is_set():
                raise NativeFileCaptureError("cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeFileCaptureError("timeout")
            if exchange.read_done.is_set() and len(exchange.output) > MAX_RESPONSE_BYTES:
                raise NativeFileCaptureError("output_limit")
            if exchange.failed:
                raise NativeFileCaptureError("helper_unavailable")
            if (
                exchange.read_done.is_set()
                and exchange.write_done.is_set()
                and process.poll() is not None
            ):
                if process.returncode != 0:
                    raise NativeFileCaptureError("helper_unavailable")
                try:
                    captured = NativeFileResponse.model_validate_json(
                        exchange.output
                    ).private_capture()
                except (ValueError, TypeError):
                    raise NativeFileCaptureError("invalid_response") from None
                if cancel_event.is_set():
                    raise NativeFileCaptureError("cancelled")
                return captured
            cancel_event.wait(min(0.1, remaining))
    except OSError:
        raise NativeFileCaptureError("helper_unavailable") from None
    finally:
        try:
            _stop_owned_helper(process)
        except (OSError, subprocess.TimeoutExpired):
            raise NativeFileCaptureError("helper_unavailable") from None
        finally:
            if exchange is not None:
                exchange.join()
            else:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
