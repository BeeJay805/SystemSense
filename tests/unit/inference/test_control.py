import socket
import threading
import time

import pytest

from systemsense.inference.control import inference_cancellation
from systemsense.inference.ollama import LocalInferenceError, OllamaTransport


def test_cancel_interrupts_stalled_inference_without_waiting_for_model_deadline() -> None:
    client, server = socket.socketpair()
    cancellation = threading.Event()
    entered = threading.Event()

    def stall() -> None:
        with server:
            server.recv(4096)
            entered.set()
            cancellation.wait(2)
            time.sleep(0.3)

    worker = threading.Thread(target=stall, daemon=True)
    worker.start()
    transport = OllamaTransport(connect=lambda _address, _timeout: client)
    timer = threading.Timer(0.1, cancellation.set)
    timer.start()
    started = time.monotonic()
    try:
        with (
            inference_cancellation(cancellation),
            pytest.raises(LocalInferenceError, match="cancel"),
        ):
            transport.post(b"{}", timeout_seconds=20, max_response_bytes=1024)
        assert entered.is_set()
        assert time.monotonic() - started < 0.5
    finally:
        timer.cancel()
        cancellation.set()
        worker.join(1)
