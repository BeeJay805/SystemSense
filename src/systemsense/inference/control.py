"""Thread-scoped cooperative cancellation without putting authority in model JSON."""

import threading
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar

_cancellation: ContextVar[threading.Event | None] = ContextVar(
    "inference_cancellation", default=None
)


def current_cancellation() -> threading.Event | None:
    return _cancellation.get()


@contextmanager
def inference_cancellation(event: threading.Event | None) -> Generator[None]:
    token = _cancellation.set(event)
    try:
        yield
    finally:
        _cancellation.reset(token)
