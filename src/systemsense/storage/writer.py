"""Dedicated single-writer thread for all SQLite mutations."""

from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from threading import Event, Thread
from typing import cast

from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(slots=True)
class _Request:
    operation: Callable[[SQLiteStore], object]
    future: Future[object]


class SingleWriter:
    """Serialize operations through a connection owned by one worker thread."""

    def __init__(self, database_path: Path, *, busy_timeout_ms: int = 1000) -> None:
        self._database_path = database_path
        self._busy_timeout_ms = busy_timeout_ms
        self._requests: Queue[_Request | None] = Queue()
        self._ready = Event()
        self._initialization_error: BaseException | None = None
        self._closed = False
        self._thread = Thread(
            target=self._run,
            name="systemsense-sqlite-writer",
            daemon=True,
        )
        self._thread.start()
        self._ready.wait()
        if self._initialization_error is not None:
            raise RuntimeError("writer initialization failed") from self._initialization_error

    def __enter__(self) -> "SingleWriter":
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self.close()

    def execute[T](self, operation: Callable[[SQLiteStore], T]) -> T:
        if self._closed:
            raise RuntimeError("writer is closed")
        future: Future[object] = Future()
        self._requests.put(
            _Request(
                operation=cast("Callable[[SQLiteStore], object]", operation),
                future=future,
            )
        )
        return cast("T", future.result())

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._requests.put(None)
        self._thread.join()

    def _run(self) -> None:
        try:
            with SQLiteStore(
                self._database_path,
                busy_timeout_ms=self._busy_timeout_ms,
            ) as store:
                self._ready.set()
                while True:
                    request = self._requests.get()
                    if request is None:
                        return
                    try:
                        request.future.set_result(request.operation(store))
                    except BaseException as error:
                        request.future.set_exception(error)
        except BaseException as error:
            self._initialization_error = error
            self._ready.set()
