"""Independent native-grant regressions; no live collectors or model calls."""

from __future__ import annotations

import importlib.util
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from systemsense.application import service as service_module
from systemsense.application.investigator import Investigator
from systemsense.application.service import ApplicationService
from systemsense.platform.windows.selected_file import SelectedFileCapture
from systemsense.storage.sqlite_store import SQLiteStore


def _native_handler() -> Callable[[object, object], dict[str, str] | None]:
    root = Path(service_module.__file__).parents[3]
    specification = importlib.util.spec_from_file_location(
        "native_file_boundary_launcher", root / "desktop" / "backend" / "launcher.py"
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return cast("Callable[[object, object], dict[str, str] | None]", module.handle_native_command)


def _unused_factory(_store: SQLiteStore) -> Investigator:
    pytest.fail("native protocol review must not start collectors or models")


@pytest.mark.parametrize("same_path", [True, False], ids=["replay", "rebound-path"])
def test_native_request_id_cannot_start_a_second_file_case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, same_path: bool
) -> None:
    handler = _native_handler()
    service = ApplicationService(
        tmp_path / "native-review.db", factory=_unused_factory, enable_local_json=True
    )
    granted_paths: list[str] = []

    def start(selected_path: str) -> dict[str, object]:
        granted_paths.append(selected_path)
        return {"case_id": "case_" + str(len(granted_paths)) * 32}

    monkeypatch.setattr(service, "start_local_json_case", start)
    monkeypatch.setattr(service, "capabilities", lambda: {"active_case_id": None})
    command = {
        "type": "start_local_json_case",
        "request_id": "12345678-1234-1234-1234-123456789abc",
        "selected_path": r"C:\native-selection\first.json",
    }
    repeated = {
        **command,
        "selected_path": command["selected_path"] if same_path else r"C:\other\second.json",
    }
    try:
        first = handler(service, command)
        second = handler(service, repeated)
        assert first is not None and first["type"] == "local_json_case_started"
        assert granted_paths == [command["selected_path"]]
        if same_path:
            assert second == first
        else:
            assert second is not None and second["type"] == "local_json_case_error"
    finally:
        service.close()


def test_stalled_precase_capture_does_not_block_owner_shutdown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    service = ApplicationService(
        tmp_path / "capture-shutdown.db", factory=_unused_factory, enable_local_json=True
    )
    capture_entered = threading.Event()
    release_capture = threading.Event()
    close_finished = threading.Event()

    def stalled_capture(_path: str) -> SelectedFileCapture:
        capture_entered.set()
        assert release_capture.wait(2)
        raise RuntimeError("synthetic capture released")

    def start() -> None:
        try:
            service.start_local_json_case(r"C:\native-selection\file.json")
        except RuntimeError:
            pass

    def close() -> None:
        service.close(interrupted=True)
        close_finished.set()

    monkeypatch.setattr(service_module, "capture_selected_file", stalled_capture)
    starter = threading.Thread(target=start)
    closer = threading.Thread(target=close)
    starter.start()
    try:
        assert capture_entered.wait(1)
        closer.start()
        assert close_finished.wait(0.25), "pre-case file I/O holds the service lock across shutdown"
    finally:
        release_capture.set()
        starter.join(2)
        if closer.ident is not None:
            closer.join(2)
        else:
            service.close()
