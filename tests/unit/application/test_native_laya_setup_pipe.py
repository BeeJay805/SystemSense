"""Synthetic inherited-pipe authority checks, no installation or downloads."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from typing import Protocol, TextIO, cast

import pytest


class Controller:
    def __init__(self, *, cleanup: bool = True) -> None:
        self.calls: list[str] = []
        self.cleanup = cleanup

    def status(self) -> dict[str, object]:
        self.calls.append("status")
        return {"state": "ready_to_install"}

    def start(self) -> dict[str, object]:
        self.calls.append("install")
        return {"state": "installing"}

    def cancel(self) -> dict[str, object]:
        self.calls.append("cancel")
        return {"state": "cancelling"}

    def close(self, timeout: float = 5.0) -> bool:
        self.calls.append("close")
        return self.cleanup


class PipeHandler(Protocol):
    def __call__(self, controller: Controller, source: TextIO, destination: TextIO) -> int: ...


def handler() -> PipeHandler:
    specification = importlib.util.spec_from_file_location(
        "setup_pipe_launcher", Path(__file__).parents[3] / "desktop/backend/launcher.py"
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return cast(PipeHandler, module.run_setup_pipe)


def test_install_returns_before_cancel_and_eof_always_closes_owned_controller() -> None:
    controller = Controller()
    output = io.StringIO()
    result = handler()(controller, io.StringIO('{"type":"install"}\n{"type":"cancel"}\n'), output)
    assert result == 0
    assert controller.calls == ["install", "cancel", "close"]
    assert [json.loads(line)["state"] for line in output.getvalue().splitlines()] == [
        "installing",
        "cancelling",
    ]


@pytest.mark.parametrize(
    "line",
    [
        '{"type":"install","path":"C:/elsewhere"}\n',
        '{"type":"command"}\n',
        '{"type":"install"}',
        "x" * 4097 + "\n",
        "null\n",
        "[]\n",
    ],
)
def test_unknown_or_parameterized_commands_close_without_execution(line: str) -> None:
    controller = Controller()
    output = io.StringIO()
    assert handler()(controller, io.StringIO(line), output) == 1
    assert controller.calls == ["close"]
    assert output.getvalue() == ""


def test_failed_cleanup_is_not_reported_as_success() -> None:
    controller = Controller(cleanup=False)
    assert handler()(controller, io.StringIO(""), io.StringIO()) == 2
    assert controller.calls == ["close"]
