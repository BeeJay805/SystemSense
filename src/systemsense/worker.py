"""One-request structured worker for fixed diagnostic probe IDs."""

import json
import os
import sys
import time
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from systemsense.domain.ids import JsonValue


class WorkerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    probe_id: str
    parameters: dict[str, JsonValue]


class _EchoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(max_length=1000)


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _DelayParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delay_ms: int = Field(ge=0, le=10_000)


def _emit(payload: dict[str, JsonValue]) -> None:
    print(
        json.dumps(
            {"type": "evidence", "payload": payload},
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        flush=True,
    )


def _echo(parameters: dict[str, JsonValue]) -> None:
    typed = _EchoParameters.model_validate(parameters)
    _emit({"message": typed.message})


def _environment(parameters: dict[str, JsonValue]) -> None:
    _NoParameters.model_validate(parameters)
    keys: list[JsonValue] = list(sorted(os.environ))
    _emit({"keys": keys})


def _partial_then_sleep(parameters: dict[str, JsonValue]) -> None:
    typed = _DelayParameters.model_validate(parameters)
    _emit({"stage": "started"})
    time.sleep(typed.delay_ms / 1000)


type _Handler = Callable[[dict[str, JsonValue]], None]
_HANDLERS: dict[str, _Handler] = {
    "fixture.echo": _echo,
    "fixture.environment": _environment,
    "fixture.partial_then_sleep": _partial_then_sleep,
}
REGISTERED_PROBE_IDS = frozenset(_HANDLERS)


def main() -> int:
    request_line = sys.stdin.readline()
    try:
        request = WorkerRequest.model_validate_json(request_line)
        handler = _HANDLERS.get(request.probe_id)
        if handler is None:
            print(
                json.dumps({"type": "result", "status": "denied"}),
                flush=True,
            )
            return 2
        handler(request.parameters)
    except (ValidationError, ValueError) as error:
        print(
            json.dumps(
                {
                    "type": "result",
                    "status": "failed",
                    "error": f"{type(error).__name__}: {error}",
                }
            ),
            flush=True,
        )
        return 1
    except Exception as error:
        print(
            json.dumps(
                {
                    "type": "result",
                    "status": "failed",
                    "error": f"{type(error).__name__}: {error}",
                }
            ),
            flush=True,
        )
        return 1
    print(json.dumps({"type": "result", "status": "ok"}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
