"""One-request structured worker for fixed diagnostic probe IDs."""

import json
import os
import sys
import time
from collections.abc import Callable
from typing import cast

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


def _devices_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.devices.drivers import WmiDriverBackend
    from systemsense.packs.devices.pnp import WmiDeviceBackend

    _NoParameters.model_validate(parameters)
    devices = WmiDeviceBackend().devices(max_records=64)
    drivers = WmiDriverBackend().drivers(max_records=64)
    _emit(
        {
            "summary": (f"Observed {len(devices)} devices and {len(drivers)} signed drivers"),
            "facts": {
                "devices": [cast("JsonValue", item.model_dump(mode="json")) for item in devices],
                "drivers": [cast("JsonValue", item.model_dump(mode="json")) for item in drivers],
            },
            "limitations": [],
        }
    )


def _servicing_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.servicing.history import (
        RegistryRebootBackend,
        WmiServicingBackend,
        assess_reboot_pending,
    )

    _NoParameters.model_validate(parameters)
    updates = WmiServicingBackend().updates(max_records=128)
    reboot = assess_reboot_pending(RegistryRebootBackend().sources())
    _emit(
        {
            "summary": (
                f"Observed {len(updates)} installed updates; "
                f"reboot pending={str(reboot.pending).lower()}"
            ),
            "facts": {
                "updates": [cast("JsonValue", item.model_dump(mode="json")) for item in updates],
                "reboot": cast("JsonValue", reboot.model_dump(mode="json")),
            },
            "limitations": [],
        }
    )


def _local_ai_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.local_ai.gpu import WmiGpuBackend
    from systemsense.packs.local_ai.packages import current_packages
    from systemsense.packs.local_ai.python import current_python_environment

    _NoParameters.model_validate(parameters)
    gpus = WmiGpuBackend().gpus(max_records=8)
    python_environment = current_python_environment()
    packages = current_packages(max_records=256)
    _emit(
        {
            "summary": (
                f"Observed {len(gpus)} GPUs, Python {python_environment.version}, "
                f"and {len(packages)} packages"
            ),
            "facts": {
                "gpus": [cast("JsonValue", item.model_dump(mode="json")) for item in gpus],
                "python": cast(
                    "JsonValue",
                    python_environment.model_dump(mode="json"),
                ),
                "packages": [cast("JsonValue", item.model_dump(mode="json")) for item in packages],
            },
            "limitations": [
                "framework packages were not imported; CUDA facts are metadata-only",
            ],
        }
    )


type _Handler = Callable[[dict[str, JsonValue]], None]
_HANDLERS: dict[str, _Handler] = {
    "devices.snapshot": _devices_snapshot,
    "fixture.echo": _echo,
    "fixture.environment": _environment,
    "fixture.partial_then_sleep": _partial_then_sleep,
    "local_ai.snapshot": _local_ai_snapshot,
    "servicing.snapshot": _servicing_snapshot,
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
