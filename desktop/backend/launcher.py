"""Desktop-only lifecycle wrapper. No extra HTTP routes or machine authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import queue
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, TextIO, cast
from uuid import UUID
from weakref import WeakKeyDictionary

_NATIVE_REQUEST_LOCK = threading.Lock()
_NATIVE_REQUESTS: WeakKeyDictionary[object, dict[str, tuple[str, dict[str, object]]]] = (
    WeakKeyDictionary()
)
# Retain the non-inheritable lifetime handle until normal release or OS exit.
_setup_owner_job: object | None = None


class _ConfigurableInput(Protocol):
    def reconfigure(self, *, encoding: str, errors: str) -> None: ...


class _SetupController(Protocol):
    def status(self) -> dict[str, object]: ...
    def start(self) -> dict[str, object]: ...
    def cancel(self) -> dict[str, object]: ...
    def close(self, timeout: float = 5.0) -> bool: ...


def run_setup_pipe(controller: _SetupController, source: TextIO, destination: TextIO) -> int:
    """Only the owning native parent's inherited pipe may request fixed setup."""
    result = 0
    try:
        while True:
            line = source.readline(4097)
            if not line:
                break
            if len(line) > 4096 or not line.endswith("\n"):
                result = 1
                break
            try:
                command: object = json.loads(line)
            except ValueError:
                result = 1
                break
            if command == {"type": "shutdown"}:
                break
            if command == {"type": "status"}:
                snapshot = controller.status()
            elif command == {"type": "install"}:
                # start returns immediately; the next command can cancel its worker.
                snapshot = controller.start()
            elif command == {"type": "cancel"}:
                snapshot = controller.cancel()
            else:
                result = 1
                break
            destination.write(json.dumps(snapshot, separators=(",", ":")) + "\n")
            destination.flush()
    finally:
        if not controller.close():
            result = 2
    return result


def run_native_pipe(service: object) -> bool:
    """Read owner loss even while a bounded native request is still being processed."""
    from systemsense.application.service import ApplicationService

    if not isinstance(service, ApplicationService):
        raise TypeError("invalid native service")
    commands: queue.Queue[object] = queue.Queue(maxsize=1)
    stopped = threading.Event()
    parent_lost = True

    def receive() -> None:
        nonlocal parent_lost
        try:
            while True:
                line = sys.stdin.readline(65537)
                if line == "":
                    break
                if line.strip() in {"", "shutdown"}:
                    parent_lost = False
                    break
                if len(line) > 65536 or not line.endswith("\n"):
                    break
                try:
                    command = json.loads(line)
                except ValueError:
                    continue
                if command == {"type": "shutdown"}:
                    parent_lost = False
                    break
                try:
                    commands.put_nowait(command)
                except queue.Full:
                    # The owning native client sends only one request at a time.
                    break
        except (OSError, UnicodeError):
            pass
        finally:
            service.request_shutdown(interrupted=parent_lost)
            stopped.set()

    reader = threading.Thread(target=receive, name="native-owner-pipe", daemon=True)
    reader.start()
    while not stopped.is_set():
        try:
            command = commands.get(timeout=0.1)
        except queue.Empty:
            continue
        response = handle_native_command(service, command)
        if response is not None and not stopped.is_set():
            print(json.dumps(response), flush=True)
    reader.join(timeout=1)
    return parent_lost


def main() -> int:
    if sys.argv[1:] == ["--laya-setup"]:
        from systemsense.application.laya_provisioning import LayaSetupController
        from systemsense.orchestration.windows_setup_owner import WindowsSetupOwner

        global _setup_owner_job
        owner = WindowsSetupOwner()
        _setup_owner_job = owner
        cast("_ConfigurableInput", sys.stdin).reconfigure(encoding="utf-8", errors="strict")
        result = run_setup_pipe(
            LayaSetupController(lifetime_job_name=owner.name), sys.stdin, sys.stdout
        )
        if result != 2 and owner.release_if_alone():
            _setup_owner_job = None
            return result
        # Unproven cleanup retains kill-on-close and its durable recovery receipt.
        return 2

    # The unchanged isolated executor invokes sys.executable with this exact module.
    # Frozen builds route ONLY that fixed worker, never arbitrary -m modules.
    if sys.argv[1:] == ["-m", "systemsense.worker"]:
        from systemsense.worker import main as worker_main

        return worker_main()

    if sys.argv[1:] == ["-m", "systemsense.platform.windows.selected_file_worker"]:
        from systemsense.platform.windows.selected_file_worker import main as capture_main

        return capture_main()

    if sys.argv[1:] == ["-m", "systemsense.platform.windows.selected_file_copy_worker"]:
        from systemsense.platform.windows.selected_file_copy_worker import main as copy_main

        return copy_main()

    cast("_ConfigurableInput", sys.stdin).reconfigure(encoding="utf-8", errors="strict")

    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument(
        "--inference-mode", choices=("deterministic", "laya-sol"), default="deterministic"
    )
    args = parser.parse_args()
    from systemsense.application.bootstrap import (
        default_capabilities,
        default_case_runtime,
        default_investigator,
    )
    from systemsense.application.investigator import Investigator
    from systemsense.application.service import ApplicationService
    from systemsense.application.subscription_setup import (
        SubscriptionSetupError,
        load_desktop_subscription_providers,
    )
    from systemsense.interface.server import serve
    from systemsense.storage.sqlite_store import SQLiteStore

    providers = None
    factory = default_investigator
    inference_status: dict[str, object] | Callable[[], dict[str, object]] | None = None
    if args.inference_mode == "laya-sol":
        try:
            providers = load_desktop_subscription_providers()
        except SubscriptionSetupError as error:
            inference_status = {
                "enabled": False,
                "mode": "laya-sol",
                "start_allowed": False,
                "readiness": "setup_blocked",
                "reason": str(error),
            }
        else:
            active_providers = providers

            def model_investigator(store: SQLiteStore) -> Investigator:
                return Investigator(
                    store=store,
                    runtime=default_case_runtime(store),
                    capabilities=default_capabilities(),
                    decision=active_providers.decision,
                    reasoning=active_providers.reasoning,
                    knowledge=active_providers.knowledge,
                    catalog_attention=active_providers.catalog_attention,
                    frontier_ranker=active_providers.frontier_ranker,
                )

            factory = model_investigator

            def model_status() -> dict[str, object]:
                runtime = active_providers.runtime_status()
                ready = active_providers.decision_runtime_ready
                return {
                    **runtime,
                    "enabled": True,
                    "mode": "laya-sol",
                    "start_allowed": ready,
                    "readiness": (
                        "laya_warm_chatgpt_login_reported" if ready else "model_unavailable"
                    ),
                    "reasoning_status": "login_reported",
                }

            inference_status = model_status

    try:
        service = ApplicationService(
            args.database,
            factory=factory,
            inference_status=inference_status,
            enable_local_json=True,
            enable_json_copy=True,
        )
    except BaseException:
        if providers is not None:
            providers.close()
        raise
    parent_lost = True
    try:
        server = serve(service, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(json.dumps({"port": server.server_address[1]}), flush=True)
        try:
            parent_lost = run_native_pipe(service)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    finally:
        service.close(interrupted=parent_lost)
        if providers is not None:
            providers.close()
    return 0


def handle_native_command(service: object, command: object) -> dict[str, object] | None:
    """Only the owning native parent's inherited pipe can supply an exact selection."""
    from systemsense.application.service import ApplicationService

    if not isinstance(service, ApplicationService) or not isinstance(command, dict):
        return None
    command = cast("dict[str, object]", command)
    request_id = command.get("request_id")
    if not isinstance(request_id, str):
        return None
    try:
        if str(UUID(request_id)) != request_id:
            return None
    except ValueError:
        return None
    is_repair = isinstance(command.get("type"), str) and str(command["type"]).startswith(
        "json_repair_"
    )
    response: dict[str, object] = {
        "type": "json_repair_error" if is_repair else "local_json_case_error",
        "request_id": request_id,
    }
    selected_path = command.get("selected_path")
    if not is_repair and (
        set(command) != {"type", "request_id", "selected_path"}
        or command.get("type") != "start_local_json_case"
        or not isinstance(selected_path, str)
        or not 1 <= len(selected_path) <= 32700
    ):
        return {**response, "error_code": "invalid_request"}
    digest = hashlib.sha256(
        json.dumps(command, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    with _NATIVE_REQUEST_LOCK:
        ledger = _NATIVE_REQUESTS.setdefault(service, {})
        previous = ledger.get(request_id)
        if previous is not None:
            return (
                dict(previous[1])
                if previous[0] == digest
                else {**response, "error_code": "invalid_request"}
            )
        if len(ledger) >= 1024:
            return {**response, "error_code": "unavailable"}
        # Consume before any action. An uncertain failure can never repeat a grant.
        ledger[request_id] = (digest, {**response, "error_code": "unavailable"})
    answer: dict[str, object]
    try:
        if is_repair:
            from systemsense.application.native_json_repair import JsonRepairError

            fields = {
                key: value for key, value in command.items() if key not in {"type", "request_id"}
            }
            if not all(
                isinstance(value, str) and 0 < len(value) <= 32700 for value in fields.values()
            ):
                answer = {**response, "error_code": "invalid_request"}
            else:
                try:
                    answer = {
                        **service.native_json_repair(
                            str(command["type"]), cast("dict[str, str]", fields)
                        ),
                        "request_id": request_id,
                    }
                except JsonRepairError as error:
                    answer = {**response, "error_code": error.code}
        elif service.capabilities().get("active_case_id") is not None:
            answer = {**response, "error_code": "busy"}
        else:
            result = service.start_local_json_case(cast("str", selected_path))
            answer = {
                "type": "local_json_case_started",
                "request_id": request_id,
                "case_id": str(result["case_id"]),
            }
    except (OSError, RuntimeError, ValueError):
        answer = {**response, "error_code": "unavailable"}
    with _NATIVE_REQUEST_LOCK:
        ledger[request_id] = (digest, answer)
    return dict(answer)


if __name__ == "__main__":
    raise SystemExit(main())
