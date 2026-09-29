"""Desktop-only lifecycle wrapper. No extra HTTP routes or machine authority."""

from __future__ import annotations

import argparse
import json
import sys
import threading
from collections.abc import Callable
from pathlib import Path


def main() -> int:
    # The unchanged isolated executor invokes sys.executable with this exact module.
    # Frozen builds route ONLY that fixed worker, never arbitrary -m modules.
    if sys.argv[1:] == ["-m", "systemsense.worker"]:
        from systemsense.worker import main as worker_main

        return worker_main()

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
            args.database, factory=factory, inference_status=inference_status
        )
    except BaseException:
        if providers is not None:
            providers.close()
        raise
    try:
        server = serve(service, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(json.dumps({"port": server.server_address[1]}), flush=True)
        try:
            # Only the owning native parent holds this pipe. EOF also covers parent crash.
            sys.stdin.readline()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    finally:
        service.close()
        if providers is not None:
            providers.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
