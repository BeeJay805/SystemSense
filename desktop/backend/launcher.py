"""Desktop-only lifecycle wrapper. No extra HTTP routes or machine authority."""

from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path


def main() -> int:
    # The unchanged isolated executor invokes sys.executable with this exact module.
    # Frozen builds route ONLY that fixed worker, never arbitrary -m modules.
    if sys.argv[1:] == ["-m", "systemsense.worker"]:
        from systemsense.worker import main as worker_main

        return worker_main()

    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    from systemsense.application.bootstrap import default_investigator
    from systemsense.application.service import ApplicationService
    from systemsense.interface.server import serve

    service = ApplicationService(args.database, factory=default_investigator)
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
        service.close()
        thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
