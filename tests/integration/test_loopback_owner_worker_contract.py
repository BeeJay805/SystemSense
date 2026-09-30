"""Exercise the real isolated worker's full output against its registered limits."""

import os
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil
import pytest

from systemsense.orchestration.probes import ProbeRunStatus
from systemsense.packs.runtime import default_probe_runner


@pytest.mark.skipif(os.name != "nt", reason="Windows loopback worker qualification")
def test_owner_worker_preserves_boundary_proof_without_output_truncation() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            threading.Event().wait(2.2)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        if server.server_port < 49152:
            pytest.skip("High-port fixture unavailable")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            runner = default_probe_runner()
            run = runner.run(
                "network.listener_owner_pressure",
                {
                    "pid": os.getpid(),
                    "creation_time": datetime.fromtimestamp(
                        psutil.Process().create_time(), UTC
                    ).isoformat(),
                    "port": server.server_port,
                    "nonce": "a" * 32,
                },
            )
            assert run.status is ProbeRunStatus.OK, run
            assert run.observation is not None
            assert "listener_ownership" in run.observation.facts
            assert "coincident_owner_cpu" in run.observation.facts
            assert len(run.observation.facts) == 5
        finally:
            server.shutdown()
            thread.join(timeout=3)
