"""Real test-owned HTTP tasks through normal Basic, without model calls."""

import json
from pathlib import Path
from secrets import token_hex
from typing import Any, cast

import pytest

from benchmarks.private_alpha_loopback import OwnedServer, _get, _port
from systemsense.application.bootstrap import default_investigator
from systemsense.application.service import ApplicationService
from systemsense.storage.sqlite_store import SQLiteStore

# Test-owned loopback fixture helpers, never a user-configurable endpoint.
# pyright: reportPrivateUsage=false


@pytest.mark.parametrize("mode", ["healthy", "http_503", "no_listener"])
def test_basic_uses_same_scoped_replay_and_retains_exact_decision(
    tmp_path: Path, mode: str
) -> None:
    port, nonce = _port(), token_hex(16)
    server = None if mode == "no_listener" else OwnedServer(port, nonce, mode).start()
    service = ApplicationService(tmp_path / "cases.db", factory=default_investigator)
    try:
        expected = "request_error" if mode == "no_listener" else mode
        assert _get(port, nonce)["outcome"] == expected
        result = service.start_case(f"Check http://127.0.0.1:{port}/health/{nonce}", 30000, 6)
        service.wait(25)
        result = service.get_case(str(result["case_id"]))
        assert result["status"] == "complete", result
        evidence = cast("list[dict[str, Any]]", result["evidence"])
        probes = {item["probe_id"] for item in evidence}
        assert probes <= {"task.loopback_http", "network.loopback_replay", "network.listeners"}
        if mode == "healthy":
            assert result["outcome"] == "awaiting_recurrence"
            assert "network.loopback_replay" not in probes
        else:
            assert "network.loopback_replay" in probes
            assert "later exact request" in str(result["summary"])
            with SQLiteStore(service.database) as store:
                responses = store.connection.execute(
                    "SELECT response_json FROM candidate_decision_snapshots"
                ).fetchall()
                assert any(
                    json.loads(row[0])["provider"]["provider_id"] == "basic-source-bound-v1"
                    for row in responses
                )
                assert (
                    store.connection.execute(
                        "SELECT COUNT(*) FROM candidate_decision_execution_links"
                    ).fetchone()[0]
                    >= 1
                )
    finally:
        service.close()
        if server is not None:
            server.stop()
