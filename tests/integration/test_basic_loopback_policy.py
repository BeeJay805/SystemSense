"""Real test-owned HTTP tasks through normal Basic, without model calls."""

import json
from pathlib import Path
from secrets import token_hex
from typing import Any, cast

import pytest

from benchmarks.private_alpha_loopback import OwnedServer, _get, _port
from systemsense.application.bootstrap import default_investigator
from systemsense.application.service import ApplicationService
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

# Test-owned loopback fixture helpers, never a user-configurable endpoint.
# pyright: reportPrivateUsage=false


@pytest.mark.parametrize(
    "mode,ready_for_model_review",
    [("healthy", False), ("http_503", False), ("no_listener", True)],
)
def test_basic_uses_same_scoped_replay_and_retains_exact_decision(
    tmp_path: Path, mode: str, ready_for_model_review: bool
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
        with SQLiteStore(service.database) as store:
            app = default_investigator(store)
            state = InvestigationRepository(store).load(str(result["case_id"]))
            # Basic can finish HTTP responses without a listener check. Model
            # closure needs that source-bound check, so it must not idle yet.
            assert app._scoped_measurements_ready_for_review(state) is ready_for_model_review
            assert not app._scoped_measurements_ready_for_review(
                state.model_copy(update={"completed_probe_ids": ()})
            )
            reference = state.task_observation_reference
            assert reference is not None
            assert not app._scoped_measurements_ready_for_review(
                state.model_copy(
                    update={
                        "task_observation_reference": reference.model_copy(
                            update={"record_sha256": "0" * 64}
                        )
                    }
                )
            )
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
