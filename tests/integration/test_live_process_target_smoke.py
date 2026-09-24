"""Opt-in Windows smoke for a user-bound, read-only process observation.

Run with SYSTEMSENSE_LIVE_TARGET_SMOKE=1. This creates only a temporary case DB;
it does not change, stop, or launch the selected process.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import psutil
import pytest

from systemsense.application.bootstrap import default_capabilities, default_case_runtime
from systemsense.application.investigator import Investigator
from systemsense.application.service import ApplicationService
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.domain.ids import JsonValue
from systemsense.packs.runtime import default_probe_runner
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("SYSTEMSENSE_LIVE_TARGET_SMOKE") != "1",
    reason="explicit opt-in Windows read-only target smoke",
)


def _deterministic_pdf_investigator(store: SQLiteStore) -> Investigator:
    application_snapshot = tuple(
        capability
        for capability in default_capabilities()
        if capability.probe_id == "application.snapshot"
    )
    assert len(application_snapshot) == 1
    return Investigator(
        store=store,
        runtime=default_case_runtime(store),
        capabilities=application_snapshot,
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
    )


def test_production_isolated_target_probe_checks_live_creation_identity() -> None:
    """Read only this pytest process; never adopt an arbitrary inventory PID."""

    runner = default_probe_runner()
    creation = datetime.fromtimestamp(psutil.Process(os.getpid()).create_time(), tz=UTC)
    parameters: dict[str, JsonValue] = {"pid": os.getpid(), "creation_time": creation.isoformat()}
    exact = runner.run("application.target_pressure", parameters)
    assert exact.status.value == "ok", exact.error
    assert exact.observation is not None
    pressure = cast("dict[str, object]", exact.observation.facts["target_pressure"])
    assert pressure["target_pid"] == os.getpid()
    assert pressure["status"] in {"available", "partial"}
    assert len(cast("list[object]", pressure["samples"])) == 3

    reused = runner.run(
        "application.target_pressure",
        {"pid": os.getpid(), "creation_time": (creation - timedelta(seconds=1)).isoformat()},
    )
    assert reused.status.value == "ok", reused.error
    assert reused.observation is not None
    reused_pressure = cast("dict[str, object]", reused.observation.facts["target_pressure"])
    assert reused_pressure["status"] == "reused"
    assert len(cast("list[object]", reused_pressure["samples"])) == 1


def test_live_pdf_case_selects_persisted_process_and_audits_target(
    tmp_path: Path,
) -> None:
    database = tmp_path / "live-process-target.db"
    app = ApplicationService(database, factory=_deterministic_pdf_investigator)
    try:
        assert "application.target_pressure" not in {
            item["probe_id"]
            for item in cast("list[dict[str, object]]", app.capabilities()["probes"])
        }
        opened = app.start_case("A PDF viewer is slow", budget_ms=40_000, max_rounds=1)
        case_id = str(opened["case_id"])
        app.wait(timeout=45)
        waiting = app.get_case(case_id)
        assert waiting["status"] == "awaiting_target", waiting.get("stop_reason")
        inventory = cast("dict[str, object]", waiting["process_target_inventory"])
        candidates = cast("list[dict[str, object]]", inventory["candidates"])
        assert candidates, inventory
        selected = candidates[0]
        candidate_id = str(selected["candidate_id"])
        assert candidate_id.startswith("proc_")
        assert selected["case_id"] == case_id

        app.select_process_target(case_id, candidate_id)
        app.wait(timeout=45)
        finished = app.get_case(case_id)
        assert finished["status"] == "complete", finished.get("stop_reason")
    finally:
        app.close()

    with SQLiteStore(database) as store:
        rows = store.connection.execute(
            "SELECT execution_id, status, parameters_json FROM probe_executions "
            "WHERE case_id = ? AND probe_id = 'application.target_pressure'",
            (case_id,),
        ).fetchall()
        assert len(rows) == 1
        execution_id, status, parameters_json = map(str, rows[0])
        assert status in {"ok", "unavailable"}
        audit = tuple(
            item
            for item in store.audit_entries(case_id=case_id)
            if item.probe_id == "application.target_pressure"
        )
        assert len(audit) == 1
        assert (
            audit[0].parameters["parameters_sha256"]
            == hashlib.sha256(parameters_json.encode("utf-8")).hexdigest()
        )
        if status == "ok":
            parameters = json.loads(parameters_json)
            assert parameters["pid"] == selected["pid"]
            assert datetime.fromisoformat(parameters["creation_time"]) == datetime.fromisoformat(
                str(selected["creation_time"])
            )
            assert audit[0].parameters["target_candidate_id"] == candidate_id
            assert audit[0].parameters["target_evidence_id"] == selected["evidence_id"]
            assert store.connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND execution_id = ?",
                (case_id, execution_id),
            ).fetchone() == (1,)
        else:
            assert parameters_json == "{}"
            assert audit[0].outcome == "unavailable"
            assert audit[0].parameters["target_binding_status"] == "unavailable"
            assert store.connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND execution_id = ? "
                "AND json_type(record_json, '$.status') IS NOT NULL",
                (case_id, execution_id),
            ).fetchone() == (1,)
        print(
            json.dumps(
                {
                    "case_id": case_id,
                    "candidate_id": candidate_id,
                    "source_evidence_id": selected["evidence_id"],
                    "target_probe_status": status,
                    "audit_parameters_sha256": audit[0].parameters["parameters_sha256"],
                },
                sort_keys=True,
            )
        )
