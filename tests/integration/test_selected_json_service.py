"""Normal Basic selected-file cases using only test-owned native temporary files."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, cast

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.investigation_state import InvestigationState
from systemsense.application.investigator import Investigator
from systemsense.application.service import ApplicationService
from systemsense.domain.ids import JsonValue
from systemsense.orchestration.probes import ProbeRun, ProbeRunner
from systemsense.storage.sqlite_store import SQLiteStore

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="native selected-file capture is Windows-only"
)
_SECRET = "private_document_canary_7ff396"
_PROBES = {"task.local_json", "file.utf8", "file.json_syntax"}


@pytest.fixture(autouse=True)
def prohibit_unrelated_host_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A routing regression must fail before reading unrelated machine state."""
    original = ProbeRunner.run

    def guarded(
        self: ProbeRunner, probe_id: str, parameters: dict[str, JsonValue], **kwargs: Any
    ) -> ProbeRun:
        assert probe_id in _PROBES, f"selected-file case attempted unrelated probe {probe_id}"
        return original(self, probe_id, parameters, **kwargs)

    monkeypatch.setattr(ProbeRunner, "run", guarded)


def _evidence(result: dict[str, object]) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", result["evidence"])


def _assert_private(value: object, path: Path) -> None:
    serialized = json.dumps(value, ensure_ascii=False)
    assert _SECRET not in serialized
    assert path.name not in serialized
    assert str(path) not in serialized


@pytest.mark.parametrize(
    "contents,task_outcome,error_code,summary_phrase",
    [
        (b'{"private_document_canary_7ff396":1}', "accepted", "none", "accepted"),
        (b'{"private_document_canary_7ff396":', "rejected", "json_syntax", "syntax"),
        (b"\xffprivate_document_canary_7ff396", "rejected", "invalid_utf8", "UTF-8"),
        (None, "unavailable", "read_unavailable", "could not be checked"),
    ],
)
def test_normal_basic_service_preserves_parser_evidence_and_private_history(
    tmp_path: Path,
    contents: bytes | None,
    task_outcome: str,
    error_code: str,
    summary_phrase: str,
) -> None:
    selected = tmp_path / "private-selected-filename-67f2.json"
    if contents is not None:
        selected.write_bytes(contents)
    database = tmp_path / "cases.db"
    app = ApplicationService(database, factory=default_investigator, enable_local_json=True)
    try:
        started = app.start_local_json_case(str(selected))
        case_id = str(started["case_id"])
        app.wait(timeout=15)
        result = app.get_case(case_id)
        assert result["status"] == "complete", result.get("stop_reason")
        records = _evidence(result)
        assert {item["probe_id"] for item in records} == _PROBES
        task = next(item for item in records if item["probe_id"] == "task.local_json")
        assert task["facts"]["outcome"] == task_outcome
        syntax = next(item for item in records if item["probe_id"] == "file.json_syntax")
        assert syntax["facts"]["selected_file_check"]["error_code"] == error_code
        assert summary_phrase.casefold() in str(result["summary"]).casefold()
        assert "schema validity" in str(result["summary"])
        assert "immutable" in str(result["summary"])
        _assert_private(result, selected)
        _assert_private(app.export_case(case_id), selected)
        with SQLiteStore(database) as store:
            executions = store.connection.execute(
                "SELECT probe_id,parameters_json FROM probe_executions WHERE case_id=?",
                (case_id,),
            ).fetchall()
            assert {row[0] for row in executions} == _PROBES
            _assert_private(executions, selected)
            for probe_id, parameters in executions:
                if probe_id in {"file.utf8", "file.json_syntax"}:
                    assert json.loads(parameters) == {}
    finally:
        app.close()
    if selected.exists():
        selected.unlink()
    # History is readable even when native selection is disabled and the file is gone.
    reopened = ApplicationService(database, factory=default_investigator)
    try:
        saved = reopened.get_case(case_id)
        assert saved["status"] == "complete"
        assert saved["summary"] == result["summary"]
        assert {item["evidence_id"] for item in _evidence(saved)} == {
            item["evidence_id"] for item in records
        }
        history = cast("list[dict[str, object]]", reopened.list_cases()["cases"])
        assert [item["case_id"] for item in history] == [case_id]
        _assert_private(saved, selected)
        with pytest.raises(RuntimeError, match="Select the file again"):
            reopened.resume_case(case_id)
    finally:
        reopened.close()


def test_default_service_rejects_selection_before_reading_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_read(_path: str, _cancel_event: threading.Event) -> None:
        raise AssertionError("feature-disabled service attempted a file capture")

    monkeypatch.setattr(
        "systemsense.application.service.capture_selected_file_bounded", forbidden_read
    )
    app = ApplicationService(tmp_path / "disabled.db", factory=default_investigator)
    try:
        with pytest.raises(RuntimeError, match="unavailable"):
            app.start_local_json_case(str(tmp_path / "not-authorized.json"))
        assert app.list_cases()["cases"] == []
    finally:
        app.close()


def test_cancel_preserves_task_evidence_and_requires_explicit_reselection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "cancelled-private-filename.json"
    selected.write_bytes(b'{"private_document_canary_7ff396":')
    entered, release = threading.Event(), threading.Event()
    original = Investigator.run

    def gated(
        self: Investigator, case_id: str, *, cancel_event: threading.Event | None = None
    ) -> InvestigationState:
        entered.set()
        assert release.wait(timeout=10), "test did not release the owned worker"
        return original(self, case_id, cancel_event=cancel_event)

    app = ApplicationService(
        tmp_path / "cancelled.db", factory=default_investigator, enable_local_json=True
    )
    try:
        with monkeypatch.context() as gate_patch:
            gate_patch.setattr(Investigator, "run", gated)
            started = app.start_local_json_case(str(selected))
            case_id = str(started["case_id"])
            assert entered.wait(timeout=5)
            app.cancel_case(case_id)
            release.set()
            app.wait(timeout=10)
        cancelled = app.get_case(case_id)
        assert cancelled["status"] == "cancelled"
        assert any(item["probe_id"] == "task.local_json" for item in _evidence(cancelled))
        _assert_private(cancelled, selected)
        with pytest.raises(RuntimeError, match="Select the file again"):
            app.resume_case(case_id)
        selected.write_bytes(b"{}")
        new_case = app.start_local_json_case(str(selected))
        assert new_case["case_id"] != case_id
        app.wait(timeout=15)
        fresh = app.get_case(str(new_case["case_id"]))
        assert fresh["status"] == "complete", fresh.get("stop_reason")
        assert "accepted" in str(fresh["summary"]).casefold()
        assert app.get_case(case_id)["status"] == "cancelled"
    finally:
        release.set()
        app.close()
