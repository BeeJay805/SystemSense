"""Real selected temp-file captures and synthetic persisted-custody mutations."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import cast

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.local_json_task import (
    SELECTED_JSON_ACTION,
    SELECTED_JSON_LIMITATION,
    observe_selected_json_task,
    resolve_selected_json_task,
    selected_json_capabilities,
    selected_json_definitions,
    selected_json_target_handle,
)
from systemsense.application.task_observation import TaskObservationUnavailable
from systemsense.domain.affected_task import (
    AffectedTaskKind,
    ReportedAffectedTaskV1,
    TaskObservationReferenceV1,
)
from systemsense.domain.evidence import EvidenceFact, EvidenceRecord
from systemsense.domain.ids import CaseId
from systemsense.orchestration.probes import ProbeRunner
from systemsense.platform.windows.selected_file import SelectedFileCapture, capture_selected_file
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="native selected-file capture is Windows-only"
)


def _capture(tmp_path: Path, contents: bytes) -> SelectedFileCapture:
    path = tmp_path / "private-contents.json"
    path.write_bytes(contents)
    captured = capture_selected_file(str(path))
    assert captured.observation.outcome == "read_ok"
    return captured


def _record(
    store: SQLiteStore, capture: SelectedFileCapture
) -> tuple[EvidenceRecord, TaskObservationReferenceV1]:
    # A successful capture has a stable identity handle before case creation.
    target = selected_json_target_handle(capture, CaseId.new())
    state = default_investigator(store).create(
        objective="Check the selected JSON file with Dyad's parser",
        reported_task=ReportedAffectedTaskV1(
            kind=AffectedTaskKind.APPLICATION_OPERATION,
            action=SELECTED_JSON_ACTION,
            target_hint=target,
            reported_outcome="Please check it.",
        ),
    )
    record = observe_selected_json_task(store, case_id=state.case_id, capture=capture)
    reference = InvestigationRepository(store).load(str(state.case_id)).task_observation_reference
    assert reference is not None
    return record, reference


@pytest.mark.parametrize(
    "contents,expected",
    [
        (b'{"secret_value": 123}', "accepted"),
        (b'{"secret_value":', "rejected"),
        (b"\xff", "rejected"),
    ],
)
def test_actual_parser_result_has_exact_custody_without_contents(
    tmp_path: Path, contents: bytes, expected: str
) -> None:
    capture = _capture(tmp_path, contents)
    with SQLiteStore(tmp_path / "case.db") as store:
        record, reference = _record(store, capture)
        context = resolve_selected_json_task(store, case_id=record.case_id, reference=reference)
        assert context.observed == expected
        assert context.reported_task_relation == "exact_action_replayed"
        assert context.scope == "user_selected_file"
        assert context.limitation == SELECTED_JSON_LIMITATION
        assert context.window_end == context.observed_at
        assert capture.observation.collection_completed_at <= context.window_start
        serialized = record.model_dump_json() + json.dumps(context.model_visible())
        assert "secret_value" not in serialized
        assert "private-contents.json" not in serialized
        assert str(tmp_path) not in serialized
        assert "json_syntax" not in serialized
        assert "invalid_utf8" not in serialized
        with pytest.raises(ValueError, match="unstarted"):
            observe_selected_json_task(store, case_id=record.case_id, capture=capture)


def test_unavailable_capture_is_data_and_cannot_claim_report_binding(tmp_path: Path) -> None:
    capture = capture_selected_file(str(tmp_path / "missing.json"))
    with SQLiteStore(tmp_path / "case.db") as store:
        state = default_investigator(store).create(objective="Check selected file")
        record = observe_selected_json_task(store, case_id=state.case_id, capture=capture)
        reference = (
            InvestigationRepository(store).load(str(state.case_id)).task_observation_reference
        )
        assert reference is not None
        context = resolve_selected_json_task(store, case_id=state.case_id, reference=reference)
        assert context.observed == "unavailable"
        assert context.reported_task_relation == "unbound"
        assert context.target_handle == selected_json_target_handle(capture, state.case_id)
        assert "missing.json" not in record.model_dump_json()


def test_bound_parameter_free_probes_reuse_capture_after_disk_changes(tmp_path: Path) -> None:
    capture = _capture(tmp_path, b'{"private_key":')
    (tmp_path / "private-contents.json").write_bytes(b"{}")
    definitions = selected_json_definitions(capture)
    assert {item.manifest.probe_id for item in definitions} == {"file.utf8", "file.json_syntax"}
    assert {item.probe_id for item in selected_json_capabilities()} == {
        "file.utf8",
        "file.json_syntax",
    }
    runner = ProbeRunner(definitions=definitions)
    for definition in definitions:
        assert (
            definition.manifest.input_model
            == definition.parameter_model.__name__
            == "NoParametersV1"
        )
        assert not definition.isolated
        assert definition.manifest.limits.max_records == 1
        result = runner.run(definition.manifest.probe_id, {})
        assert result.status == "ok"
        assert result.observation is not None
        check = cast("dict[str, object]", result.observation.facts["selected_file_check"])
        assert check["content_sha256"] == capture.observation.content_sha256
        assert check["outcome"] == (
            "valid_utf8" if definition.manifest.probe_id == "file.utf8" else "invalid_json"
        )
        assert result.observation.observed_at == capture.observation.collection_completed_at
        assert "private_key" not in result.model_dump_json()
        denied = runner.run(definition.manifest.probe_id, {"path": str(tmp_path / "other.json")})
        assert denied.status == "denied"


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_handle", "selected_file_" + "0" * 64),
        ("observation_sha256", "0" * 64),
        ("action", "Other action"),
        ("scope", "synthetic_fixture"),
    ],
)
def test_execution_parameters_cannot_rebind_selected_capture(
    tmp_path: Path, field: str, value: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        record, reference = _record(store, _capture(tmp_path, b"{}"))
        execution = store.probe_execution(str(reference.execution_id))
        assert execution is not None
        parameters = json.loads(execution.parameters_json)
        parameters[field] = value
        with store.transaction():
            store.connection.execute(
                "UPDATE probe_executions SET parameters_json=? WHERE execution_id=?",
                (json.dumps(parameters), str(reference.execution_id)),
            )
        with pytest.raises(TaskObservationUnavailable):
            resolve_selected_json_task(store, case_id=record.case_id, reference=reference)


@pytest.mark.parametrize("column", ["started_at", "finished_at"])
def test_execution_times_must_match_parser_window(tmp_path: Path, column: str) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        record, reference = _record(store, _capture(tmp_path, b"{}"))
        with store.transaction():
            store.connection.execute(
                f"UPDATE probe_executions SET {column}=? WHERE execution_id=?",
                ("2020-01-01T00:00:00+00:00", str(reference.execution_id)),
            )
        with pytest.raises(TaskObservationUnavailable):
            resolve_selected_json_task(store, case_id=record.case_id, reference=reference)


@pytest.mark.parametrize("duplicate", [False, True])
def test_mutated_or_duplicate_facts_fail_even_with_updated_reference_hash(
    tmp_path: Path, duplicate: bool
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        record, reference = _record(store, _capture(tmp_path, b"{}"))
        if duplicate:
            facts = (*record.facts, record.facts[0])
        else:
            facts = tuple(
                EvidenceFact(name=item.name, value="rejected") if item.name == "outcome" else item
                for item in record.facts
            )
        changed = record.model_copy(update={"facts": facts})
        encoded = changed.model_dump_json()
        changed_ref = reference.model_copy(
            update={"record_sha256": hashlib.sha256(encoded.encode()).hexdigest()}
        )
        with store.transaction():
            store.connection.execute(
                "UPDATE evidence SET record_json=? WHERE evidence_id=?",
                (encoded, str(record.evidence_id)),
            )
        with pytest.raises(TaskObservationUnavailable):
            resolve_selected_json_task(store, case_id=record.case_id, reference=changed_ref)


def test_cross_case_and_altered_reference_are_rejected(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        record, reference = _record(store, _capture(tmp_path, b"{}"))
        with pytest.raises(TaskObservationUnavailable):
            resolve_selected_json_task(store, case_id=CaseId.new(), reference=reference)
        with pytest.raises(TaskObservationUnavailable):
            resolve_selected_json_task(
                store,
                case_id=record.case_id,
                reference=reference.model_copy(update={"record_sha256": "0" * 64}),
            )


@pytest.mark.parametrize("field", ["identity_sha256", "content_sha256", "stage"])
def test_private_initial_check_must_bind_the_same_capture(tmp_path: Path, field: str) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        record, reference = _record(store, _capture(tmp_path, b"{}"))
        execution = store.probe_execution(str(reference.execution_id))
        assert execution is not None
        parameters = json.loads(execution.parameters_json)
        parameters["initial_check"][field] = "utf8" if field == "stage" else "0" * 64
        with store.transaction():
            store.connection.execute(
                "UPDATE probe_executions SET parameters_json=? WHERE execution_id=?",
                (json.dumps(parameters), str(reference.execution_id)),
            )
        with pytest.raises(TaskObservationUnavailable):
            resolve_selected_json_task(store, case_id=record.case_id, reference=reference)


def test_wrong_producer_locator_is_rejected_even_with_updated_hash(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        record, reference = _record(store, _capture(tmp_path, b"{}"))
        changed = record.model_copy(
            update={
                "source": record.source.model_copy(
                    update={"locator": {"probe_id": "other.producer"}}
                )
            }
        )
        encoded = changed.model_dump_json()
        changed_ref = reference.model_copy(
            update={"record_sha256": hashlib.sha256(encoded.encode()).hexdigest()}
        )
        with store.transaction():
            store.connection.execute(
                "UPDATE evidence SET record_json=? WHERE evidence_id=?",
                (encoded, str(record.evidence_id)),
            )
        with pytest.raises(TaskObservationUnavailable):
            resolve_selected_json_task(store, case_id=record.case_id, reference=changed_ref)


def test_reported_action_mismatch_is_rejected_before_any_persistence(tmp_path: Path) -> None:
    capture = _capture(tmp_path, b"{}")
    with SQLiteStore(tmp_path / "case.db") as store:
        state = default_investigator(store).create(
            objective="Check file",
            reported_task=ReportedAffectedTaskV1(
                kind=AffectedTaskKind.OTHER, action="Other action", reported_outcome="Unverified"
            ),
        )
        with pytest.raises(ValueError, match="reported exact action"):
            observe_selected_json_task(store, case_id=state.case_id, capture=capture)
        assert store.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 0
