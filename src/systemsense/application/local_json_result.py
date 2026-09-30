"""Project only exact captured-file parser facts, never application causes."""

import json
from dataclasses import dataclass
from datetime import datetime

from systemsense.application.investigation_state import InvestigationOutcome, InvestigationState
from systemsense.application.task_observation import resolve_task_observation
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import stable_source_id
from systemsense.domain.time import ensure_utc
from systemsense.platform.windows.selected_file import SelectedFileCheck, SelectedFileObservation
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True)
class SelectedJsonFinding:
    summary: str
    outcome: InvestigationOutcome
    evidence_ids: frozenset[str]


def selected_json_finding(
    store: SQLiteStore, state: InvestigationState, records: tuple[EvidenceRecord, ...]
) -> SelectedJsonFinding | None:
    reference = state.task_observation_reference
    if reference is None or reference.scope != "user_selected_file":
        return None
    task = resolve_task_observation(store, case_id=state.case_id, reference=reference)
    source = store.evidence(case_id=str(state.case_id), evidence_id=str(task.evidence_id))
    if source is None:
        return None
    source_record = EvidenceRecord.model_validate_json(source.record_json)
    capture = SelectedFileObservation.model_validate(
        next(fact.value for fact in source_record.facts if fact.name == "selected_file")
    )
    source_execution = store.probe_execution(str(task.execution_id))
    if source_execution is None:
        return None
    # The source task was independently checked when admitted. Detailed checks
    # must agree with that exact immutable capture, not just its rejected label.
    initial_check = SelectedFileCheck.model_validate(
        json.loads(source_execution.parameters_json)["initial_check"]
    )
    checked: list[tuple[EvidenceRecord, SelectedFileCheck]] = []
    for record in records:
        execution = store.probe_execution(str(record.collector.execution_id))
        row = store.evidence(case_id=str(state.case_id), evidence_id=str(record.evidence_id))
        if (
            record.collector.id not in {"file.utf8", "file.json_syntax"}
            or record.collector.version != 1
            or record.case_id != state.case_id
            or record.statement_kind is not StatementKind.OBSERVED_FACT
            or record.source.type != "systemsense.probe"
            or record.source.source_id
            != stable_source_id(
                "systemsense.probe", {"probe_id": record.collector.id, "probe_version": 1}
            )
            or row is None
            or row.execution_id != str(record.collector.execution_id)
            or EvidenceRecord.model_validate_json(row.record_json) != record
            or len(record.facts) != 1
            or record.facts[0].name != "selected_file_check"
            or execution is None
            or execution.status != "ok"
            or execution.case_id != str(state.case_id)
            or execution.probe_id != record.collector.id
            or execution.probe_version != record.collector.version
            or execution.parameters_json != "{}"
            or execution.finished_at is None
        ):
            continue
        try:
            check = SelectedFileCheck.model_validate(record.facts[0].value)
            execution_start = ensure_utc(datetime.fromisoformat(execution.started_at))
            execution_end = ensure_utc(datetime.fromisoformat(execution.finished_at))
        except ValueError:
            continue
        if (
            check.identity_sha256 != capture.identity_sha256
            or check.content_sha256 != capture.content_sha256
            or check.collection_started_at != capture.collection_started_at
            or check.collection_completed_at != capture.collection_completed_at
            or record.observed_at != capture.collection_completed_at
            or check.stage != ("utf8" if record.collector.id == "file.utf8" else "json")
            or not capture.collection_completed_at
            <= task.window_end
            <= execution_start
            <= record.captured_at
            <= execution_end
            or (check.stage == "json" and check != initial_check)
            or (
                check.outcome == "invalid_utf8"
                and (
                    initial_check.outcome != "invalid_utf8"
                    or check.error_code != initial_check.error_code
                )
            )
        ):
            continue
        checked.append((record, check))
    decisive = next(
        ((record, check) for record, check in checked if check.stage == "json"),
        next(
            ((record, check) for record, check in checked if check.outcome == "invalid_utf8"), None
        ),
    )
    if decisive is None:
        return None
    record, check = decisive
    suffix = (
        " This describes the immutable file capture at "
        f"{capture.collection_completed_at.isoformat()}. "
        "Application acceptance and schema validity remain unverified."
    )
    if check.outcome == "valid_json" and task.observed == "accepted":
        return SelectedJsonFinding(
            "The selected capture was accepted by Dyad's strict UTF-8 JSON parser." + suffix,
            InvestigationOutcome.AWAITING_RECURRENCE,
            frozenset({str(task.evidence_id), str(record.evidence_id)}),
        )
    if check.outcome == "read_unavailable" and task.observed == "unavailable":
        return SelectedJsonFinding(
            f"The selected file could not be checked: {capture.error_code}. "
            "Select an available local regular file within the 256 KiB limit; "
            "no file content was available for a parser diagnosis." + suffix,
            InvestigationOutcome.INSUFFICIENT_OBSERVABILITY,
            frozenset({str(task.evidence_id), str(record.evidence_id)}),
        )
    if task.observed != "rejected" or check.outcome not in {"invalid_json", "invalid_utf8"}:
        return None
    descriptions = {
        "invalid_utf8": "The captured bytes cannot be decoded as strict UTF-8.",
        "utf8_bom": (
            "The capture begins with a UTF-8 byte-order mark, which this strict parser rejects."
        ),
        "empty_document": "The capture contains no JSON value.",
        "json_syntax": "The strict JSON parser rejected the captured syntax.",
        "non_finite_number": "A number is outside this parser's finite-number policy.",
        "nesting_limit": (
            "The capture exceeds this parser's nesting limit; JSON validity is unresolved."
        ),
        "number_limit": (
            "The capture exceeds this parser's integer-length limit; JSON validity is unresolved."
        ),
    }
    description = descriptions.get(check.error_code)
    if description is None:
        return None
    location = (
        f" The reported position is line {check.line}, column {check.column}."
        if check.line is not None and check.column is not None
        else ""
    )
    next_step = (
        " Check the file's intended encoding before converting a copy."
        if check.error_code in {"invalid_utf8", "utf8_bom"}
        else " Review the indicated position using the source editor."
        if check.error_code == "json_syntax"
        else " Check the document against the consuming application's format and limits."
    )
    return SelectedJsonFinding(
        description + location + next_step + suffix,
        InvestigationOutcome.INSUFFICIENT_OBSERVABILITY
        if check.error_code in {"nesting_limit", "number_limit"}
        else InvestigationOutcome.SUPPORTED_EXPLANATION,
        frozenset({str(task.evidence_id), str(record.evidence_id)}),
    )
