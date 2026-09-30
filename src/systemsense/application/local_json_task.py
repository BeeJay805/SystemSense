"""Custodied parser observations and checks of one private immutable file capture."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from typing import Literal, cast

from systemsense.application.task_observation import TaskObservationUnavailable
from systemsense.decision.contracts import ProbeCapability
from systemsense.domain.affected_task import (
    TaskObservationContextV1,
    TaskObservationFactPathsV1,
    TaskObservationReferenceV1,
)
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    FrozenModel,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeOutputFieldV1,
    ProbeSafety,
    ProbeToolMetadataV1,
    SafetyClass,
    SelfWrite,
)
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.platform.windows.selected_file import (
    SelectedFileCapture,
    SelectedFileCheck,
    SelectedFileObservation,
    check_json,
    check_utf8,
)
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import RelevantVersionsV1, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore

SELECTED_JSON_ACTION = "Parse strict UTF-8 JSON"
SELECTED_JSON_LIMITATION = (
    "Dyad selected-file parser outcome; application acceptance and schema validity unverified."
)
_EXPECTED = "Accepted by Dyad's bounded strict UTF-8 JSON parser"
_PROBE = "task.local_json"
_PATHS = TaskObservationFactPathsV1(
    target_handle="target_handle",
    action="action",
    expected="expected",
    observed="outcome",
    window_start="window_started_at",
    window_end="window_finished_at",
    window_ms="sample_window_ms",
)


class NoParametersV1(FrozenModel):
    """A model cannot choose another path, byte buffer, parser option or capture."""


class _SelectedTaskExecutionV1(FrozenModel):
    scope: Literal["user_selected_file"] = "user_selected_file"
    target_handle: str
    action: Literal["Parse strict UTF-8 JSON"] = SELECTED_JSON_ACTION
    observation_sha256: str
    initial_check: SelectedFileCheck


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def selected_json_target_handle(capture: SelectedFileCapture, case_id: CaseId) -> str:
    return _target_handle(capture.observation, case_id)


def _target_handle(observation: SelectedFileObservation, case_id: CaseId) -> str:
    return "selected_file_" + (observation.identity_sha256 or _sha(str(case_id)))


def _outcome(check: SelectedFileCheck) -> str:
    if check.stage != "json" or check.outcome not in {
        "valid_json",
        "invalid_json",
        "invalid_utf8",
        "read_unavailable",
    }:
        raise TaskObservationUnavailable("selected JSON task check has an invalid stage or outcome")
    return (
        "accepted"
        if check.outcome == "valid_json"
        else "unavailable"
        if check.outcome == "read_unavailable"
        else "rejected"
    )


def observe_selected_json_task(
    store: SQLiteStore, *, case_id: CaseId, capture: SelectedFileCapture
) -> EvidenceRecord:
    """Run the real fixed parse against captured bytes, never reopen a path."""
    repository = InvestigationRepository(store)
    state = repository.load(str(case_id))
    if state.task_observation_reference is not None or state.status.value != "queued":
        raise ValueError("selected JSON task requires one unstarted case")
    target = selected_json_target_handle(capture, case_id)
    if state.reported_task is not None and (
        state.reported_task.target_hint != target
        or state.reported_task_action_sha256 != _sha(SELECTED_JSON_ACTION)
    ):
        raise ValueError("selected JSON task differs from the reported exact action")
    started = utc_now()
    checked = check_json(capture)
    finished = utc_now()
    captured = utc_now()
    if not capture.observation.collection_completed_at <= started <= finished <= captured:
        raise ValueError("selected JSON task clock or capture chronology is invalid")
    window_ms = max(1, round((finished - started).total_seconds() * 1000))
    if window_ms > 600_000:
        raise ValueError("selected JSON task duration exceeds the observation contract")
    execution_id, evidence_id = ExecutionId.new(), EvidenceId.new()
    source_id = stable_source_id(
        "systemsense.probe",
        {"case_id": str(case_id), "target": target, "action": SELECTED_JSON_ACTION},
    )
    parameters = _SelectedTaskExecutionV1(
        target_handle=target,
        observation_sha256=_sha(capture.observation.model_dump_json()),
        initial_check=checked,
    )
    outcome = _outcome(checked)
    record = EvidenceRecord(
        case_id=case_id,
        evidence_id=evidence_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=finished,
        captured_at=captured,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": _PROBE, "target_handle": target, "action": SELECTED_JSON_ACTION},
        ),
        collector=CollectorReference(id=_PROBE, version=1, execution_id=execution_id),
        summary=f"Dyad's selected-file strict UTF-8 JSON parse was {outcome}.",
        facts=tuple(
            EvidenceFact(name=name, value=value)
            for name, value in {
                "target_handle": target,
                "action": SELECTED_JSON_ACTION,
                "expected": _EXPECTED,
                "outcome": outcome,
                "window_started_at": started.isoformat(),
                "window_finished_at": finished.isoformat(),
                "sample_window_ms": window_ms,
                "selected_file": capture.observation.model_dump(mode="json"),
            }.items()
        ),
        extraction=Extraction(confidence=1.0, parser=_PROBE, parser_version=1),
        sensitivity=Sensitivity.PERSONAL,
        limitations=(SELECTED_JSON_LIMITATION,),
    )
    reference = TaskObservationReferenceV1(
        case_id=case_id,
        evidence_id=evidence_id,
        source_id=source_id,
        collector_id=_PROBE,
        collector_version=1,
        execution_id=execution_id,
        record_sha256=_sha(record.model_dump_json()),
        fact_paths=_PATHS,
        scope="user_selected_file",
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id=_PROBE,
            probe_version=1,
            status="ok",
            parameters_json=parameters.model_dump_json(),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            state_version=state.state_version,
        )
        if not transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=finished.isoformat(),
            captured_at=captured.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"{_PROBE}:{case_id}",
            time_basis="collector_observed",
            time_quality="exact",
        ):
            raise ValueError("selected JSON task already recorded")
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()
        if generation is None:
            raise ValueError("selected JSON evidence generation unavailable")
        SearchFrontierRepository(store).append_result_event(
            case_id,
            source_evidence_id=evidence_id,
            source_execution_id=execution_id,
            versions=RelevantVersionsV1(objective=1, evidence=int(generation[0])),
        )
        resolve_selected_json_task(store, case_id=case_id, reference=reference)
    repository.save(
        state.model_copy(update={"task_observation_reference": reference}),
        expected_version=state.state_version,
        event="task_observed",
        detail="Exact selected-file parser task result bound to this case.",
    )
    return record


def resolve_selected_json_task(
    store: SQLiteStore, *, case_id: CaseId, reference: TaskObservationReferenceV1
) -> TaskObservationContextV1:
    """Validate persisted producer, parameters, identity, times and exact-action binding."""
    try:
        return _resolve_selected_json_task(store, case_id, reference)
    except TaskObservationUnavailable:
        raise
    except (TypeError, ValueError, KeyError) as error:
        raise TaskObservationUnavailable("selected JSON task custody is invalid") from error


def _resolve_selected_json_task(
    store: SQLiteStore, case_id: CaseId, reference: TaskObservationReferenceV1
) -> TaskObservationContextV1:
    if (
        reference.scope != "user_selected_file"
        or reference.case_id != case_id
        or reference.collector_id != _PROBE
        or reference.collector_version != 1
        or reference.fact_paths != _PATHS
    ):
        raise TaskObservationUnavailable("selected JSON task producer is invalid")
    row = store.evidence(case_id=str(case_id), evidence_id=str(reference.evidence_id))
    if row is None or row.execution_id != str(reference.execution_id):
        raise TaskObservationUnavailable("selected JSON task evidence unavailable")
    count = store.connection.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id=? "
        "AND json_extract(record_json,'$.collector.id')=?",
        (str(case_id), _PROBE),
    ).fetchone()
    if count is None or count[0] != 1 or _sha(row.record_json) != reference.record_sha256:
        raise TaskObservationUnavailable("selected JSON task record changed or is not unique")
    record = EvidenceRecord.model_validate_json(row.record_json)
    execution = store.probe_execution(str(reference.execution_id))
    if (
        record.case_id != case_id
        or record.evidence_id != reference.evidence_id
        or record.collector
        != CollectorReference(id=_PROBE, version=1, execution_id=reference.execution_id)
        or record.statement_kind is not StatementKind.OBSERVED_FACT
        or record.source.type != "systemsense.probe"
        or record.source.source_id != reference.source_id
        or record.extraction.parser != _PROBE
        or record.extraction.parser_version != 1
        or row.time_basis != "collector_observed"
        or row.time_quality != "exact"
        or row.observed_at != record.observed_at.isoformat()
        or row.captured_at != record.captured_at.isoformat()
        or record.limitations != (SELECTED_JSON_LIMITATION,)
        or execution is None
        or execution.case_id != str(case_id)
        or execution.probe_id != _PROBE
        or execution.probe_version != 1
        or execution.status != "ok"
        or execution.finished_at is None
    ):
        raise TaskObservationUnavailable("selected JSON record/execution custody differs")
    facts = {fact.name: fact.value for fact in record.facts}
    if len(facts) != len(record.facts) or set(facts) != {
        "target_handle",
        "action",
        "expected",
        "outcome",
        "window_started_at",
        "window_finished_at",
        "sample_window_ms",
        "selected_file",
    }:
        raise TaskObservationUnavailable(
            "selected JSON facts are duplicate or differ from contract"
        )
    observation = SelectedFileObservation.model_validate(facts["selected_file"])
    parameters = _SelectedTaskExecutionV1.model_validate_json(execution.parameters_json)
    target = _target_handle(observation, case_id)
    check = parameters.initial_check
    start = ensure_utc(datetime.fromisoformat(str(facts["window_started_at"])))
    end = ensure_utc(datetime.fromisoformat(str(facts["window_finished_at"])))
    window_ms = facts["sample_window_ms"]
    if (
        parameters.target_handle != target
        or facts["target_handle"] != target
        or facts["action"] != SELECTED_JSON_ACTION
        or facts["expected"] != _EXPECTED
        or facts["outcome"] != _outcome(check)
        or parameters.observation_sha256 != _sha(observation.model_dump_json())
        or check.identity_sha256 != observation.identity_sha256
        or check.content_sha256 != observation.content_sha256
        or check.collection_started_at != observation.collection_started_at
        or check.collection_completed_at != observation.collection_completed_at
        or (check.outcome == "read_unavailable") != (observation.outcome != "read_ok")
        or type(window_ms) is not int
        or not 1 <= window_ms <= 600_000
        or abs((end - start).total_seconds() * 1000 - window_ms) > 1
        or not observation.collection_completed_at
        <= start
        <= end
        == record.observed_at
        <= record.captured_at
        or ensure_utc(datetime.fromisoformat(execution.started_at)) != start
        or ensure_utc(datetime.fromisoformat(execution.finished_at)) != end
        or record.source.locator
        != {"probe_id": _PROBE, "target_handle": target, "action": SELECTED_JSON_ACTION}
        or record.source.source_id
        != stable_source_id(
            "systemsense.probe",
            {"case_id": str(case_id), "target": target, "action": SELECTED_JSON_ACTION},
        )
    ):
        raise TaskObservationUnavailable("selected JSON facts do not bind their execution")
    state = InvestigationRepository(store).load(str(case_id))
    relation: Literal["unbound", "exact_action_replayed"] = "unbound"
    if state.reported_task is not None:
        if state.reported_task.target_hint != target or state.reported_task_action_sha256 != _sha(
            SELECTED_JSON_ACTION
        ):
            raise TaskObservationUnavailable("selected JSON task differs from reported action")
        relation = "exact_action_replayed"
    return TaskObservationContextV1(
        case_id=case_id,
        evidence_id=record.evidence_id,
        source_id=record.source.source_id,
        collector_id=_PROBE,
        collector_version=1,
        execution_id=reference.execution_id,
        record_sha256=reference.record_sha256,
        target_handle=target,
        action=SELECTED_JSON_ACTION,
        expected=_EXPECTED,
        observed=cast("str", facts["outcome"]),
        window_start=start,
        window_end=end,
        sample_window_ms=window_ms,
        observed_at=record.observed_at,
        captured_at=record.captured_at,
        limitation=SELECTED_JSON_LIMITATION,
        scope="user_selected_file",
        reported_task_relation=relation,
    )


def selected_json_capabilities() -> tuple[ProbeCapability, ...]:
    return tuple(
        ProbeCapability(
            probe_id=probe,
            probe_version=1,
            description=description,
            keywords=frozenset({"json", "file"}),
            cost_ms=100,
            resource_class=ResourceClass.CPU,
            safety_class=SafetyClass.R0,
            baseline_priority=1.0,
        )
        for probe, description in (
            ("file.utf8", "Check strict UTF-8 encoding of the immutable selected-file capture"),
            (
                "file.json_syntax",
                "Check Dyad's strict JSON parser result for the immutable capture",
            ),
        )
    )


def selected_json_definitions(capture: SelectedFileCapture) -> tuple[ProbeDefinition, ...]:
    """Bind two parameter-free, in-process checks to this capture alone."""

    def handler(
        checker: Callable[[SelectedFileCapture], SelectedFileCheck],
    ) -> Callable[[dict[str, JsonValue]], ProbeObservation]:
        def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
            NoParametersV1.model_validate(parameters)
            checked = checker(capture)
            return ProbeObservation(
                summary=(
                    f"Selected-file {checked.stage} check: "
                    f"{checked.outcome} ({checked.error_code})."
                ),
                facts={"selected_file_check": checked.model_dump(mode="json")},
                observed_at=capture.observation.collection_completed_at,
                captured_at=utc_now(),
                limitations=(
                    SELECTED_JSON_LIMITATION,
                    "Checks use the immutable capture, not current disk contents.",
                ),
            )

        return collect

    definitions: list[ProbeDefinition] = []
    for capability, checker in zip(
        selected_json_capabilities(), (check_utf8, check_json), strict=True
    ):
        manifest = ProbeManifest(
            probe_id=capability.probe_id,
            version=1,
            implementation_id=f"builtin.{capability.probe_id}",
            question=capability.description,
            input_model=NoParametersV1.__name__,
            category="file",
            safety=ProbeSafety(
                safety_class=SafetyClass.R0,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
                self_writes=(SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
            ),
            limits=ProbeLimits(timeout_ms=1000, max_output_bytes=4096, max_records=1),
        )
        definitions.append(
            ProbeDefinition(
                manifest=manifest,
                parameter_model=NoParametersV1,
                handler=handler(checker),
                isolated=False,
                discovery=ProbeToolMetadataV1(
                    probe_id=capability.probe_id,
                    probe_version=1,
                    observable_ids=(capability.probe_id,),
                    parameter_fields=(),
                    supports_window=False,
                    outputs=(ProbeOutputFieldV1(name="selected_file_check"),),
                    estimated_cost_ms=100,
                    resource_class="cpu",
                    sensitivity=Sensitivity.PERSONAL,
                    network_effect="none",
                    io_intensity="light",
                    target_state_effect="none",
                    self_writes=manifest.safety.self_writes,
                    purpose=capability.description,
                ),
            )
        )
    return tuple(definitions)
