"""Caller-level custody regressions for the owner-replay closure exception.

All records are synthetic SQLite fixtures. These tests do not contact a host,
network listener, or model provider.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from systemsense.application import investigator as investigator_module
from systemsense.application import loopback_owner as loopback_owner_module
from systemsense.application.bootstrap import default_investigator
from systemsense.application.deep_worker import (
    DeepMailboxRepository,
    DeepWorkerResultV1,
    freeze_deep_task,
)
from systemsense.application.investigation_state import InvestigationState
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity, ResourceClass
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
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.presented_read_set import (
    PresentedReadSetEntryV1,
    PresentedReadSetV1,
    _snapshot_digest,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_loopback_owner_replay_listener_coverage import (
    _persist_pressure,
    _replace_facts,
)

# These tests intentionally exercise private custody and completion boundaries.
# pyright: reportPrivateUsage=false

_PROVIDER = ProviderIdentity(provider_id="synthetic-review", provider_version="1", role="reasoning")
_PORT = 59152
_NONCE = "a" * 32
_PID = 4321


def _persist_listener(
    store: SQLiteStore, task: TaskObservationContextV1, created_at: datetime
) -> EvidenceRecord:
    probe_id = "network.listeners"
    observed_at = task.window_end + timedelta(seconds=4)
    record = EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=task.case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at + timedelta(milliseconds=500),
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=stable_source_id(
                "systemsense.probe", {"probe_id": probe_id, "probe_version": 1}
            ),
            locator={"probe_id": probe_id},
        ),
        collector=CollectorReference(id=probe_id, version=1, execution_id=ExecutionId.new()),
        summary="Synthetic later listener snapshot.",
        facts=(
            EvidenceFact(
                name="listeners",
                value=[
                    {
                        "local_port": _PORT,
                        "local_address": "127.0.0.1",
                        "protocol": "tcp4",
                        "pid": _PID,
                        "process_name": "fixture-service.exe",
                        "process_creation_time": created_at.isoformat(),
                        "owner_status": "available",
                    }
                ],
            ),
        ),
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(record.collector.execution_id),
            case_id=str(task.case_id),
            probe_id=probe_id,
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=task.window_end.isoformat(),
            finished_at=record.captured_at.isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(task.case_id),
            evidence_id=str(record.evidence_id),
            source_id=record.source.source_id,
            record_json=record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
            execution_id=str(record.collector.execution_id),
            dedupe_key=f"execution:{record.collector.execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )
    return record


def _mailbox_applied_owner_review(
    store: SQLiteStore,
    task: TaskObservationContextV1,
    listener: EvidenceRecord,
    replay: EvidenceRecord,
    pressure: EvidenceRecord,
) -> None:
    evidence = tuple(
        EvidenceContext(
            evidence_id=evidence_id,
            observed_at=observed_at,
            captured_at=captured_at,
            probe_id=probe_id,
            summary=summary,
            facts={},
            status=EvidenceContextStatus.OBSERVED,
            case_scope="current_case",
            incident_relevant=True,
        )
        for evidence_id, observed_at, captured_at, probe_id, summary in (
            (
                task.evidence_id,
                task.observed_at,
                task.captured_at,
                "task.loopback_http",
                "Synthetic exact request observation.",
            ),
            (
                listener.evidence_id,
                listener.observed_at,
                listener.captured_at,
                "network.listeners",
                listener.summary,
            ),
            (
                replay.evidence_id,
                replay.observed_at,
                replay.captured_at,
                "network.loopback_replay",
                replay.summary,
            ),
            (
                pressure.evidence_id,
                pressure.observed_at,
                pressure.captured_at,
                "network.listener_owner_pressure",
                pressure.summary,
            ),
        )
    )
    request = ReasoningRequest(
        schema_version=3,
        case_id=task.case_id,
        state_version=1,
        correlation_id="synthetic-owner-closure",
        deadline_at=utc_now() + timedelta(minutes=1),
        objective="Review one synthetic failed loopback health request.",
        evidence_ids=tuple(item.evidence_id for item in evidence),
        evidence_context=evidence,
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="Synthetic registered read-only check",
                keywords=frozenset({"application"}),
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=5000,
        max_probes=1,
    )
    visible = tuple(
        PresentedReadSetEntryV1(
            evidence_id=item.evidence_id,
            kind="evidence",
            owner_case_id=task.case_id,
            row_sha256="a" * 64,
        )
        for item in evidence
    )
    read_set = PresentedReadSetV1(
        case_id=task.case_id,
        case_generation=1,
        entries=visible,
        read_set_sha256=_snapshot_digest(task.case_id, 1, visible),
    )
    frozen = freeze_deep_task(request, read_set, provider_identity=_PROVIDER, hypothesis_revision=0)
    # Listener is deliberately considered but not used. The owner-pressure
    # record is the source-bound substitute for a separate listener citation.
    response = ReasoningResponse(
        schema_version=1,
        provider=_PROVIDER,
        case_id=task.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="The synthetic owner replay was reviewed; cause remains unresolved.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="request_failure",
                statement="The exact synthetic request timed out.",
                status=HypothesisStatus.UNRESOLVED,
                supporting_evidence_ids=(
                    task.evidence_id,
                    replay.evidence_id,
                    pressure.evidence_id,
                ),
            ),
        ),
        considered_evidence_ids=tuple(item.evidence_id for item in evidence),
    )
    result = DeepWorkerResultV1(
        case_id=task.case_id,
        request_sha256=frozen.request_sha256,
        provider_identity=_PROVIDER,
        status="completed",
        started_at=listener.captured_at,
        finished_at=pressure.captured_at + timedelta(seconds=1),
        elapsed_ms=100,
        response=response,
    )
    mailbox = DeepMailboxRepository(store)
    assert mailbox.admit(frozen)
    assert mailbox.finish(frozen, "applied", result=result)


@pytest.mark.parametrize("invalid_boundary", [False, True])
def test_owner_review_closure_requires_verified_boundary_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_boundary: bool
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, pressure, fixture_owner = _persist_pressure(store)
        # The replay record is persisted by the custody fixture alongside the
        # owner pressure record; locate it by its registered collector.
        replay_exec = store.connection.execute(
            "SELECT record_json FROM evidence WHERE case_id=? AND source_id=?",
            (
                str(task.case_id),
                stable_source_id(
                    "systemsense.probe",
                    {"probe_id": "network.loopback_replay", "probe_version": 1},
                ),
            ),
        ).fetchone()
        assert replay_exec is not None
        replay = EvidenceRecord.model_validate_json(str(replay_exec[0]))
        listener = _persist_listener(store, task, fixture_owner.creation_time)
        if invalid_boundary:
            facts = {fact.name: fact.value for fact in pressure.facts}
            facts.pop("listener_ownership")
            pressure = _replace_facts(store, pressure, facts)

        reference = TaskObservationReferenceV1(
            case_id=task.case_id,
            evidence_id=task.evidence_id,
            source_id=task.source_id,
            collector_id=task.collector_id,
            collector_version=task.collector_version,
            execution_id=task.execution_id,
            record_sha256=task.record_sha256,
            fact_paths=TaskObservationFactPathsV1(
                target_handle="target_handle",
                action="action",
                expected="expected",
                observed="observed",
                window_start="window_start",
                window_end="window_end",
                window_ms="sample_window_ms",
            ),
            scope="test_owned_loopback",
        )
        repository = InvestigationRepository(store)
        state = repository.load(str(task.case_id)).model_copy(
            update={"task_observation_reference": reference}
        )
        state = repository.save(
            state,
            expected_version=state.state_version,
            event="synthetic_task_bound",
            detail="Synthetic test fixture binds the task observation.",
        )
        _mailbox_applied_owner_review(store, task, listener, replay, pressure)

        listener_context = EvidenceContext(
            evidence_id=listener.evidence_id,
            observed_at=listener.observed_at,
            captured_at=listener.captured_at,
            probe_id="network.listeners",
            summary=listener.summary,
            facts={"target_listener_search": [{"status": "listener_present"}]},
            status=EvidenceContextStatus.OBSERVED,
            case_scope="current_case",
            incident_relevant=True,
        )

        def resolve(*_args: object, **_kwargs: object) -> TaskObservationContextV1:
            return task

        def remaining(*_args: object, **_kwargs: object) -> int:
            return 5000

        def context(*_args: object, **_kwargs: object) -> tuple[EvidenceContext, ...]:
            return (listener_context,)

        def records(
            _owner: object, _state: object, _context: object, probe_id: str
        ) -> tuple[EvidenceRecord, ...]:
            return {
                "network.listeners": (listener,),
                "network.listener_owner_pressure": (pressure,),
                "network.loopback_replay": (replay,),
            }.get(probe_id, ())

        def selection(*_args: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(
                truncated=False, context=(listener_context,), matched_row_paths=("listeners[0]",)
            )

        def finish(
            _owner: object, updated: InvestigationState, *_args: object, **_kwargs: object
        ) -> InvestigationState:
            return updated

        monkeypatch.setattr(investigator_module, "resolve_task_observation", resolve)
        monkeypatch.setattr(loopback_owner_module, "resolve_task_observation", resolve)
        monkeypatch.setattr(
            loopback_owner_module, "utc_now", lambda: listener.captured_at + timedelta(seconds=1)
        )
        monkeypatch.setattr(investigator_module.Investigator, "_remaining_ms", remaining)
        monkeypatch.setattr(investigator_module.Investigator, "context", context)
        monkeypatch.setattr(investigator_module.Investigator, "_trusted_probe_records", records)
        monkeypatch.setattr(investigator_module.Investigator, "_select_target_evidence", selection)
        monkeypatch.setattr(investigator_module.Investigator, "_finish", finish)

        assert investigator_module.trusted_loopback_owner(store, state.case_id) is not None
        result = default_investigator(store)._complete_reviewed_loopback_task(state, None)

        assert (result is not None) is (not invalid_boundary)
