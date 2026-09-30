"""Synthetic custody regression for a narrow process-presence review."""

import threading
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.deep_worker import (
    DeepMailboxRepository,
    DeepWorkerResultV1,
    freeze_deep_task,
)
from systemsense.application.investigation_state import InvestigationState
from systemsense.application.investigator import Investigator
from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.time import utc_now
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.presented_read_set import capture_presented_read_set
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_process_target_binding import _snapshot

# Only synthetic persisted observations and provider responses; no host/model calls.
# pyright: reportPrivateUsage=false
IDENTITY = ProviderIdentity(
    provider_id="synthetic-reviewed-provider", provider_version="1", role="reasoning"
)


def setup_case(
    store: SQLiteStore,
    *,
    present: bool = False,
    omitted: int = 0,
    objective: str = "Is sample.exe present in the current process list?",
) -> tuple[Investigator, InvestigationState, EvidenceId]:
    app = default_investigator(store)
    state = app.create(objective=objective)
    rows: list[dict[str, JsonValue]] = (
        [{"name": "sample.exe", "pid": 1234, "creation_time": state.incident_start.isoformat()}]
        if present
        else []
    )
    eid = _snapshot(store, state.case_id, processes=rows, omitted=omitted, at=utc_now())
    state = state.model_copy(update={"completed_probe_ids": ("application.snapshot",)})
    return app, state, eid


def apply_review(
    store: SQLiteStore,
    app: Investigator,
    state: InvestigationState,
    eid: EvidenceId,
    *,
    used: bool = True,
    considered: bool = True,
    degraded: bool = False,
    applied: bool = True,
) -> None:
    context = app.context(str(state.case_id), state=state)
    request = ReasoningRequest(
        schema_version=3,
        case_id=state.case_id,
        state_version=state.state_version,
        correlation_id="synthetic-presence",
        deadline_at=state.deadline_at,
        objective=state.objective,
        evidence_ids=(eid,),
        evidence_context=context,
        available_probes=app._case_capabilities(state),
        completed_probe_ids=frozenset(state.completed_probe_ids),
        budget_ms=30000,
        max_probes=2,
    )
    task = freeze_deep_task(
        request,
        capture_presented_read_set(store, state.case_id, tuple(x.evidence_id for x in context)),
        provider_identity=IDENTITY,
        hypothesis_revision=0,
    )
    response = ReasoningResponse(
        schema_version=3,
        provider=IDENTITY,
        case_id=state.case_id,
        state_version=state.state_version,
        correlation_id=request.correlation_id,
        deadline_at=state.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="Only the saved sampled process state is known.",
        degraded=degraded,
        considered_evidence_ids=(eid,) if considered else (),
        hypotheses=(
            Hypothesis(
                hypothesis_id="sample_state",
                statement="Sampled state only; earlier cause unknown.",
                status=HypothesisStatus.UNRESOLVED,
                supporting_evidence_ids=(eid,) if used else (),
            ),
        ),
    )
    response.validate_against(request)
    now = utc_now()
    result = DeepWorkerResultV1(
        case_id=state.case_id,
        request_sha256=task.request_sha256,
        provider_identity=IDENTITY,
        status="completed",
        started_at=now,
        finished_at=now,
        elapsed_ms=0,
        response=response,
    )
    mailbox = DeepMailboxRepository(store)
    assert mailbox.admit(task)
    assert mailbox.finish(task, "applied" if applied else "rejected", result=result)


@pytest.mark.parametrize("present", [True, False])
def test_narrow_presence_waits_for_review_then_closes_after_source_use(
    tmp_path: Path, present: bool
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        app, state, eid = setup_case(store, present=present)
        assert app._scoped_measurements_ready_for_review(state)
        assert app._complete_reviewed_loopback_task(state, None) is None
        apply_review(store, app, state, eid)
        result = app._complete_reviewed_loopback_task(state, None)
        assert result is not None
        assert result.outcome.value == "supported_explanation"
        assert "sample" in result.summary and "earlier" in result.summary
        assert result.assessment is not None and result.assessment.evidence_ids == (eid,)


@pytest.mark.parametrize(
    "defect", ["unused", "unconsidered", "degraded", "rejected", "cancelled", "partial", "causal"]
)
def test_presence_does_not_close_without_complete_reviewed_custody(
    tmp_path: Path, defect: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        app, state, eid = setup_case(
            store,
            omitted=1 if defect == "partial" else 0,
            objective="Why did sample.exe stop?"
            if defect == "causal"
            else "Is sample.exe present?",
        )
        apply_review(
            store,
            app,
            state,
            eid,
            used=defect != "unused",
            considered=defect != "unconsidered",
            degraded=defect == "degraded",
            applied=defect != "rejected",
        )
        cancel = threading.Event()
        if defect == "cancelled":
            cancel.set()
        assert app._complete_reviewed_loopback_task(state, cancel) is None
