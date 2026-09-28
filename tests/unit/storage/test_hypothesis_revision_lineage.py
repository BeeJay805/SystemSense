"""A retired citation stays visible in the immutable hypothesis step history."""

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

from systemsense.application.deep_worker import (
    DeepMailboxCompletionV1,
    DeepMailboxRepository,
    DeepWorkerResultV1,
    freeze_deep_task,
)
from systemsense.application.investigation_state import InvestigationState, InvestigationStep
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity, ResourceClass
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import (
    ExpectedFact,
    Hypothesis,
    HypothesisRevisionIntentV1,
    HypothesisStatus,
    PriorHypothesisRevisionRefV1,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    hypothesis_revision_sha256,
)
from systemsense.reasoning.hypothesis_progression import progress_hypotheses
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.presented_read_set import PresentedReadSetEntryV1, PresentedReadSetV1
from systemsense.storage.sqlite_store import SQLiteStore


def _applied_completion(
    case_id: CaseId,
    state_version: int,
    old: Hypothesis,
    revised: Hypothesis,
    old_id: EvidenceId,
    new_id: EvidenceId,
    counter_id: EvidenceId,
) -> DeepMailboxCompletionV1:
    now = utc_now()
    provider = ProviderIdentity(provider_id="fake-deep", provider_version="1", role="reasoning")
    context = tuple(
        EvidenceContext(
            evidence_id=eid,
            observed_at=now,
            captured_at=now,
            probe_id="application.snapshot",
            summary="Synthetic scoped observation",
            status=EvidenceContextStatus.OBSERVED,
            case_scope="current_case",
        )
        for eid in (old_id, new_id, counter_id)
    )
    request = ReasoningRequest(
        schema_version=7,
        case_id=case_id,
        state_version=state_version,
        correlation_id="lineage:test",
        deadline_at=now + timedelta(minutes=1),
        objective="Memory concern",
        evidence_ids=(old_id, new_id, counter_id),
        evidence_context=context,
        previous_hypotheses=(old,),
        prior_hypothesis_revision_refs=(
            PriorHypothesisRevisionRefV1(
                hypothesis_id=old.hypothesis_id,
                hypothesis_sha256=hypothesis_revision_sha256(old),
            ),
        ),
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="Synthetic read-only snapshot",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=1000,
        max_probes=1,
    )
    entries = tuple(
        PresentedReadSetEntryV1(
            evidence_id=eid,
            kind="evidence",
            owner_case_id=case_id,
            row_sha256="b" * 64,
        )
        for eid in (old_id, new_id, counter_id)
    )
    basis = {
        "schema_version": 1,
        "case_id": str(case_id),
        "case_generation": 1,
        "entries": [item.model_dump(mode="json") for item in entries],
    }
    digest = hashlib.sha256(
        json.dumps(
            basis,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    read_set = PresentedReadSetV1(
        case_id=case_id,
        case_generation=1,
        entries=entries,
        read_set_sha256=digest,
    )
    task = freeze_deep_task(
        request,
        read_set,
        provider_identity=provider,
        hypothesis_revision=1,
    )
    response = ReasoningResponse(
        schema_version=4,
        provider=provider,
        case_id=case_id,
        state_version=state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="A later scoped reading contests broad pressure.",
        hypotheses=(revised,),
        considered_evidence_ids=(old_id, new_id, counter_id),
        presented_prior_hypothesis_ids=(old.hypothesis_id,),
        hypothesis_revision_intents=(
            HypothesisRevisionIntentV1(
                hypothesis_id=old.hypothesis_id,
                prior_hypothesis_sha256=hypothesis_revision_sha256(old),
                retired_supporting_evidence_ids=(old_id,),
            ),
        ),
    ).validate_against(request)
    result = DeepWorkerResultV1(
        case_id=case_id,
        request_sha256=task.request_sha256,
        provider_identity=provider,
        status="completed",
        started_at=now,
        finished_at=now + timedelta(milliseconds=1),
        elapsed_ms=1,
        response=response,
    )
    return DeepMailboxCompletionV1(task=task, result=result, status="applied")


def test_accepted_retirement_and_old_snapshot_read_back_from_steps(tmp_path: Path) -> None:
    now = utc_now()
    old_id, new_id, counter_id = EvidenceId.new(), EvidenceId.new(), EvidenceId.new()
    old = Hypothesis(
        hypothesis_id="memory_pressure",
        statement="Capacity is known; pressure unmeasured.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(old_id,),
        contradicting_evidence_ids=(counter_id,),
        expected_facts=(
            ExpectedFact(
                probe_id="application.snapshot",
                fact_name="memory_pressure",
                expected_value="available",
            ),
        ),
        expected_facts_observed_after=now,
    )
    advice = Hypothesis(
        hypothesis_id=old.hypothesis_id,
        statement="A newer scoped reading contests pressure.",
        status=HypothesisStatus.CONTESTED,
        contradicting_evidence_ids=(counter_id, new_id),
    )
    with SQLiteStore(tmp_path / "lineage.db") as store:
        repository = InvestigationRepository(store)
        state = InvestigationState(
            case_id=CaseId.new(),
            objective="Memory concern",
            created_at=now,
            updated_at=now,
            deadline_at=now + timedelta(minutes=2),
            incident_start=now - timedelta(minutes=10),
            incident_end=now,
            budget_ms=120_000,
        )
        repository.create(state)
        old_state = repository.save(
            state.model_copy(update={"hypotheses": (old,)}),
            expected_version=0,
            event="deep_applied",
            detail="Older advisory",
        )
        completion = _applied_completion(
            state.case_id,
            old_state.state_version,
            old,
            advice,
            old_id,
            new_id,
            counter_id,
        )
        assert DeepMailboxRepository(store).admit(completion.task)
        assert completion.result.response is not None
        progression = progress_hypotheses(
            previous=(old,),
            advisory=(advice,),
            custodied_evidence_ids=(old_id, new_id, counter_id),
            visible_evidence_ids=(old_id, new_id, counter_id),
            revision_intents=completion.result.response.hypothesis_revision_intents,
            visible_prior_hypothesis_ids=(old.hypothesis_id,),
            source_request_sha256=completion.task.request_sha256,
        )
        with pytest.raises(ValueError, match="applied intent"):
            repository.save(
                old_state.model_copy(update={"hypotheses": progression.hypotheses}),
                expected_version=old_state.state_version,
                event="deep_applied",
                detail="Wrong prior digest",
                deep_completion=completion,
                hypothesis_revision_links=(
                    progression.revision_links[0].model_copy(
                        update={"prior_hypothesis_sha256": "f" * 64}
                    ),
                ),
            )
        with pytest.raises(ValueError, match="applied intent"):
            repository.save(
                old_state.model_copy(update={"hypotheses": progression.hypotheses}),
                expected_version=old_state.state_version,
                event="deep_applied",
                detail="Forged request pointer",
                deep_completion=completion,
                hypothesis_revision_links=(
                    progression.revision_links[0].model_copy(
                        update={"source_request_sha256": "f" * 64}
                    ),
                ),
            )
        with pytest.raises(ValueError, match="applied deep custody"):
            repository.save(
                old_state.model_copy(update={"hypotheses": progression.hypotheses}),
                expected_version=old_state.state_version,
                event="deep_applied",
                detail="Rejected completion",
                deep_completion=completion.model_copy(update={"status": "rejected"}),
                hypothesis_revision_links=progression.revision_links,
            )
        active = progression.hypotheses[0]
        for bad in (
            active.model_copy(update={"supporting_evidence_ids": (old_id,)}),
            active.model_copy(update={"contradicting_evidence_ids": (new_id,)}),
            active.model_copy(update={"expected_facts": ()}),
            active.model_copy(update={"missing_evidence_ids": (old_id,)}),
            active.model_copy(update={"contradicting_evidence_ids": (counter_id,)}),
        ):
            with pytest.raises(ValueError, match="citation continuity"):
                repository.save(
                    old_state.model_copy(update={"hypotheses": (bad,)}),
                    expected_version=old_state.state_version,
                    event="deep_applied",
                    detail="Forged revision",
                    deep_completion=completion,
                    hypothesis_revision_links=(
                        progression.revision_links[0].model_copy(
                            update={"revised_hypothesis_sha256": hypothesis_revision_sha256(bad)}
                        ),
                    ),
                )
        with pytest.raises(ValueError, match="applied deep custody"):
            repository.save(
                old_state.model_copy(update={"hypotheses": progression.hypotheses}),
                expected_version=old_state.state_version,
                event="deep_applied",
                detail="Foreign completion",
                deep_completion=completion.model_copy(
                    update={
                        "result": completion.result.model_copy(update={"case_id": CaseId.new()})
                    }
                ),
                hypothesis_revision_links=progression.revision_links,
            )
        assert len(repository.steps(str(state.case_id))) == 2
        new_state = repository.save(
            old_state.model_copy(update={"hypotheses": progression.hypotheses}),
            expected_version=old_state.state_version,
            event="deep_applied",
            detail="Newer advisory",
            deep_completion=completion,
            hypothesis_revision_links=progression.revision_links,
        )
        steps = repository.steps(str(state.case_id))
        assert steps[-2].hypotheses == (old,)
        assert steps[-1].hypotheses == progression.hypotheses
        assert steps[-1].hypothesis_revision_links == progression.revision_links
        assert (
            steps[-1].hypothesis_revision_links[0].source_request_sha256
            == completion.task.request_sha256
        )
        assert repository.load(str(state.case_id)) == new_state
        assert steps[0].hypothesis_revision_links == ()
        legacy_step = steps[0].model_dump(mode="json")
        del legacy_step["hypothesis_revision_links"]
        assert InvestigationStep.model_validate(legacy_step) == steps[0]
        with pytest.raises(ValueError, match="lineage differs"):
            repository.save(
                new_state,
                expected_version=new_state.state_version,
                event="invalid",
                detail="Tampered link",
                hypothesis_revision_links=(
                    progression.revision_links[0].model_copy(
                        update={"revised_hypothesis_sha256": "f" * 64}
                    ),
                ),
            )
        assert repository.steps(str(state.case_id)) == steps
