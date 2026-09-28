"""Noncausal same-ID revisions commit only with exact applied deep custody."""

from datetime import datetime, timedelta
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
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    NoncausalHypothesisRefV1,
    NoncausalObservationReviewV1,
    PriorHypothesisRevisionRefV1,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    hypothesis_revision_sha256,
)
from systemsense.reasoning.hypothesis_progression import progress_hypotheses
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.presented_read_set import capture_presented_read_set
from systemsense.storage.sqlite_store import SQLiteStore


def _record(
    store: SQLiteStore,
    case_id: CaseId,
    evidence_id: EvidenceId,
    number: int,
    observed_at: datetime,
) -> None:
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at,
        source=EvidenceSource(type="test.fixture", source_id="src_" + f"{number:064x}", locator={}),
        collector=CollectorReference(id="core.system", version=1, execution_id=ExecutionId.new()),
        summary="Scoped synthetic resource observation",
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=record.source.source_id,
            record_json=record.model_dump_json(),
            observed_at=observed_at.isoformat(),
            captured_at=observed_at.isoformat(),
        )


@pytest.mark.parametrize("same_statement", (False, True))
@pytest.mark.parametrize("project_extra_support", (False, True))
def test_noncausal_link_survives_readback_and_forgery_rolls_back(
    tmp_path: Path, same_statement: bool, project_extra_support: bool
) -> None:
    now = utc_now()
    old_id, reviewed_id = EvidenceId.new(), EvidenceId.new()
    provider = ProviderIdentity(provider_id="scripted-deep", provider_version="1", role="reasoning")
    with SQLiteStore(tmp_path / "noncausal.db") as store:
        repository = InvestigationRepository(store)
        state = InvestigationState(
            case_id=CaseId.new(),
            objective="Slow renderer",
            created_at=now,
            updated_at=now,
            deadline_at=now + timedelta(minutes=2),
            incident_start=now - timedelta(minutes=2),
            incident_end=now + timedelta(minutes=2),
            budget_ms=120_000,
        )
        repository.create(state)
        old_at = now - timedelta(seconds=1)
        _record(store, state.case_id, old_id, 1, old_at)
        _record(store, state.case_id, reviewed_id, 2, now)
        cpu = Hypothesis(
            hypothesis_id="cpu_contention",
            statement="Earlier CPU pressure is possible.",
            status=HypothesisStatus.UNRESOLVED,
            supporting_evidence_ids=(old_id,),
        )
        gpu = Hypothesis(
            hypothesis_id="gpu_bottleneck",
            statement="No GPU measurement supplied.",
            status=HypothesisStatus.UNRESOLVED,
        )
        prior = repository.save(
            state.model_copy(update={"hypotheses": (cpu, gpu)}),
            expected_version=0,
            event="fixture_prior",
            detail="Prior rivals",
        )
        context = (
            EvidenceContext(
                evidence_id=old_id,
                observed_at=old_at,
                captured_at=old_at,
                probe_id="core.snapshot",
                summary="Older CPU observation",
                status=EvidenceContextStatus.OBSERVED,
                case_scope="current_case",
            ),
            EvidenceContext(
                evidence_id=reviewed_id,
                observed_at=now,
                captured_at=now,
                probe_id="local_ai.snapshot",
                summary="GPU sample not bound to renderer",
                status=EvidenceContextStatus.OBSERVED,
                case_scope="current_case",
            ),
        )
        request = ReasoningRequest(
            schema_version=7,
            case_id=state.case_id,
            state_version=prior.state_version,
            correlation_id="noncausal:test",
            deadline_at=now + timedelta(minutes=1),
            objective=state.objective,
            evidence_ids=(old_id, reviewed_id),
            evidence_context=context,
            available_probes=(
                ProbeCapability(
                    probe_id="application.snapshot",
                    description="Synthetic read-only snapshot",
                    cost_ms=100,
                    resource_class=ResourceClass.CPU,
                ),
            ),
            previous_hypotheses=(cpu, gpu),
            prior_hypothesis_revision_refs=tuple(
                PriorHypothesisRevisionRefV1(
                    hypothesis_id=item.hypothesis_id,
                    hypothesis_sha256=hypothesis_revision_sha256(item),
                )
                for item in (cpu, gpu)
            ),
            budget_ms=1000,
            max_probes=1,
        )
        read_set = capture_presented_read_set(store, state.case_id, (old_id, reviewed_id))
        task = freeze_deep_task(
            request, read_set, provider_identity=provider, hypothesis_revision=1
        )
        ref = NoncausalHypothesisRefV1(evidence_id=reviewed_id, disposition="target_unbound")
        revised = gpu.model_copy(
            update={
                "statement": gpu.statement
                if same_statement
                else "A GPU sample exists but is not bound to slow frames.",
                "noncausal_observation_refs": (ref,),
                "supporting_evidence_ids": (old_id,) if project_extra_support else (),
            }
        )
        review = NoncausalObservationReviewV1(
            evidence_id=reviewed_id,
            disposition="target_unbound",
            explanation="The sampled GPU is not bound to the affected renderer.",
        )
        response = ReasoningResponse(
            schema_version=6,
            provider=provider,
            case_id=state.case_id,
            state_version=prior.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=ReasoningStatus.UNRESOLVED,
            summary="The GPU sample is not target-bound.",
            hypotheses=(cpu, revised),
            considered_evidence_ids=(old_id, reviewed_id),
            presented_prior_hypothesis_ids=(cpu.hypothesis_id, gpu.hypothesis_id),
            noncausal_observation_reviews=(review,),
        ).validate_against(request)
        result = DeepWorkerResultV1(
            case_id=state.case_id,
            request_sha256=task.request_sha256,
            provider_identity=provider,
            status="completed",
            started_at=now,
            finished_at=now + timedelta(milliseconds=1),
            elapsed_ms=1,
            response=response,
        )
        completion = DeepMailboxCompletionV1(task=task, result=result, status="applied")
        assert DeepMailboxRepository(store).admit(task)
        progression = progress_hypotheses(
            previous=(cpu, gpu),
            advisory=(cpu, revised),
            custodied_evidence_ids=(old_id, reviewed_id),
            visible_evidence_ids=(old_id, reviewed_id),
            noncausal_reviews=(review,),
            frozen_prior_refs=request.prior_hypothesis_revision_refs,
            visible_prior_hypothesis_ids=(cpu.hypothesis_id, gpu.hypothesis_id),
            source_request_sha256=task.request_sha256,
        )
        assert len(progression.noncausal_revision_links) == 1
        if project_extra_support:
            assert progression.hypotheses[1] == gpu.model_copy(
                update={"noncausal_observation_refs": (ref,)}
            )
            assert any("partial" in note.lower() for note in progression.notes)
        proposed = prior.model_copy(update={"hypotheses": progression.hypotheses})
        with pytest.raises(ValueError, match="requires applied revision lineage"):
            repository.save(
                proposed,
                expected_version=prior.state_version,
                event="deep_applied",
                detail="No link",
                deep_completion=completion,
            )
        with pytest.raises(ValueError, match="reviewed response"):
            repository.save(
                proposed,
                expected_version=prior.state_version,
                event="deep_applied",
                detail="Forged source request",
                deep_completion=completion,
                noncausal_revision_links=(
                    progression.noncausal_revision_links[0].model_copy(
                        update={"source_request_sha256": "f" * 64}
                    ),
                ),
            )
        forged_probe = revised.model_copy(
            update={"distinguishing_probe_ids": ("application.snapshot",)}
        )
        with pytest.raises(ValueError, match="reviewed response"):
            repository.save(
                prior.model_copy(update={"hypotheses": (cpu, forged_probe)}),
                expected_version=prior.state_version,
                event="deep_applied",
                detail="Forged probe advice",
                deep_completion=completion,
                noncausal_revision_links=(
                    progression.noncausal_revision_links[0].model_copy(
                        update={
                            "revised_hypothesis_sha256": hypothesis_revision_sha256(forged_probe)
                        }
                    ),
                ),
            )
        forged_missing = revised.model_copy(update={"missing_evidence_ids": (old_id,)})
        with pytest.raises(ValueError, match="reviewed response"):
            repository.save(
                prior.model_copy(update={"hypotheses": (cpu, forged_missing)}),
                expected_version=prior.state_version,
                event="deep_applied",
                detail="Forged missing advice",
                deep_completion=completion,
                noncausal_revision_links=(
                    progression.noncausal_revision_links[0].model_copy(
                        update={
                            "revised_hypothesis_sha256": hypothesis_revision_sha256(forged_missing),
                            "added_missing_evidence_ids": (old_id,),
                        }
                    ),
                ),
            )
        if project_extra_support:
            projected = progression.hypotheses[1]
            for forged in (
                projected.model_copy(update={"statement": "Unreviewed accepted rewrite"}),
                projected.model_copy(update={"supporting_evidence_ids": (old_id,)}),
                projected.model_copy(update={"status": HypothesisStatus.SUPPORTED}),
            ):
                with pytest.raises(ValueError):
                    repository.save(
                        prior.model_copy(update={"hypotheses": (cpu, forged)}),
                        expected_version=prior.state_version,
                        event="deep_applied",
                        detail="Forged projected checkpoint",
                        deep_completion=completion,
                        noncausal_revision_links=(
                            progression.noncausal_revision_links[0].model_copy(
                                update={
                                    "revised_hypothesis_sha256": hypothesis_revision_sha256(forged)
                                }
                            ),
                        ),
                    )
        assert repository.load(str(state.case_id)) == prior
        assert len(repository.steps(str(state.case_id))) == 2
        accepted = repository.save(
            proposed,
            expected_version=prior.state_version,
            event="deep_applied",
            detail="Reviewed GPU limit",
            deep_completion=completion,
            noncausal_revision_links=progression.noncausal_revision_links,
        )
        steps = repository.steps(str(state.case_id))
        assert steps[-2].hypotheses == (cpu, gpu)
        assert steps[-1].hypotheses == progression.hypotheses
        assert steps[-1].noncausal_revision_links == progression.noncausal_revision_links
        assert repository.load(str(state.case_id)) == accepted
        legacy = steps[0].model_dump(mode="json")
        legacy.pop("noncausal_revision_links", None)
        assert InvestigationStep.model_validate(legacy) == steps[0]
        bad = revised.model_copy(update={"supporting_evidence_ids": (reviewed_id,)})
        with pytest.raises(ValueError, match="cannot gain causal"):
            repository.save(
                accepted.model_copy(update={"hypotheses": (cpu, bad)}),
                expected_version=accepted.state_version,
                event="invalid",
                detail="Ref reclassified as support",
            )
        assert repository.load(str(state.case_id)) == accepted
        assert repository.steps(str(state.case_id)) == steps
        cited = revised.model_copy(update={"supporting_evidence_ids": (old_id,)})
        seeded = repository.save(
            accepted.model_copy(update={"hypotheses": (cpu, cited)}),
            expected_version=accepted.state_version,
            event="fixture_positive_basis",
            detail="Separate positive source admitted for ordinary advisory continuity.",
        )
        ordinary = cited.model_copy(
            update={"statement": "The earlier CPU fact remains relevant to a separate rival."}
        )
        ordinary_progression = progress_hypotheses(
            previous=(cpu, cited),
            advisory=(cpu, ordinary),
            custodied_evidence_ids=(old_id, reviewed_id),
            visible_evidence_ids=(old_id, reviewed_id),
        )
        assert ordinary_progression.hypotheses[1].statement == ordinary.statement
        assert ordinary_progression.hypotheses[1].noncausal_observation_refs == (ref,)
        assert ordinary_progression.noncausal_revision_links == ()
        ordinary_saved = repository.save(
            seeded.model_copy(update={"hypotheses": ordinary_progression.hypotheses}),
            expected_version=seeded.state_version,
            event="ordinary_advisory",
            detail="Existing positive basis changed prose without new noncausal refs.",
        )
        assert repository.load(str(state.case_id)) == ordinary_saved
