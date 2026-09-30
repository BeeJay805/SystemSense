"""Bounded deep work overlaps the real coordinator's durable collection path."""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from systemsense.application.investigation_state import InvestigationState
from systemsense.decision.contracts import (
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.decision.frontier_ranker import MixedFrontierRanker
from systemsense.domain.evidence import EvidenceRecord, Sensitivity
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.probes import (
    ProbeOutputFieldV1,
    ProbePredictionOutputV1,
    ProbeToolMetadataV1,
    SelfWrite,
)
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.probes import ProbeObservation
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisRevisionIntentV1,
    HypothesisStatus,
    NoncausalHypothesisRefV1,
    NoncausalObservationReviewV1,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    hypothesis_revision_sha256,
)
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import (
    _persist_evidence,  # pyright: ignore[reportPrivateUsage]
    investigator,
    probe_definition,
)


def _proposal(probe_id: str) -> ProbeProposal:
    return ProbeProposal(
        probe_id=probe_id,
        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
        priority=1,
        estimated_cost_ms=1,
        resource_class=ResourceClass.CPU,
        dedupe_key=probe_id,
    )


@pytest.mark.parametrize("explicit_retirement", (False, True))
def test_async_same_id_retirement_has_exact_step_lineage(
    tmp_path: Path,
    explicit_retirement: bool,
) -> None:
    class RevisingDeep:
        identity = ProviderIdentity(
            provider_id="scripted-revision", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            assert request.schema_version == 7
            prior = request.previous_hypotheses[0]
            assert request.prior_hypothesis_revision_refs[0].hypothesis_sha256 == (
                hypothesis_revision_sha256(prior)
            )
            new_id = next(
                item.evidence_id
                for item in request.evidence_context
                if item.evidence_id not in prior.supporting_evidence_ids and item.facts
            )
            revision = Hypothesis(
                hypothesis_id=prior.hypothesis_id,
                statement="The later scoped observation contests the older explanation.",
                status=HypothesisStatus.CONTESTED,
                contradicting_evidence_ids=(new_id,),
            )
            return ReasoningResponse(
                schema_version=4 if explicit_retirement else 3,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="A later observation changes the advisory interpretation.",
                hypotheses=(revision,),
                considered_evidence_ids=tuple(
                    item.evidence_id for item in request.evidence_context
                ),
                hypothesis_revision_intents=(
                    HypothesisRevisionIntentV1(
                        hypothesis_id=prior.hypothesis_id,
                        prior_hypothesis_sha256=hypothesis_revision_sha256(prior),
                        retired_supporting_evidence_ids=prior.supporting_evidence_ids,
                    ),
                )
                if explicit_retirement
                else (),
                presented_prior_hypothesis_ids=(prior.hypothesis_id,)
                if explicit_retirement
                else (),
            )

    with SQLiteStore(tmp_path / "async-lineage.db") as store:
        app = investigator(store, reasoning=RevisingDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Memory concern", budget_ms=20_000, max_probes=3)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        context = app.context(str(state.case_id), state=state)
        old_id = next(item.evidence_id for item in context if item.facts)
        old = Hypothesis(
            hypothesis_id="memory_pressure",
            statement="One older reading raises a concern.",
            status=HypothesisStatus.UNRESOLVED,
            supporting_evidence_ids=(old_id,),
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"hypotheses": (old,)}),
            "fixture_prior",
            "Older advisory retained.",
        )
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("network.snapshot"),), None, baseline=True
        )
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        steps = app.repository.steps(str(state.case_id))
        assert any(step.event == "fixture_prior" and step.hypotheses == (old,) for step in steps)
        assert steps[-1].event == "deep_applied"
        if explicit_retirement:
            assert state.hypotheses[0].statement != old.statement
            assert state.hypotheses[0].supporting_evidence_ids == ()
            assert steps[-1].hypothesis_revision_links[0].retired_supporting_evidence_ids == (
                old_id,
            )
            mailbox = store.connection.execute(
                "SELECT request_sha256 FROM deep_mailbox WHERE case_id=? AND status='applied'",
                (str(state.case_id),),
            ).fetchone()
            assert mailbox is not None
            assert steps[-1].hypothesis_revision_links[0].source_request_sha256 == mailbox[0]
        else:
            assert state.hypotheses[0].statement == old.statement
            assert steps[-1].hypothesis_revision_links == ()


@pytest.mark.parametrize(
    ("explicit_ref", "combined_unavailable", "project_extra_support"),
    ((False, False, False), (True, False, False), (True, True, False), (True, False, True)),
)
def test_async_uncited_rival_needs_exact_noncausal_ref_lineage(
    tmp_path: Path, explicit_ref: bool, combined_unavailable: bool, project_extra_support: bool
) -> None:
    class ReviewingDeep:
        identity = ProviderIdentity(
            provider_id="scripted-noncausal-review", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            prior = {item.hypothesis_id: item for item in request.previous_hypotheses}
            old = prior["gpu_bottleneck"]
            new_id = next(
                item.evidence_id
                for item in request.evidence_context
                if item.probe_id == "network.snapshot" and item.facts
            )
            ref = NoncausalHypothesisRefV1(evidence_id=new_id, disposition="target_unbound")
            unavailable_id = next(
                (
                    item.evidence_id
                    for item in request.evidence_context
                    if item.probe_id == "application.snapshot"
                ),
                None,
            )
            revised = old.model_copy(
                update={
                    "statement": "A later resource sample exists, but its target is unbound.",
                    "noncausal_observation_refs": (ref,) if explicit_ref else (),
                    "missing_evidence_ids": (unavailable_id,)
                    if combined_unavailable and unavailable_id is not None
                    else (),
                    "distinguishing_probe_ids": ("core.snapshot",) if combined_unavailable else (),
                    "supporting_evidence_ids": prior["cpu_contention"].supporting_evidence_ids
                    if project_extra_support
                    else (),
                }
            )
            return ReasoningResponse(
                schema_version=6 if explicit_ref else 5,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The new resource sample is not bound to the affected operation.",
                hypotheses=(prior["cpu_contention"], revised),
                considered_evidence_ids=tuple(
                    item.evidence_id for item in request.evidence_context
                ),
                presented_prior_hypothesis_ids=tuple(prior),
                noncausal_observation_reviews=(
                    NoncausalObservationReviewV1(
                        evidence_id=new_id,
                        disposition="target_unbound",
                        explanation="The source is not bound to the affected workload.",
                    ),
                ),
            )

    def unavailable_collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary="Registered application check unavailable",
            facts={"collection_status": "unsupported"},
            observed_at=observed_at,
            captured_at=observed_at,
        )

    unavailable_definition = replace(probe_definition("application"), handler=unavailable_collect)
    with SQLiteStore(tmp_path / "async-noncausal.db") as store:
        app = investigator(
            store,
            definitions=(
                probe_definition("core"),
                probe_definition("network"),
                unavailable_definition,
            ),
            reasoning=ReviewingDeep(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Slow renderer", budget_ms=20_000, max_probes=4)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        old_id = next(item.evidence_id for item in app.context(str(state.case_id)) if item.facts)
        cpu = Hypothesis(
            hypothesis_id="cpu_contention",
            statement="An older CPU sample raises a concern.",
            status=HypothesisStatus.UNRESOLVED,
            supporting_evidence_ids=(old_id,),
        )
        gpu = Hypothesis(
            hypothesis_id="gpu_bottleneck",
            statement="GPU limitation is possible; no GPU measurement is supplied.",
            status=HypothesisStatus.UNRESOLVED,
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"hypotheses": (cpu, gpu)}),
            "fixture_prior",
            "Older advisory retained.",
        )
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("network.snapshot"),), None, baseline=True
        )
        if combined_unavailable:
            state = app._collect(  # pyright: ignore[reportPrivateUsage]
                state, (_proposal("application.snapshot"),), None, baseline=True
            )
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        active = {item.hypothesis_id: item for item in state.hypotheses}["gpu_bottleneck"]
        step = app.repository.steps(str(state.case_id))[-1]
        assert step.event == "deep_applied"
        if explicit_ref:
            assert (active.statement == gpu.statement) == project_extra_support
            assert active.supporting_evidence_ids == active.contradicting_evidence_ids == ()
            assert len(active.noncausal_observation_refs) == 1
            assert step.noncausal_revision_links[0].added_refs == (
                active.noncausal_observation_refs[0],
            )
            if combined_unavailable:
                assert len(active.missing_evidence_ids) == 1
                assert step.noncausal_revision_links[0].added_missing_evidence_ids == (
                    active.missing_evidence_ids[0],
                )
                assert active.distinguishing_probe_ids == ("core.snapshot",)
            if project_extra_support:
                assert active.status == gpu.status
                assert active.distinguishing_probe_ids == gpu.distinguishing_probe_ids
                assert any("Partial same-ID" in warning for warning in state.warnings)
        else:
            assert active == gpu
            assert step.noncausal_revision_links == ()


@pytest.mark.parametrize(
    ("facts", "retained"),
    (
        ({"collection_status": "unsupported"}, True),
        ({"collection_status": "available"}, False),
        ({"collection_status": "unsupported", "events": ["observed"]}, False),
    ),
)
def test_async_missing_only_update_retains_only_verified_absence(
    tmp_path: Path, facts: dict[str, JsonValue], retained: bool
) -> None:
    class MissingOnlyDeep:
        identity = ProviderIdentity(
            provider_id="scripted-missing", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            prior = {item.hypothesis_id: item for item in request.previous_hypotheses}
            observed = next(
                item for item in request.evidence_context if item.probe_id == "network.snapshot"
            )
            changed = prior["security_block"].model_copy(
                update={
                    "statement": "The unavailable check proves a security block.",
                    "status": HypothesisStatus.UNRESOLVED,
                    "missing_evidence_ids": (observed.evidence_id,),
                    "distinguishing_probe_ids": (),
                }
            )
            return ReasoningResponse(
                schema_version=5,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The check does not establish a security cause.",
                hypotheses=(prior["application_fault"], changed),
                noncausal_observation_reviews=(
                    NoncausalObservationReviewV1(
                        evidence_id=observed.evidence_id,
                        disposition="target_unbound",
                        explanation="The result does not establish the affected task outcome.",
                    ),
                ),
                presented_prior_hypothesis_ids=tuple(prior),
                considered_evidence_ids=tuple(
                    item.evidence_id for item in request.evidence_context
                ),
            )

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary="Synthetic scoped check",
            facts=facts,
            observed_at=observed_at,
            captured_at=observed_at,
        )

    unavailable = replace(probe_definition("network"), handler=collect)
    with SQLiteStore(tmp_path / "missing-only.db") as store:
        app = investigator(
            store,
            definitions=(probe_definition("core"), unavailable),
            reasoning=MissingOnlyDeep(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Application concern", budget_ms=20_000, max_probes=2)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        core_id = next(
            item.evidence_id
            for item in app.context(str(state.case_id), state=state)
            if item.probe_id == "core.snapshot"
        )
        application = Hypothesis(
            hypothesis_id="application_fault",
            statement="An application fault remains possible.",
            status=HypothesisStatus.UNRESOLVED,
            supporting_evidence_ids=(core_id,),
        )
        security = Hypothesis(
            hypothesis_id="security_block",
            statement="A security block remains possible but unobserved.",
            status=HypothesisStatus.UNRESOLVED,
            distinguishing_probe_ids=("network.snapshot",),
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"hypotheses": (application, security)}),
            "fixture_prior",
            "Uncited rival retained.",
        )
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("network.snapshot"),), None, baseline=True
        )
        observed_id = next(
            item.evidence_id
            for item in app.context(str(state.case_id), state=state)
            if item.probe_id == "network.snapshot"
        )
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert (
            store.connection.execute(
                "SELECT status FROM deep_mailbox WHERE case_id=?", (str(state.case_id),)
            ).fetchone()[0]
            == "applied"
        )
        persisted = app.repository.load(str(state.case_id))
        assert persisted is not None
        current = next(
            item for item in persisted.hypotheses if item.hypothesis_id == "security_block"
        )
        assert current.statement == security.statement
        assert current.status is HypothesisStatus.UNRESOLVED
        assert current.supporting_evidence_ids == ()
        assert current.distinguishing_probe_ids == security.distinguishing_probe_ids
        assert current.missing_evidence_ids == ((observed_id,) if retained else ())
        assert app.repository.steps(str(state.case_id))[-1].hypotheses == persisted.hypotheses


def test_synchronous_reasoning_does_not_advertise_or_accept_retirement(
    tmp_path: Path,
) -> None:
    class UnsolicitedIntent:
        identity = ProviderIdentity(
            provider_id="scripted-sync", provider_version="1", role="reasoning"
        )
        seen_schema: int | None = None

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.seen_schema = request.schema_version
            assert request.prior_hypothesis_revision_refs == ()
            prior = request.previous_hypotheses[0]
            return ReasoningResponse(
                schema_version=4,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Unsolicited retirement.",
                hypotheses=(
                    prior.model_copy(
                        update={
                            "statement": "A different explanation without old support.",
                            "supporting_evidence_ids": (),
                        }
                    ),
                ),
                hypothesis_revision_intents=(
                    HypothesisRevisionIntentV1(
                        hypothesis_id=prior.hypothesis_id,
                        prior_hypothesis_sha256=hypothesis_revision_sha256(prior),
                        retired_supporting_evidence_ids=prior.supporting_evidence_ids,
                    ),
                ),
                presented_prior_hypothesis_ids=(prior.hypothesis_id,),
            )

    provider = UnsolicitedIntent()
    with SQLiteStore(tmp_path / "sync-revision.db") as store:
        app = investigator(store, reasoning=provider)
        state = app.create(objective="Memory concern", budget_ms=20_000, max_probes=2)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        context = app.context(str(state.case_id), state=state)
        old_id = next(item.evidence_id for item in context if item.facts)
        old = Hypothesis(
            hypothesis_id="memory_pressure",
            statement="An older reading raises a concern.",
            status=HypothesisStatus.UNRESOLVED,
            supporting_evidence_ids=(old_id,),
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"hypotheses": (old,)}),
            "fixture_prior",
            "Old advisory",
        )
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert provider.seen_schema == 6
        assert updated.hypotheses == (old,)
        assert any("synchronous_revision_intent_unavailable" in item for item in updated.warnings)
        assert all(
            not step.hypothesis_revision_links for step in app.repository.steps(str(state.case_id))
        )


def test_oversized_deep_admission_does_not_block_selected_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "deep-admission-limit.db") as store:
        app = investigator(store)
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=5000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )

        def reject_oversized(_task: object) -> bool:
            raise ValueError("deep mailbox request exceeds byte bound")

        monkeypatch.setattr(app._deep_mailbox, "admit", reject_oversized)  # pyright: ignore[reportPrivateUsage]
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state,
            app.context(str(state.case_id), state=state),
            concurrent_proposals=(_proposal("network.snapshot"),),
        )
        assert "network.snapshot" in updated.completed_probe_ids
        assert any("Deep request could not be admitted" in item for item in updated.warnings)
        assert not app._deep_lane.occupied  # pyright: ignore[reportPrivateUsage]


def test_adaptive_deep_clears_an_exact_considered_evidence_request(tmp_path: Path) -> None:
    class ConsideringDeep:
        identity = ProviderIdentity(
            provider_id="considering-deep", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            considered = tuple(item.evidence_id for item in request.evidence_context if item.facts)[
                :1
            ]
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The requested observation was considered; cause remains uncertain.",
                considered_evidence_ids=considered,
            )

    with SQLiteStore(tmp_path / "deep-request-lifecycle.db") as store:
        app = investigator(store, reasoning=ConsideringDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=5000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        context = app.context(str(state.case_id), state=state)
        requested = next(item.evidence_id for item in context if item.facts)
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"requested_evidence_ids": (requested,)}),
            "request_test",
            "An exact current-case observation was requested.",
        )

        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state,
            context,
            concurrent_proposals=(_proposal("network.snapshot"),),
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        updated = app._drain_deep(updated)  # pyright: ignore[reportPrivateUsage]
        assert updated.reasoning_provider == "considering-deep"
        assert requested not in updated.requested_evidence_ids
        assert requested in updated.completed_evidence_requests


def test_adaptive_deep_advances_only_its_frozen_catalog_page(tmp_path: Path) -> None:
    class PagingDeep:
        identity = ProviderIdentity(
            provider_id="paging-deep", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            assert request.catalog_has_more
            assert len(request.evidence_catalog) == 1
            return ReasoningResponse(
                schema_version=3,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Next catalog page is needed.",
                request_next_catalog_page=True,
            )

    with SQLiteStore(tmp_path / "deep-catalog-page.db") as store:
        app = investigator(store, reasoning=PagingDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=5000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"), _proposal("network.snapshot")), None, baseline=True
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"evidence_catalog_limit": 1}),
            "catalog_test",
            "Constrain the frozen catalog page to one entry.",
        )
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        updated = app._drain_deep(updated)  # pyright: ignore[reportPrivateUsage]
        assert updated.evidence_catalog_cursor is not None, updated.warnings
        assert updated.evidence_catalog_followup_pending


@pytest.mark.parametrize("degraded", [False, True])
def test_persisted_collection_unblocks_deep_without_promoting_old_hypothesis(
    tmp_path: Path,
    degraded: bool,
) -> None:
    database = tmp_path / "independent.db"
    started = threading.Event()
    collection_overlapped = threading.Event()
    base = probe_definition("network")

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert started.wait(1), "deep inference must start before selected collection"
        collection_overlapped.set()
        assert base.handler is not None
        return base.handler(parameters)

    class DelayedDeep:
        identity = ProviderIdentity(provider_id="delayed", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            started.set()
            deadline = time.monotonic() + 2
            persisted = False
            with SQLiteStore(database) as reader:
                while time.monotonic() < deadline:
                    row = reader.connection.execute(
                        "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id=?",
                        (str(request.case_id), "network.snapshot"),
                    ).fetchone()
                    if row and int(row[0]) > 0:
                        persisted = True
                        break
                    time.sleep(0.005)
            assert persisted, "deep inference blocked unrelated evidence persistence"
            return ReasoningResponse(
                schema_version=3,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.SUPPORTED,
                summary="An old proposed explanation.",
                degraded=degraded,
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="old",
                        statement="Old snapshot suggests a device issue.",
                        status=HypothesisStatus.SUPPORTED,
                        supporting_evidence_ids=(request.evidence_context[0].evidence_id,),
                    ),
                ),
                distinguishing_probes=(_proposal("devices.snapshot"),),
            )

    with SQLiteStore(database) as store:
        app = investigator(
            store,
            reasoning=DelayedDeep(),
            definitions=(
                probe_definition("core"),
                replace(base, handler=collect),
                probe_definition("devices"),
            ),
        )
        state = app.create(objective="application device issue", budget_ms=4000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        context = app.context(str(state.case_id), state=state)
        updated, proposals = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, context, concurrent_proposals=(_proposal("network.snapshot"),)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        updated = app._drain_deep(updated)  # pyright: ignore[reportPrivateUsage]
        proposals = updated.pending_distinguishing_probes
        assert collection_overlapped.is_set()
        assert "network.snapshot" in updated.completed_probe_ids
        assert all(h.status is HypothesisStatus.UNRESOLVED for h in updated.hypotheses)
        assert updated.assessment is None, "model assertions cannot become verified findings"
        assert tuple(item.probe_id for item in proposals) == (
            () if degraded else ("devices.snapshot",)
        )
        if not degraded:
            assert any("historical" in warning.lower() for warning in updated.warnings)
            assert updated.summary_source == "advisory_async"
            assert updated.summary_reviewed_evidence_generation is not None
            current_generation = (
                EvidenceRetriever(store)
                .discover(EvidenceCatalogQuery(case_id=updated.case_id, limit=1))
                .case_evidence_generation
            )
            assert updated.summary_reviewed_evidence_generation < current_generation


def test_late_collected_fact_gets_one_fresh_deep_request(tmp_path: Path) -> None:
    """A finished deep request cannot stand in for a fact collected afterward."""

    database = tmp_path / "late-fact-review.db"
    requests: list[ReasoningRequest] = []

    class ReviewingDeep:
        identity = ProviderIdentity(provider_id="reviewing", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            if len(requests) == 1:
                deadline = time.monotonic() + 2
                with SQLiteStore(database) as reader:
                    while time.monotonic() < deadline:
                        row = reader.connection.execute(
                            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id=?",
                            (str(request.case_id), "network.snapshot"),
                        ).fetchone()
                        if row and int(row[0]) > 0:
                            break
                        time.sleep(0.005)
                    else:
                        raise AssertionError("collection did not overlap the first deep request")
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The cause remains unknown after selected evidence review.",
            )

    with SQLiteStore(database) as store:
        app = investigator(store, reasoning=ReviewingDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=5000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state,
            app.context(str(state.case_id), state=state),
            concurrent_proposals=(_proposal("network.snapshot"),),
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert len(requests) == 1
        first_reviewed_generation = state.summary_reviewed_evidence_generation
        first_summary = state.summary
        assert state.summary_source == "advisory_async"
        assert first_reviewed_generation is not None
        current_generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        assert first_reviewed_generation < current_generation
        state, started = app._refresh_deep_after_late_evidence(state)  # pyright: ignore[reportPrivateUsage]
        assert started
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert len(requests) == 2
        assert state.summary_reviewed_evidence_generation == current_generation
        assert state.summary == first_summary
        assert any(item.probe_id == "network.snapshot" for item in requests[1].evidence_context)
        _, started_again = app._refresh_deep_after_late_evidence(state)  # pyright: ignore[reportPrivateUsage]
        assert not started_again, "an unchanged evidence generation must not trigger another call"
        assert state.assessment is None


@pytest.mark.parametrize("degraded", (False, True))
def test_exhausted_probe_budget_reviews_later_fact_without_dispatch(
    tmp_path: Path, degraded: bool
) -> None:
    """Probe capacity must not make an earlier deep answer the final review."""

    database = tmp_path / "final-late-review.db"
    requests: list[ReasoningRequest] = []

    class ReviewingDeep:
        identity = ProviderIdentity(
            provider_id="final-review", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary=f"Reviewed evidence generation {len(request.evidence_context)}.",
                degraded=degraded and len(requests) == 2,
                distinguishing_probes=(
                    (_proposal("devices.snapshot"),) if len(requests) == 2 else ()
                ),
            )

    with SQLiteStore(database) as store:
        app = investigator(store, reasoning=ReviewingDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=10_000, max_probes=2)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state,
            app.context(str(state.case_id), state=state),
            concurrent_proposals=(_proposal("network.snapshot"),),
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert len(requests) == 1
        prior_reviewed_generation = state.summary_reviewed_evidence_generation
        assert prior_reviewed_generation is not None
        assert not any(item.probe_id == "network.snapshot" for item in requests[0].evidence_context)

        final = app._finish_probe_budget(state, None)  # pyright: ignore[reportPrivateUsage]

        assert len(requests) == 2
        assert any(item.probe_id == "network.snapshot" for item in requests[1].evidence_context)
        if degraded:
            assert "Reviewed evidence generation 2" not in final.summary
            assert any("Deep advice was unavailable or rejected" in w for w in final.warnings)
            assert final.summary_reviewed_evidence_generation == prior_reviewed_generation
        else:
            assert "Reviewed evidence generation 2" in final.summary
        assert final.stop_reason is not None
        assert "collected evidence was assessed" not in final.stop_reason
        assert "devices.snapshot" not in final.pending_probe_ids
        assert "devices.snapshot" not in {p.probe_id for p in final.pending_distinguishing_probes}
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=?",
                (str(state.case_id),),
            ).fetchone()[0]
            == 2
        )


def test_exhausted_probe_budget_does_not_repeat_unchanged_deep_basis(tmp_path: Path) -> None:
    requests: list[ReasoningRequest] = []

    class ReviewingDeep:
        identity = ProviderIdentity(
            provider_id="single-review", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Reviewed the only observation.",
            )

    with SQLiteStore(tmp_path / "final-unchanged.db") as store:
        app = investigator(store, reasoning=ReviewingDeep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=10_000, max_probes=1)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )

        final = app._finish_probe_budget(state, None)  # pyright: ignore[reportPrivateUsage]

        assert len(requests) == 1
        assert "Reviewed the only observation" in final.summary
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=?",
                (str(state.case_id),),
            ).fetchone()[0]
            == 1
        )


def test_adaptive_run_starts_deep_before_selected_collection(tmp_path: Path) -> None:
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    started = threading.Event()
    overlapped = threading.Event()
    base = probe_definition("network")

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        if started.wait(0.3):
            overlapped.set()
        assert base.handler is not None
        return base.handler(parameters)

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            started.set()
            overlapped.wait(0.4)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Insufficient evidence.",
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=()
                if "network.snapshot" in request.completed_probe_ids
                else (_proposal("network.snapshot"),),
            )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "run.db") as store:
        app = investigator(
            store,
            definitions=(core, replace(base, handler=collect)),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        case = app.create(objective="network issue", budget_ms=3000)
        result = app.run(str(case.case_id))
        assert overlapped.is_set(), "default adaptive run still waited for collection before deep"
        assert "network.snapshot" in result.completed_probe_ids


@pytest.mark.parametrize("collection_mode", ("observed", "unsupported", "failed"))
@pytest.mark.parametrize(
    ("max_rounds", "max_probes", "next_probe"),
    ((4, 2, False), (1, 3, False), (4, 3, True), (1, 3, True)),
)
def test_just_accepted_deep_check_gets_reviewed_after_its_result(
    tmp_path: Path,
    collection_mode: str,
    max_rounds: int,
    max_probes: int,
    next_probe: bool,
) -> None:
    """A selected deep-origin check must not spend a review on pre-result context."""
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    requests: list[ReasoningRequest] = []

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            if len(requests) == 2 and max_rounds == 1:
                time.sleep(0.15)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The observed result still requires scoped interpretation.",
                distinguishing_probes=(_proposal("network.snapshot"),)
                if len(requests) == 1
                else (
                    (_proposal("devices.snapshot"),) if len(requests) == 2 and next_probe else ()
                ),
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))

    def unavailable_collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        if collection_mode == "failed":
            raise RuntimeError("synthetic collector failure")
        now = datetime.now(UTC)
        return ProbeObservation(
            summary="Registered network check unavailable",
            facts={"collection_status": "unsupported"},
            observed_at=now,
            captured_at=now,
        )

    network = probe_definition("network")
    if collection_mode != "observed":
        network = replace(network, handler=unavailable_collect)
    with SQLiteStore(tmp_path / "deep-check-coalescing.db") as store:
        app = investigator(
            store,
            definitions=(core, network, probe_definition("devices")),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        case = app.create(
            objective="network issue",
            budget_ms=5_000,
            max_probes=max_probes,
            max_rounds=max_rounds,
        )
        result = app.run(str(case.case_id))
        assert "network.snapshot" in result.completed_probe_ids
        if max_rounds == 1:
            assert result.round_count - result.run_start_round == max_rounds
        assert len(requests) >= 2
        if next_probe and max_rounds > 1:
            assert "devices.snapshot" in result.completed_probe_ids
        elif next_probe:
            assert "devices.snapshot" not in result.completed_probe_ids
            assert any(
                item.probe_id == "devices.snapshot" for item in result.pending_distinguishing_probes
            )
            assert result.outcome.value == "budget_exhausted"
        else:
            assert len(requests) == 2
        assert all(item.probe_id != "network.snapshot" for item in requests[0].evidence_context)
        linked = store.connection.execute(
            "SELECT COUNT(*) FROM deep_proposal_execution_links WHERE case_id=? "
            "AND probe_id='network.snapshot'",
            (str(case.case_id),),
        ).fetchone()
        assert linked == ((0,) if collection_mode == "failed" else (1,))
        if collection_mode == "failed":
            assert store.connection.execute(
                "SELECT status FROM probe_executions WHERE case_id=? "
                "AND probe_id='network.snapshot'",
                (str(case.case_id),),
            ).fetchone() == ("failed",)
            failed_id = store.connection.execute(
                "SELECT e.evidence_id FROM evidence AS e "
                "JOIN probe_executions AS x ON x.execution_id=e.execution_id "
                "WHERE x.case_id=? AND x.probe_id='network.snapshot'",
                (str(case.case_id),),
            ).fetchone()[0]
            assert any(
                str(item.evidence_id) == failed_id
                and item.status.value == "failed"
                and item.summary
                for item in requests[1].evidence_context
            )
        assert requests[1].state_version > requests[0].state_version
        if collection_mode != "failed":
            assert any(item.probe_id == "network.snapshot" for item in requests[1].evidence_context)
        if collection_mode == "unsupported":
            assert any(
                item.probe_id == "network.snapshot"
                and item.facts.get("collection_status") == "unsupported"
                for item in requests[1].evidence_context
            )
        assert result.summary_reviewed_evidence_generation is not None
        assert result.summary_reviewed_evidence_generation == (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=case.case_id, limit=1))
            .case_evidence_generation
        )


@pytest.mark.parametrize(
    ("saturated_context", "late_focus_delivery", "queued_old_event", "post_noop_change"),
    (
        (False, False, False, "none"),
        (True, False, False, "none"),
        (True, True, False, "none"),
        (False, False, True, "none"),
        (False, False, True, "rejected"),
        (False, False, True, "fresh"),
        (True, False, True, "focus"),
        (False, False, True, "fast"),
    ),
)
def test_completed_terminal_review_is_not_restarted_at_idle_boundary(
    tmp_path: Path,
    saturated_context: bool,
    late_focus_delivery: bool,
    queued_old_event: bool,
    post_noop_change: str,
) -> None:
    """An already-reviewed chosen result needs no third same-state deep request."""
    from systemsense.decision.contracts import (
        DecisionRequest,
        DecisionResponse,
        FastSignal,
        FastSignalKind,
    )

    requests: list[ReasoningRequest] = []
    terminal_review_completed = threading.Event()
    delivered_focus = threading.Event()
    queued_event_id: str | None = None
    post_noop_injected = False

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            network_evidence = tuple(
                item.evidence_id
                for item in request.evidence_context
                if item.probe_id == "network.snapshot"
            )
            response = ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The chosen check has been reviewed; the cause remains unknown.",
                degraded=post_noop_change == "rejected" and len(requests) == 2,
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="unknown_cause",
                        statement="The registered network result leaves the cause unknown.",
                        status=HypothesisStatus.UNRESOLVED,
                        supporting_evidence_ids=network_evidence,
                    ),
                )
                if len(requests) == 2
                else (),
                distinguishing_probes=(_proposal("network.snapshot"),)
                if len(requests) == 1
                else (),
            )
            if len(requests) == 2:
                terminal_review_completed.set()
            return response

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            nonlocal post_noop_injected
            if "network.snapshot" in request.completed_probe_ids:
                assert terminal_review_completed.wait(1.5)
                if queued_event_id is not None and not post_noop_injected:
                    frontier = SearchFrontierRepository(store)
                    turns = frontier.investigator_turns(request.case_id, queued_event_id)
                    outcome = (
                        frontier.read_investigator_turn_outcome(turns[-1].turn_id)
                        if turns
                        else None
                    )
                    if outcome is not None and outcome.outcome == "no_new_fact":
                        post_noop_injected = True
                        if post_noop_change == "focus":
                            current = app.repository.load(str(request.case_id))
                            current_context = app.context(str(request.case_id), state=current)
                            shown_ids = {
                                str(item.evidence_id) for item in requests[1].evidence_context
                            }
                            omitted = sorted(
                                str(item.evidence_id)
                                for item in current_context
                                if str(item.evidence_id) not in shown_ids
                            )
                            assert omitted
                            selected_old = EvidenceId(root=omitted[0])
                            generation = (
                                EvidenceRetriever(store)
                                .discover(EvidenceCatalogQuery(case_id=request.case_id, limit=1))
                                .case_evidence_generation
                            )
                            versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
                            item = frontier.upsert_item(
                                request.case_id,
                                FrontierReferenceV1(
                                    kind="retrieve_evidence", evidence_id=selected_old
                                ),
                                versions,
                            )
                            frontier.claim_ready(item.item_id, versions)
                            frontier.transition(
                                item.item_id,
                                FrontierStatus.CLAIMED,
                                FrontierStatus.ADMITTED,
                                "retrieving",
                            )
                            frontier.transition(
                                item.item_id,
                                FrontierStatus.ADMITTED,
                                FrontierStatus.RUNNING,
                                "retrieving",
                            )
                            with store.transaction():
                                frontier.commit_focus_delivery_in_transaction(
                                    item.item_id,
                                    request.case_id,
                                    selected_old,
                                    epoch_state_version=current.state_version,
                                    evidence_generation=generation,
                                )
                            delivered_focus.set()
                        elif post_noop_change == "fast":
                            return DecisionResponse(
                                provider=self.identity,
                                case_id=request.case_id,
                                state_version=request.state_version,
                                correlation_id=request.correlation_id,
                                deadline_at=request.deadline_at,
                                requires_reasoning=True,
                                signals=(FastSignal(kind=FastSignalKind.COVERAGE_GAP),),
                            )
                if late_focus_delivery and not delivered_focus.is_set():
                    current = app.repository.load(str(request.case_id))
                    current_context = app.context(str(request.case_id), state=current)
                    shown_ids = {str(item.evidence_id) for item in requests[1].evidence_context}
                    omitted = sorted(
                        str(item.evidence_id)
                        for item in current_context
                        if str(item.evidence_id) not in shown_ids
                    )
                    assert omitted
                    selected_old = EvidenceId(root=omitted[0])
                    generation = (
                        EvidenceRetriever(store)
                        .discover(EvidenceCatalogQuery(case_id=request.case_id, limit=1))
                        .case_evidence_generation
                    )
                    frontier = SearchFrontierRepository(store)
                    versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
                    item = frontier.upsert_item(
                        request.case_id,
                        FrontierReferenceV1(kind="retrieve_evidence", evidence_id=selected_old),
                        versions,
                    )
                    frontier.claim_ready(item.item_id, versions)
                    frontier.transition(
                        item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "retrieving"
                    )
                    frontier.transition(
                        item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
                    )
                    with store.transaction():
                        frontier.commit_focus_delivery_in_transaction(
                            item.item_id,
                            request.case_id,
                            selected_old,
                            epoch_state_version=current.state_version,
                            evidence_generation=generation,
                        )
                    delivered_focus.set()
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "idle-terminal-review.db") as store:
        app = investigator(
            store,
            definitions=(core, probe_definition("network")),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        if queued_old_event:
            app.knowledge = ReferenceKnowledgeGraph.load_default()
            settle = app._settle_coalesced_idle  # pyright: ignore[reportPrivateUsage]

            def settle_then_queue_seen_event(
                state: InvestigationState, *, batch_limit: int | None = None
            ) -> tuple[InvestigationState, bool]:
                nonlocal queued_event_id
                settled = settle(state, batch_limit=batch_limit)
                if queued_event_id is None and terminal_review_completed.is_set():
                    source = store.connection.execute(
                        "SELECT e.evidence_id,x.execution_id FROM evidence AS e "
                        "JOIN probe_executions AS x ON x.execution_id=e.execution_id "
                        "WHERE e.case_id=? AND x.probe_id='network.snapshot'",
                        (str(state.case_id),),
                    ).fetchone()
                    assert source is not None
                    frontier = SearchFrontierRepository(store)
                    event_row = store.connection.execute(
                        "SELECT event_id FROM search_frontier_events "
                        "WHERE case_id=? AND source_evidence_id=?",
                        (str(state.case_id), str(source[0])),
                    ).fetchone()
                    assert event_row is not None
                    existing = frontier.read_event(str(event_row[0]))
                    with store.transaction():
                        event = frontier.append_result_event(
                            state.case_id,
                            source_evidence_id=EvidenceId(root=str(source[0])),
                            source_execution_id=None,
                            versions=existing.versions,
                        )
                    assert isinstance(event, FrontierEventV1)
                    assert event.event_id != existing.event_id
                    frontier.intake_investigator_event(state.case_id, event.event_id)
                    queued_event_id = event.event_id
                    if post_noop_change == "fresh":
                        _persist_evidence(
                            store,
                            case_id=state.case_id,
                            facts={"new_after_noop": True},
                            captured_at=datetime.now(UTC),
                            sequence=201,
                        )
                return settled

            app._settle_coalesced_idle = settle_then_queue_seen_event  # type: ignore[method-assign]  # pyright: ignore[reportAttributeAccessIssue]
        case = app.create(objective="network issue", budget_ms=5_000, max_probes=3)
        if saturated_context:
            for sequence in range(100, 116):
                _persist_evidence(
                    store,
                    case_id=case.case_id,
                    facts={"sequence": sequence},
                    captured_at=datetime.now(UTC),
                    sequence=sequence,
                )
        result = app.run(str(case.case_id))

        assert "network.snapshot" in result.completed_probe_ids
        expect_third = late_focus_delivery or post_noop_change in {"fresh", "focus", "fast"}
        assert len(requests) == (3 if expect_third else 2)
        assert any(item.probe_id == "network.snapshot" for item in requests[1].evidence_context)
        if post_noop_change == "fresh":
            assert requests[2].state_version > requests[1].state_version
            assert any(
                item.facts.get("new_after_noop") is True for item in requests[2].evidence_context
            )
        elif post_noop_change == "focus":
            assert delivered_focus.is_set()
            assert set(requests[2].priority_evidence_ids) - set(requests[1].priority_evidence_ids)
        elif post_noop_change == "fast":
            assert any(
                item.kind == FastSignalKind.COVERAGE_GAP.value for item in requests[2].fast_concerns
            )
            assert any(
                step.event == "fast_escalation" for step in app.repository.steps(str(case.case_id))
            )
        elif post_noop_change == "rejected":
            assert not any(item.hypothesis_id == "unknown_cause" for item in result.hypotheses)
            rows = store.connection.execute(
                "SELECT status,request_sha256 FROM deep_mailbox WHERE case_id=? ORDER BY rowid",
                (str(case.case_id),),
            ).fetchall()
            assert len(rows) == 2
            assert rows[1][0] == "rejected" and len(str(rows[1][1])) == 64
        assert delivered_focus.is_set() == (late_focus_delivery or post_noop_change == "focus")
        if queued_old_event:
            assert queued_event_id is not None
            frontier = SearchFrontierRepository(store)
            turns = frontier.investigator_turns(case.case_id, queued_event_id)
            assert turns
            outcome = frontier.read_investigator_turn_outcome(turns[-1].turn_id)
            assert outcome is not None and outcome.outcome == "no_new_fact"
            assert post_noop_injected
        if saturated_context:
            shown_ids = {str(item.evidence_id) for item in requests[1].evidence_context}
            current_context = app.context(str(case.case_id), state=result)
            current_ids = {str(item.evidence_id) for item in current_context}
            assert current_ids - shown_ids, "the focused packet should omit older unrelated rows"
            latest = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
            assert latest is not None
            if not delivered_focus.is_set():
                assert not app._later_focus_delivery_needs_review(  # pyright: ignore[reportPrivateUsage]
                    result, latest, current_context
                )
                absent_mailbox = latest.model_copy(update={"request_sha256": "0" * 64})
                assert not app._later_focus_delivery_needs_review(  # pyright: ignore[reportPrivateUsage]
                    result, absent_mailbox, current_context
                )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM deep_mailbox WHERE case_id=?", (str(case.case_id),)
        ).fetchone() == (3 if expect_third else 2,)


@pytest.mark.parametrize("collection_mode", ("observed", "changed", "failed"))
def test_collecting_epoch_review_of_every_terminal_fact_needs_no_reconsult(
    tmp_path: Path,
    collection_mode: str,
) -> None:
    """A fast consult sees final rows only while their frozen content remains current."""
    from systemsense.application.investigator import (
        _CoalescedTerminalReview,  # pyright: ignore[reportPrivateUsage]
    )
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    requests: list[ReasoningRequest] = []

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            network_ids = tuple(
                item.evidence_id
                for item in request.evidence_context
                if item.probe_id == "network.snapshot"
            )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The registered result was reviewed; the cause remains unknown.",
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="unknown_cause",
                        statement="The registered result leaves the cause unknown.",
                        status=HypothesisStatus.UNRESOLVED,
                        supporting_evidence_ids=network_ids,
                    ),
                )
                if len(requests) == 2
                else (),
                distinguishing_probes=(
                    _proposal("network.snapshot"),
                    _proposal("devices.snapshot"),
                )
                if len(requests) == 1
                else (),
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))

    def failed_collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        raise RuntimeError("synthetic collector failure")

    network = probe_definition("network")
    devices = probe_definition("devices")
    if collection_mode == "failed":
        devices = replace(devices, handler=failed_collect)
    with SQLiteStore(tmp_path / "collecting-epoch-reviewed.db") as store:
        app = investigator(
            store,
            definitions=(core, network, devices),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        save = app._save  # pyright: ignore[reportPrivateUsage]
        during_collection = False

        def save_after_fast_review(
            state: InvestigationState, event: str, detail: str
        ) -> InvestigationState:
            nonlocal during_collection
            if event == "collected" and "network.snapshot" in state.completed_probe_ids:
                assert not during_collection
                assert len(requests) == 1
                during_collection = True
                app._defer_reasoning_checkpoint = True  # pyright: ignore[reportPrivateUsage]
                try:
                    app._reason(  # pyright: ignore[reportPrivateUsage]
                        state, app.context(str(state.case_id), state=state)
                    )
                finally:
                    app._defer_reasoning_checkpoint = False  # pyright: ignore[reportPrivateUsage]
                if collection_mode == "changed":
                    row = store.connection.execute(
                        "SELECT e.evidence_id,e.record_json FROM evidence AS e "
                        "JOIN probe_executions AS x ON x.execution_id=e.execution_id "
                        "WHERE e.case_id=? AND x.probe_id='network.snapshot'",
                        (str(state.case_id),),
                    ).fetchone()
                    assert row is not None
                    record = EvidenceRecord.model_validate_json(str(row[1]))
                    changed = record.model_copy(update={"summary": record.summary + " corrected"})
                    with store.transaction():
                        store.connection.execute(
                            "UPDATE evidence SET record_json=? WHERE evidence_id=? AND case_id=?",
                            (changed.model_dump_json(), str(row[0]), str(state.case_id)),
                        )
            return save(state, event, detail)

        app._save = save_after_fast_review  # type: ignore[method-assign]  # pyright: ignore[reportAttributeAccessIssue]
        case = app.create(objective="network issue", budget_ms=5_000, max_probes=3)
        result = app.run(str(case.case_id))
        assert during_collection
        assert "network.snapshot" in result.completed_probe_ids
        assert len(requests) == (2 if collection_mode == "observed" else 3)
        terminal = next(
            item for item in requests[1].evidence_context if item.probe_id == "network.snapshot"
        )
        assert terminal.facts
        if collection_mode == "failed":
            failed = next(
                item for item in requests[1].evidence_context if item.probe_id == "devices.coverage"
            )
            assert failed.status.value == "failed"
        assert requests[1].state_version < next(
            step.state_version
            for step in app.repository.steps(str(case.case_id))
            if step.event == "collected" and step.state_version > requests[0].state_version
        )
        if collection_mode == "observed":
            latest = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
            assert latest is not None
            rows = tuple(
                store.connection.execute(
                    "SELECT x.execution_id,e.evidence_id FROM probe_executions AS x "
                    "LEFT JOIN evidence AS e ON e.case_id=x.case_id "
                    "AND e.execution_id=x.execution_id WHERE x.case_id=? "
                    "AND x.probe_id IN ('network.snapshot','devices.snapshot')",
                    (str(case.case_id),),
                )
            )
            assert len(rows) == 2
            target = _CoalescedTerminalReview(
                case_id=case.case_id,
                state_version=next(
                    step.state_version
                    for step in app.repository.steps(str(case.case_id))
                    if step.event == "collected" and step.state_version > requests[0].state_version
                ),
                execution_ids=frozenset(str(row[0]) for row in rows),
                evidence_ids=frozenset(str(row[1]) for row in rows),
            )
            assert app._precheckpoint_deep_covers_terminal_results(  # pyright: ignore[reportPrivateUsage]
                target, latest
            )
            omitted_id = str(rows[0][1])
            omitted_context = latest.request.model_copy(
                update={
                    "evidence_context": tuple(
                        item
                        for item in latest.request.evidence_context
                        if str(item.evidence_id) != omitted_id
                    )
                }
            )
            assert not app._precheckpoint_deep_covers_terminal_results(  # pyright: ignore[reportPrivateUsage]
                target, latest.model_copy(update={"request": omitted_context})
            )
            omitted_read_set = latest.presented_read_set.model_copy(
                update={
                    "entries": tuple(
                        item
                        for item in latest.presented_read_set.entries
                        if str(item.evidence_id) != omitted_id
                    )
                }
            )
            assert not app._precheckpoint_deep_covers_terminal_results(  # pyright: ignore[reportPrivateUsage]
                target, latest.model_copy(update={"presented_read_set": omitted_read_set})
            )
            missing_execution = replace(
                target, execution_ids=target.execution_ids | {"exec_" + "0" * 32}
            )
            assert not app._precheckpoint_deep_covers_terminal_results(  # pyright: ignore[reportPrivateUsage]
                missing_execution, latest
            )
            with store.transaction():
                store.connection.execute(
                    "DELETE FROM evidence WHERE evidence_id=? AND case_id=?",
                    (omitted_id, str(case.case_id)),
                )
            assert not app._precheckpoint_deep_covers_terminal_results(  # pyright: ignore[reportPrivateUsage]
                target, latest
            )


def test_accepted_costly_check_precedes_its_next_deep_review(tmp_path: Path) -> None:
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    second_started = threading.Event()
    overlapped = threading.Event()
    collected = threading.Event()
    requests: list[ReasoningRequest] = []

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            requests.append(request)
            if self.calls == 2:
                second_started.set()
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The cause is not established.",
                distinguishing_probes=(
                    _proposal("network.snapshot").model_copy(update={"estimated_cost_ms": 1_000}),
                )
                if self.calls == 1
                else (),
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    base = probe_definition("network")

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        if second_started.is_set():
            overlapped.set()
        assert base.handler is not None
        observation = base.handler(parameters)
        collected.set()
        return observation

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "slow-deep-check.db") as store:
        app = investigator(
            store,
            definitions=(core, replace(base, handler=collect)),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        app.capabilities = tuple(
            item.model_copy(update={"cost_ms": 1_000})
            if item.probe_id == "network.snapshot"
            else item
            for item in app.capabilities
        )
        case = app.create(objective="network issue", budget_ms=5_000, max_probes=2)
        result = app.run(str(case.case_id))
        assert collected.is_set()
        assert not overlapped.is_set()
        assert len(requests) == 2
        assert all(item.probe_id != "network.snapshot" for item in requests[0].evidence_context)
        assert any(item.probe_id == "network.snapshot" for item in requests[1].evidence_context)
        assert "network.snapshot" in result.completed_probe_ids


def test_terminal_batch_review_requires_exact_focused_result(tmp_path: Path) -> None:
    """A later request at the right generation may still omit the chosen result."""
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    requests: list[ReasoningRequest] = []

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The result requires a scoped review.",
                distinguishing_probes=(_proposal("network.snapshot"),)
                if len(requests) == 1
                else (),
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "focused-omission.db") as store:
        app = investigator(
            store,
            definitions=(core, probe_definition("network")),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        original_collect = app._collect  # pyright: ignore[reportPrivateUsage]

        def collect_with_unrelated_review(
            state: InvestigationState,
            proposals: tuple[ProbeProposal, ...],
            cancel_event: threading.Event | None,
            *,
            baseline: bool = False,
            decision_snapshot_id: str | None = None,
            adaptive_followups: bool = False,
        ) -> InvestigationState:
            collected = original_collect(
                state,
                proposals,
                cancel_event,
                baseline=baseline,
                decision_snapshot_id=decision_snapshot_id,
                adaptive_followups=adaptive_followups,
            )
            if any(item.probe_id == "network.snapshot" for item in proposals):
                core_only = tuple(
                    item
                    for item in app.context(str(collected.case_id), state=collected)
                    if item.probe_id == "core.system"
                )
                collected, _ = app._reason_with_details(  # pyright: ignore[reportPrivateUsage]
                    collected, core_only
                )
            return collected

        app._collect = collect_with_unrelated_review  # type: ignore[method-assign]  # pyright: ignore[reportAttributeAccessIssue]
        case = app.create(objective="network issue", budget_ms=5_000, max_probes=2)
        result = app.run(str(case.case_id))
        assert "network.snapshot" in result.completed_probe_ids
        assert len(requests) == 3
        assert requests[1].state_version >= requests[0].state_version
        assert all(item.probe_id != "network.snapshot" for item in requests[1].evidence_context)
        assert any(item.probe_id == "network.snapshot" for item in requests[2].evidence_context)


def test_partial_coalesced_batch_fast_deep_still_reviews_later_unavailable(
    tmp_path: Path,
) -> None:
    """A fast consult during one result cannot stand in for a later batch result."""
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    requests: list[ReasoningRequest] = []
    fast_review_started = threading.Event()
    later_collector_finished = threading.Event()

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            if len(requests) == 2:
                fast_review_started.set()
                later_collector_finished.wait(1.5)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The scoped cause remains unresolved.",
                distinguishing_probes=(
                    _proposal("network.snapshot"),
                    _proposal("devices.snapshot"),
                )
                if len(requests) == 1
                else (),
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    def unavailable_collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert fast_review_started.wait(1.5)
        now = datetime.now(UTC)
        later_collector_finished.set()
        return ProbeObservation(
            summary="Registered device check unavailable",
            facts={"collection_status": "unsupported"},
            observed_at=now,
            captured_at=now,
        )

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    devices = replace(probe_definition("devices"), handler=unavailable_collect)
    with SQLiteStore(tmp_path / "partial-coalesced.db") as store:
        app = investigator(
            store,
            definitions=(core, probe_definition("network"), devices),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        ordinary_collect = app._collect  # pyright: ignore[reportPrivateUsage]

        def collect_with_early_fast_review(
            state: InvestigationState,
            proposals: tuple[ProbeProposal, ...],
            cancel_event: threading.Event | None,
            *,
            baseline: bool = False,
            decision_snapshot_id: str | None = None,
            adaptive_followups: bool = False,
        ) -> InvestigationState:
            if any(item.probe_id == "network.snapshot" for item in proposals):
                # Simulate the existing fast frontier's early consult callback
                # while the selected batch is still open. The real registered
                # collectors and deep mailbox still execute below.
                before = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
                app._defer_reasoning_checkpoint = True  # pyright: ignore[reportPrivateUsage]
                try:
                    app._reason(  # pyright: ignore[reportPrivateUsage]
                        state, app.context(str(state.case_id), state=state)
                    )
                finally:
                    app._defer_reasoning_checkpoint = False  # pyright: ignore[reportPrivateUsage]
                assert app._last_deep_admission is not before  # pyright: ignore[reportPrivateUsage]
            return ordinary_collect(
                state,
                proposals,
                cancel_event,
                baseline=baseline,
                decision_snapshot_id=decision_snapshot_id,
                adaptive_followups=adaptive_followups,
            )

        app._collect = collect_with_early_fast_review  # type: ignore[method-assign]  # pyright: ignore[reportAttributeAccessIssue]
        case = app.create(
            objective="network and device issue", budget_ms=5_000, max_probes=3, max_rounds=1
        )
        result = app.run(str(case.case_id))
        assert fast_review_started.is_set()
        assert later_collector_finished.is_set()
        assert {"network.snapshot", "devices.snapshot"} <= set(result.completed_probe_ids)
        assert len(requests) == 3
        assert all(item.probe_id != "devices.snapshot" for item in requests[1].evidence_context)
        assert any(
            item.probe_id == "devices.snapshot"
            and item.facts.get("collection_status") == "unsupported"
            for item in requests[2].evidence_context
        )


def test_cancelled_coalesced_collection_does_not_start_post_result_deep(tmp_path: Path) -> None:
    from systemsense.application.investigation_state import InvestigationStatus
    from systemsense.decision.contracts import DecisionRequest, DecisionResponse

    cancel = threading.Event()
    requests: list[ReasoningRequest] = []

    class Deep:
        identity = ProviderIdentity(provider_id="deep", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            requests.append(request)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The cause is not established.",
                distinguishing_probes=(_proposal("network.snapshot"),),
            )

    class Decision:
        identity = ProviderIdentity(provider_id="fast", provider_version="1", role="fast_decision")

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    base = probe_definition("network")

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        cancel.set()
        assert base.handler is not None
        return base.handler(parameters)

    core = probe_definition("core")
    core = replace(core, manifest=core.manifest.model_copy(update={"probe_id": "core.system"}))
    with SQLiteStore(tmp_path / "cancelled-coalescing.db") as store:
        app = investigator(
            store,
            definitions=(core, replace(base, handler=collect)),
            reasoning=Deep(),
            decision=Decision(),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None, provider=Decision.identity, model_weight_sha256="a" * 64
        )
        case = app.create(objective="network issue", budget_ms=5_000, max_probes=2)
        started = time.monotonic()
        result = app.run(str(case.case_id), cancel_event=cancel)
        assert time.monotonic() - started < 2
        assert cancel.is_set()
        assert result.status is InvestigationStatus.CANCELLED
        assert len(requests) == 1


def test_fast_followup_completes_while_deep_waits_for_it(tmp_path: Path) -> None:
    from systemsense.application.investigation_state import InvestigationStatus
    from systemsense.decision.laya import LayaDecisionProvider
    from tests.integration.test_investigator_dynamic_followup import (
        ChoosingRanker,
        _investigator,  # pyright: ignore[reportPrivateUsage]
    )

    child_finished = threading.Event()
    deep_saw_child = threading.Event()

    class WaitingDeep:
        identity = ProviderIdentity(provider_id="waiting", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            assert child_finished.wait(2), "fast follow-up was blocked by deep inference"
            deep_saw_child.set()
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="No supported explanation.",
            )

    with SQLiteStore(tmp_path / "followup.db") as store:
        collected: list[str] = []
        app = _investigator(
            store,
            decision=LayaDecisionProvider(ranker=ChoosingRanker()),
            slow_started=threading.Event(),
            child_finished=child_finished,
            collected=collected,
        )
        app.reasoning = WaitingDeep()
        state = app.create(objective="Game runs at 12 FPS", budget_ms=8000, max_probes=3)
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "started",
            "Started controlled collection overlap.",
        )
        proposals = tuple(
            ProbeProposal(
                probe_id=capability.probe_id,
                purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
                priority=1,
                estimated_cost_ms=capability.cost_ms,
                resource_class=capability.resource_class,
                dedupe_key=capability.probe_id,
            )
            for capability in app.capabilities
            if capability.probe_id != "devices.snapshot"
        )
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, (), concurrent_proposals=proposals
        )
        assert deep_saw_child.is_set()
        assert collected.index("devices.snapshot") < collected.index("gpu.telemetry.sample")
        assert "devices.snapshot" in updated.completed_probe_ids
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM collection_followup_admissions WHERE case_id=?",
                (str(state.case_id),),
            ).fetchone()[0]
            == 1
        )


def test_cancelled_deep_worker_does_not_allow_another_provider_call(tmp_path: Path) -> None:
    from systemsense.inference.control import inference_cancellation

    started = threading.Event()
    release = threading.Event()
    cancel = threading.Event()
    base = probe_definition("network")

    class HangingDeep:
        identity = ProviderIdentity(provider_id="hanging", provider_version="1", role="reasoning")
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            started.set()
            assert release.wait(3)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="No supported explanation.",
            )

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert started.wait(1)
        cancel.set()
        assert base.handler is not None
        return base.handler(parameters)

    provider = HangingDeep()
    with SQLiteStore(tmp_path / "cancel.db") as store:
        app = investigator(store, definitions=(replace(base, handler=collect),), reasoning=provider)
        state = app.create(objective="network issue", budget_ms=3000)
        try:
            with inference_cancellation(cancel):
                state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                    state, (), concurrent_proposals=(_proposal("network.snapshot"),)
                )
            assert provider.calls == 1
            assert app._deep_lane.occupied  # pyright: ignore[reportPrivateUsage]
            app._reason(state, ())  # pyright: ignore[reportPrivateUsage]
            assert provider.calls == 1
        finally:
            release.set()
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]


def test_deep_start_failure_preserves_selected_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_start(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("no worker capacity")

    with SQLiteStore(tmp_path / "start-failure.db") as store:
        app = investigator(store, definitions=(probe_definition("network"),))
        monkeypatch.setattr(app._deep_lane, "start", reject_start)  # pyright: ignore[reportPrivateUsage]
        state = app.create(objective="network issue", budget_ms=3000)
        updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, (), concurrent_proposals=(_proposal("network.snapshot"),)
        )
        assert "network.snapshot" in updated.completed_probe_ids
        assert any("unavailable" in warning.lower() for warning in updated.warnings)


def test_one_investigator_rejects_concurrent_case_owners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    release = threading.Event()
    with SQLiteStore(tmp_path / "ownership.db") as store:
        app = investigator(store)
        first = app.create(objective="first", budget_ms=3000)
        second = app.create(objective="second", budget_ms=3000)

        def run_case(case_id: str, *, cancel_event: threading.Event | None) -> InvestigationState:
            if case_id == str(first.case_id):
                started.set()
                assert release.wait(2)
                return first
            return second

        monkeypatch.setattr(app, "_run", run_case)
        thread = threading.Thread(target=app.run, args=(str(first.case_id),))
        thread.start()
        try:
            assert started.wait(1)
            with pytest.raises(RuntimeError, match="owns this investigator"):
                app.run(str(second.case_id))
        finally:
            release.set()
            thread.join(1)
        assert app.run(str(second.case_id)) == second


def test_slow_deep_does_not_spend_remaining_case_budget_after_collection(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()
    base = probe_definition("network")

    class SlowDeep:
        identity = ProviderIdentity(provider_id="slow", provider_version="1", role="reasoning")

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            started.set()
            assert release.wait(2)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="No supported explanation.",
            )

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        assert started.wait(1)
        assert base.handler is not None
        return base.handler(parameters)

    with SQLiteStore(tmp_path / "bounded-wait.db") as store:
        app = investigator(
            store, definitions=(replace(base, handler=collect),), reasoning=SlowDeep()
        )
        state = app.create(objective="network issue", budget_ms=3000)
        try:
            before = time.monotonic()
            updated, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                state, (), concurrent_proposals=(_proposal("network.snapshot"),)
            )
            assert time.monotonic() - before < 0.5, "deep blocked the next fast round"
            assert "network.snapshot" in updated.completed_probe_ids
        finally:
            release.set()
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]


def test_deep_mailbox_survives_two_collections_and_merges_advisory_predictions(
    tmp_path: Path,
) -> None:
    from systemsense.inference.control import current_cancellation
    from systemsense.reasoning.contracts import ExpectedFact

    device = probe_definition("devices")
    device = replace(
        device,
        discovery=ProbeToolMetadataV1(
            probe_id="devices.snapshot",
            probe_version=1,
            observable_ids=("devices.snapshot",),
            parameter_fields=(),
            supports_window=False,
            outputs=(ProbeOutputFieldV1(name="value"),),
            estimated_cost_ms=25,
            resource_class="cpu",
            sensitivity=Sensitivity.SYSTEM_METADATA,
            network_effect="none",
            io_intensity="light",
            target_state_effect="none",
            self_writes=(SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
            purpose="Observe the synthetic device value",
        ),
        prediction_outputs=(ProbePredictionOutputV1(name="value", allowed_values=(0, 1)),),
    )

    release = threading.Event()
    started = threading.Event()
    provider_saw_cancel = threading.Event()

    class StrategicDeep:
        identity = ProviderIdentity(provider_id="strategic", provider_version="1", role="reasoning")
        calls = 0

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            started.set()
            assert release.wait(2)
            cancel = current_cancellation()
            if cancel is not None and cancel.is_set():
                provider_saw_cancel.set()
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.SUPPORTED,
                summary="Advisory device explanation.",
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="device",
                        statement="A device condition may explain the symptom.",
                        status=HypothesisStatus.SUPPORTED,
                        supporting_evidence_ids=(request.evidence_context[0].evidence_id,),
                        expected_facts=(
                            ExpectedFact(
                                probe_id="devices.snapshot", fact_name="value", expected_value=1
                            ),
                        ),
                    ),
                ),
                distinguishing_probes=(_proposal("devices.snapshot"),),
            )

    provider = StrategicDeep()
    with SQLiteStore(tmp_path / "cross-round.db") as store:
        app = investigator(
            store,
            reasoning=provider,
            definitions=tuple(
                device if name == "devices" else probe_definition(name)
                for name in ("core", "network", "storage", "devices")
            ),
        )
        state = app.create(objective="application issue", budget_ms=4000)
        state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        try:
            state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                state,
                app.context(str(state.case_id), state=state),
                concurrent_proposals=(_proposal("network.snapshot"),),
            )
            assert started.wait(1)
            state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
                state,
                app.context(str(state.case_id), state=state),
                concurrent_proposals=(_proposal("storage.snapshot"),),
            )
            assert provider.calls == 1
        finally:
            release.set()
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        assert not provider_saw_cancel.is_set(), "unrelated observations cancelled strategic work"
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert state.hypotheses[0].status is HypothesisStatus.UNRESOLVED
        assert state.hypotheses[0].expected_facts
        assert state.hypotheses[0].expected_facts[0].probe_version == 1
        assert state.hypotheses[0].expected_facts_observed_after is not None
        assert state.assessment is None
        assert tuple(p.probe_id for p in state.pending_distinguishing_probes) == (
            "devices.snapshot",
        )
        assert (
            store.connection.execute("SELECT status FROM deep_mailbox").fetchone()[0] == "applied"
        )
